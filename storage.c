#include <assert.h> // For assert()
#include <errno.h>
#include <fcntl.h>  // For O_* flags (needed by uv_fs_open)
#include <libgen.h> // For dirname
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // For mkdir mode, S_IFDIR
#include <uv.h>

#define DEFAULT_BACKLOG   128
#define READ_BUFFER_SIZE  4096
#define WRITE_BUFFER_SIZE 4096
#define MAX_PATH_LEN      512
#define MAX_HEADER_LEN    8192 // Max size for accumulating request headers

char root_dir[MAX_PATH_LEN];
uv_loop_t* loop;

typedef struct client_context_s client_context_t;
void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf);
void on_alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void on_close(uv_handle_t* handle);
void close_client(client_context_t* ctx);

typedef enum {
  READING_HEADERS,
  READING_BODY,
  WRITING_RESPONSE,
  FILE_OP,
  CLOSING
} client_state_t;

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  char buffer[WRITE_BUFFER_SIZE];
} write_req_t;

typedef struct {
  uv_work_t req;
  client_context_t* client_ctx;
  char path[MAX_PATH_LEN];
  int result;
} mkdirs_work_t;

struct client_context_s {
  uv_tcp_t handle;
  uv_fs_t fs_req; // For async file operations
  client_state_t state;
  char request_buffer[MAX_HEADER_LEN]; // Buffer to accumulate headers
  size_t request_buffer_len;
  char method[16];
  char url[MAX_PATH_LEN];
  char filepath[MAX_PATH_LEN]; // Full path on server
  long long content_length;
  long long body_bytes_received;
  long long file_size;
  long long file_bytes_sent;
  int file_fd;           // File descriptor from uv_fs_open
  char* body_start;      // Pointer to start of body in request_buffer (if any)
  size_t body_in_buffer; // Size of body data already in request_buffer
};

// Simple helper to create write requests
write_req_t*
create_write_req(const char* data, ssize_t len)
{
  write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
  if (!wr)
    return NULL;

  // Ensure len isn't too large if using embedded buffer
  ssize_t copy_len = len;
  if (len < 0) { // If len is -1, assume null terminated string
    copy_len = strlen(data);
  }

  if (copy_len >= WRITE_BUFFER_SIZE) {
    fprintf(stderr, "Write request too large for embedded buffer\n");
    free(wr);
    return NULL; // Or handle dynamic allocation
  }

  memcpy(wr->buffer, data, copy_len);
  wr->buffer[copy_len] = '\0'; // Null terminate for safety if needed
  wr->buf = uv_buf_init(wr->buffer, copy_len);
  return wr;
}

// Callback after a uv_write operation completes
void
on_write_complete(uv_write_t* req, int status)
{
  write_req_t* wr = (write_req_t*)req; // We stored our write_req_t pointer in uv_write_t
  client_context_t* ctx = (client_context_t*)req->handle->data;

  if (status < 0) {
    fprintf(stderr, "Write error: %s\n", uv_strerror(status));
    // Don't close here if already closing
    if (ctx && ctx->state != CLOSING) {
      close_client(ctx);
    }
  }

  // Free the write request structure and potentially its buffer if dynamically allocated
  free(wr);

  // If this write was the end of the response, we might close here
  // Or if it was a chunk of a file, we might trigger the next read/write
  // This logic is handled within specific operation flows (e.g., on_fs_event for GET)
}

// Generic callback for uv_fs operations
void
on_fs_event(uv_fs_t* req)
{
  client_context_t* ctx = (client_context_t*)req->data;
  int result = req->result;

  // Check context validity
  if (!ctx || ctx->state == CLOSING) {
    // If client is already closing, just clean up FS resources
    if (req->fs_type == UV_FS_OPEN && result >= 0) {
      uv_fs_close(loop, &ctx->fs_req, result, NULL); // Fire-and-forget close
    }
    uv_fs_req_cleanup(req);
    return;
  }

  ctx->state = FILE_OP; // Mark state during FS handling

  switch (req->fs_type) {
  case UV_FS_OPEN:
    if (result < 0) {
      fprintf(stderr, "Error opening file %s: %s\n", ctx->filepath, uv_strerror(result));
      const char* response;
      if (result == UV_ENOENT) {
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";
      } else {
        response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\n\r\nError opening file\n";
      }
      write_req_t* wr = create_write_req(response, -1);
      if (wr) {
        ctx->state = WRITING_RESPONSE;
        uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
      }
      // Close after sending response - handled implicitly by state change and eventual close
      close_client(ctx);

    } else {
      ctx->file_fd = result; // Store file descriptor
      if (strcmp(ctx->method, "GET") == 0) {
        // File opened successfully for GET, now get its size
        uv_fs_fstat(loop, &ctx->fs_req, ctx->file_fd, on_fs_event);
      } else if (strcmp(ctx->method, "POST") == 0) {
        // File opened successfully for POST, now start writing body
        ctx->state = READING_BODY;    // Ready to write received body data
        ctx->body_bytes_received = 0; // Ensure counter is reset

        // Check if some body data was already in the initial buffer
        if (ctx->body_start && ctx->body_in_buffer > 0) {
          uv_buf_t write_buf = uv_buf_init(ctx->body_start, ctx->body_in_buffer);
          // Note: uv_fs_write modifies the request struct, so use ctx->fs_req
          // We write starting at offset 0
          uv_fs_write(loop, &ctx->fs_req, ctx->file_fd, &write_buf, 1, 0, on_fs_event);
          ctx->body_bytes_received += ctx->body_in_buffer;
          // Clear these so they aren't processed again
          ctx->body_start = NULL;
          ctx->body_in_buffer = 0;
        } else if (ctx->content_length == 0) {
          // If content length was 0, we are done.
          char response[] = "HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\nCreated\n";
          write_req_t* wr = create_write_req(response, -1);
          if (wr) {
            ctx->state = WRITING_RESPONSE;
            uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
          }
          // Close the file first!
          uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, on_fs_event);
          ctx->file_fd = -1; // Mark as closed
        } else {
          // Start reading body from socket if not already done
          uv_read_start((uv_stream_t*)&ctx->handle, on_alloc_buffer, on_read);
        }
      }
    }
    break;

  case UV_FS_FSTAT:
    if (result < 0) {
      fprintf(stderr, "Error stating file %s: %s\n", ctx->filepath, uv_strerror(result));
      const char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 18\r\n\r\nError getting size\n";
      write_req_t* wr = create_write_req(response, -1);
      if (wr) {
        ctx->state = WRITING_RESPONSE;
        uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
      }
      uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL); // Best effort close
      close_client(ctx);
    } else {
      ctx->file_size = req->statbuf.st_size;
      ctx->file_bytes_sent = 0;

      // Send HTTP header for GET
      char header[256];
      int header_len = snprintf(header, sizeof(header),
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/octet-stream\r\n"
          "Content-Length: %lld\r\n\r\n",
          ctx->file_size);

      write_req_t* wr = create_write_req(header, header_len);
      if (wr) {
        ctx->state = WRITING_RESPONSE; // Indicate we are sending response now
        uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
        // After header is sent, start reading file content
        // Need a buffer for file reading, allocate inside write_req_t or separately
        write_req_t* file_read_wr = malloc(sizeof(write_req_t)); // Re-use write_req struct for buffer mgmt
        if (!file_read_wr) {
          perror("Failed to allocate buffer for file read");
          uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL);
          close_client(ctx);
          break; // Exit case UV_FS_FSTAT
        }
        file_read_wr->buf = uv_buf_init(file_read_wr->buffer, sizeof(file_read_wr->buffer));
        // Store pointer in fs_req for retrieval in callback
        ctx->fs_req.data = file_read_wr;
        uv_fs_read(loop, &ctx->fs_req, ctx->file_fd, &file_read_wr->buf, 1, ctx->file_bytes_sent, on_fs_event);

      } else {
        fprintf(stderr, "Failed to create header write request\n");
        uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL);
        close_client(ctx);
      }
    }
    break;

  case UV_FS_READ: {                                     // New scope for variable declaration
    write_req_t* file_read_wr = (write_req_t*)req->data; // Retrieve the buffer info

    if (result < 0) {
      fprintf(stderr, "Error reading file %s: %s\n", ctx->filepath, uv_strerror(result));
      free(file_read_wr);                                  // Free the buffer structure
      uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL); // Best effort close
      close_client(ctx);
    } else if (result == 0) {
      // EOF reached
      free(file_read_wr); // Free the buffer structure
      // File fully sent, close file and then client connection
      uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, on_fs_event); // Trigger close callback
      ctx->file_fd = -1;                                          // Mark as closed
    } else {
      // Successfully read 'result' bytes into file_read_wr->buffer
      ctx->file_bytes_sent += result;

      // Create a new write request for this chunk
      // Important: The buffer (file_read_wr->buffer) must remain valid until on_write_complete
      // So we pass file_read_wr itself to on_write_complete
      uv_write_t* wreq = (uv_write_t*)malloc(sizeof(uv_write_t)); // Need a separate uv_write_t
      if (!wreq) {
        perror("Failed alloc write req for file chunk");
        free(file_read_wr);
        uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL);
        close_client(ctx);
        break;
      }
      wreq->data = file_read_wr; // Link the buffer info

      uv_buf_t write_buf = uv_buf_init(file_read_wr->buffer, result);
      uv_write(wreq, (uv_stream_t*)&ctx->handle, &write_buf, 1, [](uv_write_t* wreq, int status) {
        // This callback is primarily to free the buffer and request struct
        write_req_t* fr_wr = (write_req_t*)wreq->data;
        client_context_t* ctx_inner = (client_context_t*)wreq->handle->data;
        free(fr_wr); // Free the structure holding the buffer
        free(wreq);  // Free the uv_write_t

        if (status < 0) {
          fprintf(stderr, "Write error sending file chunk: %s\n", uv_strerror(status));
          if (ctx_inner && ctx_inner->state != CLOSING) {
            uv_fs_close(loop, &ctx_inner->fs_req, ctx_inner->file_fd, NULL);
            close_client(ctx_inner);
          }
          return;
        }

        // If client still valid and file not closed, read the next chunk
        if (ctx_inner && ctx_inner->state != CLOSING && ctx_inner->file_fd != -1) {
          write_req_t* next_file_read_wr = malloc(sizeof(write_req_t));
          if (!next_file_read_wr) {
            perror("Failed alloc buffer for next file read");
            uv_fs_close(loop, &ctx_inner->fs_req, ctx_inner->file_fd, NULL);
            close_client(ctx_inner);
            return;
          }
          next_file_read_wr->buf = uv_buf_init(next_file_read_wr->buffer, sizeof(next_file_read_wr->buffer));
          ctx_inner->fs_req.data = next_file_read_wr; // Link for next callback
          uv_fs_read(loop, &ctx_inner->fs_req, ctx_inner->file_fd, &next_file_read_wr->buf, 1, ctx_inner->file_bytes_sent, on_fs_event);
        }
      });
    }
  } break;

  case UV_FS_WRITE:
    if (result < 0) {
      fprintf(stderr, "Error writing to file %s: %s\n", ctx->filepath, uv_strerror(result));
      // Send error response
      const char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 19\r\n\r\nFailed file write\n";
      write_req_t* wr = create_write_req(response, -1);
      if (wr) {
        ctx->state = WRITING_RESPONSE;
        uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
      }
      uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL); // Best effort close
      close_client(ctx);

    } else {
      // Written 'result' bytes. Note: uv_fs_write writes all or errors.
      // We tracked bytes received from socket in body_bytes_received already

      if (ctx->body_bytes_received >= ctx->content_length) {
        // Finished writing file
        char response[] = "HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\nCreated\n";
        write_req_t* wr = create_write_req(response, -1);
        if (wr) {
          ctx->state = WRITING_RESPONSE;
          uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
        }
        // Close the file *after* sending response potentially? No, close now.
        uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, on_fs_event);
        ctx->file_fd = -1; // Mark as closed
      } else {
        // More data expected, ensure reading continues
        ctx->state = READING_BODY; // Ready for more data
        uv_read_start((uv_stream_t*)&ctx->handle, on_alloc_buffer, on_read);
      }
    }
    break;

  case UV_FS_CLOSE:
    // File handle closed.
    ctx->file_fd = -1; // Mark as invalid
    // If the operation that triggered the close was the *last* step, close client.
    if (ctx->state != CLOSING) {
      // If we were writing a response or finishing a GET/POST, now close socket.
      if (strcmp(ctx->method, "GET") == 0 && ctx->file_bytes_sent >= ctx->file_size) {
        close_client(ctx);
      } else if (strcmp(ctx->method, "POST") == 0 && ctx->body_bytes_received >= ctx->content_length) {
        close_client(ctx);
      }
      // Otherwise, maybe an error happened, close handled elsewhere.
    }
    break;

  default:
    fprintf(stderr, "Warning: Unhandled fs_type %d\n", req->fs_type);
    break;
  }

  // Cleanup the request structure *unless* it's needed for a subsequent linked operation
  // (like uv_fs_close after a read/write error)
  if (req->fs_type != UV_FS_CLOSE &&                                                  // Don't cleanup close itself
      !(req->fs_type == UV_FS_READ && result > 0) &&                                  // Don't cleanup if read successful (buffer passed to write)
      !(req->fs_type == UV_FS_OPEN && result >= 0 && strcmp(ctx->method, "GET") == 0) // Keep for fstat
  ) {
    uv_fs_req_cleanup(req);
  }
  // Careful: If an operation failed and we issued a uv_fs_close, the original req might
  // still be in use by the close operation. Libuv handles this internally.
}

// --- mkdirs helper using uv_queue_work ---

// The actual blocking work for mkdirs
void
mkdirs_work_cb(uv_work_t* req)
{
  mkdirs_work_t* work = (mkdirs_work_t*)req->data;
  char tmp[MAX_PATH_LEN];
  char* p = NULL;
  snprintf(tmp, sizeof(tmp), "%s", work->path);
  size_t len = strlen(tmp);

  if (len == 0) { // Cannot create empty path
    work->result = -1;
    return;
  }
  if (tmp[len - 1] == '/') {
    tmp[len - 1] = 0;
  }

  struct stat st;
  // Check if path already exists and is a directory
  if (stat(tmp, &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
      work->result = 0; // Already exists
      return;
    } else {
      errno = ENOTDIR; // Exists but is not a directory
      work->result = -1;
      return;
    }
  }

  // Create intermediate directories
  // Skip leading '/' if present
  for (p = tmp + (tmp[0] == '/'); *p; p++) {
    if (*p == '/') {
      *p = 0;
      // Use uv_fs_mkdir sync equivalent for simplicity inside worker thread
      // Or just use standard mkdir
      if (mkdir(tmp, 0755) != 0) {
        if (errno != EEXIST) {
          work->result = -1;
          *p = '/'; // Restore for potential future use/logging?
          return;
        }
        // If EEXIST, it's okay, might be concurrent creation or pre-existing
      }
      *p = '/';
    }
  }

  // Create the final directory
  if (mkdir(tmp, 0755) != 0) {
    if (errno != EEXIST) {
      work->result = -1;
      return;
    }
  }

  work->result = 0; // Success
}

// After mkdirs work is done (runs in the loop thread)
void
mkdirs_after_work_cb(uv_work_t* req, int status)
{
  mkdirs_work_t* work = (mkdirs_work_t*)req->data;
  client_context_t* ctx = work->client_ctx;

  // Check if client is still valid
  if (!ctx || ctx->state == CLOSING) {
    free(work);
    return;
  }

  if (status < 0 || work->result < 0) {
    fprintf(stderr, "Failed to create directories for %s (status: %d, result: %d, errno: %d)\n",
        work->path, status, work->result, work->result < 0 ? errno : 0);
    // Send error response
    char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 20\r\n\r\nCannot create path\n";
    write_req_t* wr = create_write_req(response, -1);
    if (wr) {
      ctx->state = WRITING_RESPONSE;
      uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
    }
    close_client(ctx);
  } else {
    // Directories created successfully, now open the file for writing
    ctx->fs_req.data = ctx; // Associate context with FS request
    uv_fs_open(loop, &ctx->fs_req, ctx->filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644, on_fs_event);
  }

  free(work); // Free the work request structure
}

// --- HTTP Request Parsing and Handling ---

// VERY basic HTTP header parser
// Looks for method, URL, Content-Length, and end of headers (\r\n\r\n)
// Returns 1 if headers complete, 0 if not, -1 on error
int
parse_http_headers(client_context_t* ctx)
{
  char* headers_end = strstr(ctx->request_buffer, "\r\n\r\n");
  if (!headers_end) {
    return 0; // Headers not complete yet
  }

  // Null-terminate the header section for easier parsing
  *headers_end = '\0';
  size_t header_section_len = headers_end - ctx->request_buffer;

  // Parse the first line: METHOD URL VERSION
  char* first_line_end = strstr(ctx->request_buffer, "\r\n");
  if (!first_line_end)
    return -1; // Malformed
  *first_line_end = '\0';

  char* method_end = strchr(ctx->request_buffer, ' ');
  if (!method_end)
    return -1; // Malformed
  strncpy(ctx->method, ctx->request_buffer, method_end - ctx->request_buffer);
  ctx->method[method_end - ctx->request_buffer] = '\0';

  char* url_start = method_end + 1;
  char* url_end = strchr(url_start, ' '); // Find space before HTTP version
  if (!url_end)
    return -1; // Malformed
  strncpy(ctx->url, url_start, url_end - url_start);
  ctx->url[url_end - url_start] = '\0';

  *first_line_end = '\r'; // Restore for potential later use? (Not strictly necessary)

  // Find Content-Length header (case-insensitive search)
  ctx->content_length = 0;                                // Default
  char* header_line = strtok(first_line_end + 2, "\r\n"); // Start after first line
  while (header_line != NULL) {
    if (strncasecmp(header_line, "Content-Length:", 15) == 0) {
      ctx->content_length = atoll(header_line + 15);
      break; // Found it
    }
    header_line = strtok(NULL, "\r\n"); // Get next header line
  }

  // Restore header buffer end marker for body calculation
  *headers_end = '\r';

  // Calculate where body starts and how much is already in the buffer
  ctx->body_start = headers_end + 4; // Point after \r\n\r\n
  size_t total_parsed_len = (headers_end + 4) - ctx->request_buffer;
  if (ctx->request_buffer_len > total_parsed_len) {
    ctx->body_in_buffer = ctx->request_buffer_len - total_parsed_len;
  } else {
    ctx->body_in_buffer = 0;
    ctx->body_start = NULL; // No body data in this buffer
  }

  return 1; // Headers parsed successfully
}

void
url_to_filepath(const char* url, char* filepath_out, size_t size)
{
  char clean_url[MAX_PATH_LEN];
  strncpy(clean_url, url, sizeof(clean_url) - 1);
  clean_url[sizeof(clean_url) - 1] = '\0';

  // Remove query string if present
  char* question_mark = strchr(clean_url, '?');
  if (question_mark) {
    *question_mark = '\0';
  }

  // Handle root case
  if (strcmp(clean_url, "/") == 0 || strlen(clean_url) == 0) {
    snprintf(filepath_out, size, "%s/index", root_dir);
  } else {
    // Basic path traversal prevention (very basic)
    if (strstr(clean_url, "..")) {
      snprintf(filepath_out, size, "%s/invalid_path", root_dir); // Or handle error more robustly
      return;
    }
    snprintf(filepath_out, size, "%s%s", root_dir, clean_url);
  }
  // Sanitize further if needed (e.g., decode URL encoding)
}

void
handle_request(client_context_t* ctx)
{
  url_to_filepath(ctx->url, ctx->filepath, sizeof(ctx->filepath));
  printf("Request: %s %s -> %s (Content-Length: %lld)\n", ctx->method, ctx->url, ctx->filepath, ctx->content_length);

  if (strcmp(ctx->method, "GET") == 0) {
    ctx->state = FILE_OP;
    ctx->fs_req.data = ctx;
    uv_fs_open(loop, &ctx->fs_req, ctx->filepath, O_RDONLY, 0, on_fs_event);
  } else if (strcmp(ctx->method, "POST") == 0) {
    // Need to create directories first using the worker thread approach
    char dirpath[MAX_PATH_LEN];
    strncpy(dirpath, ctx->filepath, sizeof(dirpath) - 1);
    dirpath[sizeof(dirpath) - 1] = '\0';

    char* parent_dir = dirname(dirpath); // WARNING: dirname might modify dirpath!
                                         // Make a copy if necessary. For this example, assume ok.
                                         // If parent_dir is "." or "/", no need to create.

    if (strcmp(parent_dir, ".") != 0 && strcmp(parent_dir, "/") != 0) {
      mkdirs_work_t* work = (mkdirs_work_t*)malloc(sizeof(mkdirs_work_t));
      if (!work) {
        perror("Failed to allocate mkdirs work");
        char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 19\r\n\r\nInternal error #1\n";
        write_req_t* wr = create_write_req(response, -1);
        if (wr)
          uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
        close_client(ctx);
        return;
      }
      work->req.data = work;
      work->client_ctx = ctx;
      strncpy(work->path, parent_dir, MAX_PATH_LEN - 1);
      work->path[MAX_PATH_LEN - 1] = '\0';
      work->result = -1; // Default to error

      ctx->state = FILE_OP; // Indicate async operation running
      uv_queue_work(loop, &work->req, mkdirs_work_cb, mkdirs_after_work_cb);
    } else {
      // No intermediate dirs needed, just open the file directly
      ctx->state = FILE_OP;
      ctx->fs_req.data = ctx;
      uv_fs_open(loop, &ctx->fs_req, ctx->filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644, on_fs_event);
    }

  } else {
    // Unsupported method
    const char response[] = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 19\r\n\r\nMethod Not Allowed\n";
    write_req_t* wr = create_write_req(response, -1);
    if (wr) {
      ctx->state = WRITING_RESPONSE;
      uv_write(&wr->req, (uv_stream_t*)&ctx->handle, &wr->buf, 1, on_write_complete);
    }
    close_client(ctx); // Close after sending response
  }
}

// --- libuv Callbacks ---

void
on_alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
  // Allocate buffer for reading. +1 for null terminator safety if needed.
  // Using a fixed-size buffer per client might be better in a real server.
  *buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
  if (buf->base == NULL) {
    fprintf(stderr, "Failed to allocate read buffer\n");
    // No context here directly, but can try to close handle if possible
    uv_close(handle, NULL); // Attempt basic close
  }
}

void
on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
  client_context_t* ctx = (client_context_t*)client->data;

  if (!ctx || ctx->state == CLOSING) {
    if (buf->base)
      free(buf->base); // Free allocated buffer if context gone
    return;
  }

  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Read error: %s\n", uv_err_name(nread));
    }
    // Client disconnected or error
    close_client(ctx);
    if (buf->base)
      free(buf->base); // Free the buffer allocated by on_alloc_buffer
    return;
  }

  if (nread == 0) {
    // This means EAGAIN or EWOULDBLOCK, just ignore and wait for next read event.
    if (buf->base)
      free(buf->base);
    return;
  }

  // --- Process received data ---
  if (ctx->state == READING_HEADERS) {
    // Append data to request buffer
    if (ctx->request_buffer_len + nread > MAX_HEADER_LEN) {
      fprintf(stderr, "Request headers too large\n");
      // Send 413 Payload Too Large? Or just close.
      close_client(ctx);
      if (buf->base)
        free(buf->base);
      return;
    }
    memcpy(ctx->request_buffer + ctx->request_buffer_len, buf->base, nread);
    ctx->request_buffer_len += nread;
    ctx->request_buffer[ctx->request_buffer_len] = '\0'; // Null terminate

    // Try parsing headers
    int parse_result = parse_http_headers(ctx);

    if (parse_result == 1) {
      // Headers complete! Stop reading for now.
      uv_read_stop(client);
      handle_request(ctx); // Process the request (GET/POST etc.)
                           // handle_request will start async ops (FS or worker)
                           // If POST and body data was in this buffer, handle_request -> on_fs_event(open)
                           // will start the uv_fs_write with ctx->body_start/body_in_buffer.
    } else if (parse_result == -1) {
      fprintf(stderr, "Malformed HTTP request\n");
      // Send 400 Bad Request? Or just close.
      close_client(ctx);
    }
    // If parse_result == 0, headers incomplete, wait for more data in next on_read

  } else if (ctx->state == READING_BODY) {
    // Assumes we are in POST request and file is open (fd is valid)
    if (ctx->file_fd < 0) {
      fprintf(stderr, "Error: Reading body but file not open.\n");
      close_client(ctx);
      if (buf->base)
        free(buf->base);
      return;
    }

    // Stop reading temporarily while FS write happens
    uv_read_stop(client);

    ctx->body_bytes_received += nread;

    // Use the buffer directly from on_read for uv_fs_write
    // Need to ensure buf->base persists until FS write completes.
    // We can copy it, or manage the lifetime carefully. Let's copy for simplicity.
    char* write_buf_data = malloc(nread);
    if (!write_buf_data) {
      perror("Failed to alloc buffer for fs_write");
      close_client(ctx);
      if (buf->base)
        free(buf->base);
      return;
    }
    memcpy(write_buf_data, buf->base, nread);
    uv_buf_t write_buf = uv_buf_init(write_buf_data, nread);

    // Associate buffer with request to free it in the callback
    ctx->fs_req.data = write_buf_data;

    // Write at the offset corresponding to bytes *previously* written
    uv_fs_write(loop, &ctx->fs_req, ctx->file_fd, &write_buf, 1, ctx->body_bytes_received - nread,
        [](uv_fs_t* req) {
          // FS write completion callback (nested)
          char* data_ptr = (char*)req->data; // Get buffer pointer
          if (data_ptr)
            free(data_ptr);                                 // Free the copied buffer
          req->data = ((client_context_t*)req->loop->data); // Restore context pointer for main handler
          on_fs_event(req);                                 // Call main FS handler
        });

  } else {
    // Should not be reading in other states? Maybe log warning.
    // fprintf(stderr, "Warning: Data received in unexpected state %d\n", ctx->state);
  }

  // Free the buffer allocated by on_alloc_buffer for this read operation
  if (buf->base)
    free(buf->base);
}

void
on_close(uv_handle_t* handle)
{
  client_context_t* ctx = (client_context_t*)handle->data;
  printf("Connection closed.\n");
  // Free the context structure itself
  if (ctx) {
    // Ensure file descriptor is closed if it was still open
    if (ctx->file_fd >= 0) {
      // Use synchronous close here as we are cleaning up anyway
      // Or fire-and-forget async close
      uv_fs_req_cleanup(&ctx->fs_req); // Clean any pending FS request state
      // close(ctx->file_fd); // Might block briefly
      uv_fs_close(loop, &ctx->fs_req, ctx->file_fd, NULL); // Fire and forget async
    }
    free(ctx);
  }
}

void
close_client(client_context_t* ctx)
{
  if (ctx && ctx->state != CLOSING) {
    printf("Closing client connection...\n");
    ctx->state = CLOSING;
    // Ensure read stops
    uv_read_stop((uv_stream_t*)&ctx->handle);
    // Clean up any pending FS request (important!)
    // uv_fs_req_cleanup(&ctx->fs_req); // Done in on_close now

    // Close the handle - on_close callback will free the context
    uv_close((uv_handle_t*)&ctx->handle, on_close);
  }
}

void
on_new_connection(uv_stream_t* server, int status)
{
  if (status < 0) {
    fprintf(stderr, "New connection error: %s\n", uv_strerror(status));
    return;
  }

  // Allocate context for the new client
  client_context_t* ctx = (client_context_t*)malloc(sizeof(client_context_t));
  if (!ctx) {
    fprintf(stderr, "Failed to allocate memory for client context\n");
    // Cannot accept client without context
    // How to properly reject? Maybe accept then immediately close?
    uv_tcp_t temp_client;
    uv_tcp_init(loop, &temp_client);
    if (uv_accept(server, (uv_stream_t*)&temp_client) == 0) {
      uv_close((uv_handle_t*)&temp_client, NULL); // Close immediately
    }
    return;
  }

  // Initialize the context
  memset(ctx, 0, sizeof(client_context_t));
  ctx->state = READING_HEADERS;
  ctx->request_buffer_len = 0;
  ctx->file_fd = -1;        // Indicate no file open initially
  ctx->content_length = -1; // Unknown
  ctx->handle.data = ctx;   // Link context to handle
  ctx->fs_req.data = ctx;   // Link context to fs request structure too
                            // (will be overwritten per operation if needed)

  // Initialize the client handle
  uv_tcp_init(loop, &ctx->handle);

  // Accept the connection
  if (uv_accept(server, (uv_stream_t*)&ctx->handle) == 0) {
    printf("New connection accepted.\n");
    // Start reading data from the client
    uv_read_start((uv_stream_t*)&ctx->handle, on_alloc_buffer, on_read);
  } else {
    fprintf(stderr, "Failed to accept client connection.\n");
    // Close the handle and free context if accept failed
    uv_close((uv_handle_t*)&ctx->handle, on_close); // on_close will free ctx
  }
}

// --- Main Function ---

int
main(int argc, char** argv)
{
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <port> <root_dir>\n", argv[0]);
    return EXIT_FAILURE;
  }

  int port = atoi(argv[1]);
  strncpy(root_dir, argv[2], sizeof(root_dir) - 1);
  root_dir[sizeof(root_dir) - 1] = '\0';

  // Create root directory if it doesn't exist (synchronously before loop)
  struct stat st = { 0 };
  if (stat(root_dir, &st) == -1) {
    if (mkdir(root_dir, 0755) != 0) {
      perror("Failed to create root directory");
      return EXIT_FAILURE;
    }
    printf("Created root directory: %s\n", root_dir);
  } else if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "Error: %s exists but is not a directory\n", root_dir);
    return EXIT_FAILURE;
  }

  loop = uv_default_loop();
  if (!loop) {
    fprintf(stderr, "Failed to initialize event loop\n");
    return EXIT_FAILURE;
  }
  // Store context pointer in loop data for nested FS callbacks
  loop->data = NULL; // Initially no shared context needed

  uv_tcp_t server_handle;
  uv_tcp_init(loop, &server_handle);

  struct sockaddr_in bind_addr;
  uv_ip4_addr("0.0.0.0", port, &bind_addr);

  uv_tcp_bind(&server_handle, (const struct sockaddr*)&bind_addr, 0);

  int r = uv_listen((uv_stream_t*)&server_handle, DEFAULT_BACKLOG, on_new_connection);
  if (r) {
    fprintf(stderr, "Listen error: %s\n", uv_strerror(r));
    return EXIT_FAILURE;
  }

  printf("Server listening on port %d\n", port);
  printf("Storage directory: %s\n", root_dir);

  // Start the event loop
  uv_run(loop, UV_RUN_DEFAULT);

  // --- Cleanup (usually not reached in a simple server unless uv_stop is called) ---
  printf("Server shutting down.\n");
  // Close loop resources if necessary, uv_loop_close(loop) after all handles closed.

  return 0;
}
