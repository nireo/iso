#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PORT 8080
#define MAX_HEADER_SIZE 1024
#define BUFFER_SIZE 4096

#define FILE_PATH_MAX_SIZE 128
#define MAX_VOLUME_SIZE 64
#define MAX_VOLUMES 6

typedef struct {
  uint16_t ports[16];
  size_t volume_count;
  char volumes[16][64];
} Iso;

static void add_volume(Iso *iso, const char *addr, uint16_t port) {
  memcpy(iso->volumes[iso->volume_count], addr, strlen(addr) + 1);
  iso->ports[iso->volume_count] = port;
  iso->volume_count++;
}

static char *key_to_path(const char *key, size_t keylen) {
  unsigned int hash = 0;
  for (size_t i = 0; i < keylen; i++) {
    hash = ((hash << 5) + hash) + (unsigned char)key[i];
  }

  unsigned char hash_chars[2];
  hash_chars[0] = (hash >> 8) & 0xFF;
  hash_chars[1] = hash & 0xFF;

  size_t encoded_size = 4 * ((keylen + 2) / 3) + 1;
  char *encoded = malloc(encoded_size);
  if (!encoded)
    return NULL;

  const char base64_chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  size_t j = 0;
  for (size_t i = 0; i < keylen; i += 3) {
    unsigned int val =
        ((i < keylen) ? ((unsigned char)key[i]) << 16 : 0) |
        ((i + 1 < keylen) ? ((unsigned char)key[i + 1]) << 8 : 0) |
        ((i + 2 < keylen) ? ((unsigned char)key[i + 2]) : 0);

    encoded[j++] = base64_chars[(val >> 18) & 0x3F];
    encoded[j++] = base64_chars[(val >> 12) & 0x3F];
    encoded[j++] = (i + 1 < keylen) ? base64_chars[(val >> 6) & 0x3F] : '=';
    encoded[j++] = (i + 2 < keylen) ? base64_chars[val & 0x3F] : '=';
  }
  encoded[j] = '\0';

  size_t nbytes = snprintf(NULL, 0, "/%02x/%02x/%s", hash_chars[0],
                           hash_chars[1], encoded) +
                  1;
  char *path = malloc(nbytes * sizeof(char));
  if (!path) {
    free(encoded);
    return NULL;
  }

  snprintf(path, nbytes, "/%02x/%02x/%s", hash_chars[0], hash_chars[1],
           encoded);
  free(encoded);

  return path;
}

static int pick_volume(Iso *fs, const char *key, size_t keylen) {
  int best_volume = 0;
  unsigned long best_score = ULONG_MAX;
  int first = 1;

  for (int i = 0; i < fs->volume_count; ++i) {
    unsigned long curr_score = 0;
    size_t vol_len = strlen(fs->volumes[i]);

    const unsigned long FNV_PRIME = 16777619UL;
    const unsigned long FNV_OFFSET = 2166136261UL;

    curr_score = FNV_OFFSET;
    for (size_t j = 0; j < vol_len; j++) {
      curr_score ^= (unsigned char)fs->volumes[i][j];
      curr_score *= FNV_PRIME;
    }

    for (size_t j = 0; j < keylen; j++) {
      curr_score ^= (unsigned char)key[j];
      curr_score *= FNV_PRIME;
    }

    if (first == 1 || curr_score < best_score) {
      first = 0;
      best_score = curr_score;
      best_volume = i;
    }
  }

  return best_volume;
}

void send_response(int client_socket, int status_code, const char *status_text,
                   const char *content_type, const char *body) {
  char header[MAX_HEADER_SIZE];
  int body_len = strlen(body);

  snprintf(header, MAX_HEADER_SIZE,
           "HTTP/1.1 %d %s\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %d\r\n"
           "Connection: close\r\n"
           "\r\n",
           status_code, status_text, content_type, body_len);

  send(client_socket, header, strlen(header), 0);
  send(client_socket, body, body_len, 0);
}

static int connect_to_forward_server(const char *addr, uint16_t port) {
  int forward_socket;
  struct sockaddr_in server_addr;

  if ((forward_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("forward socket creation failed");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  // TODO: handle forward port or somethin
  server_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, addr, &server_addr.sin_addr) < 0) {
    perror("invalid address or adress not supported");
    return -1;
  }

  if (connect(forward_socket, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    perror("connection to forward server failed");
    close(forward_socket);
    return -1;
  }

  return forward_socket;
}

void handle_get(int client_socket, const char *path) {
  char response_body[BUFFER_SIZE];
  snprintf(response_body, BUFFER_SIZE,
           "<html><body><h1>Hello from C HTTP Server</h1>"
           "<p>GET request received for path: %s</p></body></html>",
           path);

  send_response(client_socket, 200, "OK", "text/html", response_body);
}

void handle_post(Iso *iso, int client_socket, const char *path,
                 const char *body, int clen) {
  printf("writing file %s to volume idx", path);
  const int path_len = strlen(path);
  const int chosen_volume = pick_volume(iso, path, path_len);
  printf("%d\n", chosen_volume);

  char request_header[BUFFER_SIZE];
  snprintf(request_header, MAX_HEADER_SIZE,
           "POST %s HTTP/1.1\r\n"
           "Host: %s:%d\r\n"
           "Content-Type: application/octet-stream\r\n"
           "Content-Length: %d\r\n"
           "Connection: close\r\n"
           "\r\n",
           path, iso->volumes[chosen_volume], iso->ports[chosen_volume], clen);

  const int socket = connect_to_forward_server(iso->volumes[chosen_volume],
                                               iso->ports[chosen_volume]);
  if (socket < 0) {
    char response_body[BUFFER_SIZE];
    snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
    send_response(client_socket, 502, "Bad Gateway", "text/plain",
                  response_body);
    return;
  }

  send(socket, request_header, strlen(request_header), 0);
  if (clen > 0 && body) {
    if (send(socket, body, clen, 0) < 0) {
      perror("error sending body to storage server.");
      close(socket);

      char response_body[BUFFER_SIZE];
      snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
      send_response(client_socket, 502, "Bad Gateway", "text/plain",
                    response_body);
      return;
    }
  }

  char response_buffer[BUFFER_SIZE];
  int bytes_read = 0;
  int total_read = 0;
  char *response_data = NULL;

  bytes_read = recv(socket, response_buffer, BUFFER_SIZE - 1, 0);
  if (bytes_read <= 0) {
    close(socket);
    char response_body[BUFFER_SIZE];
    snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
    send_response(client_socket, 502, "Bad Gateway", "text/plain",
                  response_body);
    return;
  }

  response_buffer[bytes_read] = '\0';
  response_data = strdup(response_buffer);
  if (!response_data) {
    close(socket);
    send_response(client_socket, 500, "Internal Server Error", "text/html",
                  "<html><body><h1>Error</h1><p>Memory allocation "
                  "error</p></body></html>");
    return;
  }

  int status_code = 200;
  char status_text[100] = "OK";

  sscanf(response_data, "HTTP/%*s %d %99[^\r\n]", &status_code, status_text);

  char *body_start = strstr(response_data, "\r\n\r\n");
  if (body_start) {
    body_start += 4;
    send_response(client_socket, status_code, status_text, "application/json",
                  body_start);
  } else {
    send_response(client_socket, 200, "OK", "text/plain",
                  "File upload processed");
  }

  free(response_data);
  close(socket);
}

void handle_req(Iso *iso, int client_socket) {
  char buffer[BUFFER_SIZE];
  char path[255];
  char method[10];
  char protocol[20];
  int clen = 0;
  char *body = NULL;
  char *temp_body = NULL;

  int received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
  if (received <= 0) {
    return;
  }
  buffer[received] = '\0';
  sscanf(buffer, "%s %s %s", method, path, protocol);

  char *end = strstr(buffer, "\r\n\r\n");
  if (end) {
    end += 4; // skip the blank line
    body = end;

    char *clen_header = strstr(buffer, "Content-Length:");
    if (clen_header) {
      sscanf(clen_header, "Content-Length: %d", &clen);
    }

    const int already_received = (received - (end - buffer));
    if (clen > already_received) {
      temp_body = malloc(clen + 1);
      if (temp_body) {
        memcpy(temp_body, body, already_received);
        int total_read = already_received;
        while (total_read < clen) {
          received =
              recv(client_socket, temp_body + total_read, clen - total_read, 0);
          if (received <= 0)
            break;
          total_read += received;
        }
        temp_body[total_read] = '\0';
        body = temp_body;
      } else {
      }
    }
  }
  printf("%s %s\n", method, path);

  if (strcmp(method, "GET") == 0) {
    handle_get(client_socket, path);
  } else if (strcmp(method, "POST") == 0) {
    printf("handling post\n");
    handle_post(iso, client_socket, path, temp_body, clen);
  }

  if (temp_body != NULL) {
    free(temp_body);
  }
}

int main() {
  int server_fd, client_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);

  printf("%s\n", key_to_path("test.mp4", strlen("test.mp4")));
  printf("%s\n", key_to_path("another_test.mp4", strlen("another_test.mp4")));

  Iso iso;
  memset(&iso, 0, sizeof(Iso));

  add_volume(&iso, "127.0.0.1", 8001);

  int vol_idx = pick_volume(&iso, "lol.bat", strlen("lol.bat"));
  printf("%d\n", vol_idx);
  printf("%s\n", iso.volumes[vol_idx]);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket creation failed");
    exit(1);
  }

  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt failed");
    exit(1);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(1);
  }

  if (listen(server_fd, 10) < 0) {
    perror("listen failed");
    exit(1);
  }

  for (;;) {
    if ((client_socket = accept(server_fd, (struct sockaddr *)&address,
                                (socklen_t *)&addrlen)) < 0) {
      perror("accept failed");
      continue;
    }

    handle_req(&iso, client_socket);
    close(client_socket);
  }

  close(server_fd);
  return 0;
}
