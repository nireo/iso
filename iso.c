#include <arpa/inet.h>
#include <fcntl.h>
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

typedef struct {
  char path[FILE_PATH_MAX_SIZE];
  char volumes[MAX_VOLUME_SIZE][MAX_VOLUMES];
  int vol_count;
} FileMetadata;

typedef struct {
  FileMetadata *entries;
  int size;
  int capacity;
  char *fpath;
} MetadataStorage;

MetadataStorage *metadata_storage_init(const char *filename) {
  MetadataStorage *storage = (MetadataStorage *)malloc(sizeof(MetadataStorage));
  if (!storage) {
    return NULL;
  }

  storage->entries = (FileMetadata *)malloc(sizeof(FileMetadata) * 16);
  if (!storage->entries) {
    free(storage);
    return NULL;
  }

  storage->size = 0;
  storage->capacity = 16;
  storage->fpath = strdup(filename);

  FILE *file = fopen(filename, "rb");
  if (file) {
    fread(&storage->size, sizeof(int), 1, file);

    if (storage->size > storage->capacity) {
      FileMetadata *new_entries = (FileMetadata *)realloc(
          storage->entries, sizeof(FileMetadata) * storage->size);
      if (new_entries) {
        storage->entries = new_entries;
        storage->capacity = storage->size;
      } else {
        storage->size = storage->capacity;
      }
    }

    fread(storage->entries, sizeof(FileMetadata), storage->size, file);
    fclose(file);
  }

  return storage;
}

void metadata_storage_free(MetadataStorage *storage) {
  if (storage) {
    free(storage->entries);
    free(storage->fpath);
    free(storage);
  }
}

int metadata_storage_dump(MetadataStorage *storage) {
  if (!storage)
    return -1;

  // TODO: this is very stupid especially when doing this every time we insert
  // something
  FILE *file = fopen(storage->fpath, "wb");
  if (!file)
    return -1;

  fwrite(&storage->size, sizeof(int), 1, file);
  fwrite(storage->entries, sizeof(FileMetadata), storage->size, file);
  fclose(file);

  return 0;
}

static int find_entry(MetadataStorage *storage, const char *key) {
  for (int i = 0; i < storage->size; i++) {
    if (strcmp(storage->entries[i].path, key) == 0) {
      return i;
    }
  }
  return -1;
}

int metadata_storage_set(MetadataStorage *storage, const char *key,
                         const char **values, int count) {
  if (!storage || !key || count > MAX_VOLUMES) {
    return -1;
  }

  int index = find_entry(storage, key);

  if (index == -1) {
    if (storage->size >= storage->capacity) {
      int new_capacity = storage->capacity * 2;
      FileMetadata *new_entries = (FileMetadata *)realloc(
          storage->entries, sizeof(FileMetadata) * new_capacity);

      if (!new_entries) {
        return -1;
      }

      storage->entries = new_entries;
      storage->capacity = new_capacity;
    }

    index = storage->size++;
    strncpy(storage->entries[index].path, key, FILE_PATH_MAX_SIZE - 1);
    storage->entries[index].path[MAX_HEADER_SIZE - 1] = '\0';
  }

  storage->entries[index].vol_count = count;
  for (int i = 0; i < count; i++) {
    strncpy(storage->entries[index].volumes[i], values[i], MAX_VOLUME_SIZE - 1);
    storage->entries[index].volumes[i][MAX_VOLUME_SIZE - 1] = '\0';
  }

  return metadata_storage_dump(storage);
}
const char **metadata_storage_get(MetadataStorage *storage, const char *key,
                                  int *count) {
  if (!storage || !key || !count) {
    *count = 0;
    return NULL;
  }

  int index = find_entry(storage, key);
  if (index == -1) {
    *count = 0;
    return NULL;
  }

  FileMetadata *entry = &storage->entries[index];
  *count = entry->vol_count;

  char **result = (char **)malloc(sizeof(char *) * entry->vol_count);
  if (!result) {
    *count = 0;
    return NULL;
  }

  for (int i = 0; i < entry->vol_count; i++) {
    result[i] = entry->volumes[i];
  }

  return (const char **)result;
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

static int connect_to_forward_server(const char *addr) {
  int forward_socket;
  struct sockaddr_in server_addr;

  if ((forward_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("forward socket creation failed");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  // TODO: handle forward port or somethin
  server_addr.sin_port = htons(PORT);

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

void handle_post(int client_socket, const char *path, const char *body,
                 int clen, const char *headers) {
  char *final_path = key_to_path(path, strlen(path));
}

void handle_req(int client_socket) {
#define BUFFER_SIZE 4096
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

  if (strcmp(method, "GET") == 0) {
    handle_get(client_socket, path);
  } else if (strcmp(method, "POST") == 0) {
    // TODO: handle post
  }

  if (temp_body != NULL) {
    free(temp_body);
  }
}

typedef struct {
  char **volumes;
  size_t volume_count;
} Iso;

int main() {
  int server_fd, client_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);

  printf("%s\n", key_to_path("test.mp4", strlen("test.mp4")));
  printf("%s\n", key_to_path("another_test.mp4", strlen("another_test.mp4")));

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

    handle_req(client_socket);
    close(client_socket);
  }

  close(server_fd);
  return 0;
}
