#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
char root_dir[64];

int mkdirs(const char *path) {
  char tmp[256];
  char *p = NULL;
  snprintf(tmp, sizeof(tmp), "%s", path);
  size_t len = strlen(tmp);

  if (tmp[len - 1] == '/') {
    tmp[len - 1] = 0;
  }

  // this is a bit hacky lol
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, 0755) != 0) {
        if (errno != EEXIST) {
          return -1;
        }
      }

      *p = '/';
    }
  }

  if (mkdir(tmp, 0755) != 0) {
    if (errno != EEXIST) {
      return -1;
    }
  }

  return 0;
}

void url_to_filepath(const char *url, char *filepath, size_t size) {
  char clean_url[256];
  strncpy(clean_url, url, sizeof(clean_url) - 1);
  clean_url[sizeof(clean_url) - 1] = '\0';

  char *question_mark = strchr(clean_url, '?');
  if (question_mark) {
    *question_mark = '\0';
  }

  if (strcmp(clean_url, "/") == 0) {
    snprintf(filepath, size, "%s/index", root_dir);
    return;
  }

  snprintf(filepath, size, "%s%s", root_dir, clean_url);
}

void parse_request_header(const char *request, char *method, char *url,
                          long *content_length) {
  sscanf(request, "%s %s", method, url);

  *content_length = 0;
  const char *content_len_str = strstr(request, "Content-Length:");
  if (content_len_str) {
    sscanf(content_len_str, "Content-Length: %ld", content_length);
  }
}

void handle_request(int client_socket) {
  char buffer[BUFFER_SIZE];
  char method[10];
  char url[256];
  char filepath[512];
  char dirpath[512];
  long content_length = 0;
  ssize_t bytes_read;

  bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
  if (bytes_read <= 0) {
    return;
  }
  buffer[bytes_read] = '\0';

  parse_request_header(buffer, method, url, &content_length);

  url_to_filepath(url, filepath, sizeof(filepath));

  printf("%s %s -> %s\n", method, url, filepath);

  if (strcmp(method, "POST") == 0) {
    strcpy(dirpath, filepath);
    mkdirs(dirname(dirpath));

    FILE *file = fopen(filepath, "wb");
    if (!file) {
      char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: "
                        "22\r\n\r\nFailed to create file\n";
      send(client_socket, response, strlen(response), 0);
      return;
    }

    const char *body_start = strstr(buffer, "\r\n\r\n");
    if (body_start) {
      body_start += 4;
      size_t initial_body_length = bytes_read - (body_start - buffer);
      if (initial_body_length > 0) {
        fwrite(body_start, 1, initial_body_length, file);
        content_length -= initial_body_length;
      }
    }

    while (content_length > 0) {
      bytes_read =
          recv(client_socket, buffer,
               content_length > BUFFER_SIZE ? BUFFER_SIZE : content_length, 0);
      if (bytes_read <= 0) {
        break;
      }
      fwrite(buffer, 1, bytes_read, file);
      content_length -= bytes_read;
    }

    fclose(file);

    char response[] =
        "HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\nCreated\n";
    send(client_socket, response, strlen(response), 0);
  } else if (strcmp(method, "GET") == 0) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
      char response[] =
          "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";
      send(client_socket, response, strlen(response), 0);
      return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char header[BUFFER_SIZE];
    snprintf(header, BUFFER_SIZE,
             "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\nContent-Type: "
             "application/octet-stream\r\n\r\n",
             file_size);
    send(client_socket, header, strlen(header), 0);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
      send(client_socket, buffer, bytes_read, 0);
    }

    fclose(file);
  } else {
    char response[] = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: "
                      "19\r\n\r\nMethod Not Allowed\n";
    send(client_socket, response, strlen(response), 0);
  }
}

int main(int argc, char **argv) {
  int server_fd, client_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);

  if (argc < 3) {
    fprintf(stderr, "port and/or root_dir not supplied");
    exit(EXIT_FAILURE);
  }

  uint16_t port = atoi(argv[1]);
  strcpy(root_dir, argv[2]);
  if (mkdir(root_dir, 0755) != 0 && errno != EEXIST) {
    perror("Failed to create storage directory");
    exit(EXIT_FAILURE);
  }

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("Setsockopt failed");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 10) < 0) {
    perror("Listen failed");
    exit(EXIT_FAILURE);
  }

  printf("Server started on port %d\n", port);
  printf("Storage directory: %s\n", root_dir);

  while (1) {
    client_socket =
        accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (client_socket < 0) {
      perror("Accept failed");
      continue;
    }

    handle_request(client_socket);
    close(client_socket);
  }

  close(server_fd);
  return 0;
}
