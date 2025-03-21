#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PORT 8080
#define MAX_HEADER_SIZE 1024
#define BUFFER_SIZE 4096

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

void handle_get(int client_socket, const char *path) {
  char response_body[BUFFER_SIZE];
  snprintf(response_body, BUFFER_SIZE,
           "<html><body><h1>Hello from C HTTP Server</h1>"
           "<p>GET request received for path: %s</p></body></html>",
           path);

  send_response(client_socket, 200, "OK", "text/html", response_body);
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
      int remaining = clen - already_received;
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
