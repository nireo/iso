#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT            8080
#define MAX_BUFFER_SIZE 1024
#define MAX_EVENTS      10

int
set_fd_nonblocking(int fd)
{
  // get existing flags
  int flags = fcntl(fd, F_GETFL);
  if (flags == -1) {
    perror("fcntl(F_GETFL)");
    return -1;
  }

  // add non blocking to the exsting flags and update the descriptors flags.
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl(F_SETFL, O_NONBLOCK)");
    return -1;
  }

  return 0;
}

int
main()
{
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  struct epoll_event ev, events[MAX_EVENTS];
  char buffer[MAX_BUFFER_SIZE];

  int listen_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sock_fd == -1) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt SO_REUSEADDR failed");
    close(listen_sock_fd);
    exit(EXIT_FAILURE);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(listen_sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
    perror("bind failed");
    close(listen_sock_fd);
    exit(EXIT_FAILURE);
  }

  if (set_fd_nonblocking(listen_sock_fd) == -1) {
    close(listen_sock_fd);
    exit(EXIT_FAILURE);
  }

  if (listen(listen_sock_fd, SOMAXCONN) == -1) {
    perror("listen failed");
    close(listen_sock_fd);
    exit(EXIT_FAILURE);
  }

  printf("server listening on port %d\n", PORT);

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1 failed");
    close(listen_sock_fd);
    exit(EXIT_FAILURE);
  }

  ev.events = EPOLLIN;
  ev.data.fd = listen_sock_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock_fd, &ev) == -1) {
    perror("epoll_ctl: listen_sock_fd");
    close(listen_sock_fd);
    close(epoll_fd);
    exit(EXIT_FAILURE);
  }

  while (1) {
    int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1); // -1 for infinite timeout
    if (nfds == -1) {
      perror("epoll_wait failed");
      if (errno == EINTR)
        continue;
      close(listen_sock_fd);
      close(epoll_fd);
      exit(EXIT_FAILURE);
    }

    for (int n = 0; n < nfds; ++n) {
      if (events[n].data.fd == listen_sock_fd) {
        int conn_sock_fd = accept(listen_sock_fd,
            (struct sockaddr*)&client_addr, &client_addr_len);
        if (conn_sock_fd == -1) {
          if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            perror("accept (non-blocking)");
          } else {
            perror("accept failed");
          }
          continue;
        }

        printf("accepted new connection on fd %d\n", conn_sock_fd);
        if (set_fd_nonblocking(conn_sock_fd) == -1) {
          close(conn_sock_fd);
          continue;
        }

        ev.events = EPOLLIN;
        ev.data.fd = conn_sock_fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock_fd, &ev) == -1) {
          perror("epoll_ctl: conn_sock_fd");
          close(conn_sock_fd);
        }
      } else {
        int current_fd = events[n].data.fd;
        ssize_t count;

        count = read(current_fd, buffer, sizeof(buffer) - 1);
        if (count == -1) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read failed");
            close(current_fd);                                    // Close on error
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL); // Remove from epoll
          }
        } else if (count == 0) {
          printf("Client on fd %d closed connection\n", current_fd);
          close(current_fd);
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL); // Remove from epoll
        } else {
          buffer[count] = '\0';
          printf("ceceived from fd %d:\n---\n%s\n---\n", current_fd, buffer);

          const char* http_response =
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/html\r\n"
              "Content-Length: 49\r\n"
              "\r\n"
              "<html><body><h1>Hello, Epoll!</h1></body></html>";

          ssize_t written_bytes = write(current_fd, http_response, strlen(http_response));
          if (written_bytes == -1) {
            perror("write failed");
          } else {
            printf("sent response to fd %d (%zd bytes)\n", current_fd, written_bytes);
          }

          printf("closing connection on fd %d after response\n", current_fd);
          close(current_fd);
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL); // Remove from epoll
        }
      }
    }
  }

  printf("closing server.\n");
  close(listen_sock_fd);
  close(epoll_fd);

  return 0;
}
