#include "util.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libdill.h>
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

int
mkdirs(const char* path)
{
    char tmp[256];
    char* p = NULL;
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

void
url_to_filepath(const char* url, char* filepath, size_t size)
{
    char clean_url[256];
    strncpy(clean_url, url, sizeof(clean_url) - 1);
    clean_url[sizeof(clean_url) - 1] = '\0';

    char* question_mark = strchr(clean_url, '?');
    if (question_mark) {
        *question_mark = '\0';
    }

    if (strcmp(clean_url, "/") == 0) {
        snprintf(filepath, size, "%s/index", root_dir);
        return;
    }

    snprintf(filepath, size, "%s%s", root_dir, clean_url);
}

coroutine void
client_handler(int client_socket)
{
    char filepath[512] = { 0 };
    char dirpath[512] = { 0 };
    Request req;
    if (get_req_from_socket(client_socket, &req) < 0) {
        hclose(client_socket);
        return;
    }
    const int64_t deadline = now() + 10000;

    url_to_filepath(req.url, filepath, sizeof(filepath));
    printf("%s %s -> %s\n", req.method, req.url, filepath);

    if (strcmp(req.method, "POST") == 0 && req.content_length > 0) {
        strcpy(dirpath, filepath);
        if (mkdirs(dirname(dirpath)) < 0) {
            char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nFailed to create file\n";
            bsend(client_socket, response, strlen(response), deadline);
            hclose(client_socket);
            return;
        }

        FILE* file = fopen(filepath, "wb");
        if (!file) {
            char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nFailed to create file\n";
            bsend(client_socket, response, strlen(response), deadline);
            hclose(client_socket);
            return;
        }

        char buffer[BUFFER_SIZE];
        size_t remaining = req.content_length;
        size_t total_read = 0;
        int read_bytes;

        while (remaining > 0) {
            size_t to_read = remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE;
            read_bytes = brecv(client_socket, buffer, to_read, deadline);

            if (read_bytes < 0) {
                fprintf(stderr, "error reading from socket: %d\n", errno);
                break;
            }

            size_t written = fwrite(buffer, 1, read_bytes, file);
            if (written != read_bytes) {
                fprintf(stderr, "error writing to file :%s\n", strerror(errno));
                break;
            }
            remaining -= read_bytes;
            total_read += read_bytes;
        }
        fclose(file);

        if (total_read != req.content_length) {
            char response[] = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 26\r\n\r\nFailed to save complete file\n";
            bsend(client_socket, response, strlen(response), deadline);
        } else {
            char response[] = "HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\nCreated\n";
            bsend(client_socket, response, strlen(response), deadline);
        }
    } else if (strcmp(req.method, "GET") == 0) {
        FILE* file = fopen(filepath, "rb");
        if (!file) {
            char response[] =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";
            bsend(client_socket, response, strlen(response), -1);
            hclose(client_socket);
            return;
        }

        char buffer[4096];
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char header[BUFFER_SIZE];
        snprintf(header, BUFFER_SIZE,
            "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\nContent-Type: "
            "application/octet-stream\r\n\r\n",
            file_size);

        size_t bytes_read = 0;
        if (bsend(client_socket, header, strlen(header), -1) < 0) {
            fprintf(stderr, "failed to send header: %d\n", errno);
            fclose(file);
            hclose(client_socket);
            return;
        }
        while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            if (bsend(client_socket, buffer, bytes_read, -1) < 0) {
                fclose(file);
                hclose(client_socket);
                return;
            }
        }

        fclose(file);
    } else {
        char response[] = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 19\r\n\r\nMethod Not Allowed\n";
        bsend(client_socket, response, strlen(response), deadline);
    }

    hclose(client_socket);
}

int
main(int argc, char** argv)
{
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

    struct ipaddr addr;
    int rc = ipaddr_local(&addr, NULL, port, 0);
    if (rc < 0) {
        perror("cannot create local address");
        exit(EXIT_FAILURE);
    }

    int ln = tcp_listen(&addr, 128);
    if (ln < 0) {
        perror("error creating listener");
        exit(EXIT_FAILURE);
    }

    printf("Server started on port %d\n", port);
    printf("Storage directory: %s\n", root_dir);
    int b = bundle();

    while (1) {
        int c_socket = tcp_accept(ln, NULL, -1);
        printf("got socket: %d\n", c_socket);
        if (c_socket < 0) {
            if (errno == ETIMEDOUT) {
                continue;
            }

            perror("accept failed");
            continue;
        }

        bundle_go(b, client_handler(c_socket));
    }
    hclose(b);
    hclose(ln);

    return 0;
}
