#include "util.h"
#include <libdill.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

ssize_t
read_header_line(int socket, char* buffer, size_t max_len, int64_t deadline)
{
    size_t pos = 0;
    char c;
    ssize_t rc;
    max_len--;

    while (pos < max_len) {
        rc = brecv(socket, &c, 1, deadline);
        if (rc < 0) {
            return -1;
        }

        if (c == '\r') {
            rc = brecv(socket, &c, 1, deadline);
            if (rc < 0) {
                return -1;
            }

            if (c == '\n') {
                break;
            } else {
                if (pos < max_len - 1) {
                    buffer[pos++] = '\r';
                    buffer[pos++] = c;
                }
            }
        } else {
            buffer[pos++] = c;
        }
    }

    buffer[pos] = '\0';
    return pos;
}

int
get_req_from_socket(int socket, Request* req)
{
    char line[512];
    char header_name[64] = { 0 };
    char header_value[256] = { 0 };
    const int64_t deadline = now() + 10000;

    ssize_t bytes_read = read_header_line(socket, line, sizeof(line), deadline);
    if (bytes_read <= 0) {
        return -1; // closing the socket is handled by the caller
    }
    sscanf(line, "%15s %255s", req->method, req->url);
    // keep reading the headers
    while (1) {
        bytes_read = read_header_line(socket, line, sizeof(line), deadline);
        if (bytes_read < 0) {
            return -1;
        }

        if (bytes_read == 0 && line[0] == '\0') {
            break;
        }

        if (sscanf(line, "%63[^:]: %255s", header_name, header_value) == 2) {
            if (strcasecmp(header_name, "Content-Length") == 0) {
                req->content_length = atol(header_value);
            }
        }
    }

    printf("%s %s\n", req->method, req->url);
    return 0;
}

int
get_resp_from_socket(int socket, Response* resp)
{
    char line[512];
    const int64_t deadline = now() + 10000;

    ssize_t bytes_read = read_header_line(socket, line, sizeof(line), deadline);
    if (bytes_read <= 0) {
        return -1; // Error reading from socket
    }

    char protocol[16];
    if (sscanf(line, "%15s %d %255[^\r\n]", protocol, &resp->status_code, resp->status_message) < 2) {
        return -1;
    }

    while (1) {
        bytes_read = read_header_line(socket, line, sizeof(line), deadline);
        if (bytes_read < 0) {
            return -1;
        }
        if (bytes_read == 0 && line[0] == '\0') {
            break;
        }
    }

    printf("Response: %d %s\n", resp->status_code, resp->status_message);
    return 0;
}
