#ifndef __ISO_UTIL_H__
#define __ISO_UTIL_H__

#include <stdlib.h>

typedef struct {
    char method[16];
    char url[256];

    // only care about this header now, would need to implement some sort of list
    // if the other mattered
    long content_length;
} Request;

typedef struct {
    int status_code;
    char status_message[256];
    long content_length;
} Response;

ssize_t
read_header_line(int socket, char* buffer, size_t max_len, int64_t deadline);
int get_req_from_socket(int socket, Request* req);
int get_resp_from_socket(int socket, Response* req);

#endif
