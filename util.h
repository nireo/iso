#ifndef __ISO_UTIL_H__
#define __ISO_UTIL_H__

#include <stdlib.h>

ssize_t
read_header_line(int socket, char* buffer, size_t max_len, int64_t deadline);

#endif
