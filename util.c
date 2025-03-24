#include "util.h"
#include <libdill.h>

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
