#ifndef __ISO_H__
#define __ISO_H__

#include <leveldb/c.h>

typedef struct iso {
  leveldb_t *store;
  char **volumes;
  size_t volume_count;
} iso_t;

void start_http(const char *addr);

#endif
