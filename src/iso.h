#ifndef __ISO_H__
#define __ISO_H__

#include <leveldb/c.h>

typedef struct iso {
  leveldb_t *store;
  char **volumes;
  size_t volume_count;
  char *index_path;
} iso_t;

void start_http(const char *addr);
void init_iso(char **volumes, size_t volume_count, char *index_path);
void close_iso(void);

#endif
