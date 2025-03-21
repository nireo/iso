#ifndef __ISO_H__
#define __ISO_H__

#include <leveldb/c.h>

typedef struct {
  leveldb_t *metadata;
  char **volumes;
  size_t volume_count;
} Iso;

#endif
