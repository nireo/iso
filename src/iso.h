#ifndef __ISO_H__
#define __ISO_H__

#include <leveldb/c.h>

typedef struct iso {
  leveldb_t *store;
} iso_t;

iso_t *new_iso(void);

#endif
