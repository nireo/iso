#include "iso.h"

#include <leveldb/c.h>
#include <stdio.h>
#include <stdlib.h>

iso_t *new_iso(void) {
  iso_t *v = malloc(sizeof(iso_t));

  char *err = NULL;
  v->store = leveldb_open(leveldb_options_create(), "iso.db", &err);

  if (err != NULL) {
    fprintf(stderr, "failed opening database\n");
    return NULL;
  }
  leveldb_free(err);
  err = NULL;

  return v;
}

void free_iso(iso_t *iso) {
  leveldb_close(iso->store);
  free(iso);
}
