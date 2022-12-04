#include "iso.h"
#include "entry.pb-c.h"
#include "mongoose.h"

#include <leveldb/c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 64
#define READ_MAX_SIZE 1024

// global variable to make the code a lot simpler
static iso_t *fs;

void init_iso(void) {}

static Entry *_get_entry(const char *key) {
  size_t read_len = 0;
  // handle possible errors
  char *err = NULL;

  // read should be freed at some point
  char *read = leveldb_get(fs->store, leveldb_readoptions_create(), key,
                           strlen(key), &read_len, &err);

  // don't really have anything better for this at the moment.
  if (err != NULL) {
    fprintf(stderr, "failed getting key %s from store\n", key);
    leveldb_free(err);
    return NULL;
  }
  Entry *entry = entry__unpack(NULL, read_len, (uint8_t *)read);
  if (entry == NULL) {
    leveldb_free(read);
    entry__free_unpacked(entry, NULL);
    return NULL;
  }

  return NULL;
}

// _write_to_store writes a given key-value pair into the database.
// It encodes the given protobuf message and writes that the leveldb database.
static void _write_to_store(const char *key, const Entry *entry) {
  // create a buffer based on the entry
  size_t needed_entry_size = entry__get_packed_size(entry);
  uint8_t *data = calloc(needed_entry_size, sizeof(uint8_t));

  char *err = NULL;

  leveldb_put(fs->store, leveldb_writeoptions_create(), key, strlen(key),
              (char *)data, needed_entry_size, &err);
  if (err != NULL) {
    fprintf(stderr, "failed writing entry into database %s\n", err);
    leveldb_free(err);
    return;
  }
}

static void handler(struct mg_connection *c, int ev, void *ev_data,
                    void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *http_msg = ev_data;

    char key[KEY_SIZE];
    if ((int)http_msg->uri.len >= KEY_SIZE) {
      mg_http_reply(c, 403, "", "key is too long");
      return;
    }

    strncpy(key, http_msg->uri.ptr, http_msg->uri.len);
    if (strncmp(http_msg->method.ptr, "PUT", (int)http_msg->method.len) == 0) {
      // handle creation of entry into the database.
    }

    if (strncmp(http_msg->method.ptr, "GET", (int)http_msg->method.len) == 0) {
    }

    mg_http_reply(c, 405, "", "method not allowed... only: PUT/GET");
  }
  (void)fn_data;
}

void start_http(const char *addr) {
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, addr, handler, &mgr);
  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);
}

void free_iso(iso_t *iso) {
  leveldb_close(iso->store);
  free(iso);
}
