#include "iso.h"
#include "base64.h"
#include "entry.pb-c.h"
#include "mongoose.h"

#include <leveldb/c.h>
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 64
#define READ_MAX_SIZE 1024

// global variable to make the code a lot simpler
static iso_t *fs;

void init_iso(void) {}

static char *_key_to_volume(const char *key) {
  unsigned char md5_sum[MD5_DIGEST_LENGTH];
  MD5(key, strlen(key), md5_sum);

  size_t base64_size;
  unsigned char *encoded = base64_encode(key, strlen(key), &base64_size);

  size_t nbytes =
      snprintf(NULL, 0, "/%02x/%02x/%s", md5_sum[0], md5_sum[1], encoded) + 1;
  char *path = malloc(nbytes * sizeof(char));
  snprintf(path, nbytes, "/%02x/%02x/%s", md5_sum[0], md5_sum[1], encoded);

  return path;
}

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
  }
  free(data);
}

static char *_pick_volume(iso_t *iso, const char *key) {
  char *best_volume = NULL;

  return best_volume;
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

    // uri.ptr + 1 to skip the '/'
    strncpy(key, http_msg->uri.ptr + 1, http_msg->uri.len - 1);
    if (strncmp(http_msg->method.ptr, "PUT", (int)http_msg->method.len) == 0) {
      return;
    }

    if (strncmp(http_msg->method.ptr, "GET", (int)http_msg->method.len) == 0) {
      printf("this is a get request and the key is %s", key);
      return;
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
