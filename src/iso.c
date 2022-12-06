#include "iso.h"
#include "base64.h"
#include "entry.pb-c.h"
#include "mongoose.h"

#include <leveldb/c.h>
#include <openssl/md5.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 64
#define READ_MAX_SIZE 1024

// global variable to make the code a lot simpler
static iso_t *fs;
static s_signo;

static void signal_handler(int signo) { s_signo = signo; }

void init_iso(char **volumes, size_t volume_count, char *index_path) {
  fs = malloc(sizeof(iso_t));
  if (fs == NULL) {
    fprintf(stderr, "not enough memory for iso_t*\n");
    exit(1);
  }

  char *err = NULL;
  fs->store = leveldb_open(leveldb_options_create(), index_path, &err);
  if (err != NULL) {
    fprintf(stderr, "could not open index file: %s\n", err);
    exit(1);
  }

  fs->volumes = volumes;
  fs->volume_count = volume_count;
  fs->index_path = index_path;
}

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

// _set_entry writes a given key-volume pair into the leveldb store.
static void _set_entry(const char *key, const char *volume) {
  char *err = NULL;

  leveldb_put(fs->store, leveldb_writeoptions_create(), key, strlen(key),
              volume, strlen(volume), &err);
  if (err != NULL) {
    fprintf(stderr, "failed writing entry into database %s\n", err);
    leveldb_free(err);
  }
}

static char *_get_entry_(const char *key) {
  char *err = NULL;
  if (err != NULL) {
    fprintf(stderr, "error getting entry from database %s\n", err);
    leveldb_free(err);
  }

  size_t read_len = 0;
  char *read = leveldb_get(fs->store, leveldb_readoptions_create(), key,
                           strlen(key), &read_len, &err);

  return read;
}

// _pick_volume returns a copy of the best volume for a given key.
static char *_pick_volume(const char *key) {
  int best_volume = 0;
  unsigned char best_score[MD5_DIGEST_LENGTH];
  int first = 1;

  for (int i = 0; i < fs->volume_count; ++i) {
    unsigned char curr_score[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_INIT(&ctx);
    MD5_Update(&ctx, fs->volumes[i], strlen(fs->volumes[i]));
    MD5_Final(curr_score, &ctx);

    if (first == 1 ||
        strncmp(&best_score[0], &curr_score[0], MD5_DIGEST_LENGTH) == 1) {
      first = 0;
      memcpy(best_score, curr_score, MD5_DIGEST_LENGTH);
      best_volume = i;
    }
  }

  return strdup(fs->volumes[best_volume]);
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

    strncpy(&key[0], http_msg->uri.ptr + 1, http_msg->uri.len);
    key[http_msg->uri.len] = '\0';
    printf("%s\n", key);

    if (strncmp(http_msg->method.ptr, "PUT", 3) == 0) {
      mg_http_reply(c, 201, "", "key was created.\n");
      return;
    }

    if (strncmp(http_msg->method.ptr, "GET", 3) == 0) {
      printf("this is a get request and the key is %s", key);
      mg_http_reply(c, 200, "", "GET request received\n");
      return;
    }

    mg_http_reply(c, 405, "", "method not allowed... only: PUT/GET");
  }
  (void)fn_data;
}

void start_http(const char *addr) {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, addr, handler, &mgr);
  while (s_signo == 0) {
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);
}

void free_iso() {
  for (size_t i = 0; i < fs->volume_count; ++i) {
    free(fs->volumes[i]);
  }

  leveldb_close(fs->store);
  free(fs->index_path);
  free(fs);
}
