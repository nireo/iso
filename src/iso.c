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
static int s_signo = 0;

// variable used to send data to volume servers.
// mongoose needs to use a separate handler for sending
// requests.
static uint64_t timeout_ms = 10000;
static char *put_data = NULL;
static char *volume_url = NULL;

static void signal_handler(int signo) {
  printf("stopping...\n");
  s_signo = signo;
}

void init_iso(char **volumes, size_t volume_count, char *index_path) {
  fs = malloc(sizeof(iso_t));
  if (fs == NULL) {
    fprintf(stderr, "not enough memory for iso_t*\n");
    exit(1);
  }

  char *err = NULL;
  leveldb_options_t *opts = leveldb_options_create();
  leveldb_options_set_create_if_missing(opts, 1);

  fs->store = leveldb_open(opts, index_path, &err);
  if (err != NULL) {
    fprintf(stderr, "could not open index file: %s\n", err);
    exit(1);
  }

  fs->volumes = volumes;
  fs->volume_count = volume_count;
  fs->index_path = index_path;
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
  size_t read_len = 0;
  char *read = leveldb_get(fs->store, leveldb_readoptions_create(), key,
                           strlen(key), &read_len, &err);

  if (err != NULL) {
    fprintf(stderr, "error getting entry from database %s\n", err);
    leveldb_free(err);
    return NULL;
  }

  return read;
}

// _pick_volume returns a copy of the best volume for a given key.
static char *_pick_volume(const char *key, int keylen) {
  int best_volume = 0;
  unsigned char best_score[MD5_DIGEST_LENGTH];
  int first = 1;

  for (int i = 0; i < fs->volume_count; ++i) {
    unsigned char curr_score[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, fs->volumes[i], strlen(fs->volumes[i]));
    MD5_Update(&ctx, key, keylen);
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

static char *_key_to_path(const char *key, int keylen) {
  unsigned char md5_sum[MD5_DIGEST_LENGTH];
  MD5(key, strlen(key), md5_sum);

  size_t base64_size;
  unsigned char *encoded = base64_encode(key, keylen, &base64_size);

  size_t nbytes =
      snprintf(NULL, 0, "/%02x/%02x/%s", md5_sum[0], md5_sum[1], encoded) + 1;
  char *path = malloc(nbytes * sizeof(char));
  snprintf(path, nbytes, "/%02x/%02x/%s", md5_sum[0], md5_sum[1], encoded);
  path[nbytes] = '\0';
  free(encoded);

  return path;
}

static void data_sender(struct mg_connection *c, int ev, void *ev_data,
                        void *fn_data) {
  if (ev == MG_EV_OPEN) {
    *(uint64_t *)c->label = mg_millis() + timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *)c->label &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    struct mg_str host = mg_url_host(volume_url);
    int content_length = put_data ? strlen(put_data) : 0;
    mg_printf(c,
              "%s %s HTTP/1.0\r\n"
              "Host: %.*s\r\n"
              "Content-Type: octet-stream\r\n"
              "Content-Length: %d\r\n"
              "\r\n",
              put_data ? "PUT" : "GET", mg_url_uri(volume_url), (int)host.len,
              host.ptr, content_length);
    mg_send(c, put_data, content_length);
  } else if (ev == MG_EV_HTTP_MSG) {
    // print response
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    printf("%.*s", (int)hm->message.len, hm->message.ptr);
    // close connection and event loop.
    c->is_closing = 1;
    *(bool *)fn_data = true;
  } else if (ev == MG_EV_ERROR) {
    // tell event loop to stop
    *(bool *)fn_data = true;
  }
}

static void http_handler(struct mg_connection *c, int ev, void *ev_data,
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

    int keylen = strlen(key);

    if (strncmp(http_msg->method.ptr, "PUT", 3) == 0) {
      // ignore empty request bodies
      if (http_msg->body.len == 0) {
        mg_http_reply(c, 411, "", "request body empty.\n");
        return;
      }

      // TODO: check if key already exists
      char *path = _key_to_path(key, keylen);
      printf("path: %s\n", path);
      char *volume = _pick_volume(key, keylen);
      printf("picked volume: %s\n", volume);

      // copy request data.
      put_data = malloc(http_msg->body.len + 1);
      strncpy(put_data, http_msg->body.ptr, http_msg->body.len);
      put_data[http_msg->body.len] = '\0';

      size_t nbytes = snprintf(NULL, 0, "%s%s", volume, path) + 1;
      volume_url = malloc(nbytes * sizeof(char));
      snprintf(volume_url, nbytes, "%s%s", volume, path);
      volume_url[nbytes] = '\0';

      printf("volume address: %s\n", volume_url);
      printf("data: %s\n", put_data);

      // struct mg_mgr mgr;
      // bool done = false;
      // mg_mgr_init(&mgr);
      // mg_http_connect(&mgr, volume_url, data_sender, &done);
      // while (!done)
      //   mg_mgr_poll(&mgr, 100);
      //
      // mg_mgr_free(&mgr);
      free(path);
      free(volume);
      free(volume_url);
      free(put_data);
      volume_url = NULL;
      put_data = NULL;

      mg_http_reply(c, 201, "", "key was created.\n");
      return;
    }

    if (strncmp(http_msg->method.ptr, "GET", 3) == 0) {
      char *volume = _get_entry_(key);
      if (volume == NULL) {
        mg_http_reply(c, 404, "", "entry with key not found.\n");
        return;
      }

      char *path = _key_to_path(key, keylen);

      size_t nbytes =
          snprintf(NULL, 0, "Location: %s/%s\r\n", volume, path) + 1;
      char *header = malloc(nbytes * sizeof(char));
      snprintf(header, nbytes, "Location: %s/%s\r\n", volume, path);
      header[nbytes] = '\0';

      free(path);
      free(volume);
      mg_http_reply(c, 302, header, "");
      free(header);
      return;
    }

    mg_http_reply(c, 405, "", "method not allowed... only: PUT/GET");
  }
  (void)fn_data;
}

void start_http(const char *addr) {
  // handle signals properly.
  // signal(SIGINT, signal_handler);
  // signal(SIGTERM, signal_handler);

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, addr, http_handler, &mgr);
  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }

  printf("service has gracefully stopped.\n");
  mg_mgr_free(&mgr);
}

void close_iso() {
  for (size_t i = 0; i < fs->volume_count; ++i) {
    free(fs->volumes[i]);
  }

  leveldb_close(fs->store);
  free(fs->index_path);
  free(fs);
}
