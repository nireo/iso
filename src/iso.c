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

// Maximum size of a key
#define KEY_SIZE 64

// global variable to make the code a lot simpler
static iso_t *fs;

// Handle interrupts, like Ctrl-C
static int s_signo;
static void signal_handler(int signo) { s_signo = signo; }

// variable used to send data to volume servers.
// mongoose needs to use a separate handler for sending
// requests.
static uint64_t timeout_ms = 10000;
static char *put_data = NULL;
static char *volume_url = NULL;

// init_iso sets up all the fields in the global 'fs' variable. We use a global
// variable because this makes the code cleaner and the application is simple.
void init_iso(char **volumes, size_t volume_count, char *index_path) {
  fs = malloc(sizeof(iso_t));
  if (fs == NULL) {
    fprintf(stderr, "not enough memory for iso_t*\n");
    exit(1);
  }

  // setup leveldb, if the index file doesn't exist, create one!
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

  // store them here such that we don't need to continiously create these.
  fs->ropts = leveldb_readoptions_create();
  fs->wopts = leveldb_writeoptions_create();
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
static void _set_entry(const char *key, size_t keylen, const char *volume) {
  char *err = NULL;

  leveldb_put(fs->store, fs->wopts, key, keylen, volume, strlen(volume), &err);
  if (err != NULL) {
    fprintf(stderr, "failed writing entry into database %s\n", err);
    leveldb_free(err);
  }
}

static char *_get_entry_(const char *key, size_t keylen) {
  char *err = NULL;
  size_t read_len = 0;
  char *read = leveldb_get(fs->store, fs->ropts, key, keylen, &read_len, &err);
  if (err != NULL) {
    fprintf(stderr, "error getting entry from database %s\n", err);
    leveldb_free(err);
    return NULL;
  }

  return read;
}

static int _delete_entry(const char *key, size_t klen) {
  char *err = NULL;

  leveldb_delete(fs->store, fs->wopts, key, klen, &err);
  if (err != NULL) {
    leveldb_free(err);
    return -1;
  }

  return 0;
}

// _pick_volume returns a copy of the best volume for a given key.
static char *_pick_volume(const char *key, size_t keylen) {
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

static char *_key_to_path(const char *key, size_t keylen) {
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
    size_t content_length = put_data ? strlen(put_data) : 0;
    mg_printf(c,
              "%s %s HTTP/1.0\r\n"
              "Host: %.*s\r\n"
              "Content-Type: octet-stream\r\n"
              "Content-Length: %d\r\n"
              "\r\n",
              put_data ? "PUT" : "DELETE", mg_url_uri(volume_url),
              (int)host.len, host.ptr, content_length);
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

// http_handler handles all of the logic the web server has. it handles
// redirecting requests to volume servers and sending file data to volume
// servers.
static void http_handler(struct mg_connection *c, int ev, void *ev_data,
                         void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *http_msg = ev_data;

    // parse and validate key size.
    char key[KEY_SIZE];
    if ((int)http_msg->uri.len >= KEY_SIZE) {
      mg_http_reply(c, 403, "", "key is too long");
      return;
    }
    strncpy(&key[0], http_msg->uri.ptr + 1, http_msg->uri.len);
    key[http_msg->uri.len] = '\0';
    size_t keylen = strlen(key);

    if (strncmp(http_msg->method.ptr, "PUT", 3) == 0) {
      // ignore empty request bodies
      if (http_msg->body.len == 0) {
        mg_http_reply(c, 411, "", "request body empty.\n");
        return;
      }

      // check if the entry already exists in the database.
      char *exists = _get_entry_(key, keylen);
      if (exists) {
        free(exists);
        // tell the user that the entry already exists.
        mg_http_reply(c, 409, NULL, NULL);
        return;
      }

      char *path = _key_to_path(key, keylen);
      char *volume = _pick_volume(key, keylen);

      // copy request data.
      put_data = malloc(http_msg->body.len + 1);
      strncpy(put_data, http_msg->body.ptr, http_msg->body.len);
      put_data[http_msg->body.len] = '\0';

      size_t nbytes = snprintf(NULL, 0, "%s%s", volume, path) + 1;
      volume_url = malloc(nbytes * sizeof(char));
      snprintf(volume_url, nbytes, "%s%s", volume, path);
      volume_url[nbytes] = '\0';

      // store the address instead of the just the volume name
      // so we don't have to recalculate the address every time.
      _set_entry(key, keylen, volume_url);
      struct mg_mgr mgr;
      bool done = false;
      mg_mgr_init(&mgr);
      mg_http_connect(&mgr, volume_url, data_sender, &done);
      while (!done)
        mg_mgr_poll(&mgr, 100);

      mg_mgr_free(&mgr);
      free(path);
      free(volume);
      free(volume_url);
      free(put_data);

      // make sure these fields are NULL when they're used again.
      volume_url = NULL;
      put_data = NULL;

      mg_http_reply(c, 201, NULL, NULL);
      return;
    }

    if (strncmp(http_msg->method.ptr, "GET", 3) == 0) {
      char *volume = _get_entry_(key, keylen);
      if (volume == NULL) {
        mg_http_reply(c, 404, "", "key not found.\n");
        return;
      }

      // redirect request to the volume server.
      mg_printf(c,
                "HTTP/1.1 302 Found\r\n"
                "Location: %s\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                volume);
      free(volume);
      return;
    }

    if (strncmp(http_msg->method.ptr, "DELETE", 6) == 0) {
      volume_url = _get_entry_(key, keylen);
      if (volume_url == NULL) {
        mg_http_reply(c, 404, "", "key not found.\n");
        return;
      }

      // delete the entry from the database
      int status = _delete_entry(key, keylen);
      if (status != 0) {
        mg_http_reply(c, 500, NULL, NULL);
        return;
      }

      // send delete request to volume server using the data_sender
      // which is also used for sending data. we just don't set a body
      // so the data_sender interptrets that as a delete request.
      struct mg_mgr mgr;
      bool done = false;
      mg_mgr_init(&mgr);
      mg_http_connect(&mgr, volume_url, data_sender, &done);
      while (!done)
        mg_mgr_poll(&mgr, 100);

      mg_mgr_free(&mgr);
      free(volume_url);
      volume_url = NULL;

      // return successful
      mg_http_reply(c, 204, NULL, NULL);
      return;
    }

    // only GET, PUT, DELETE
    mg_http_reply(c, 405, "", "method not allowed... only: PUT/GET");
  }
  (void)fn_data;
}

void start_http(const char *addr) {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, addr, http_handler, &mgr);
  while (s_signo == 0) {
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
