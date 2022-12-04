#include "iso.h"
#include "mongoose.h"

#include <leveldb/c.h>
#include <stdio.h>
#include <stdlib.h>

// global variable to make the code a lot simpler
static iso_t *fs;

void init_iso(void) {}

static void handler(struct mg_connection *c, int ev, void *ev_data,
                    void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Hello, %s\n",
                  "world");
  }
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
