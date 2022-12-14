#include "base64.h"
#include "iso.h"
#include <assert.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// strsplit used to parse server list arguments
static char **strsplit(char *input, const char delim) {
  char **res = 0;
  size_t count = 0;
  char *tmp = input;
  char *last = 0;

  while (*tmp) {
    if (delim == *tmp)
      ++count, last = tmp;
    ++tmp;
  }
  count += last < (input + strlen(input) - 1);
  ++count;

  res = malloc(sizeof(char *) * count);
  if (!res) {
    fprintf(stderr, "not enough memory for allocating server list\n");
    return NULL;
  }

  size_t idx = 0;
  char dl[2];
  dl[0] = delim;
  dl[1] = '\n';

  char *tok = strtok(input, dl);
  while (tok) {
    assert(idx < count);
    *(res + idx++) = strdup(tok);
    tok = strtok(NULL, dl);
  }
  assert(idx == count - 1);
  *(res + idx) = 0;

  return res;
}

static void usage(const char *name) {
  fprintf(stderr,
          "%s usage: -p <port> -s <servers separated with commas> -i "
          "<path to database file>\n",
          name);
  exit(1);
}

int main(int argc, char **argv) {
  int port = 8080;
  char **server_list = NULL;
  char *db_index = NULL;

  if (argc <= 3) {
    usage(argv[0]);
  }

  // parse command-line arguments.
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "-p", 2) == 0) {
      port = atoi(argv[++i]);
    } else if (strncmp(argv[i], "-s", 2) == 0) {
      server_list = strsplit(argv[++i], ',');
    } else if (strncmp(argv[i], "-i", 2) == 0) {
      db_index = strdup(argv[++i]);
    } else {
      usage(argv[0]);
    }
  }

  printf("starting index server at port: %d\n", port);
  // startup the server
  size_t nbytes = snprintf(NULL, 0, "https://localhost:%d", port) + 1;
  char *host = malloc(nbytes * sizeof(char));
  snprintf(host, nbytes, "https://localhost:%d", port);
  host[nbytes] = '\0';

  init_iso(server_list, 1, db_index);

  start_http(host);
  close_iso();
  free(db_index);
  free(host);
}
