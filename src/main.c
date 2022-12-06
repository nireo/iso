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

int main(int argc, char **argv) {
  int port;
  char **server_list = NULL;
  char *db_index = NULL;

  // parse command-line arguments.
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "-p", 2) == 0) {
      port = atoi(argv[++i]);
    } else if (strncmp(argv[i], "-s", 2) == 0) {
      server_list = strsplit(argv[++i], ',');
    } else if (strncmp(argv[i], "-i", 2) == 0) {
      db_index = strdup(argv[++i]);
    }
  }

  // TODO: initialize the service with the given parameters
  printf("starting index server at port: %d\n", port);

  // startup the server
  size_t nbytes = snprintf(NULL, 0, "https://localhost:%d", port) + 1;
  char *host = malloc(nbytes * sizeof(char));
  snprintf(host, nbytes, "https://localhost:%d", port);

  start_http(host);
  free(db_index);
  free(host);
}
