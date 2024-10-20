#include "iso2.h"
#include <stdlib.h>

typedef enum {
  EXISTS = 1,
  HARD_DELETED = 2,
  SOFT_DELETED = 3,
} entry_status_t;

typedef struct {
  uint16_t volume_count;
  char **volumes;
  entry_status_t status;
} entry_t;

static char *_encode_entry(entry_t *entry) {
  if (entry == NULL) {
    return NULL;
  }

  size_t total_length =
      snprintf(NULL, 0, "%u,%d", entry->volume_count, entry->status);
  for (uint16_t i = 0; i < entry->volume_count; i++) {
    total_length += strlen(entry->volumes[i]) + 1; // +1 for the comma
  }

  char *encoded = malloc(total_length + 1); // +1 for null terminator
  if (encoded == NULL) {
    return NULL;
  }

  int offset = sprintf(encoded, "%u,%d", entry->volume_count, entry->status);
  for (uint16_t i = 0; i < entry->volume_count; i++) {
    offset += sprintf(encoded + offset, ",%s", entry->volumes[i]);
  }

  return encoded;
}

static entry_t *_decode_entry(const char *encoded) {
  if (encoded == NULL) {
    return NULL;
  }

  entry_t *entry = malloc(sizeof(entry_t));
  if (entry == NULL) {
    return NULL;
  }

  if (sscanf(encoded, "%hu,%d", &entry->volume_count, (int *)&entry->status) !=
      2) {
    free(entry);
    return NULL;
  }

  entry->volumes = malloc(entry->volume_count * sizeof(char *));
  if (entry->volumes == NULL) {
    free(entry);
    return NULL;
  }

  const char *volume_start = strchr(encoded, ',');
  if (volume_start == NULL) {
    free(entry->volumes);
    free(entry);
    return NULL;
  }
  volume_start = strchr(volume_start + 1, ',');
  if (volume_start == NULL) {
    free(entry->volumes);
    free(entry);
    return NULL;
  }
  volume_start++;

  for (uint16_t i = 0; i < entry->volume_count; i++) {
    const char *next_comma = strchr(volume_start, ',');
    size_t volume_len =
        next_comma ? (size_t)(next_comma - volume_start) : strlen(volume_start);

    entry->volumes[i] = malloc(volume_len + 1);
    if (entry->volumes[i] == NULL) {
      for (uint16_t j = 0; j < i; j++) {
        free(entry->volumes[j]);
      }
      free(entry->volumes);
      free(entry);
      return NULL;
    }

    strncpy(entry->volumes[i], volume_start, volume_len);
    entry->volumes[i][volume_len] = '\0';

    volume_start = next_comma ? (next_comma + 1) : NULL;
    if (volume_start == NULL && i != entry->volume_count - 1) {
      for (uint16_t j = 0; j <= i; j++) {
        free(entry->volumes[j]);
      }
      free(entry->volumes);
      free(entry);
      return NULL;
    }
  }

  return entry;
}

static char *_key_to_path(const char *key, size_t keylen) {
  XXH64_hash_t hash = XXH3_64bits(key, keylen);
  unsigned char hash_chars[sizeof(XXH64_hash_t)];
  memcpy(hash_chars, &hash, sizeof(hash));

  size_t base64_size;
  unsigned char *encoded = base64_encode(key, keylen, &base64_size);

  // 2 byte layers deep, meaning a fanout of 256; optimized for 16M files per
  // volume server
  size_t nbytes = snprintf(NULL, 0, "/%02x/%02x/%s", hash_chars[0],
                           hash_chars[1], encoded) +
                  1;
  char *path = malloc(nbytes * sizeof(char));
  snprintf(path, nbytes, "/%02x/%02x/%s", hash_chars[0], hash_chars[1],
           encoded);
  path[nbytes] = '\0';
  free(encoded);

  return path;
}
