#include "util.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <leveldb/c.h>
#include <libdill.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEBUG 1
#if DEBUG
#define DEBUG_LOG(msg, ...) printf("[DEBUG] " msg "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(msg, ...) \
    do {                    \
    } while (0) // Expands to nothing when DEBUG is 0
#endif

#define PORT               8080
#define MAX_HEADER_SIZE    1024
#define BUFFER_SIZE        4096

#define FILE_PATH_MAX_SIZE 128
#define MAX_VOLUME_SIZE    64
#define MAX_VOLUMES        6

typedef struct {
    uint16_t ports[16];
    size_t volume_count;
    int replication_factor;
    char volumes[16][64];
    leveldb_t* metadata;
    leveldb_writeoptions_t* woptions;
    leveldb_readoptions_t* roptions;
    leveldb_options_t* opts;
} Iso;

static void
fnv1a_hash(const void* key, size_t keylen, const void* salt,
    size_t saltlen, unsigned char* result)
{
    const uint32_t FNV_PRIME = 16777619;
    const uint32_t FNV_OFFSET_BASIS = 2166136261;

    uint32_t hash[4] = { FNV_OFFSET_BASIS, FNV_OFFSET_BASIS, FNV_OFFSET_BASIS,
        FNV_OFFSET_BASIS };

    const unsigned char* data = (const unsigned char*)key;
    for (size_t i = 0; i < keylen; i++) {
        hash[i % 4] ^= data[i];
        hash[i % 4] *= FNV_PRIME;
    }

    data = (const unsigned char*)salt;
    for (size_t i = 0; i < saltlen; i++) {
        hash[i % 4] ^= data[i];
        hash[i % 4] *= FNV_PRIME;
    }

    for (int i = 0; i < 4; i++) {
        result[i * 4] = (hash[i] >> 24) & 0xFF;
        result[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
        result[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
        result[i * 4 + 3] = hash[i] & 0xFF;
    }
}

typedef struct {
    unsigned char score[16];
    int vol_index;
} SortVolume;

static int
compare_sortvol(const void* a, const void* b)
{
    const SortVolume* s_a = (const SortVolume*)a;
    const SortVolume* s_b = (const SortVolume*)b;

    return -memcmp(s_a->score, s_b->score, 16);
}

// get_key_volumes returns the picked volumes for a given key. there will be volumes until a
// -1 key. the caller needs to free the resulting list.
static int*
get_key_volumes(Iso* iso, const char* key, size_t keylen, int count)
{
    // ensure we don't go overboard
    if (count > iso->volume_count) {
        count = iso->volume_count;
    }

    SortVolume* vols = malloc(iso->volume_count * sizeof(SortVolume));
    if (!vols) {
        return NULL;
    }

    for (int i = 0; i < iso->volume_count; i++) {
        fnv1a_hash(key, keylen,
            iso->volumes[i], strlen(iso->volumes[i]),
            vols[i].score);
        vols[i].vol_index = i;
    }

    qsort(vols, iso->volume_count, sizeof(SortVolume), compare_sortvol);

    int* result = malloc(count * sizeof(int) + 1);
    if (!result) {
        free(vols);
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        result[i] = vols[i].vol_index;
    }
    result[count] = -1; // mark the end

    free(vols);
    return result;
}

static void
add_volume(Iso* iso, const char* addr, uint16_t port)
{
    memcpy(iso->volumes[iso->volume_count], addr, strlen(addr) + 1);
    iso->ports[iso->volume_count] = port;
    iso->volume_count++;
}

static char*
key_to_path(const char* key, size_t keylen)
{
    unsigned int hash = 0;
    for (size_t i = 0; i < keylen; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)key[i];
    }

    unsigned char hash_chars[2];
    hash_chars[0] = (hash >> 8) & 0xFF;
    hash_chars[1] = hash & 0xFF;

    size_t encoded_size = 4 * ((keylen + 2) / 3) + 1;
    char* encoded = malloc(encoded_size);
    if (!encoded)
        return NULL;

    const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t j = 0;
    for (size_t i = 0; i < keylen; i += 3) {
        unsigned int val =
            ((i < keylen) ? ((unsigned char)key[i]) << 16 : 0) |
            ((i + 1 < keylen) ? ((unsigned char)key[i + 1]) << 8 : 0) |
            ((i + 2 < keylen) ? ((unsigned char)key[i + 2]) : 0);

        encoded[j++] = base64_chars[(val >> 18) & 0x3F];
        encoded[j++] = base64_chars[(val >> 12) & 0x3F];
        encoded[j++] = (i + 1 < keylen) ? base64_chars[(val >> 6) & 0x3F] : '=';
        encoded[j++] = (i + 2 < keylen) ? base64_chars[val & 0x3F] : '=';
    }
    encoded[j] = '\0';

    size_t nbytes = snprintf(NULL, 0, "/%02x/%02x/%s", hash_chars[0],
                        hash_chars[1], encoded) +
        1;
    char* path = malloc(nbytes * sizeof(char));
    if (!path) {
        free(encoded);
        return NULL;
    }

    snprintf(path, nbytes, "/%02x/%02x/%s", hash_chars[0], hash_chars[1],
        encoded);
    free(encoded);

    return path;
}

void
send_response(int client_socket, int status_code, const char* status_text,
    const char* content_type, const char* body)
{
    char header[MAX_HEADER_SIZE];
    int body_len = strlen(body);

    snprintf(header, MAX_HEADER_SIZE,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);

    bsend(client_socket, header, strlen(header), -1);
    bsend(client_socket, body, body_len, -1);
}

static int
connect_to_forward_server(const char* addr, uint16_t port)
{
    struct ipaddr ip_addr;
    // TODO: support non local ip addrs
    ipaddr_local(&ip_addr, NULL, port, 0);
    int s = tcp_connect(&ip_addr, -1);
    return s;
}

typedef struct {
    uint16_t port;
    char addr[64];
} DecodedVolume;

static char*
serialize_volume_data(Iso* iso, int* rvols, size_t* size)
{
    uint16_t count = 0;
    size_t string_size = 0;
    for (int i = 0; rvols[i] != -1; ++i) {
        count++;
        string_size += strlen(iso->volumes[i]);
    }

    // 2 bytes for amount of volumes
    // volume_count * 2 bytes for ports
    // space for all strings + comma between addresses
    size_t buf_size = sizeof(uint16_t) + count * sizeof(uint16_t) + (string_size + count) * sizeof(char);
    *size = buf_size;
    size_t offset = 0;

    char* buffer = malloc(buf_size);
    if (!buffer) {
        fprintf(stderr, "cannot allocate memory for volumes");
        return NULL;
    }

    memcpy(buffer + offset, &count, sizeof(uint16_t));
    offset += 2;

    for (int i = 0; i < count; ++i) {
        memcpy(buffer + offset, &iso->ports[rvols[i]], sizeof(uint16_t));
        offset += sizeof(uint16_t);
    }

    for (int i = 0; i < count; ++i) {
        size_t s_size = strlen(iso->volumes[rvols[i]]);
        memcpy(buffer + offset, iso->volumes[rvols[i]], s_size);
        offset += s_size;
        buffer[offset] = ',';
        ++offset;
    }

    return buffer;
}

static DecodedVolume*
decode_volumes(char* data, size_t* count)
{
    size_t offset = 0;
    uint16_t hc;
    memcpy(&hc, data, sizeof(uint16_t));
    offset += 2;

    DecodedVolume* vols = calloc(hc, sizeof(DecodedVolume));
    if (!vols) {
        fprintf(stderr, "cannot alloc volumes");
        return NULL;
    }

    for (uint16_t i = 0; i < hc; ++i) {
        memcpy(&vols[i].port, data + offset, sizeof(uint16_t));
        offset += 2;
    }

    for (uint16_t i = 0; i < hc; ++i) {
        int volume_ptr = 0;
        while (data[offset] != ',') {
            vols[i].addr[volume_ptr++] = data[offset++];
        }
        offset++; // skip the next comma
        vols[i].addr[volume_ptr] = '\0';
    }

    *count = (size_t)hc;

    return vols;
}

static int
store_replication_info(Iso* iso, const char* path, int* volume_indices)
{
    char* err = NULL;
    char value_buf[BUFFER_SIZE];
    int value_len = 0;

    // Format: volume_count:addr1:port1:addr2:port2:...
    value_len = snprintf(value_buf, BUFFER_SIZE, "%d", iso->replication_factor);

    for (int i = 0; volume_indices[i] != -1; i++) {
        int idx = volume_indices[i];
        value_len += snprintf(value_buf + value_len, BUFFER_SIZE - value_len,
            ":%s:%d",
            iso->volumes[idx],
            iso->ports[idx]);
    }

    DEBUG_LOG("Storing replication info for path %s: %s", path, value_buf);

    leveldb_put(iso->metadata, iso->woptions,
        path, strlen(path),
        value_buf, value_len,
        &err);

    if (err != NULL) {
        fprintf(stderr, "Failed to store replication info: %s\n", err);
        leveldb_free(err);
        return -1;
    }

    return 0;
}

static char*
get_replication_info(Iso* iso, const char* path)
{
    char* err = NULL;
    size_t value_len;

    char* value = leveldb_get(iso->metadata, iso->roptions,
        path, strlen(path),
        &value_len, &err);

    if (err != NULL) {
        fprintf(stderr, "Failed to get replication info: %s\n", err);
        leveldb_free(err);
        return NULL;
    }

    if (value == NULL) {
        return NULL;
    }

    // Create a null-terminated string
    char* result = malloc(value_len + 1);
    if (!result) {
        leveldb_free(value);
        return NULL;
    }

    memcpy(result, value, value_len);
    result[value_len] = '\0';

    leveldb_free(value);
    return result;
}

int
send_file_to_storage(Iso* iso, int volume_index, const char* path, const char* body, int clen)
{
    char request_header[BUFFER_SIZE];
    snprintf(request_header, MAX_HEADER_SIZE,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, iso->volumes[volume_index], iso->ports[volume_index], clen);

    const int storage_socket = connect_to_forward_server(iso->volumes[volume_index], iso->ports[volume_index]);
    DEBUG_LOG("sending file data to storage server at: %s:%d", iso->volumes[volume_index], iso->ports[volume_index]);
    if (storage_socket < 0) {
        perror("error connecting to server socket");
        return -1;
    }

    if (bsend(storage_socket, request_header, strlen(request_header), -1) < 0) {
        perror("error sending response header");
        hclose(storage_socket);
        return -1;
    }

    if (bsend(storage_socket, body, clen, -1) < 0) {
        perror("error sending body to storage server.");
        hclose(storage_socket);
        return -1;
    }

    Response resp;
    if (get_resp_from_socket(storage_socket, &resp) < 0) {
        hclose(storage_socket);
        return -1;
    }

    if (resp.status_code != 201) {
        hclose(storage_socket);
        return -1;
    }

    hclose(storage_socket);
    return 0;
}

void
handle_post(Iso* iso, int client_socket, const char* path,
    const char* body, int clen)
{
    const int path_len = strlen(path);
    char* encoded_path = key_to_path(path, path_len);
    int* replication_volumes = get_key_volumes(iso, path, path_len, iso->replication_factor);

    // create a coroutine bundle such that we can ensure that each goroutine has finished before this
    // // stops blocking.
    // int r_b = bundle();
    // const int deadline = now() + 10000;
    //
    // // wait for all of the coroutines to be finished
    // bundle_wait(r_b, now);
    // hclose(r_b);

    int failures = 0;
    for (int i = 0; replication_volumes[i] != -1; ++i) {
        const int ret = send_file_to_storage(iso, replication_volumes[i], encoded_path, body, clen);
        if (ret != 0) {
            failures += 1;
        }
    }

    if (failures > 0) {
        free(replication_volumes);
        free(encoded_path);
        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
        send_response(client_socket, 502, "Bad Gateway", "text/plain",
            response_body);
        return;
    }

    // now store metadata since everything was successful
    size_t serialized_size;
    char* err = NULL;
    char* serialize_locations = serialize_volume_data(iso, replication_volumes, &serialized_size);
    leveldb_put(iso->metadata, iso->woptions, path, path_len, serialize_locations, serialized_size, &err);
    if (err != NULL) {
        fprintf(stderr, "error writing values to metadata: %s", err);
        leveldb_free(err);
        free(encoded_path);

        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "cannot write metadata");
        send_response(client_socket, 500, "Internal Server Error", "text/plain",
            response_body);
        return;
    }

    free(replication_volumes);
    send_response(client_socket, 200, "OK", "text/plain",
        "File upload processed");
}

void
handle_get(Iso* iso, int c_sock, Request* req)
{
    size_t readlen;
    char* err = NULL;
    size_t path_len = strlen(req->url);
    char* data = leveldb_get(iso->metadata, iso->roptions, req->url, path_len, &readlen, &err);
    if (err != NULL) {
        fprintf(stderr, "error writing values to metadata: %s", err);
        leveldb_free(err);

        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "cannot find metadata for given file");
        send_response(c_sock, 404, "Not Found", "text/plain",
            response_body);
        return;
    }

    // TODO: implement concurrently reading from volumes maybe prob not
    size_t vol_count;
    DecodedVolume* decoded_volumes = decode_volumes(data, &vol_count);

    int s_sock = connect_to_forward_server(decoded_volumes[0].addr, decoded_volumes[0].port);
    if (s_sock < 0) {
        free(decoded_volumes);
        leveldb_free(data);

        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
        send_response(c_sock, 502, "Bad Gateway", "text/plain",
            response_body);
        return;
    }

    /*
> GET /lol1234 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.12.1
> Accept:
        */

    char* encoded_path = key_to_path(req->url, path_len);
    char request_header[BUFFER_SIZE];
    snprintf(request_header, MAX_HEADER_SIZE,
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "\r\n",
        encoded_path, decoded_volumes[0].addr, decoded_volumes[0].port);

    if (bsend(s_sock, request_header, strlen(request_header), -1) < 0) {
        perror("error sending response header");
        free(decoded_volumes);
        free(encoded_path);
        free(data);
        hclose(s_sock);
        return;
    }

    Response resp;
    if (get_resp_from_socket(s_sock, &resp) < 0) {
        free(decoded_volumes);
        free(encoded_path);
        free(data);
        hclose(s_sock);

        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
        send_response(c_sock, 502, "Bad Gateway", "text/plain",
            response_body);
        return;
    }

    // TODO: make this streaming

    char buffer[BUFFER_SIZE];
    size_t bytes_remaining = resp.content_length;
    int rc = 0;

    while (bytes_remaining > 0) {
        size_t to_read = bytes_remaining < BUFFER_SIZE ? bytes_remaining : BUFFER_SIZE;
        ssize_t bytes_read = brecv(s_sock, buffer, to_read, -1);
        if (bytes_read < 0) {
            fprintf(stderr, "Error reading from source socket: %s\n", strerror(errno));
            rc = -1;
            break;
        }

        if (bytes_read == 0 && bytes_remaining > 0) {
            fprintf(stderr, "Source socket closed prematurely\n");
            errno = ECONNRESET;
            rc = -1;
            break;
        }

        ssize_t bytes_written = 0;
        size_t total_written = 0;

        while (total_written < bytes_read) {
            bytes_written = bsend(c_sock, buffer + total_written,
                bytes_read - total_written, -1);
            if (bytes_written < 0) {
                fprintf(stderr, "Error writing to destination socket: %s\n", strerror(errno));
                rc = -1;
                break;
            }
            total_written += bytes_written;
        }

        if (rc < 0) {
            break; // Error occurred in inner loop
        }

        bytes_remaining -= bytes_read;
    }

    free(decoded_volumes);
    free(encoded_path);
    free(data);

    return;
}

coroutine void
req_handler(Iso* iso, int c_sock)
{
    Request req;
    if (get_req_from_socket(c_sock, &req) < 0) {
        hclose(c_sock);
        return;
    }
    const int deadline = now() + 10000;

    printf("%s %s\n", req.method, req.url);
    if (strcmp(req.method, "POST") == 0 && req.content_length > 0) {
        char* temp_body = malloc(req.content_length);
        int total_read = 0;

        while (total_read < req.content_length) {
            int got = brecv(c_sock, temp_body + total_read, req.content_length - total_read, -1);
            if (got <= 0)
                break;

            total_read += got;
        }

        handle_post(iso, c_sock, req.url, temp_body, req.content_length);
    } else if (strcmp(req.method, "GET") == 0) {
        handle_get(iso, c_sock, &req);
    }

    hclose(c_sock);
}

static int
init_leveldb(Iso* iso)
{
    char* err = NULL;
    iso->opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(iso->opts, 1);

    iso->woptions = leveldb_writeoptions_create();
    iso->roptions = leveldb_readoptions_create();

    iso->metadata = leveldb_open(iso->opts, "./metadata.db", &err);
    if (err != NULL) {
        fprintf(stderr, "failed to open leveldb: %s\n", err);
        leveldb_free(err);
        return -1;
    }

    return 0;
}

static void
close_leveldb(Iso* iso)
{
    if (iso->metadata)
        leveldb_close(iso->metadata);
    if (iso->opts)
        leveldb_options_destroy(iso->opts);
    if (iso->woptions)
        leveldb_writeoptions_destroy(iso->woptions);
    if (iso->roptions)
        leveldb_readoptions_destroy(iso->roptions);
}

int
main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "port not supplied");
        exit(EXIT_FAILURE);
    }

    uint16_t port = atoi(argv[1]);

    struct ipaddr addr;
    int rc = ipaddr_local(&addr, NULL, port, 0);
    if (rc < 0) {
        perror("cannot create local address");
        exit(EXIT_FAILURE);
    }

    int ln = tcp_listen(&addr, 10);
    if (ln < 0) {
        perror("error creating listener");
        exit(EXIT_FAILURE);
    }

    Iso iso;
    memset(&iso, 0, sizeof(Iso));
    add_volume(&iso, "127.0.0.1", 8001);
    add_volume(&iso, "127.0.0.1", 8002);
    iso.replication_factor = 3;
    init_leveldb(&iso);

    int b = bundle();

    while (1) {
        int c_socket = tcp_accept(ln, NULL, -1);
        printf("got socket: %d\n", c_socket);
        if (c_socket < 0) {
            if (errno == ETIMEDOUT) {
                continue;
            }

            perror("accept failed");
            continue;
        }

        bundle_go(b, req_handler(&iso, c_socket));
    }

    hclose(b);
    hclose(ln);
    close_leveldb(&iso);
    return 0;
}
