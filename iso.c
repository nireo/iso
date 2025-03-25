#include "util.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <leveldb/c.h>
#include <libdill.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
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

void
handle_get(int client_socket, const char* path)
{
    char response_body[BUFFER_SIZE];
    snprintf(response_body, BUFFER_SIZE,
        "<html><body><h1>Hello from C HTTP Server</h1>"
        "<p>GET request received for path: %s</p></body></html>",
        path);

    send_response(client_socket, 200, "OK", "text/html", response_body);
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
        const int ret = send_file_to_storage(iso, replication_volumes[i], path, body, clen);
        if (ret != 0) {
            failures += 1;
        }
    }

    if (failures > 0) {
        free(replication_volumes);
        char response_body[BUFFER_SIZE];
        snprintf(response_body, BUFFER_SIZE, "error connecting to servers");
        send_response(client_socket, 502, "Bad Gateway", "text/plain",
            response_body);
        return;
    }

    free(replication_volumes);
    send_response(client_socket, 200, "OK", "text/plain",
        "File upload processed");
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
    }

    hclose(c_sock);
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
    iso.replication_factor = 3;

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
    return 0;
}
