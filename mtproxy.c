#include "mtproxy.h"
#include "sslh-conf.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

struct MTProxyData {
    const char **secrets;
    size_t secrets_len;
};

#define TLS_START_BYTES "\x16\x03\x01\x02\x00\x01\x00\x01\x0fc\x03\x03"
#define TLS_START_BYTES_LEN 11
#define TLS_HANDSHAKE_LENGTH 1 + 2 + 2 + 512

#define RANDOM_LENGTH 32

HMAC_CTX* new_hmac();
void delete_hmac(HMAC_CTX*);

struct MTProxyData *new_mtproxy_data(const char **secrets, size_t secrets_len) {
    struct MTProxyData *mtproxy_data = malloc(sizeof(struct MTProxyData));
    CHECK_ALLOC(mtproxy_data, "malloc");

    mtproxy_data->secrets = secrets;
    mtproxy_data->secrets_len = secrets_len;

    return mtproxy_data;
}

int parse_mtproxy_header(const struct MTProxyData *mtproxy_data, const char *data, size_t data_len) {
    // checking is there any secrets in mtproxy_data
    if (!mtproxy_data->secrets_len) {
        if (cfg.verbose) fprintf(stderr, "There are no any secrets specified.\n");
        return MTPROXY_UNMATCH;
    }

    // check whether data is mtproxy header
    if (data_len != TLS_HANDSHAKE_LENGTH) {
        if (cfg.verbose) {
            fprintf(stderr, "Request has wrong length (expected: %d, actual: %zu).\n", TLS_HANDSHAKE_LENGTH, data_len);
        }

        return MTPROXY_UNMATCH;
    }

    const int is_mtproxy_header = memcmp(data, TLS_START_BYTES, TLS_START_BYTES_LEN);
    if (is_mtproxy_header) {
        if (cfg.verbose) {
            fprintf(stderr, "Request has wrong starting %d bytes.\n", TLS_START_BYTES_LEN);
        }

        return MTPROXY_UNMATCH;
    }

    // saving copy of incoming data
    char *digest_data = (char*)malloc(TLS_HANDSHAKE_LENGTH * sizeof(char));
    memcpy(digest_data, data, TLS_HANDSHAKE_LENGTH);

    // moving incoming random to validate it later
    char *incoming_digest = (char*)malloc(RANDOM_LENGTH * sizeof(char));
    memcpy(incoming_digest, digest_data + 11, RANDOM_LENGTH);
    memset(digest_data + 11, 0, 32);

    // compute then compare digests
    unsigned char *computed_digest = (unsigned char*)malloc(RANDOM_LENGTH * sizeof(unsigned char));
    int result = MTPROXY_UNMATCH;
    HMAC_CTX *hmac = new_hmac();

    for (size_t i = 0; i < mtproxy_data->secrets_len; i++) {
        // compute digest
        HMAC_Init_ex(hmac, mtproxy_data->secrets[i], SECRET_LENGTH, EVP_sha256(), NULL);
        HMAC_Update(hmac, (const unsigned char*)digest_data, TLS_HANDSHAKE_LENGTH);
        HMAC_Final(hmac, computed_digest, NULL);

        // compare digest
        result = memcmp(incoming_digest, computed_digest, RANDOM_LENGTH - 4);
        if (!result) {
            result = MTPROXY_MATCH;
            break;
        }
    }

    if (result && cfg.verbose) { // when failed
        fprintf(stderr, "Request has wrong digest.\n");
    }

    // cleaning up
    delete_hmac(hmac);
    free((void*)computed_digest);
    free((void*)digest_data);
    free((void*)incoming_digest);
    return result;
}

// HMAC SHA256 implementation taken from https://gist.github.com/SylvainCorlay/2997bd875d0527eb1ac008267876394b
// Thank you, SylvainCorlay!

HMAC_CTX* new_hmac() {
    HMAC_CTX *hmac;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // OpenSSL 1.0.x
    HMAC_CTX hmac_l;
    HMAC_CTX_init(&hmac_l);
    hmac = &hmac_l;
#else
    hmac = HMAC_CTX_new();
#endif

    return hmac;
}

void delete_hmac(HMAC_CTX *hmac) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // OpenSSL 1.0.x
    HMAC_CTX_cleanup(hmac);
#else
    HMAC_CTX_free(hmac);
#endif
}

