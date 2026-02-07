/*
 * ciph
 * © 2026 Ankit Chaubey (@ankit-chaubey)
 * https://github.com/ankit-chaubey/ciph
 *
 * Licensed under the Apache License, Version 2.0
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#include "ciph.h"
#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Format */
#define MAGIC   "CIPH"
#define VERSION 2

#define SALT_LEN   16
#define KEY_LEN    32
#define NONCE_LEN  12

/* Chunk config */
#define DEFAULT_CHUNK_MB 4
#define MAX_CHUNK_MB     1024

static size_t CHUNK_MB = DEFAULT_CHUNK_MB;

void ciph_set_chunk_mb(size_t mb) {
    if (mb < 1) mb = 1;
    if (mb > MAX_CHUNK_MB) mb = MAX_CHUNK_MB;
    CHUNK_MB = mb;
}

static size_t chunk_bytes(void) {
    return CHUNK_MB * 1024 * 1024;
}

/* Error strings */
const char *ciph_strerror(int rc) {
    switch (rc) {
        case CIPH_OK:               return "success";
        case CIPH_ERR_PARAM:        return "invalid parameter";
        case CIPH_ERR_MAGIC:        return "bad magic";
        case CIPH_ERR_VERSION:      return "unsupported version";
        case CIPH_ERR_PASSWORD:     return "wrong password";
        case CIPH_ERR_CORRUPT:      return "corrupted data";
        case CIPH_ERR_IO:           return "I/O error";
        case CIPH_ERR_MEMORY:       return "out of memory";
        case CIPH_ERR_CRYPTO:       return "cryptographic failure";
        case CIPH_ERR_UNSUPPORTED:  return "unsupported cipher";
        default:                    return "unknown error";
    }
}

/* ================================
 * Encryption
 * ================================ */
int ciph_encrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    int cipher,
    const char *original_name
) {
    if (!in || !out || !password)
        return CIPH_ERR_PARAM;

    if (cipher == CIPH_AES &&
        !crypto_aead_aes256gcm_is_available())
        return CIPH_ERR_UNSUPPORTED;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

    int rc = CIPH_OK;
    size_t CHUNK = chunk_bytes();

    uint8_t salt[SALT_LEN];
    uint8_t data_key[KEY_LEN];
    uint8_t derived[KEY_LEN];
    uint8_t nonce_key[NONCE_LEN];

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(data_key, KEY_LEN);
    randombytes_buf(nonce_key, NONCE_LEN);

    if (crypto_pwhash(
        derived, KEY_LEN,
        password, strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        rc = CIPH_ERR_CRYPTO;
        goto cleanup_keys;
    }

    uint8_t enc_data_key[KEY_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long enc_key_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        enc_data_key, &enc_key_len,
        data_key, KEY_LEN,
        NULL, 0, NULL,
        nonce_key, derived
    ) != 0) {
        rc = CIPH_ERR_CRYPTO;
        goto cleanup_keys;
    }

    if (
        fwrite(MAGIC, 1, 4, out) != 4 ||
        fputc(VERSION, out) == EOF ||
        fputc(cipher, out) == EOF ||
        fwrite(salt, 1, SALT_LEN, out) != SALT_LEN ||
        fwrite(nonce_key, 1, NONCE_LEN, out) != NONCE_LEN
    ) {
        rc = CIPH_ERR_IO;
        goto cleanup_keys;
    }

    uint8_t name_len = 0;
    if (original_name) {
        size_t len = strlen(original_name);
        if (len > 255) len = 255;
        name_len = (uint8_t)len;
    }

    if (fputc(name_len, out) == EOF ||
        (name_len && fwrite(original_name, 1, name_len, out) != name_len)) {
        rc = CIPH_ERR_IO;
        goto cleanup_keys;
    }

    uint16_t ek = htons((uint16_t)enc_key_len);
    if (
        fwrite(&ek, sizeof(uint16_t), 1, out) != 1 ||
        fwrite(enc_data_key, 1, enc_key_len, out) != enc_key_len
    ) {
        rc = CIPH_ERR_IO;
        goto cleanup_keys;
    }

    uint8_t *buf = malloc(CHUNK);
    uint8_t *outbuf = malloc(CHUNK + crypto_aead_chacha20poly1305_ietf_ABYTES);

    if (!buf || !outbuf) {
        rc = CIPH_ERR_MEMORY;
        goto cleanup_buf;
    }

    uint64_t idx = 0;

    while (1) {
        size_t r = fread(buf, 1, CHUNK, in);
        if (r == 0) break;

        uint8_t nonce[NONCE_LEN];
        crypto_generichash(nonce, NONCE_LEN,
            (uint8_t *)&idx, sizeof(idx),
            data_key, KEY_LEN
        );

        unsigned long long outlen = 0;
        int ok = (cipher == CIPH_AES)
            ? crypto_aead_aes256gcm_encrypt(
                outbuf, &outlen, buf, r, NULL, 0, NULL, nonce, data_key)
            : crypto_aead_chacha20poly1305_ietf_encrypt(
                outbuf, &outlen, buf, r, NULL, 0, NULL, nonce, data_key);

        if (ok != 0) {
            rc = CIPH_ERR_CRYPTO;
            break;
        }

        uint32_t clen = htonl((uint32_t)outlen);
        if (
            fwrite(&clen, sizeof(uint32_t), 1, out) != 1 ||
            fwrite(outbuf, 1, outlen, out) != outlen
        ) {
            rc = CIPH_ERR_IO;
            break;
        }
        idx++;
    }

cleanup_buf:
    if (buf) { sodium_memzero(buf, CHUNK); free(buf); }
    if (outbuf) { sodium_memzero(outbuf, CHUNK); free(outbuf); }

cleanup_keys:
    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    return rc;
}

/* ================================
 * Decryption (Adaptive)
 * ================================ */
int ciph_decrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    char *out_name,
    size_t out_name_len
) {
    if (!in || !out || !password)
        return CIPH_ERR_PARAM;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

    int rc = CIPH_OK;
    size_t CHUNK = chunk_bytes();

    char magic[4];
    if (fread(magic, 1, 4, in) != 4 || memcmp(magic, MAGIC, 4))
        return CIPH_ERR_MAGIC;

    int version = fgetc(in);
    int cipher  = fgetc(in);
    if (version != VERSION)
        return CIPH_ERR_VERSION;

    uint8_t salt[SALT_LEN], nonce_key[NONCE_LEN];
    if (fread(salt, 1, SALT_LEN, in) != SALT_LEN ||
        fread(nonce_key, 1, NONCE_LEN, in) != NONCE_LEN)
        return CIPH_ERR_IO;

    uint8_t name_len = fgetc(in);
    if (name_len && out_name && out_name_len > name_len) {
        fread(out_name, 1, name_len, in);
        out_name[name_len] = '\0';
    } else if (name_len) {
        fseek(in, name_len, SEEK_CUR);
    }

    uint16_t ek_len;
    if (fread(&ek_len, sizeof(uint16_t), 1, in) != 1)
        return CIPH_ERR_IO;
    ek_len = ntohs(ek_len);

    uint8_t enc_data_key[128];
    if (ek_len > sizeof(enc_data_key) ||
        fread(enc_data_key, 1, ek_len, in) != ek_len)
        return CIPH_ERR_CORRUPT;

    uint8_t derived[KEY_LEN], data_key[KEY_LEN];
    if (crypto_pwhash(
        derived, KEY_LEN,
        password, strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0)
        return CIPH_ERR_CRYPTO;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        data_key, NULL, NULL,
        enc_data_key, ek_len,
        NULL, 0,
        nonce_key, derived
    ) != 0)
        return CIPH_ERR_PASSWORD;

    uint8_t *buf = malloc(CHUNK + crypto_aead_chacha20poly1305_ietf_ABYTES);
    uint8_t *outbuf = malloc(CHUNK);
    if (!buf || !outbuf) return CIPH_ERR_MEMORY;

    uint64_t idx = 0;
    while (1) {
        uint32_t clen_net;
        if (fread(&clen_net, sizeof(uint32_t), 1, in) != 1)
            break;

        uint32_t clen = ntohl(clen_net);

        if (clen > CHUNK + crypto_aead_chacha20poly1305_ietf_ABYTES) {
            if (clen > MAX_CHUNK_MB * 1024 * 1024 + 64) {
                rc = CIPH_ERR_CORRUPT;
                break;
            }
            uint8_t *nb = realloc(buf, clen);
            uint8_t *no = realloc(outbuf, clen);
            if (!nb || !no) {
                rc = CIPH_ERR_MEMORY;
                break;
            }
            buf = nb;
            outbuf = no;
            CHUNK = clen;
        }

        if (fread(buf, 1, clen, in) != clen) {
            rc = CIPH_ERR_IO;
            break;
        }

        uint8_t nonce[NONCE_LEN];
        crypto_generichash(nonce, NONCE_LEN,
            (uint8_t *)&idx, sizeof(idx),
            data_key, KEY_LEN
        );

        unsigned long long outlen = 0;
        int ok = (cipher == CIPH_AES)
            ? crypto_aead_aes256gcm_decrypt(
                outbuf, &outlen, NULL, buf, clen, NULL, 0, nonce, data_key)
            : crypto_aead_chacha20poly1305_ietf_decrypt(
                outbuf, &outlen, NULL, buf, clen, NULL, 0, nonce, data_key);

        if (ok != 0) {
            rc = CIPH_ERR_CORRUPT;
            break;
        }

        if (fwrite(outbuf, 1, outlen, out) != outlen) {
            rc = CIPH_ERR_IO;
            break;
        }
        idx++;
    }

    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    free(buf);
    free(outbuf);
    return rc;
}
