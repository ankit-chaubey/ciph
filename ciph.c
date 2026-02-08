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

/* ================= FORMAT ================= */

#define MAGIC   "CIPH"
#define VERSION 2

#define SALT_LEN   16
#define KEY_LEN    32
#define NONCE_LEN  12

#define DEFAULT_CHUNK_MB 4
#define MAX_CHUNK_MB     1024
#define AAD_MAX          512

static size_t CHUNK_MB = DEFAULT_CHUNK_MB;

/* ================= UTIL ================= */

void ciph_set_chunk_mb(size_t mb) {
    if (mb < 1) mb = 1;
    if (mb > MAX_CHUNK_MB) mb = MAX_CHUNK_MB;
    CHUNK_MB = mb;
}

static size_t chunk_bytes(void) {
    return CHUNK_MB * 1024 * 1024;
}

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

/* ================= HEADER AAD ================= */

static size_t build_header_aad(
    uint8_t *aad,
    int cipher,
    const uint8_t *salt,
    const uint8_t *nonce_key,
    const char *name,
    const uint8_t *enc_data_key,
    uint16_t enc_key_len
) {
    uint8_t *p = aad;

    memcpy(p, MAGIC, 4); p += 4;
    *p++ = VERSION;
    *p++ = (uint8_t)cipher;

    memcpy(p, salt, SALT_LEN); p += SALT_LEN;
    memcpy(p, nonce_key, NONCE_LEN); p += NONCE_LEN;

    uint8_t name_len = 0;
    if (name) {
        size_t len = strlen(name);
        if (len > 255) len = 255;
        name_len = (uint8_t)len;
    }

    *p++ = name_len;
    if (name_len) {
        memcpy(p, name, name_len);
        p += name_len;
    }

    uint16_t ek_net = htons(enc_key_len);
    memcpy(p, &ek_net, sizeof(uint16_t));
    p += sizeof(uint16_t);

    memcpy(p, enc_data_key, enc_key_len);
    p += enc_key_len;

    return (size_t)(p - aad);
}

/* ================= ENCRYPT ================= */

int ciph_encrypt_stream(
    FILE *in,
    FILE *out,
    const uint8_t *password,
    size_t password_len,
    int cipher,
    const char *original_name
) {
    if (!in || !out || !password || password_len == 0)
        return CIPH_ERR_PARAM;

    if (cipher == CIPH_AES &&
        !crypto_aead_aes256gcm_is_available())
        return CIPH_ERR_UNSUPPORTED;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

    size_t CHUNK = chunk_bytes();
    int rc = CIPH_OK;

    uint8_t salt[SALT_LEN];
    uint8_t data_key[KEY_LEN];
    uint8_t derived[KEY_LEN];
    uint8_t nonce_key[NONCE_LEN];

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(data_key, KEY_LEN);
    randombytes_buf(nonce_key, NONCE_LEN);

    if (crypto_pwhash(
        derived, KEY_LEN,
        (const char *)password, password_len,
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        rc = CIPH_ERR_CRYPTO;
        goto cleanup_keys;
    }

    /* Key separation */
    uint8_t k_enc[KEY_LEN];
    uint8_t k_nonce[KEY_LEN];
    crypto_kdf_derive_from_key(k_enc,   KEY_LEN, 1, "CIPHenc", data_key);
    crypto_kdf_derive_from_key(k_nonce, KEY_LEN, 2, "CIPHnon", data_key);

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

    /* Write header */
    fwrite(MAGIC, 1, 4, out);
    fputc(VERSION, out);
    fputc(cipher, out);
    fwrite(salt, 1, SALT_LEN, out);
    fwrite(nonce_key, 1, NONCE_LEN, out);

    uint8_t name_len = 0;
    if (original_name) {
        size_t len = strlen(original_name);
        if (len > 255) len = 255;
        name_len = (uint8_t)len;
    }
    fputc(name_len, out);
    if (name_len) fwrite(original_name, 1, name_len, out);

    uint16_t ek = htons((uint16_t)enc_key_len);
    fwrite(&ek, sizeof(uint16_t), 1, out);
    fwrite(enc_data_key, 1, enc_key_len, out);

    /* Build AAD */
    uint8_t header_aad[AAD_MAX];
    size_t hlen = build_header_aad(
        header_aad, cipher, salt, nonce_key,
        original_name, enc_data_key, (uint16_t)enc_key_len
    );

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
        crypto_generichash(
            nonce, NONCE_LEN,
            (uint8_t *)&idx, sizeof(idx),
            k_nonce, KEY_LEN
        );

        unsigned long long outlen = 0;
        int ok = (cipher == CIPH_AES)
            ? crypto_aead_aes256gcm_encrypt(
                outbuf, &outlen,
                buf, r,
                header_aad, hlen,
                NULL, nonce, k_enc)
            : crypto_aead_chacha20poly1305_ietf_encrypt(
                outbuf, &outlen,
                buf, r,
                header_aad, hlen,
                NULL, nonce, k_enc);

        if (ok != 0) {
            rc = CIPH_ERR_CRYPTO;
            break;
        }

        uint32_t clen = htonl((uint32_t)outlen);
        fwrite(&clen, sizeof(uint32_t), 1, out);
        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

cleanup_buf:
    if (buf)    { sodium_memzero(buf, CHUNK); free(buf); }
    if (outbuf) { sodium_memzero(outbuf, CHUNK); free(outbuf); }

cleanup_keys:
    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    sodium_memzero(k_enc, KEY_LEN);
    sodium_memzero(k_nonce, KEY_LEN);
    return rc;
}

/* ================= DECRYPT ================= */

int ciph_decrypt_stream(
    FILE *in,
    FILE *out,
    const uint8_t *password,
    size_t password_len,
    char *out_name,
    size_t out_name_len
) {
    if (!in || !out || !password || password_len == 0)
        return CIPH_ERR_PARAM;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

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
        (const char *)password, password_len,
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

    uint8_t k_enc[KEY_LEN], k_nonce[KEY_LEN];
    crypto_kdf_derive_from_key(k_enc,   KEY_LEN, 1, "CIPHenc", data_key);
    crypto_kdf_derive_from_key(k_nonce, KEY_LEN, 2, "CIPHnon", data_key);

    uint8_t header_aad[AAD_MAX];
    size_t hlen = build_header_aad(
        header_aad, cipher, salt, nonce_key,
        out_name, enc_data_key, ek_len
    );

    size_t CHUNK = chunk_bytes();
    uint8_t *buf = malloc(CHUNK + 64);
    uint8_t *outbuf = malloc(CHUNK);
    if (!buf || !outbuf) return CIPH_ERR_MEMORY;

    uint64_t idx = 0;
    while (1) {
        uint32_t clen_net;
        if (fread(&clen_net, sizeof(uint32_t), 1, in) != 1)
            break;

        uint32_t clen = ntohl(clen_net);
        if (clen > MAX_CHUNK_MB * 1024 * 1024 + 64) {
            sodium_memzero(data_key, KEY_LEN);
            free(buf); free(outbuf);
            return CIPH_ERR_CORRUPT;
        }

        if (fread(buf, 1, clen, in) != clen) {
            sodium_memzero(data_key, KEY_LEN);
            free(buf); free(outbuf);
            return CIPH_ERR_CORRUPT;
        }

        uint8_t nonce[NONCE_LEN];
        crypto_generichash(
            nonce, NONCE_LEN,
            (uint8_t *)&idx, sizeof(idx),
            k_nonce, KEY_LEN
        );

        unsigned long long outlen = 0;
        int ok = (cipher == CIPH_AES)
            ? crypto_aead_aes256gcm_decrypt(
                outbuf, &outlen, NULL,
                buf, clen,
                header_aad, hlen,
                nonce, k_enc)
            : crypto_aead_chacha20poly1305_ietf_decrypt(
                outbuf, &outlen, NULL,
                buf, clen,
                header_aad, hlen,
                nonce, k_enc);

        if (ok != 0) {
            sodium_memzero(data_key, KEY_LEN);
            free(buf); free(outbuf);
            return CIPH_ERR_CORRUPT;
        }

        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    sodium_memzero(k_enc, KEY_LEN);
    sodium_memzero(k_nonce, KEY_LEN);
    free(buf);
    free(outbuf);
    return CIPH_OK;
}
