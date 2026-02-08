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

#define MAGIC   "CIPH"
#define VERSION 3

#define SALT_LEN   16
#define KEY_LEN    32
#define NONCE_LEN  12

#define DEFAULT_CHUNK_MB 4
#define MAX_CHUNK_MB     1024
#define AAD_MAX          512

static size_t CHUNK_MB = DEFAULT_CHUNK_MB;

void ciph_set_chunk_mb(size_t mb) {
    if (mb < 1) mb = 1;
    if (mb > MAX_CHUNK_MB) mb = MAX_CHUNK_MB;
    CHUNK_MB = mb;
}

static size_t chunk_bytes_mb(size_t mb) {
    return mb * 1024 * 1024;
}

const char *ciph_strerror(int rc) {
    switch (rc) {
        case CIPH_OK: return "success";
        case CIPH_ERR_PARAM: return "invalid parameter";
        case CIPH_ERR_MAGIC: return "bad magic";
        case CIPH_ERR_VERSION: return "unsupported version";
        case CIPH_ERR_PASSWORD: return "wrong password";
        case CIPH_ERR_CORRUPT: return "corrupted data";
        case CIPH_ERR_IO: return "I/O error";
        case CIPH_ERR_MEMORY: return "out of memory";
        case CIPH_ERR_CRYPTO: return "cryptographic failure";
        case CIPH_ERR_UNSUPPORTED: return "unsupported cipher";
        default: return "unknown error";
    }
}

static size_t build_header_aad(
    uint8_t *aad,
    int cipher,
    uint32_t chunk_mb,
    const uint8_t *salt,
    const uint8_t *nonce_key,
    const uint8_t *name,
    uint8_t name_len,
    const uint8_t *enc_data_key,
    uint16_t enc_key_len
) {
    uint8_t *p = aad;

    memcpy(p, MAGIC, 4); p += 4;
    *p++ = VERSION;
    *p++ = (uint8_t)cipher;

    uint32_t mb_net = htonl(chunk_mb);
    memcpy(p, &mb_net, 4); p += 4;

    memcpy(p, salt, SALT_LEN); p += SALT_LEN;
    memcpy(p, nonce_key, NONCE_LEN); p += NONCE_LEN;

    *p++ = name_len;
    if (name_len) {
        memcpy(p, name, name_len);
        p += name_len;
    }

    uint16_t ek_net = htons(enc_key_len);
    memcpy(p, &ek_net, 2); p += 2;
    memcpy(p, enc_data_key, enc_key_len); p += enc_key_len;

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
    int rc = CIPH_OK;

    if (!in || !out || !password || password_len == 0)
        return CIPH_ERR_PARAM;

    if (cipher == CIPH_AES &&
        !crypto_aead_aes256gcm_is_available())
        return CIPH_ERR_UNSUPPORTED;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

    uint32_t file_chunk_mb = (uint32_t)CHUNK_MB;
    size_t CHUNK = chunk_bytes_mb(file_chunk_mb);

    uint8_t salt[SALT_LEN];
    uint8_t nonce_key[NONCE_LEN];
    uint8_t data_key[KEY_LEN];
    uint8_t derived[KEY_LEN];

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(nonce_key, NONCE_LEN);
    randombytes_buf(data_key, KEY_LEN);

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

    uint8_t k_enc[KEY_LEN], k_nonce[KEY_LEN];
    crypto_kdf_derive_from_key(k_enc, KEY_LEN, 1, "CIPHenc", data_key);
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

    uint8_t name_len = 0;
    const uint8_t *name_ptr = NULL;
    if (original_name) {
        size_t l = strlen(original_name);
        if (l > 255) l = 255;
        name_len = (uint8_t)l;
        name_ptr = (const uint8_t *)original_name;
    }

    fwrite(MAGIC, 1, 4, out);
    fputc(VERSION, out);
    fputc(cipher, out);

    uint32_t mb_net = htonl(file_chunk_mb);
    fwrite(&mb_net, 4, 1, out);

    fwrite(salt, 1, SALT_LEN, out);
    fwrite(nonce_key, 1, NONCE_LEN, out);

    fputc(name_len, out);
    if (name_len) fwrite(name_ptr, 1, name_len, out);

    uint16_t ek_net = htons((uint16_t)enc_key_len);
    fwrite(&ek_net, 2, 1, out);
    fwrite(enc_data_key, 1, enc_key_len, out);

    uint8_t header_aad[AAD_MAX];
    size_t hlen = build_header_aad(
        header_aad, cipher, file_chunk_mb,
        salt, nonce_key,
        name_ptr, name_len,
        enc_data_key, (uint16_t)enc_key_len
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
            goto cleanup_buf;
        }

        uint32_t clen = htonl((uint32_t)outlen);
        fwrite(&clen, 4, 1, out);
        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

    {
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
                NULL, 0,
                header_aad, hlen,
                NULL, nonce, k_enc)
            : crypto_aead_chacha20poly1305_ietf_encrypt(
                outbuf, &outlen,
                NULL, 0,
                header_aad, hlen,
                NULL, nonce, k_enc);

        if (ok != 0) {
            rc = CIPH_ERR_CRYPTO;
            goto cleanup_buf;
        }

        uint32_t clen = htonl((uint32_t)outlen);
        fwrite(&clen, 4, 1, out);
        fwrite(outbuf, 1, outlen, out);
    }

cleanup_buf:
    if (buf) { sodium_memzero(buf, CHUNK); free(buf); }
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
    int rc = CIPH_OK;

    uint8_t *buf = NULL, *outbuf = NULL;
    uint8_t data_key[KEY_LEN], derived[KEY_LEN];
    uint8_t k_enc[KEY_LEN], k_nonce[KEY_LEN];

    if (!in || !out || !password || password_len == 0)
        return CIPH_ERR_PARAM;

    if (sodium_init() < 0)
        return CIPH_ERR_CRYPTO;

    char magic[4];
    if (fread(magic, 1, 4, in) != 4 || memcmp(magic, MAGIC, 4))
        return CIPH_ERR_MAGIC;

    int version = fgetc(in);
    int cipher = fgetc(in);
    if (version != VERSION)
        return CIPH_ERR_VERSION;

    uint32_t chunk_mb;
    if (fread(&chunk_mb, 4, 1, in) != 1)
        return CIPH_ERR_IO;
    chunk_mb = ntohl(chunk_mb);

    if (chunk_mb < 1 || chunk_mb > MAX_CHUNK_MB)
        return CIPH_ERR_CORRUPT;

    size_t CHUNK = chunk_bytes_mb(chunk_mb);

    uint8_t salt[SALT_LEN], nonce_key[NONCE_LEN];
    if (fread(salt, 1, SALT_LEN, in) != SALT_LEN ||
        fread(nonce_key, 1, NONCE_LEN, in) != NONCE_LEN)
        return CIPH_ERR_IO;

    uint8_t name_len = fgetc(in);
    if (name_len > 255) {
    return CIPH_ERR_CORRUPT;
    }
    uint8_t name_buf[256];
    if (name_len) {
    if (fread(name_buf, 1, name_len, in) != name_len) {
        return CIPH_ERR_CORRUPT;
    }
    }

    uint16_t ek_len;
    if (fread(&ek_len, 2, 1, in) != 1) {
        return CIPH_ERR_CORRUPT;
    }
    ek_len = ntohs(ek_len);
    uint8_t enc_data_key[128];
    if (ek_len > sizeof(enc_data_key) ||
        fread(enc_data_key, 1, ek_len, in) != ek_len)
        return CIPH_ERR_CORRUPT;

    if (out_name && out_name_len > name_len) {
        memcpy(out_name, name_buf, name_len);
        out_name[name_len] = 0;
    }

    if (crypto_pwhash(
        derived, KEY_LEN,
        (const char *)password, password_len,
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        rc = CIPH_ERR_CRYPTO;
        goto cleanup;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        data_key, NULL, NULL,
        enc_data_key, ek_len,
        NULL, 0,
        nonce_key, derived
    ) != 0) {
        rc = CIPH_ERR_PASSWORD;
        goto cleanup;
    }

    crypto_kdf_derive_from_key(k_enc, KEY_LEN, 1, "CIPHenc", data_key);
    crypto_kdf_derive_from_key(k_nonce, KEY_LEN, 2, "CIPHnon", data_key);

    uint8_t header_aad[AAD_MAX];
    size_t hlen = build_header_aad(
        header_aad, cipher, chunk_mb,
        salt, nonce_key,
        name_buf, name_len,
        enc_data_key, ek_len
    );

    buf = malloc(CHUNK + 64);
    outbuf = malloc(CHUNK);
    if (!buf || !outbuf) {
        rc = CIPH_ERR_MEMORY;
        goto cleanup;
    }

    uint64_t idx = 0;
    while (1) {
        uint32_t clen_net;
        if (fread(&clen_net, 4, 1, in) != 1)
            break;

        uint32_t clen = ntohl(clen_net);
        if (clen > CHUNK + 64) {
            rc = CIPH_ERR_CORRUPT;
            goto cleanup;
        }

        if (fread(buf, 1, clen, in) != clen) {
            rc = CIPH_ERR_CORRUPT;
            goto cleanup;
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
            rc = CIPH_ERR_CORRUPT;
            goto cleanup;
        }

        if (outlen == 0)
            break;

        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

cleanup:
    if (buf) { sodium_memzero(buf, CHUNK + 64); free(buf); }
    if (outbuf) { sodium_memzero(outbuf, CHUNK); free(outbuf); }

    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    sodium_memzero(k_enc, KEY_LEN);
    sodium_memzero(k_nonce, KEY_LEN);
    return rc;
}
