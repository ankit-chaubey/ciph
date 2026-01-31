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
#define VERSION 2

#define SALT_LEN  16
#define KEY_LEN   32
#define NONCE_LEN 12
#define CHUNK     (1024 * 1024)

static void die(const char *m) {
    fprintf(stderr, "ciph: %s\n", m);
    exit(1);
}

int ciph_encrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    int cipher,
    const char *original_name
) {
    if (sodium_init() < 0) die("sodium init failed");

    uint8_t salt[SALT_LEN], data_key[KEY_LEN], derived[KEY_LEN];
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(data_key, KEY_LEN);

    if (crypto_pwhash(
        derived, KEY_LEN,
        password, strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) die("pwhash failed");

    uint8_t nonce_key[NONCE_LEN];
    randombytes_buf(nonce_key, NONCE_LEN);

    uint8_t enc_data_key[KEY_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long enc_key_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        enc_data_key, &enc_key_len,
        data_key, KEY_LEN,
        NULL, 0, NULL,
        nonce_key, derived
    );

    /* Header */
    fwrite(MAGIC, 1, 4, out);
    fputc(VERSION, out);
    fputc(cipher, out);
    fwrite(salt, 1, SALT_LEN, out);
    fwrite(nonce_key, 1, NONCE_LEN, out);

    /* Filename */
    uint8_t name_len = 0;
    if (original_name) {
        size_t len = strlen(original_name);
        if (len > 255) len = 255;
        name_len = (uint8_t)len;
    }
    fputc(name_len, out);
    if (name_len > 0)
        fwrite(original_name, 1, name_len, out);

    uint16_t ek = htons((uint16_t)enc_key_len);
    fwrite(&ek, sizeof(uint16_t), 1, out);
    fwrite(enc_data_key, 1, enc_key_len, out);

    /* Stream encryption (FRAMED) */
    uint8_t buf[CHUNK];
    uint64_t idx = 0;

    while (1) {
        size_t r = fread(buf, 1, CHUNK, in);
        if (r == 0) break;

        uint8_t nonce[NONCE_LEN];
        crypto_generichash(
            nonce, NONCE_LEN,
            (uint8_t*)&idx, sizeof(idx),
            data_key, KEY_LEN
        );

        uint8_t outbuf[CHUNK + crypto_aead_chacha20poly1305_ietf_ABYTES];
        unsigned long long outlen;
        int ok;

        if (cipher == CIPH_AES) {
            ok = crypto_aead_aes256gcm_encrypt(
                outbuf, &outlen, buf, r,
                NULL, 0, NULL, nonce, data_key
            );
        } else {
            ok = crypto_aead_chacha20poly1305_ietf_encrypt(
                outbuf, &outlen, buf, r,
                NULL, 0, NULL, nonce, data_key
            );
        }

        if (ok != 0) die("encrypt failed");

        uint32_t clen = htonl((uint32_t)outlen);
        fwrite(&clen, sizeof(uint32_t), 1, out);
        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    return CIPH_OK;
}

int ciph_decrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    char *out_name,
    size_t out_name_len
) {
    if (sodium_init() < 0) die("sodium init failed");

    char magic[4];
    fread(magic, 1, 4, in);
    if (memcmp(magic, MAGIC, 4)) die("bad magic");

    int version = fgetc(in);
    int cipher  = fgetc(in);
    if (version != VERSION) die("bad version");

    uint8_t salt[SALT_LEN], nonce_key[NONCE_LEN];
    fread(salt, 1, SALT_LEN, in);
    fread(nonce_key, 1, NONCE_LEN, in);

    uint8_t name_len = fgetc(in);
    if (name_len > 0 && out_name && out_name_len > name_len) {
        fread(out_name, 1, name_len, in);
        out_name[name_len] = '\0';
    } else if (name_len > 0) {
        fseek(in, name_len, SEEK_CUR);
    }

    uint16_t ek_len;
    fread(&ek_len, sizeof(uint16_t), 1, in);
    ek_len = ntohs(ek_len);

    uint8_t enc_data_key[128];
    fread(enc_data_key, 1, ek_len, in);

    uint8_t derived[KEY_LEN], data_key[KEY_LEN];
    if (crypto_pwhash(
        derived, KEY_LEN,
        password, strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) die("pwhash failed");

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        data_key, NULL, NULL,
        enc_data_key, ek_len,
        NULL, 0,
        nonce_key, derived
    ) != 0) {
        fprintf(stderr, "ciph: wrong password or corrupted file\n");
        return CIPH_ERR;
    }

    /* Stream decryption (FRAMED) */
    uint8_t buf[CHUNK + crypto_aead_chacha20poly1305_ietf_ABYTES];
    uint64_t idx = 0;

    while (1) {
        uint32_t clen_net;
        if (fread(&clen_net, sizeof(uint32_t), 1, in) != 1)
            break;

        uint32_t clen = ntohl(clen_net);
        if (clen > sizeof(buf)) {
            fprintf(stderr, "ciph: corrupted chunk size\n");
            return CIPH_ERR;
        }

        if (fread(buf, 1, clen, in) != clen) {
            fprintf(stderr, "ciph: truncated file\n");
            return CIPH_ERR;
        }

        uint8_t nonce[NONCE_LEN];
        crypto_generichash(
            nonce, NONCE_LEN,
            (uint8_t*)&idx, sizeof(idx),
            data_key, KEY_LEN
        );

        uint8_t outbuf[CHUNK];
        unsigned long long outlen;
        int ok;

        if (cipher == CIPH_AES) {
            ok = crypto_aead_aes256gcm_decrypt(
                outbuf, &outlen, NULL,
                buf, clen, NULL, 0, nonce, data_key
            );
        } else {
            ok = crypto_aead_chacha20poly1305_ietf_decrypt(
                outbuf, &outlen, NULL,
                buf, clen, NULL, 0, nonce, data_key
            );
        }

        if (ok != 0) {
            fprintf(stderr, "ciph: integrity failure\n");
            return CIPH_ERR;
        }

        fwrite(outbuf, 1, outlen, out);
        idx++;
    }

    sodium_memzero(data_key, KEY_LEN);
    sodium_memzero(derived, KEY_LEN);
    return CIPH_OK;
}
