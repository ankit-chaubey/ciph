/*
 * ciph
 * © 2026 Ankit Chaubey (@ankit-chaubey)
 * https://github.com/ankit-chaubey/ciph
 *
 * Licensed under the Apache License, Version 2.0
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CIPH_H
#define CIPH_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

/* Cipher identifiers */
#define CIPH_AES    1
#define CIPH_CHACHA 2

/* Return codes */
#define CIPH_OK               0
#define CIPH_ERR_PARAM       -1
#define CIPH_ERR_MAGIC       -2
#define CIPH_ERR_VERSION     -3
#define CIPH_ERR_PASSWORD    -4
#define CIPH_ERR_CORRUPT     -5
#define CIPH_ERR_IO          -6
#define CIPH_ERR_MEMORY      -7
#define CIPH_ERR_CRYPTO      -8
#define CIPH_ERR_UNSUPPORTED -9

/* Chunk size (MB) */
void ciph_set_chunk_mb(size_t mb);

/* ===== SECURE API ===== */

int ciph_encrypt_stream(
    FILE *in,
    FILE *out,
    const uint8_t *password,
    size_t password_len,
    int cipher,
    const char *original_name
);

int ciph_decrypt_stream(
    FILE *in,
    FILE *out,
    const uint8_t *password,
    size_t password_len,
    char *out_name,
    size_t out_name_len
);

/* Error string */
const char *ciph_strerror(int rc);

#endif /* CIPH_H */
