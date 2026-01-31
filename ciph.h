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

#define CIPH_AES    1
#define CIPH_CHACHA 2

#define CIPH_OK  0
#define CIPH_ERR -1

int ciph_encrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    int cipher,
    const char *original_name
);

int ciph_decrypt_stream(
    FILE *in,
    FILE *out,
    const char *password,
    char *out_name,      // buffer (>=256 bytes)
    size_t out_name_len
);

#endif
