/* Stolen from https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.h,
 * with only the two ' > 90' checks hoisted */

/* Copyright (c) 2017, 2021 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


// adapted for aedile-ndk by Finrod Felagund (finrod.felagund.97@gmail.com)
// a.k.a. npub1ecdlntvjzexlyfale2egzvvncc8tgqsaxkl5hw7xlgjv2cxs705s9qs735

#pragma once

#ifndef LIGHTNING_COMMON_BECH32_H
#define LIGHTNING_COMMON_BECH32_H

#include <stdint.h>
#include <stdlib.h>

/** Supported encodings. */
typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

// supported protocols
typedef enum {
    SEGWIT_BITCOIN,
    SEGWIT_NOSTR,

    SEGWIT_MAX
} segwit_protocol;

/**
 * @brief Encode a SegWit address while managing the subtleties
 * betweem nostr segwit encoding and proper bitcoin segwit encoding.
 *
 * @param output Pointer to a buffer of size 73 + strlen(hrp) that will be
 * updated to contain the null-terminated address.
 * @param hrp Pointer to the null-terminated human readable part to use
 * (chain/network specific).
 * @param ver Version of the witness program (between 0 and 16 inclusive,
 * should default to 0 when encoding a nostr address).
 * @param prog Data bytes for the witness program (between 2 and 40 bytes).
 * @param prog_len Number of data bytes in prog.
 * @param protocol An enum to indicate whether the encoding is for bitcoin
 * or for nostr, because it is not 100% the same.
 * For Nostr, the the witversion variable is not added to the beginning
 * of the data array.
 * @return int
 */
int segwit_addr_encode(
    char *output,
    const char *hrp,
    int ver,
    const uint8_t *prog,
    size_t prog_len,
    segwit_protocol protocol
);

/**
 * @brief Decode a SegWit address
 *
 * @param ver  Pointer to an int that will be updated to contain the witness
 * program version (between 0 and 16 inclusive).
 * @param prog Pointer to a buffer of size 40 that will be updated to
 * contain the witness program bytes.
 * @param prog_len Pointer to a size_t that will be updated to contain the length
 * of bytes in prog.
 * @param hrp Pointer to the null-terminated human readable part that is
 * expected (chain/network specific).
 * @param addr Pointer to the null-terminated address.
 * @param protocol An enum to indicate whether the encoding is for bitcoin
 * or for nostr, because it is not 100% the same.
 * For Nostr, the the witversion variable is not added to the beginning
 * of the data array.
 * @return int 1 if successful, otherwise 0.
 */
int segwit_addr_decode(
    int* ver,
    uint8_t* prog,
    size_t* prog_len,
    const char* hrp,
    const char* addr,
    segwit_protocol protocol
);



/**
 * @brief Encode a Bech32 or Bech32m string
 *
 * @param output Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 * will be updated to contain the null-terminated Bech32 string.
 * @param hrp Pointer to the null-terminated human readable part.
 * @param data Pointer to an array of 5-bit values.
 * @param data_len Length of the data array.
 * @param max_input_len Maximum valid length of input (90 for segwit usage).
 * @param enc Which encoding to use (BECH32_ENCODING_BECH32{,M}).
 * @return int: 1 if successful, else 0
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len,
    size_t max_input_len,
    bech32_encoding enc
);


/**
 * @brief Decode a Bech32 or Bech32m string. Decoded address
 * will be found at the address pointed to by `data`.
 * Will call `bech32_decode_len` if `data_len` is less than
 *
 * @param hrp Pointer to a buffer of size strlen(input) - 6. Will be
 * updated to contain the null-terminated human readable part.
 * @param data Pointer to a buffer of size strlen(input) - 8 that will
 * hold the encoded 5-bit data values.
 * @param data_len Pointer to a size_t that will be updated to be the number
 * of entries in data.
 * @param input Pointer to a null-terminated Bech32 string.
 * @param max_input_len Maximum valid length of input (90 for segwit usage).
 * @return bech32_encoding enum to specify which bech32 was just decoded
 */
bech32_encoding bech32_decode(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input,
    size_t max_input_len
);

/**
 * @brief Decode a Bech32 or Bech32m string. Decoded address
 * will be found at the address pointed to by `data` if the value
 * pointed to by`data_len` is less than or equal to `max_input_len`
 *
 * @param hrp Pointer to a buffer of size strlen(input) - 6. Will be
 * updated to contain the null-terminated human readable part.
 * @param data Pointer to a buffer of size strlen(input) - 8 that will
 * hold the encoded 5-bit data values.
 * @param data_len Pointer to a size_t that will be updated to be the number
 * of entries in data.
 * @param input Pointer to a null-terminated Bech32 string.
 * @param max_input_len Maximum valid length of input (90 for segwit usage).
 * @return bech32_encoding enum to specify which bech32 was just decoded
 */
bech32_encoding bech32_decode_len(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input,
    size_t input_len
);

/* Helper from bech32: translates inbits-bit bytes to outbits-bit bytes.
 * @outlen is incremented as bytes are added.
 * @pad is true if we're to pad, otherwise truncate last byte if necessary
 */
int bech32_convert_bits(uint8_t* out, size_t* outlen, int outbits,
            const uint8_t* in, size_t inlen, int inbits,
            int pad);

/* The charset, and reverse mapping */
extern const char bech32_charset[33];
extern const int8_t bech32_charset_rev[128];

#endif /* LIGHTNING_COMMON_BECH32_H */
