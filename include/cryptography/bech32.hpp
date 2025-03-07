#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <sstream>

#define MAX_INPUT_LENGTH 256
#define FROM_BITS 8
#define TO_BITS 5

typedef std::string PubKey, EventId, PrivKey, Tag;
typedef std::vector<uint8_t> TlvValues, BytesArray;
typedef std::vector<std::string> Relays;

const int8_t bech32CharsetRev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

const char bech32Charset[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

namespace nostr
{
namespace encoding
{

typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} Bech32EncodingType;

// supported protocols
typedef enum {
    SEGWIT_BITCOIN,
    SEGWIT_NOSTR,
    SEGWIT_MAX
} SegwitProtocol;

class Bech32
{
public:
    /**
     * @brief Encode a SegWit address while managing the subtleties
     * betweem nostr segwit encoding and proper bitcoin segwit encoding.
     *
     * @param output string that will contain the encoded address.
     * @param hrp Pointer to the null-terminated human readable part to use
     * (chain/network specific).
     * @param ver Version of the witness program (between 0 and 16 inclusive,
     * should default to 0 when encoding a nostr address).
     * @param prog Data bytes for the witness program (between 2 and 40 bytes).
     * @param protocol An enum to indicate whether the encoding is for bitcoin
     * or for nostr, because it is not 100% the same.
     * For Nostr, the the witversion variable is not added to the beginning
     * of the data array.
     * @return int
     */
    static int segwitAddrEncode(
        std::string &output,
        const std::string hrp,
        int ver,
        const BytesArray &prog,
        SegwitProtocol protocol
    );

    /**
     * @brief Decode a SegWit address
     *
     * @param ver  Pointer to an int that will be updated to contain the witness
     * program version (between 0 and 16 inclusive).
     * @param prog Pointer to a buffer of size 40 that will be updated to
     * contain the witness program bytes.
     * @param hrp Pointer to the null-terminated human readable part that is
     * expected (chain/network specific).
     * @param addr Pointer to the null-terminated address.
     * @param protocol An enum to indicate whether the encoding is for bitcoin
     * or for nostr, because it is not 100% the same.
     * For Nostr, the the witversion variable is not added to the beginning
     * of the data array.
     * @return int 1 if successful, otherwise 0.
     */
    static int segwitAddrDecode(
        std::shared_ptr<int> ver,
        BytesArray &prog,
        const std::string hrp,
        const std::string addr,
        SegwitProtocol protocol
    );

    /**
     * @brief Encode a Bech32 or Bech32m string
     *
     * @param output Pointer to a buffer of size strlen(hrp) + data_len + 8 that
     * will be updated to contain the null-terminated Bech32 string.
     * @param hrp Pointer to the null-terminated human readable part.
     * @param data Pointer to an array of 5-bit values.
     * @param max_input_len Maximum valid length of input (90 for segwit usage).
     * @param enc Which encoding to use (BECH32_ENCODING_BECH32{,M}).
     * @return int: 1 if successful, else 0
     */
    static int encode(
        std::string &output,
        const std::string hrp,
        const BytesArray &data,
        std::size_t max_input_len,
        Bech32EncodingType enc
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
     * @param input Pointer to a null-terminated Bech32 string.
     * @param max_input_len Maximum valid length of input (90 for segwit usage).
     * @return bech32_encoding enum to specify which bech32 was just decoded
     */
    static Bech32EncodingType decode(
        std::string &hrp,
        BytesArray &data,
        const std::string input,
        std::size_t max_input_len
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
     * @param input Pointer to a null-terminated Bech32 string.
     * @param max_input_len Maximum valid length of input (90 for segwit usage).
     * @return bech32_encoding enum to specify which bech32 was just decoded
     */
    static Bech32EncodingType decodeLen(
        std::string &hrp,
        BytesArray &data,
        const std::string input,
        std::size_t max_input_len
    );

    /* Helper from bech32: translates inbits-bit bytes to outbits-bit bytes.
    * @outlen is incremented as bytes are added.
    * @pad is true if we're to pad, otherwise truncate last byte if necessary
    */

   /**
    * @brief Helper from bech32: translates inbits-bit bytes to outbits-bit bytes.
    * `outlen` is incremented as bytes are added. `pad` is true if we're to pad,
    * otherwise truncate last byte if necessary

    * @param out output buffer where the converted words are found
    * @param outbits the number of desired bits in each word in the converted output
    * @param in input buffer where the words to convert are found.
    * @param inbits the number of bits in each word in the input
    * @param pad boolean flag to see whether or not to pad
    * @return int 1 if function was successul, 0 if not
    */
    static int convertBits(BytesArray &out, int outbits,
                const BytesArray &in, int inbits,
                int pad);
};
}
}