

#include <nostr.hpp>
#include <gtest/gtest.h>

namespace nostr_test {

class Bech32Test: public testing::Test {
    protected:
    Bech32Test() {}
    ~Bech32Test() override {}
    void SetUp() override {}
};

TEST_F(Bech32Test, NpubEncoding) {
    char output[KEY_LENGTH*2 + 1];
    char input[KEY_LENGTH*2 + 1] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }
    if (!segwit_addr_encode(output, "npub", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"), 0);
}

TEST_F(Bech32Test, NsecEncoding) {
    char output[KEY_LENGTH*2 + 1];
    char input[KEY_LENGTH*2 + 1] = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }

    if(!segwit_addr_encode(output, "nsec", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"), 0);
}

TEST_F(Bech32Test, NoteEncoding) {
    char output[KEY_LENGTH*2 + 1];
    char input[KEY_LENGTH*2 + 1] = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }

    if (!segwit_addr_encode(output, "note", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g"), 0);
}

TEST_F(Bech32Test, NprofileEncoding) {
    char pubkey[KEY_LENGTH*2 + 1] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char *relays[2] = {"wss://r.x.com", "wss://djbas.sadkb.com"};
    char expected_nprofile[132] = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    char output[256];

    char current_byte[3];

    int input_len = 2 + KEY_LENGTH;

    for (int i = 0; i < 2; i++) {
        input_len += strlen(relays[i]);
        input_len += 2;
    }

    uint8_t input_hex[input_len];
    cursor cur;
    make_cursor(input_hex, input_hex + input_len, &cur);
    uint8_t type = 0;
    uint8_t len = KEY_LENGTH;

    if (!put_byte(&cur, &type))
        FAIL() << "Failed to insert byte for type\n";

    if (!put_byte(&cur, &len))
        FAIL() << "Failed to insert type for data length\n";

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, pubkey + 2*i, 2);
        input_hex[i+2] = (uint8_t)strtol(current_byte, NULL, 16);
    }
    if (!move_bytes(&cur, KEY_LENGTH))
        FAIL() << "Failed to move " << KEY_LENGTH << " bytes\n";

    for (int i = 0; i < 2;i++) {
        uint8_t type = 1;
        uint8_t len = strlen(relays[i]);
        if (!put_byte(&cur, &type))
            FAIL() << "Failed to insert byte for type\n";
        if (!put_byte(&cur, &len))
            FAIL() << "Failed to insert type for data length\n";
        if (!put_bytes(&cur, len, (uint8_t *)relays[i]))
            FAIL() << "Failed to insert bytes for relay URL\n";
    }

    int out_len = (int)ceil(72.0 * 8 / 5);
    uint8_t data[out_len];
    size_t datalen = 0;
    bech32_convert_bits(data, &datalen, 5, input_hex, input_len, 8, 1);
    if (!bech32_encode(output, "nprofile", data, datalen, 256, BECH32_ENCODING_BECH32))
        FAIL() << "Failed to encode";

    ASSERT_EQ(strcmp(output, expected_nprofile), 0);

}

TEST_F(Bech32Test, NprofileEncoding1) {
    char pubkey[KEY_LENGTH*2 + 1] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char *relays[2] = {"wss://r.x.com", "wss://djbas.sadkb.com"};
    char expected_nprofile[132] = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    char output[256];

    if (!encode_nostr_bech32_nprofile(pubkey, output, 2, relays))
        FAIL() << "Failed to encode nprofile\n";

    ASSERT_EQ(strcmp(expected_nprofile, output), 0);

}

TEST_F(Bech32Test, NprofileDecoding) {
    char encoded_profile[132] = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    char expected_pubkey[65] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char *expected_relays[2] = {"wss://r.x.com", "wss://djbas.sadkb.com"};

    struct nostr_bech32 nprofile;

    nprofile.buffer = (uint8_t *)encoded_profile;
    nprofile.buflen = 132;
    nprofile.type = NOSTR_BECH32_NPROFILE;

    cursor cur;
    make_cursor(nprofile.buffer, nprofile.buffer + nprofile.buflen, &cur);

    parse_nostr_bech32(&cur, &nprofile);

    int num_relays = nprofile.data.nprofile.relays.num_relays;

    char pubkey[2*KEY_LENGTH + 1];
    char *relays[num_relays];

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(pubkey + i*2, "%.2x", nprofile.data.nprofile.pubkey[i]);
    }
    ASSERT_EQ(
        strcmp(pubkey, expected_pubkey), 0
    );

    ASSERT_EQ(num_relays, 2);

    for (int i=0; i<num_relays; i++) {
        size_t length = nprofile.data.nprofile.relays.relays[i].end - nprofile.data.nprofile.relays.relays[i].start;
        relays[i] = (char *)malloc(length);
        strncpy(relays[i], nprofile.data.nprofile.relays.relays[i].start, length);
        ASSERT_EQ(strcmp(relays[i], expected_relays[i]), 0);
        free(relays[i]);
    }
}
}