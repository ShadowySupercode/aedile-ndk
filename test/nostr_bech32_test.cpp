

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
    char current_byte[2];

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
    char current_byte[2];

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
    char current_byte[2];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }

    if (!segwit_addr_encode(output, "note", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g"), 0);
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