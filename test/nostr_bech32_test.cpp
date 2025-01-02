

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
    char output[65];
    char input[65] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char current_byte[2];

    uint8_t input_hex[32];

    for(int i=0;i<32;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }
    if (!segwit_addr_encode(output, "npub", 0, input_hex, 32, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"), 0);
}

TEST_F(Bech32Test, NsecEncoding) {
    char output[65];
    char input[65] = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    char current_byte[2];

    uint8_t input_hex[32];

    for(int i=0;i<32;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }

    if(!segwit_addr_encode(output, "nsec", 0, input_hex, 32, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"), 0);
}

TEST_F(Bech32Test, NoteEncoding) {
    char output[65];
    char input[65] = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";
    char current_byte[2];

    uint8_t input_hex[32];

    for(int i=0;i<32;i++) {
        strncpy(current_byte, input + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }

    if (!segwit_addr_encode(output, "note", 0, input_hex, 32, SEGWIT_NOSTR))
        FAIL();

    ASSERT_EQ(strcmp(output, "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g"), 0);
}

}