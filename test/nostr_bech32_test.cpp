

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

TEST_F(Bech32Test, NpubDecoding) {
    char encoded_npub[KEY_LENGTH*2 + 1] = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    char expected_pubkey[KEY_LENGTH*2 + 1] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    char pubkey[KEY_LENGTH*2 + 1];

    struct nostr_bech32 npub;
    npub.type = NOSTR_BECH32_NPUB;
    cursor cur;
    make_cursor((uint8_t*)encoded_npub, (uint8_t*)encoded_npub + strlen(encoded_npub), &cur);
    parse_nostr_bech32(&cur, &npub);

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(pubkey + i*2, "%.2x", npub.data.npub.pubkey[i]);
    }

    ASSERT_EQ(strcmp(expected_pubkey, pubkey), 0);
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

TEST_F(Bech32Test, NsecDecoding) {
    char encoded_nsec[KEY_LENGTH*2 + 1] = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    char expected_privkey[KEY_LENGTH*2 + 1] = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    char privkey[KEY_LENGTH*2 + 1];

    struct nostr_bech32 nsec;
    nsec.type = NOSTR_BECH32_NPUB;
    cursor cur;
    make_cursor((uint8_t*)encoded_nsec, (uint8_t*)encoded_nsec + strlen(encoded_nsec), &cur);
    parse_nostr_bech32(&cur, &nsec);

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(privkey + i*2, "%.2x", nsec.data.nsec.privkey[i]);
    }

    ASSERT_EQ(strcmp(expected_privkey, privkey), 0);
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

TEST_F(Bech32Test, NoteDecoding) {
    char encoded_note[KEY_LENGTH*2 + 1] = "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g";
    char expected_id[KEY_LENGTH*2 + 1] = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";
    char id[KEY_LENGTH*2 + 1];

    struct nostr_bech32 note;
    note.type = NOSTR_BECH32_NOTE;
    cursor cur;
    make_cursor((uint8_t*)encoded_note, (uint8_t*)encoded_note + strlen(encoded_note), &cur);
    parse_nostr_bech32(&cur, &note);

    note.data.note.event_id;
    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(id + i*2, "%.2x", note.data.note.event_id[i]);
    }

    ASSERT_EQ(strcmp(expected_id, id), 0);
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

TEST_F(Bech32Test, NeventDecoding) {
    char encoded_nevent[163] = "nevent1qqsx5u4fcsjyw3d3lz7ejfc2z5nvjpwaj90kkyrpqcvx8a9656ctwyqpzamhxue69uhhyetvv9ujumn0wd68ytnzv9hxgtczyqrgnh6cg75dxdmgjtdzjc3d0s8ac8h3jk85h3z8rkgfv64paj5lyznxtln";
    char expected_pubkey[2*KEY_LENGTH + 1] = "0689df5847a8d3376892da29622d7c0fdc1ef1958f4bc4471d90966aa1eca9f2";
    char expected_id[2*KEY_LENGTH + 1] = "6a72a9c4244745b1f8bd99270a1526c905dd915f6b1061061863f4baa6b0b710";

    char *expected_relays[1] = {"wss://relay.nostr.band/"};

    uint32_t expected_kind = 1;

    struct nostr_bech32 nevent;

    nevent.buffer = (uint8_t *)encoded_nevent;
    nevent.buflen = 163;
    nevent.type = NOSTR_BECH32_NEVENT;


    cursor cur;
    make_cursor(nevent.buffer, nevent.buffer + nevent.buflen, &cur);

    parse_nostr_bech32(&cur, &nevent);
    char id[2*KEY_LENGTH + 1];
    char pubkey[2*KEY_LENGTH + 1];

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(id + i*2, "%.2x", nevent.data.nevent.event_id[i]);
    }

    ASSERT_EQ(
        strcmp(id, expected_id), 0
    );

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(pubkey + i*2, "%.2x", nevent.data.nevent.pubkey[i]);
    }

    ASSERT_EQ(
        strcmp(pubkey, expected_pubkey), 0
    );

    int num_relays = nevent.data.nevent.relays.num_relays;
    char *relays[num_relays];


    for (int i = 0; i < num_relays; i++) {
        int length = nevent.data.nevent.relays.relays[i].end - nevent.data.nevent.relays.relays[i].start;
        relays[i] = (char*)malloc(length);
        strncpy(relays[i], nevent.data.nevent.relays.relays[i].start, length);
        ASSERT_EQ(strcmp(relays[i], expected_relays[i]), 0);
        free(relays[i]);
    }

    if (nevent.data.nevent.has_kind)
        ASSERT_EQ(expected_kind, nevent.data.nevent.kind);

}

TEST_F(Bech32Test, NeventEncoding) {
    char expected_nevent[163] = "nevent1qqsx5u4fcsjyw3d3lz7ejfc2z5nvjpwaj90kkyrpqcvx8a9656ctwyqpzamhxue69uhhyetvv9ujumn0wd68ytnzv9hxgtczyqrgnh6cg75dxdmgjtdzjc3d0s8ac8h3jk85h3z8rkgfv64paj5lyznxtln";
    char pubkey[2*KEY_LENGTH + 1] = "0689df5847a8d3376892da29622d7c0fdc1ef1958f4bc4471d90966aa1eca9f2";
    char id[2*KEY_LENGTH + 1] = "6a72a9c4244745b1f8bd99270a1526c905dd915f6b1061061863f4baa6b0b710";
    char *relays[1] = {"wss://relay.nostr.band/"};

    char output[256];

    if (!encode_nostr_bech32_nevent(id, output, nullptr, pubkey, 1, relays))
        FAIL() << "Failed to encode nevent\n";

    ASSERT_EQ(
        strcmp(output, expected_nevent), 0
    );
}

TEST_F(Bech32Test, NaddrDecoding) {
    char encoded_naddr[141] = "naddr1qqxnzdenxu6rxvp4xyenxvpsqythwumn8ghj7un9d3shjtnwdaehgu3wvfskuep0qgs82et8gqsfjcx8fl3h8e55879zr2ufdzyas6gjw6nqlp42m0y0j2srqsqqqa285r8tkj";
    char expected_pubkey[65] = "75656740209960c74fe373e6943f8a21ab896889d8691276a60f86aadbc8f92a";
    char *expected_relays[1] = {"wss://relay.nostr.band/"};
    char expected_identifier[14] = "1737430513300";
    uint32_t expected_num_relays = 1, expected_kind = 30023;

    struct nostr_bech32 naddr;

    naddr.buffer = (uint8_t *)encoded_naddr;
    naddr.buflen = 141;
    naddr.type = NOSTR_BECH32_NADDR;

    cursor cur;
    make_cursor(naddr.buffer, naddr.buffer + naddr.buflen, &cur);
    parse_nostr_bech32(&cur, &naddr);
    char id[2*KEY_LENGTH + 1];
    char pubkey[2*KEY_LENGTH + 1];

    char *identifier = naddr.data.naddr.identifier;

    ASSERT_EQ(strcmp(expected_identifier, identifier), 0);

    for (int i=0;i<KEY_LENGTH;i++) {
        sprintf(pubkey + i*2, "%.2x", naddr.data.naddr.pubkey[i]);
    }
    ASSERT_EQ(strcmp(expected_pubkey, pubkey), 0);

    int num_relays = naddr.data.naddr.relays.num_relays;

    ASSERT_EQ(num_relays, expected_num_relays);

    char *relays[num_relays];
    for (int i = 0; i < num_relays; i++) {
        int length = naddr.data.naddr.relays.relays[i].end - naddr.data.naddr.relays.relays[i].start;
        relays[i] = (char*)malloc(length);
        strncpy(relays[i], naddr.data.naddr.relays.relays[i].start, length);

        ASSERT_EQ(strcmp(expected_relays[i], relays[i]), 0);


        free(relays[i]);
    }
    ASSERT_EQ(naddr.data.naddr.kind, expected_kind);
}

TEST_F(Bech32Test, NaddrEncoding) {
    char expected_naddr[141] = "naddr1qqxnzdenxu6rxvp4xyenxvpsqythwumn8ghj7un9d3shjtnwdaehgu3wvfskuep0qgs82et8gqsfjcx8fl3h8e55879zr2ufdzyas6gjw6nqlp42m0y0j2srqsqqqa285r8tkj";
    char pubkey[2*KEY_LENGTH + 1] = "75656740209960c74fe373e6943f8a21ab896889d8691276a60f86aadbc8f92a";
    char tag[14] = "1737430513300";
    char *relays[1] = {"wss://relay.nostr.band/"};
    uint32_t kind = 30023;

    char output[256];

    if (!encode_nostr_bech32_naddr(tag, &kind, pubkey, output, 1, relays))
        FAIL() << "Failed to encode naddr\n";

    printf("output: %s\n", output);
    printf("expected_naddr: %s\n", expected_naddr);

    ASSERT_EQ(
        strcmp(output, expected_naddr), 0
    );
}

}