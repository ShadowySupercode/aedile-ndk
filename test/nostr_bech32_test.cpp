#include <gtest/gtest.h>
#include <cryptography/nostr_bech32.hpp>

using namespace nostr::encoding;
using namespace ::testing;

namespace nostr_test
{

class Bech32Test: public testing::Test
{
    protected:
    Bech32Test() {}
    ~Bech32Test() override {}
    void SetUp() override {}
};


TEST_F(Bech32Test, NpubEncoding) {

    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;
    input.data.npub.pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    input.type = NOSTR_BECH32_NPUB;

    std::string expectedEncoding = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

TEST_F(Bech32Test, NsecEncoding) {
    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;
    input.data.nsec.privkey = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    input.type = NOSTR_BECH32_NSEC;

    std::string expectedEncoding = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

TEST_F(Bech32Test, NoteEncoding) {

    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;
    input.data.note.event_id = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";
    input.type = NOSTR_BECH32_NOTE;

    std::string expectedEncoding = "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

TEST_F(Bech32Test, NprofileEncoding) {
    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;
    input.data.nprofile.pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    input.data.nprofile.relays = {"wss://r.x.com", "wss://djbas.sadkb.com"};
    input.type = NOSTR_BECH32_NPROFILE;

    std::string expectedEncoding = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

TEST_F(Bech32Test, NeventEncoding) {
    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;

    input.data.nevent.event_id = "6a72a9c4244745b1f8bd99270a1526c905dd915f6b1061061863f4baa6b0b710";
    input.data.nevent.pubkey = "0689df5847a8d3376892da29622d7c0fdc1ef1958f4bc4471d90966aa1eca9f2";
    input.data.nevent.relays = {"wss://relay.nostr.band/"};
    input.data.nevent.has_kind = false;
    input.type = NOSTR_BECH32_NEVENT;

    std::string expectedEncoding = "nevent1qqsx5u4fcsjyw3d3lz7ejfc2z5nvjpwaj90kkyrpqcvx8a9656ctwyqpzamhxue69uhhyetvv9ujumn0wd68ytnzv9hxgtczyqrgnh6cg75dxdmgjtdzjc3d0s8ac8h3jk85h3z8rkgfv64paj5lyznxtln";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

TEST_F(Bech32Test, NaddrEncoding) {
    NostrBech32 encoder = NostrBech32();
    NostrBech32Encoding input;

    input.data.naddr.tag = "1737430513300";
    input.data.naddr.pubkey = "75656740209960c74fe373e6943f8a21ab896889d8691276a60f86aadbc8f92a";
    input.data.naddr.relays = {"wss://relay.nostr.band/"};
    input.data.naddr.kind = 30023;
    input.type = NOSTR_BECH32_NADDR;

    std::string expectedEncoding = "naddr1qqxnzdenxu6rxvp4xyenxvpsqythwumn8ghj7un9d3shjtnwdaehgu3wvfskuep0qgs82et8gqsfjcx8fl3h8e55879zr2ufdzyas6gjw6nqlp42m0y0j2srqsqqqa285r8tkj";
    std::string encoding;

    if (!encoder.encodeNostrBech32(input, encoding))
        FAIL() << "Failed to encode note";
    ASSERT_EQ(expectedEncoding.compare(encoding), 0);
}

// TEST_F(Bech32Test, NsecDecoding) {
//     char encoded_nsec[KEY_LENGTH*2 + 1] = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
//     char expected_privkey[KEY_LENGTH*2 + 1] = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
//     char privkey[KEY_LENGTH*2 + 1];

//     struct nostr_bech32 nsec;
//     nsec.type = NOSTR_BECH32_NPUB;
//     cursor cur;
//     make_cursor((uint8_t*)encoded_nsec, (uint8_t*)encoded_nsec + strlen(encoded_nsec), &cur);
//     parse_nostr_bech32(&cur, &nsec);

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(privkey + i*2, "%.2x", nsec.data.nsec.privkey[i]);
//     }

//     ASSERT_EQ(strcmp(expected_privkey, privkey), 0);
// }

// TEST_F(Bech32Test, NoteDecoding) {
//     char encoded_note[KEY_LENGTH*2 + 1] = "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g";
//     char expected_id[KEY_LENGTH*2 + 1] = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";
//     char id[KEY_LENGTH*2 + 1];

//     struct nostr_bech32 note;
//     note.type = NOSTR_BECH32_NOTE;
//     cursor cur;
//     make_cursor((uint8_t*)encoded_note, (uint8_t*)encoded_note + strlen(encoded_note), &cur);
//     parse_nostr_bech32(&cur, &note);

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(id + i*2, "%.2x", note.data.note.event_id[i]);
//     }

//     ASSERT_EQ(strcmp(expected_id, id), 0);
// }

// TEST_F(Bech32Test, NprofileDecoding) {
//     char encoded_profile[132] = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
//     char expected_pubkey[65] = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
//     char *expected_relays[2] = {"wss://r.x.com", "wss://djbas.sadkb.com"};

//     struct nostr_bech32 nprofile;

//     nprofile.buffer = (uint8_t *)encoded_profile;
//     nprofile.buflen = 132;
//     nprofile.type = NOSTR_BECH32_NPROFILE;

//     cursor cur;
//     make_cursor(nprofile.buffer, nprofile.buffer + nprofile.buflen, &cur);

//     parse_nostr_bech32(&cur, &nprofile);

//     int num_relays = nprofile.data.nprofile.relays.num_relays;

//     char pubkey[2*KEY_LENGTH + 1];
//     char *relays[num_relays];

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(pubkey + i*2, "%.2x", nprofile.data.nprofile.pubkey[i]);
//     }
//     ASSERT_EQ(
//         strcmp(pubkey, expected_pubkey), 0
//     );

//     ASSERT_EQ(num_relays, 2);

//     for (int i=0; i<num_relays; i++) {
//         size_t length = nprofile.data.nprofile.relays.relays[i].end - nprofile.data.nprofile.relays.relays[i].start;
//         relays[i] = (char *)malloc(length);
//         strncpy(relays[i], nprofile.data.nprofile.relays.relays[i].start, length);
//         ASSERT_EQ(strcmp(relays[i], expected_relays[i]), 0);
//         free(relays[i]);
//     }
// }

// TEST_F(Bech32Test, NeventDecoding) {
//     char encoded_nevent[163] = "nevent1qqsx5u4fcsjyw3d3lz7ejfc2z5nvjpwaj90kkyrpqcvx8a9656ctwyqpzamhxue69uhhyetvv9ujumn0wd68ytnzv9hxgtczyqrgnh6cg75dxdmgjtdzjc3d0s8ac8h3jk85h3z8rkgfv64paj5lyznxtln";
//     char expected_pubkey[2*KEY_LENGTH + 1] = "0689df5847a8d3376892da29622d7c0fdc1ef1958f4bc4471d90966aa1eca9f2";
//     char expected_id[2*KEY_LENGTH + 1] = "6a72a9c4244745b1f8bd99270a1526c905dd915f6b1061061863f4baa6b0b710";

//     char *expected_relays[1] = {"wss://relay.nostr.band/"};

//     uint32_t expected_kind = 1;

//     struct nostr_bech32 nevent;

//     nevent.buffer = (uint8_t *)encoded_nevent;
//     nevent.buflen = 163;
//     nevent.type = NOSTR_BECH32_NEVENT;


//     cursor cur;
//     make_cursor(nevent.buffer, nevent.buffer + nevent.buflen, &cur);

//     parse_nostr_bech32(&cur, &nevent);
//     char id[2*KEY_LENGTH + 1];
//     char pubkey[2*KEY_LENGTH + 1];

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(id + i*2, "%.2x", nevent.data.nevent.event_id[i]);
//     }

//     ASSERT_EQ(
//         strcmp(id, expected_id), 0
//     );

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(pubkey + i*2, "%.2x", nevent.data.nevent.pubkey[i]);
//     }

//     ASSERT_EQ(
//         strcmp(pubkey, expected_pubkey), 0
//     );

//     int num_relays = nevent.data.nevent.relays.num_relays;
//     char *relays[num_relays];


//     for (int i = 0; i < num_relays; i++) {
//         int length = nevent.data.nevent.relays.relays[i].end - nevent.data.nevent.relays.relays[i].start;
//         relays[i] = (char*)malloc(length);
//         strncpy(relays[i], nevent.data.nevent.relays.relays[i].start, length);
//         ASSERT_EQ(strcmp(relays[i], expected_relays[i]), 0);
//         free(relays[i]);
//     }

//     if (nevent.data.nevent.has_kind)
//         ASSERT_EQ(expected_kind, nevent.data.nevent.kind);

// }


// TEST_F(Bech32Test, NaddrDecoding) {
//     char encoded_naddr[141] = "naddr1qqxnzdenxu6rxvp4xyenxvpsqythwumn8ghj7un9d3shjtnwdaehgu3wvfskuep0qgs82et8gqsfjcx8fl3h8e55879zr2ufdzyas6gjw6nqlp42m0y0j2srqsqqqa285r8tkj";
//     char expected_pubkey[65] = "75656740209960c74fe373e6943f8a21ab896889d8691276a60f86aadbc8f92a";
//     char *expected_relays[1] = {"wss://relay.nostr.band/"};
//     char expected_identifier[14] = "1737430513300";
//     uint32_t expected_num_relays = 1, expected_kind = 30023;

//     struct nostr_bech32 naddr;

//     naddr.buffer = (uint8_t *)encoded_naddr;
//     naddr.buflen = 141;
//     naddr.type = NOSTR_BECH32_NADDR;

//     cursor cur;
//     make_cursor(naddr.buffer, naddr.buffer + naddr.buflen, &cur);
//     parse_nostr_bech32(&cur, &naddr);
//     char id[2*KEY_LENGTH + 1];
//     char pubkey[2*KEY_LENGTH + 1];

//     char *identifier = naddr.data.naddr.identifier;

//     ASSERT_EQ(strcmp(expected_identifier, identifier), 0);

//     for (int i=0;i<KEY_LENGTH;i++) {
//         sprintf(pubkey + i*2, "%.2x", naddr.data.naddr.pubkey[i]);
//     }
//     ASSERT_EQ(strcmp(expected_pubkey, pubkey), 0);

//     int num_relays = naddr.data.naddr.relays.num_relays;

//     ASSERT_EQ(num_relays, expected_num_relays);

//     char *relays[num_relays];
//     for (int i = 0; i < num_relays; i++) {
//         int length = naddr.data.naddr.relays.relays[i].end - naddr.data.naddr.relays.relays[i].start;
//         relays[i] = (char*)malloc(length);
//         strncpy(relays[i], naddr.data.naddr.relays.relays[i].start, length);

//         ASSERT_EQ(strcmp(expected_relays[i], relays[i]), 0);


//         free(relays[i]);
//     }
//     ASSERT_EQ(naddr.data.naddr.kind, expected_kind);
// }



}