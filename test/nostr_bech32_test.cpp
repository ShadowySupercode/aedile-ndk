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

TEST_F(Bech32Test, NpubDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string encoding = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    std::string expected_pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    NostrBech32Encoding parsed;
    if (!encoder.parseNostrBech32(encoding, parsed))
        FAIL() << "Failed to decode npub";

    ASSERT_EQ(NOSTR_BECH32_NPUB, parsed.type);
    ASSERT_EQ(expected_pubkey, parsed.data.npub.pubkey);
}

TEST_F(Bech32Test, NsecDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string encoding = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    std::string expected_privkey = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";

    NostrBech32Encoding parsed;
    if (!encoder.parseNostrBech32(encoding, parsed))
        FAIL() << "Failed to decode nsec";

    ASSERT_EQ(NOSTR_BECH32_NSEC, parsed.type);
    ASSERT_EQ(expected_privkey, parsed.data.nsec.privkey);
}

TEST_F(Bech32Test, NoteDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string encoding = "note10nrucl4e5yqjq7ddau4ua9gq3jpq7a795y4udmg6ytkkmduamz7semt62g";
    std::string expected_id = "7cc7cc7eb9a1012079adef2bce95008c820f77c5a12bc6ed1a22ed6db79dd8bd";

    NostrBech32Encoding parsed;
    if (!encoder.parseNostrBech32(encoding, parsed))
        FAIL() << "Failed to decode note";

    ASSERT_EQ(NOSTR_BECH32_NOTE, parsed.type);
    ASSERT_EQ(expected_id, parsed.data.note.event_id);
}

TEST_F(Bech32Test, NprofileDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string encoding = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    std::string expected_pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    Relays expected_relays = {"wss://r.x.com", "wss://djbas.sadkb.com"};

    NostrBech32Encoding parsed;
    if (!encoder.parseNostrBech32(encoding, parsed))
       FAIL() << "Failed to decode note";

    ASSERT_EQ(NOSTR_BECH32_NPROFILE, parsed.type);
    ASSERT_EQ(expected_pubkey, parsed.data.nprofile.pubkey);
    ASSERT_EQ(expected_relays.size(), parsed.data.nprofile.relays.size());
    for (int i=0; i<expected_relays.size(); i++)
        ASSERT_EQ(expected_relays[i], parsed.data.nprofile.relays[i]);
}

TEST_F(Bech32Test, NaddrDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string expected_tag = "mfayffebPrMI520ftzIlE";
    std::string expected_pubkey = "dc4cd086cd7ce5b1832adf4fdd1211289880d2c7e295bcb0e684c01acee77c06";
    uint32_t expected_kind = 30023;

    NostrBech32Encoding parsed;
    std::string encoding = "naddr1qq2k6enp09nxvetz2pey6jf4xgcxvar6f9ky2q3qm3xdppkd0njmrqe2ma8a6ys39zvgp5k8u22mev8xsnqp4nh80srqxpqqqp65wfq7ufy";

    if (!encoder.parseNostrBech32(encoding, parsed))
        FAIL() << "Failed to decode naddr";

    ASSERT_EQ(NOSTR_BECH32_NADDR, parsed.type);
    ASSERT_EQ(expected_tag, parsed.data.naddr.tag);

    ASSERT_EQ(expected_pubkey, parsed.data.naddr.pubkey);
    ASSERT_EQ(expected_kind, parsed.data.naddr.kind);
}

TEST_F(Bech32Test, NeventDecoding) {
    NostrBech32 encoder = NostrBech32();

    std::string encoding = "nevent1qqsx5u4fcsjyw3d3lz7ejfc2z5nvjpwaj90kkyrpqcvx8a9656ctwyqpzamhxue69uhhyetvv9ujumn0wd68ytnzv9hxgtczyqrgnh6cg75dxdmgjtdzjc3d0s8ac8h3jk85h3z8rkgfv64paj5lyznxtln";
    std::string expected_pubkey = "0689df5847a8d3376892da29622d7c0fdc1ef1958f4bc4471d90966aa1eca9f2";
    std::string expected_id = "6a72a9c4244745b1f8bd99270a1526c905dd915f6b1061061863f4baa6b0b710";
    Relays expected_relays = {"wss://relay.nostr.band/"};

    NostrBech32Encoding parsed;
    if (!encoder.parseNostrBech32(encoding, parsed))
       FAIL() << "Failed to decode note";

    ASSERT_EQ(NOSTR_BECH32_NEVENT, parsed.type);
    ASSERT_EQ(expected_pubkey, parsed.data.nevent.pubkey);
    ASSERT_EQ(expected_id, parsed.data.nevent.event_id);

    ASSERT_EQ(expected_relays.size(), parsed.data.nevent.relays.size());
    for (int i=0; i<expected_relays.size(); i++)
        ASSERT_EQ(expected_relays[i], parsed.data.nevent.relays[i]);

    ASSERT_EQ(false, parsed.data.nevent.has_kind);
}
}