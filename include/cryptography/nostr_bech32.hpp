// adapted for aedile-ndk by Finrod Felagund (finrod.felagund.97@gmail.com)
// a.k.a. npub1ecdlntvjzexlyfale2egzvvncc8tgqsaxkl5hw7xlgjv2cxs705s9qs735

#pragma once

#include "bech32.hpp"

#define MAX_RELAYS 10

#define MAX_TLVS 16

#define TLV_SPECIAL 0
#define TLV_RELAY 1
#define TLV_AUTHOR 2
#define TLV_KIND 3
#define TLV_KNOWN_TLVS 4

#define KEY_LENGTH 32

#define CHECKSUM_LENGTH 6

#define MAX_ENCODING_LENGTH 256

namespace nostr
{
namespace encoding
{

typedef enum {
    NOSTR_BECH32_NOTE = 1,
    NOSTR_BECH32_NPUB = 2,
    NOSTR_BECH32_NPROFILE = 3,
    NOSTR_BECH32_NEVENT = 4,
    NOSTR_BECH32_NRELAY = 5,
    NOSTR_BECH32_NADDR = 6,
    NOSTR_BECH32_NSEC = 7,
} NostrBech32Type;


typedef struct Bech32Note
{
    EventId event_id;
} Bech32Note;

typedef struct Bech32Npub
{
    PubKey pubkey;
} Bech32Npub;

typedef struct Bech32Nsec
{
    PrivKey privkey;
} Bech32Nsec;


typedef struct Bech32Nevent
{
    Relays relays;
    EventId event_id;
    PubKey pubkey;
    uint32_t kind;
    bool has_kind;
} Bech32Nevent;

typedef struct Bech32Nprofile
{
    Relays relays;
    PubKey pubkey;
} Bech32Nprofile;

typedef struct Bech32Naddr
{
    Relays relays;
    std::string tag;
    PubKey pubkey;
    uint32_t kind;
} Bech32Naddr;

typedef struct
{
    uint8_t type;
    uint8_t len;
    TlvValues value;
} NostrTlv;

typedef struct {
    Bech32Note note;
    Bech32Npub npub;
    Bech32Nsec nsec;
    Bech32Nprofile nprofile;
    Bech32Nevent nevent;
    Bech32Naddr naddr;
} NostrBech32Data;

typedef struct NostrBech32Encoding
{
    NostrBech32Type type;
    NostrBech32Data data;
} NostrBech32Encoding;


class NostrBech32
{
public:
    bool encodeNostrBech32(NostrBech32Encoding &input, std::string &encoding);
    bool parseNostrBech32(std::string &encoding, NostrBech32Encoding &parsed);

private:
    bool encodeNostrBech32Note(NostrBech32Encoding &input, std::string &encoding);
    bool encodeNostrBech32Npub(NostrBech32Encoding &input, std::string &encoding);
    bool encodeNostrBech32Nsec(NostrBech32Encoding &input, std::string &encoding);
    bool encodeNostrBech32Nprofile(NostrBech32Encoding &input, std::string &encoding);
    bool encodeNostrBech32Nevent(NostrBech32Encoding &input, std::string &encoding);
    bool encodeNostrBech32Naddr(NostrBech32Encoding &input, std::string &encoding);

    bool parseNostrBech32Note(BytesArray &encoding, NostrBech32Encoding &parsed);
    bool parseNostrBech32Npub(BytesArray &encoding, NostrBech32Encoding &parsed);
    bool parseNostrBech32Nsec(BytesArray &encoding, NostrBech32Encoding &parsed);
    bool parseNostrBech32Nprofile(BytesArray &encoding, NostrBech32Encoding &parsed);
    bool parseNostrBech32Nevent(BytesArray &encoding, NostrBech32Encoding &parsed);
    bool parseNostrBech32Naddr(BytesArray &encoding, NostrBech32Encoding &parsed);

    bool findTlv(std::vector<NostrTlv> &tlvs, uint8_t type, NostrTlv &found_tlv);
    bool tlvToRelays(std::vector<NostrTlv> &tlvs, Relays &relays);
    bool parseTlv(BytesArray &encoding, NostrTlv &tlv, int &cur);
    bool parseTlvs(BytesArray &encoding, std::vector<NostrTlv> &tlvs);
};

}
}
