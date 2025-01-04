
//
//  nostr_bech32.h
//  damus
//
//  Created by William Casarin on 2023-04-09.
//

// adapted for aedile-ndk by Finrod Felagund (finrod.felagund.97@gmail.com)
// a.k.a. npub1ecdlntvjzexlyfale2egzvvncc8tgqsaxkl5hw7xlgjv2cxs705s9qs735

#pragma once

#ifndef nostr_bech32_h
#define nostr_bech32_h

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>


#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#define MAX_RELAYS 10

#define MAX_TLVS 16

#define TLV_SPECIAL 0
#define TLV_RELAY 1
#define TLV_AUTHOR 2
#define TLV_KIND 3
#define TLV_KNOWN_TLVS 4

#define KEY_LENGTH 32

typedef struct str_block {
    const char *start;
    const char *end;
} str_block_t;


struct relays {
    struct str_block relays[MAX_RELAYS];
    int num_relays;
};

enum nostr_bech32_type {
    NOSTR_BECH32_NOTE = 1,
    NOSTR_BECH32_NPUB = 2,
    NOSTR_BECH32_NPROFILE = 3,
    NOSTR_BECH32_NEVENT = 4,
    NOSTR_BECH32_NRELAY = 5,
    NOSTR_BECH32_NADDR = 6,
    NOSTR_BECH32_NSEC = 7,
};

struct bech32_note {
    const uint8_t *event_id;
};

struct bech32_npub {
    const uint8_t *pubkey;
};

struct bech32_nsec {
    const uint8_t *nsec;
};

struct bech32_nevent {
    struct relays relays;
    const uint8_t *event_id;
    const uint8_t *pubkey; // optional
    uint32_t kind;
    bool has_kind;
};

struct bech32_nprofile {
    struct relays relays;
    const uint8_t *pubkey;
};

struct bech32_naddr {
    struct relays relays;
    struct str_block identifier;
    const uint8_t *pubkey;
    uint32_t kind;
};

struct bech32_nrelay {
    struct str_block relay;
};

typedef struct nostr_bech32 {
    enum nostr_bech32_type type;
    uint8_t *buffer; // holds strings and tlv stuff
    size_t buflen;

    union {
        struct bech32_note note;
        struct bech32_npub npub;
        struct bech32_nsec nsec;
        struct bech32_nevent nevent;
        struct bech32_nprofile nprofile;
        struct bech32_naddr naddr;
        struct bech32_nrelay nrelay;
    } data;
} nostr_bech32_t;


struct cursor {
	unsigned char *start;
	unsigned char *p;
	unsigned char *end;
};

static inline void make_cursor(uint8_t *start, uint8_t *end, struct cursor *cursor)
{
	cursor->start = start;
	cursor->p = start;
	cursor->end = end;
}

static inline int pull_byte(struct cursor *cursor, uint8_t *c)
{
	if (unlikely(cursor->p >= cursor->end))
		return 0;

	*c = *cursor->p;
	cursor->p++;

	return 1;
}

static inline int pull_bytes(struct cursor *cur, int count, const uint8_t **bytes) {
    if (cur->p + count > cur->end)
        return 0;

    *bytes = cur->p;
    cur->p += count;
    return 1;
}

static inline int is_alphanumeric(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static inline int consume_until_non_alphanumeric(struct cursor *cur, int or_end) {
    char c;
    int consumedAtLeastOne = 0;

    while (cur->p < cur->end) {
        c = *cur->p;

        if (!is_alphanumeric(c))
            return consumedAtLeastOne;

        cur->p++;
        consumedAtLeastOne = 1;
    }

    return or_end;
}

int parse_nostr_bech32(struct cursor *cur, struct nostr_bech32 *obj);

#endif /* nostr_bech32_h */


