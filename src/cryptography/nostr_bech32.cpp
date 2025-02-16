
//
//  nostr_bech32.c
//  damus
//
//  Created by William Casarin on 2023-04-09.
//
#include <cryptography/nostr_bech32.h>
#include <cryptography/bech32.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <endian.h>

static inline int calc_output_length(int input_len) {
    int output_length = (int)(ceil((double)input_len * FROM_BITS / TO_BITS));
    return output_length;
}

static int parse_nostr_tlv(struct cursor *cur, struct nostr_tlv *tlv) {
    // get the tlv tag
    if (!pull_byte(cur, &tlv->type))
        return 0;

    // unknown, fail!
    if (tlv->type >= TLV_KNOWN_TLVS)
        return 0;

    // get the length
    if (!pull_byte(cur, &tlv->len))
        return 0;

    // is the reported length greater then our buffer? if so fail
    if (cur->p + tlv->len > cur->end)
        return 0;

    tlv->value = cur->p;
    cur->p += tlv->len;

    return 1;
}

static int parse_nostr_tlvs(struct cursor *cur, struct nostr_tlvs *tlvs) {
    int i = 0;
    tlvs->num_tlvs = 0;

    while (i < MAX_TLVS && parse_nostr_tlv(cur, &tlvs->tlvs[i])) {
        tlvs->num_tlvs++;
        i++;
    }

    if (tlvs->num_tlvs == 0)
        return 0;

    return 1;
}

static int find_tlv(struct nostr_tlvs *tlvs, uint8_t type, struct nostr_tlv **tlv) {
    *tlv = NULL;

    for (int i = 0; i < tlvs->num_tlvs; i++) {
        if (tlvs->tlvs[i].type == type) {
            *tlv = &tlvs->tlvs[i];
            return 1;
        }
    }

    return 0;
}

static int parse_nostr_bech32_type(const char *prefix, enum nostr_bech32_type *type) {
    // Parse type
    if (strcmp(prefix, "note") == 0) {
        *type = NOSTR_BECH32_NOTE;
        return 1;
    } else if (strcmp(prefix, "npub") == 0) {
        *type = NOSTR_BECH32_NPUB;
        return 1;
    } else if (strcmp(prefix, "nsec") == 0) {
        *type = NOSTR_BECH32_NSEC;
        return 1;
    } else if (strcmp(prefix, "nprofile") == 0) {
        *type = NOSTR_BECH32_NPROFILE;
        return 1;
    } else if (strcmp(prefix, "nevent") == 0) {
        *type = NOSTR_BECH32_NEVENT;
        return 1;
    } else if (strcmp(prefix, "nrelay") == 0) {
        *type = NOSTR_BECH32_NRELAY;
        return 1;
    } else if (strcmp(prefix, "naddr") == 0) {
        *type = NOSTR_BECH32_NADDR;
        return 1;
    }

    return 0;
}

static int parse_nostr_bech32_note(struct cursor *cur, struct bech32_note *note) {
    return pull_bytes(cur, 32, &note->event_id);
}

static int parse_nostr_bech32_npub(struct cursor *cur, struct bech32_npub *npub) {
    return pull_bytes(cur, 32, &npub->pubkey);
}

static int parse_nostr_bech32_nsec(struct cursor *cur, struct bech32_nsec *nsec) {
    return pull_bytes(cur, 32, &nsec->privkey);
}

static int tlvs_to_relays(struct nostr_tlvs *tlvs, struct relays *relays) {
    struct nostr_tlv *tlv;
    struct str_block *str;

    relays->num_relays = 0;

    for (int i = 0; i < tlvs->num_tlvs; i++) {
        tlv = &tlvs->tlvs[i];
        if (tlv->type != TLV_RELAY)
            continue;

        if (relays->num_relays + 1 > MAX_RELAYS)
            break;

        str = &relays->relays[relays->num_relays++];
        str->start = (const char*)tlv->value;
        str->end = (const char*)(tlv->value + tlv->len);
    }

    return 1;
}

static uint32_t decode_tlv_u32(const uint8_t *bytes) {
    uint32_t *be32_bytes = (uint32_t*)bytes;
    return htobe32(*be32_bytes);
}

static void encode_u32_tlv(const uint32_t *value, uint8_t *be32_value) {
    uint32_t be32 = htobe32(*value);
    memcpy(be32_value, (uint8_t*)&be32, 4);
}

static int parse_nostr_bech32_nevent(struct cursor *cur, struct bech32_nevent *nevent) {
    struct nostr_tlvs tlvs;
    struct nostr_tlv *tlv;

    if (!parse_nostr_tlvs(cur, &tlvs))
        return 0;

    if (!find_tlv(&tlvs, TLV_SPECIAL, &tlv))
        return 0;

    if (tlv->len != 32)
        return 0;

    nevent->event_id = tlv->value;

    if (find_tlv(&tlvs, TLV_AUTHOR, &tlv)) {
        nevent->pubkey = tlv->value;
    } else {
        nevent->pubkey = NULL;
    }

    if(find_tlv(&tlvs, TLV_KIND, &tlv)) {
        nevent->kind = decode_tlv_u32(tlv->value);
        nevent->has_kind = true;
    } else {
        nevent->has_kind = false;
    }

    return tlvs_to_relays(&tlvs, &nevent->relays);
}

static int parse_nostr_bech32_naddr(struct cursor *cur, struct bech32_naddr *naddr) {
    struct nostr_tlvs tlvs;
    struct nostr_tlv *tlv;

    if (!parse_nostr_tlvs(cur, &tlvs))
        return 0;

    if (!find_tlv(&tlvs, TLV_SPECIAL, &tlv))
        return 0;

    naddr->identifier = (char *)malloc(tlv->len + 1);
    naddr->identifier = (char *)tlv->value;
    naddr->identifier[tlv->len] = '\0';

    if (!find_tlv(&tlvs, TLV_AUTHOR, &tlv))
        return 0;

    naddr->pubkey = tlv->value;

    if(!find_tlv(&tlvs, TLV_KIND, &tlv)) {
        return 0;
    }
    naddr->kind = decode_tlv_u32(tlv->value);

    return tlvs_to_relays(&tlvs, &naddr->relays);
}

static int parse_nostr_bech32_nprofile(struct cursor *cur, struct bech32_nprofile *nprofile) {
    struct nostr_tlvs tlvs;
    struct nostr_tlv *tlv;

    if (!parse_nostr_tlvs(cur, &tlvs))
        return 0;

    if (!find_tlv(&tlvs, TLV_SPECIAL, &tlv))
        return 0;

    if (tlv->len != 32)
        return 0;

    nprofile->pubkey = tlv->value;

    return tlvs_to_relays(&tlvs, &nprofile->relays);
}

static int parse_nostr_bech32_nrelay(struct cursor *cur, struct bech32_nrelay *nrelay) {
    struct nostr_tlvs tlvs;
    struct nostr_tlv *tlv;

    if (!parse_nostr_tlvs(cur, &tlvs))
        return 0;

    if (!find_tlv(&tlvs, TLV_SPECIAL, &tlv))
        return 0;

    nrelay->relay.start = (const char*)tlv->value;
    nrelay->relay.end = (const char*)tlv->value + tlv->len;

    return 1;
}

int parse_nostr_bech32(struct cursor *cur, struct nostr_bech32 *obj) {
    uint8_t *start, *end;

    start = cur->p;

    if (!consume_until_non_alphanumeric(cur, 1)) {
        cur->p = start;
        return 0;
    }

    end = cur->p;

    size_t data_len;
    size_t input_len = end - start;
    if (input_len < 10 || input_len > 10000) {
        return 0;
    }

    obj->buffer = (uint8_t*)malloc(input_len * 2);
    if (!obj->buffer)
        return 0;

    uint8_t data[input_len];
    char prefix[input_len];

    if (bech32_decode_len(prefix, data, &data_len, (const char*)start, input_len) == BECH32_ENCODING_NONE) {
        cur->p = start;
        return 0;
    }

    obj->buflen = 0;
    if (!bech32_convert_bits(obj->buffer, &obj->buflen, 8, data, data_len, 5, 0)) {
        goto fail;
    }

    if (!parse_nostr_bech32_type(prefix, &obj->type)) {
        goto fail;
    }

    struct cursor bcur;
    make_cursor(obj->buffer, obj->buffer + obj->buflen, &bcur);

    switch (obj->type) {
        case NOSTR_BECH32_NOTE:
            if (!parse_nostr_bech32_note(&bcur, &obj->data.note))
                goto fail;
            break;
        case NOSTR_BECH32_NPUB:
            if (!parse_nostr_bech32_npub(&bcur, &obj->data.npub))
                goto fail;
            break;
        case NOSTR_BECH32_NSEC:
            if (!parse_nostr_bech32_nsec(&bcur, &obj->data.nsec))
                goto fail;
            break;
        case NOSTR_BECH32_NEVENT:
            if (!parse_nostr_bech32_nevent(&bcur, &obj->data.nevent))
                goto fail;
            break;
        case NOSTR_BECH32_NADDR:
            if (!parse_nostr_bech32_naddr(&bcur, &obj->data.naddr))
                goto fail;
            break;
        case NOSTR_BECH32_NPROFILE:
            if (!parse_nostr_bech32_nprofile(&bcur, &obj->data.nprofile))
                goto fail;
            break;
        case NOSTR_BECH32_NRELAY:
            if (!parse_nostr_bech32_nrelay(&bcur, &obj->data.nrelay))
                goto fail;
            break;
    }

    return 1;

fail:
    free(obj->buffer);
    cur->p = start;
    return 0;
}

int encode_nostr_bech32_npub(char *pubkey, char *npub) {
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, pubkey + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }
    int ret = segwit_addr_encode(npub, "npub", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR);

    if (!ret) {
        fprintf(stderr, "Error executing 'segwit_addr_encode'\n");
        return ret;
    }

    return 1;
}

int encode_nostr_bech32_nsec(char *privkey, char *nsec) {
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, privkey + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }
    int ret = segwit_addr_encode(nsec, "nsec", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR);

    if (!ret) {
        fprintf(stderr, "Error executing 'segwit_addr_encode'\n");
        return ret;
    }

    return 1;
}

int encode_nostr_bech32_note(char *id, char *note) {
    char current_byte[3];

    uint8_t input_hex[KEY_LENGTH];

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, id + 2*i, 2);
        input_hex[i] = (uint64_t)strtol(current_byte, NULL, 16);
    }
    int ret = segwit_addr_encode(note, "note", 0, input_hex, KEY_LENGTH, SEGWIT_NOSTR);

    if (!ret) {
        fprintf(stderr, "Error executing 'segwit_addr_encode'\n");
        return ret;
    }

    return 1;
}

int encode_nostr_bech32_naddr(char *tag, uint32_t *kind, char *pubkey, char *naddr,
    int nb_relays, char **relays) {

    char current_byte[3];
    int input_len = 2 + strlen(tag);  // for identifier tag

    if (nb_relays > 0) {
        for (int i = 0; i < nb_relays; i++) {
            input_len += strlen(relays[i]);
            input_len += 2;
        }
    }

    if (pubkey != nullptr)
        input_len += 2 + KEY_LENGTH;  // for author

    input_len += 2 + 4;  // for kind, it is not optional

    int ouput_length = calc_output_length(input_len);

    uint8_t input_hex[input_len];
    uint8_t placeholder[KEY_LENGTH];
    cursor cur;
    make_cursor(input_hex, input_hex + input_len, &cur);

    uint8_t type = TLV_SPECIAL;
    uint8_t len = strlen(tag);

    int ret;
    ret = put_byte(&cur, &type);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_byte(&cur, &len);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_bytes(&cur, strlen(tag), (uint8_t *)tag);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_bytes'\n");
        return ret;
    }

    if (nb_relays > 0) {
        for (int i = 0; i < nb_relays;i++) {
            uint8_t type = TLV_RELAY;
            uint8_t len = strlen(relays[i]);

            ret = put_byte(&cur, &type);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_byte'\n");
                return ret;
            }

            ret = put_byte(&cur, &len);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_byte'\n");
                return ret;
            }

            ret = put_bytes(&cur, len, (uint8_t *)relays[i]);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_bytes'\n");
                return ret;
            }
        }
    }

    type = TLV_AUTHOR;
    len = KEY_LENGTH;
    ret = put_byte(&cur, &type);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_byte(&cur, &len);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }
    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, pubkey + 2*i, 2);
        placeholder[i] = (uint8_t)strtol(current_byte, NULL, 16);
    }
    ret = put_bytes(&cur, KEY_LENGTH, placeholder);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_bytes'\n");
        return ret;
    }

    type = TLV_KIND;
    len = 4;
    ret = put_byte(&cur, &type);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_byte(&cur, &len);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    uint8_t *kind_bytes = (uint8_t*)malloc(len);
    encode_u32_tlv(kind, kind_bytes);

    ret = put_bytes(&cur, len, kind_bytes);

    if (!ret) {
        fprintf(stderr, "Error executing 'put_bytes'\n");
        return ret;
    }
    free(kind_bytes);

    uint8_t data[ouput_length];
    size_t datalen = 0;
    ret = bech32_convert_bits(data, &datalen, TO_BITS, input_hex, input_len, FROM_BITS, 1);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_convert_bits'\n");
        return ret;
    }

    ret = bech32_encode(naddr, "naddr", data, datalen, MAX_ENCODING_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_encode'\n");
        return ret;
    }

    return 1;

}


int encode_nostr_bech32_nrelay(struct cursor *cur, struct bech32_nrelay *obj) {

}

int encode_nostr_bech32_nevent(char *id, char *nevent, uint32_t *kind,
    char *pubkey, int nb_relays, char **relays) {

    char current_byte[3];
    int input_len = 2 + KEY_LENGTH;  // for id

    if (nb_relays > 0) {
        for (int i = 0; i < nb_relays; i++) {
            input_len += strlen(relays[i]);
            input_len += 2;
        }
    }

    if (pubkey != nullptr)
        input_len += 2 + KEY_LENGTH;  // for author

    if(kind != nullptr)
        input_len += 2 + 4;  // for kind

    int ouput_length = calc_output_length(input_len);

    uint8_t input_hex[input_len];
    uint8_t placeholder[KEY_LENGTH];
    cursor cur;
    make_cursor(input_hex, input_hex + input_len, &cur);

    uint8_t type = TLV_SPECIAL;
    uint8_t len = KEY_LENGTH;

    int ret;
    ret = put_byte(&cur, &type);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_byte(&cur, &len);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, id + 2*i, 2);
        placeholder[i] = (uint8_t)strtol(current_byte, NULL, 16);
    }

    ret = put_bytes(&cur, KEY_LENGTH, placeholder);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_bytes'\n");
        return ret;
    }

    if (nb_relays > 0) {
        for (int i = 0; i < nb_relays;i++) {
            uint8_t type = TLV_RELAY;
            uint8_t len = strlen(relays[i]);

            ret = put_byte(&cur, &type);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_byte'\n");
                return ret;
            }

            ret = put_byte(&cur, &len);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_byte'\n");
                return ret;
            }

            ret = put_bytes(&cur, len, (uint8_t *)relays[i]);
            if (!ret) {
                fprintf(stderr, "Error executing 'put_bytes'\n");
                return ret;
            }
        }
    }

    if (pubkey != nullptr) {
        type = TLV_AUTHOR;
        ret = put_byte(&cur, &type);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }

        ret = put_byte(&cur, &len);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }
        for(int i=0;i<KEY_LENGTH;i++) {
            strncpy(current_byte, pubkey + 2*i, 2);
            placeholder[i] = (uint8_t)strtol(current_byte, NULL, 16);
        }
        ret = put_bytes(&cur, KEY_LENGTH, placeholder);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_bytes'\n");
            return ret;
        }
    }

    if (kind != nullptr) {
        type = TLV_KIND;
        len = 4;
        ret = put_byte(&cur, &type);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }

        ret = put_byte(&cur, &len);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }

        uint8_t *kind_bytes = (uint8_t*)malloc(len);
        encode_u32_tlv(kind, kind_bytes);

        ret = put_bytes(&cur, len, kind_bytes);

        if (!ret) {
            fprintf(stderr, "Error executing 'put_bytes'\n");
            return ret;
        }
        free(kind_bytes);
    }

    uint8_t data[ouput_length];
    size_t datalen = 0;
    ret = bech32_convert_bits(data, &datalen, TO_BITS, input_hex, input_len, FROM_BITS, 1);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_convert_bits'\n");
        return ret;
    }

    ret = bech32_encode(nevent, "nevent", data, datalen, MAX_ENCODING_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_encode'\n");
        return ret;
    }

    return 1;
}

int encode_nostr_bech32_nprofile(char *pubkey, char *nprofile, int nb_relays, char **relays) {

    char current_byte[3];

    int input_len = 2 + KEY_LENGTH;

    for (int i = 0; i < nb_relays; i++) {
        input_len += strlen(relays[i]);
        input_len += 2;
    }
    int ouput_length = calc_output_length(input_len);

    uint8_t input_hex[input_len];
    cursor cur;
    make_cursor(input_hex, input_hex + input_len, &cur);
    uint8_t type = TLV_SPECIAL;
    uint8_t len = KEY_LENGTH;

    int ret;
    ret = put_byte(&cur, &type);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    ret = put_byte(&cur, &len);
    if (!ret) {
        fprintf(stderr, "Error executing 'put_byte'\n");
        return ret;
    }

    for(int i=0;i<KEY_LENGTH;i++) {
        strncpy(current_byte, pubkey + 2*i, 2);
        input_hex[i+2] = (uint8_t)strtol(current_byte, NULL, 16);
    }
    ret = move_bytes(&cur, KEY_LENGTH);
    if (!ret) {
        fprintf(stderr, "Error executing 'move_bytes'\n");
        return ret;
    }

    for (int i = 0; i < nb_relays;i++) {
        uint8_t type = 1;
        uint8_t len = strlen(relays[i]);

        ret = put_byte(&cur, &type);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }

        ret = put_byte(&cur, &len);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_byte'\n");
            return ret;
        }

        ret = put_bytes(&cur, len, (uint8_t *)relays[i]);
        if (!ret) {
            fprintf(stderr, "Error executing 'put_bytes'\n");
            return ret;
        }
    }

    uint8_t data[ouput_length];
    size_t datalen = 0;
    ret = bech32_convert_bits(data, &datalen, TO_BITS, input_hex, input_len, FROM_BITS, 1);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_convert_bits'\n");
        return ret;
    }

    ret = bech32_encode(nprofile, "nprofile", data, datalen, MAX_ENCODING_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret) {
        fprintf(stderr, "Error executing 'bech32_encode'\n");
        return ret;
    }

    return 1;
}