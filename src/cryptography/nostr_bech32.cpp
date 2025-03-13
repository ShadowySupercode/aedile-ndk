#include <cryptography/nostr_bech32.hpp>
#include <stdio.h>
namespace nostr
{
namespace encoding
{

// if `std::string hex_string` has an even number of character
// from the set of hexadecimal digits, then return true
bool isValidHex(std::string hex_string)
{
    if (hex_string.size() % 2 != 0)
    {
        std::cerr << "A valid hex string must have an even number of characters\n";
        return false;
    }
    for (char &c : hex_string)
        if (!std::isxdigit(c))
        {
            std::cerr << "String is invalid. It contains '"<< c << "' which is not a hex character\n";
            return false;
        }
    return true;
}

bool convertHexStringToByteArray(std::string &hex, BytesArray &array)
{
    if (!isValidHex(hex))
    {
        std::cerr << "String: '" << hex << "' is not a valid hex string\n";
        return false;
    }

    std::size_t arraySize = hex.size() / 2;
    for(int i=0; i<arraySize; i++)
    {
        array.push_back(std::stoi(hex.substr(2*i, 2), nullptr, 16));
    }

    return true;
}

bool convertByteArrayToHexString(BytesArray &array, std::string &hex)
{
    std::stringstream ss;
    char placeholder[3];
    for(uint8_t &byte : array)
    {
        sprintf(placeholder, "%02x", byte);
        ss << placeholder;
    }
    hex = ss.str();
    return true;
}

bool NostrBech32::encodeNostrBech32Note(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex;
    bool ret = convertHexStringToByteArray(input.data.note.event_id, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }
    ret = Bech32::segwitAddrEncode(encoding, "note", 0, input_hex, SEGWIT_NOSTR);
    if (!ret)
    {
        std::cerr << "Error: 'segwitAddrEncode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32Npub(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex;
    bool ret = convertHexStringToByteArray(input.data.npub.pubkey, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }
    ret = Bech32::segwitAddrEncode(encoding, "npub", 0, input_hex, SEGWIT_NOSTR);
    if (!ret)
    {
        std::cerr << "Error: 'segwitAddrEncode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32Nsec(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex;
    bool ret = convertHexStringToByteArray(input.data.nsec.privkey, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }
    ret = Bech32::segwitAddrEncode(encoding, "nsec", 0, input_hex, SEGWIT_NOSTR);
    if (!ret)
    {
        std::cerr << "Error: 'segwitAddrEncode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32Nevent(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex, squashed_input;

    if (input.data.nevent.event_id.empty())
    {
        std::cerr << "Error: 'event_id' cannot be an empty string\n";
        return false;
    }

    // include TLV for the event id
    input_hex.push_back(TLV_SPECIAL);
    input_hex.push_back(KEY_LENGTH);

    bool ret = convertHexStringToByteArray(input.data.nevent.event_id, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }

    // include TLV for the relays
    if(!input.data.nevent.relays.empty())
        for (std::string relay : input.data.nevent.relays)
        {
            input_hex.push_back(TLV_RELAY);
            input_hex.push_back(relay.length());
            input_hex.insert(input_hex.end(), relay.begin(), relay.end());
        }

    // include TLV for the pubkey
    if(!input.data.nevent.pubkey.empty())
    {
        input_hex.push_back(TLV_AUTHOR);
        input_hex.push_back(KEY_LENGTH);

        ret = convertHexStringToByteArray(input.data.nevent.pubkey, input_hex);
        if (!ret)
        {
            std::cerr << "Error: 'convertHexStringToByteArray'\n";
            return false;
        }
    }

    if(input.data.nevent.has_kind)
    {
        // include TLV for kind
        input_hex.push_back(TLV_KIND);
        input_hex.push_back(4);

        // convert kind into 4 bytes in big-endian
        for(int i=0; i<4; i++)
            input_hex.push_back((input.data.nevent.kind >> (8 * (3 - i)) & 0xFF));
    }


    ret = Bech32::convertBits(squashed_input, TO_BITS, input_hex, FROM_BITS, 1);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::convertBits'\n";
        return false;
    }

    ret = Bech32::encode(encoding, "nevent", squashed_input, MAX_INPUT_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::encode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32Nprofile(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex, squashed_input;

    // include TLV for the pubkey
    // include TLV for the 'd' tag
    if (input.data.nprofile.pubkey.empty())
    {
        std::cerr << "pubkey is mandatory for naddr encoding\n";
        return false;
    }
    input_hex.push_back(TLV_SPECIAL);
    input_hex.push_back(KEY_LENGTH);

    bool ret = convertHexStringToByteArray(input.data.nprofile.pubkey, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }

    // include TLV for the relays
    if (!input.data.nprofile.relays.empty())
    {
        for (std::string relay : input.data.nprofile.relays)
        {
            input_hex.push_back(TLV_RELAY);
            input_hex.push_back(relay.length());
            input_hex.insert(input_hex.end(), relay.begin(), relay.end());
        }
    }
    ret = Bech32::convertBits(squashed_input, TO_BITS, input_hex, FROM_BITS, 1);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::convertBits'\n";
        return false;
    }
    ret = Bech32::encode(encoding, "nprofile", squashed_input, MAX_INPUT_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::encode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32Naddr(NostrBech32Encoding &input, std::string &encoding)
{
    BytesArray input_hex, squashed_input;

    // include TLV for the 'd' tag
    if (input.data.naddr.tag.empty())
    {
        std::cerr << "'d' tag is mandatory for naddr encoding\n";
        return false;
    }

    input_hex.push_back(TLV_SPECIAL);
    input_hex.push_back(input.data.naddr.tag.size());
    input_hex.insert(input_hex.end(),
        input.data.naddr.tag.begin(), input.data.naddr.tag.end());

    // include TLV for the relays if they exist
    // optional for naddr encoding
    if (!input.data.naddr.relays.empty())
    {
        for (std::string relay : input.data.naddr.relays)
        {
            input_hex.push_back(TLV_RELAY);
            input_hex.push_back(relay.length());
            input_hex.insert(input_hex.end(), relay.begin(), relay.end());
        }
    }

    if (input.data.naddr.pubkey.empty())
    {
        std::cerr << "Pubkey metadata field is not option for naddr encoding\n";
        return false;
    }

    /// include tlv for author field
    if (!isValidHex(input.data.naddr.pubkey))
    {
        std::cerr << "Pubkey '" <<  input.data.naddr.pubkey << "' is not a valid hex key\n";
        return false;
    }
    input_hex.push_back(TLV_AUTHOR);
    input_hex.push_back(KEY_LENGTH);

    bool ret = convertHexStringToByteArray(input.data.naddr.pubkey, input_hex);
    if (!ret)
    {
        std::cerr << "Error: 'convertHexStringToByteArray'\n";
        return false;
    }

    // include TLV for kind
    input_hex.push_back(TLV_KIND);
    input_hex.push_back(4);

    // convert kind into 4 bytes in big-endian
    for(int i=0; i<4; i++)
        input_hex.push_back((input.data.naddr.kind >> (8 * (3 - i)) & 0xFF));

    ret = Bech32::convertBits(squashed_input, TO_BITS, input_hex, FROM_BITS, 1);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::convertBits'\n";
        return false;
    }

    ret = Bech32::encode(encoding, "naddr", squashed_input, MAX_INPUT_LENGTH, BECH32_ENCODING_BECH32);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::encode'\n";
        return false;
    }
    return true;
}

bool NostrBech32::encodeNostrBech32(NostrBech32Encoding &input, std::string &encoding)
{
    bool ret;
    switch (input.type)
    {
    case NOSTR_BECH32_NOTE:
        ret = encodeNostrBech32Note(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Note'");
        break;
    case NOSTR_BECH32_NPUB:
        ret = encodeNostrBech32Npub(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Npub'");
        break;
    case NOSTR_BECH32_NPROFILE:
        ret = encodeNostrBech32Nprofile(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Nprofile'");
        break;
    case NOSTR_BECH32_NEVENT:
        ret = encodeNostrBech32Nevent(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Nevent'");
        break;

    case NOSTR_BECH32_NADDR:
        ret = encodeNostrBech32Naddr(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Naddr'");
        break;
    case NOSTR_BECH32_NSEC:
        ret = encodeNostrBech32Nsec(input, encoding);
        if(!ret)
            throw std::runtime_error("Error: 'encodeNostrBech32Nsec'");
        break;
    default:
        throw std::runtime_error("Error: unrecognized encoding");
        break;
    }
    return true;
}

bool NostrBech32::parseTlv(BytesArray &encoding, NostrTlv &tlv, int &cur)
{
    tlv.type = encoding[cur++];

    // unknown, fail!
    if (tlv.type >= TLV_KNOWN_TLVS)
        return false;

    tlv.len = encoding[cur++];

    // is the reported length greater then our buffer? if so fail
    if (tlv.len + cur > encoding.size())
        return false;

    tlv.value = TlvValues(encoding.begin() + cur, encoding.begin() + cur + tlv.len);
    cur += tlv.len;

    return true;
}

bool NostrBech32::parseTlvs(BytesArray &encoding, std::vector<NostrTlv> &tlvs)
{
    int cur = 0;
    NostrTlv tlv;

    while (tlvs.size() < MAX_TLVS && parseTlv(encoding, tlv, cur))
        tlvs.push_back(tlv);

    if (tlvs.size() == 0)
        return false;

    return true;
}

bool NostrBech32::findTlv(std::vector<NostrTlv> &tlvs, uint8_t type, NostrTlv &found_tlv)
{
    for (NostrTlv tlv : tlvs)
    {
        if (tlv.type == type)
        {
            found_tlv = tlv;
            return true;
        }
    }
    return false;
}

bool NostrBech32::tlvToRelays(std::vector<NostrTlv> &tlvs, Relays &relays)
{
    for (NostrTlv tlv : tlvs)
    {
        if (tlv.type != TLV_RELAY)
            continue;

        relays.push_back(std::string(tlv.value.begin(), tlv.value.end()));
        if (relays.size() > MAX_RELAYS)
            break;
    }
    return true;
}

bool NostrBech32::parseNostrBech32Npub(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    bool ret = convertByteArrayToHexString(encoding, parsed.data.npub.pubkey);
    if (!ret)
    {
        std::cerr << "Error: 'convertByteArrayToHexString'\n";
        return false;
    }
    return true;
}

bool NostrBech32::parseNostrBech32Note(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    bool ret = convertByteArrayToHexString(encoding, parsed.data.note.event_id);
    if (!ret)
    {
        std::cerr << "Error: 'convertByteArrayToHexString'\n";
        return false;
    }
    return true;
}


bool NostrBech32::parseNostrBech32Nsec(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    bool ret = convertByteArrayToHexString(encoding, parsed.data.nsec.privkey);
    if (!ret)
    {
        std::cerr << "Error: 'convertByteArrayToHexString'\n";
        return false;
    }
    return true;
}


bool NostrBech32::parseNostrBech32Nprofile(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    std::vector<NostrTlv> tlvs;
    NostrTlv tlv;

    bool ret = parseTlvs(encoding, tlvs);
    if(!ret)
    {
        std::cerr << "Error: 'parseTlvs'\n";
        return false;
    }

    ret = findTlv(tlvs, TLV_SPECIAL, tlv);
    if(!ret)
    {
        std::cerr << "Error: 'findTlv:TLV_SPECIAL'\n";
        return false;
    }
    if (tlv.len != KEY_LENGTH)
    {
        std::cerr << "Expected pubkey of length 32 bytes\n";
        return false;
    }

    ret = convertByteArrayToHexString(tlv.value, parsed.data.nprofile.pubkey);
    if (!ret)
    {
        std::cerr << "Error: 'convertByteArrayToHexString'\n";
        return false;
    }

    ret = tlvToRelays(tlvs, parsed.data.nprofile.relays);
    if (!ret)
    {
        std::cerr << "Error: 'tlvToRelays'\n";
        return false;
    }
    return true;
}

bool NostrBech32::parseNostrBech32Nevent(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    std::vector<NostrTlv> tlvs;
    NostrTlv tlv;

    bool ret = parseTlvs(encoding, tlvs);
    if(!ret)
    {
        std::cerr << "Error: 'parseTlvs'\n";
        return false;
    }

    // find event id
    ret = findTlv(tlvs, TLV_SPECIAL, tlv);
    if(!ret)
    {
        std::cerr << "Error: 'findTlv:TLV_SPECIAL'\n";
        return false;
    }

    if (tlv.len != KEY_LENGTH)
    {
        std::cerr << "Expected event id of length 32 bytes\n";
        return false;
    }
    ret = convertByteArrayToHexString(tlv.value, parsed.data.nevent.event_id);

    // find pubkey
    ret = findTlv(tlvs, TLV_AUTHOR, tlv);
    if(!ret)
    {
        parsed.data.nevent.pubkey = "";
    }
    else
    {
        if (tlv.len != KEY_LENGTH)
        {
            std::cerr << "Expected pubkey of length 32 bytes\n";
            return false;
        }
        ret = convertByteArrayToHexString(tlv.value, parsed.data.nevent.pubkey);
        if (!ret)
        {
            std::cerr << "Error: 'convertByteArrayToHexString'\n";
            return false;
        }
    }
    ret = findTlv(tlvs, TLV_KIND, tlv);
    if (ret)
    {
        if (tlv.len != 4)
        {
            std::cerr << "Error: tlv for kind does not have 4 bytes\n";
            return false;
        }
        parsed.data.nevent.has_kind = true;
        parsed.data.nevent.kind = 0;

        // convert 4 bytes in big-endian to kind in uint32
        for(int i=0; i<4; i++)
        {
            parsed.data.nevent.kind += (tlv.value[i] & 0xFF) << (8*(3 - i));
        }
    }
    else
        parsed.data.nevent.has_kind = false;

    ret = tlvToRelays(tlvs, parsed.data.nevent.relays);
    if (!ret)
    {
        std::cerr << "Error: 'tlvToRelays'\n";
        return false;
    }

    return true;
}

bool NostrBech32::parseNostrBech32Naddr(BytesArray &encoding, NostrBech32Encoding &parsed)
{
    std::vector<NostrTlv> tlvs;
    NostrTlv tlv;

    bool ret = parseTlvs(encoding, tlvs);
    if(!ret)
    {
        std::cerr << "Error: 'parseTlvs'\n";
        return false;
    }

    // find 'd' tag
    ret = findTlv(tlvs, TLV_SPECIAL, tlv);
    if(!ret)
    {
        std::cerr << "Error: 'findTlv:TLV_SPECIAL'\n";
        return false;
    }
    parsed.data.naddr.tag = std::string(tlv.value.begin(), tlv.value.end());

    // find pubkey
    ret = findTlv(tlvs, TLV_AUTHOR, tlv);
    if(!ret)
    {
        std::cerr << "Error: 'findTlv:TLV_AUTHOR'\n";
        return false;
    }
    ret = convertByteArrayToHexString(tlv.value, parsed.data.naddr.pubkey);
    if (!ret)
    {
        std::cerr << "Error: 'convertByteArrayToHexString'\n";
        return false;
    }

    // find kind
    ret = findTlv(tlvs, TLV_KIND, tlv);
    if(!ret)
    {
        std::cerr << "Error: 'findTlv:TLV_KIND'\n";
        return false;
    }

    if (tlv.len != 4)
    {
        std::cerr << "Error: tlv for kind does not have 4 bytes\n";
        return false;
    }

    // convert 4 bytes in big-endian to kind in uint32
    parsed.data.naddr.kind = 0;
    for(int i=0; i<4; i++)
    {
        parsed.data.naddr.kind += (tlv.value[i] & 0xFF) << (8*(3 - i));
    }

    ret = tlvToRelays(tlvs, parsed.data.naddr.relays);
    if (!ret)
    {
        std::cerr << "Error: 'tlvToRelays'\n";
        return false;
    }

    return true;

}


bool NostrBech32::parseNostrBech32(std::string &encoding, NostrBech32Encoding &parsed)
{
    std::string hrp;
    BytesArray data, unsquashed_data;

    if (Bech32::decodeLen(hrp, data, encoding, MAX_INPUT_LENGTH) != BECH32_ENCODING_BECH32)
    {
        std::cerr << "Error: 'Bech32::decodeLen'\n";
        return false;
    }

    bool ret = Bech32::convertBits(unsquashed_data, FROM_BITS, data, TO_BITS, 0);
    if (!ret)
    {
        std::cerr << "Error: 'Bech32::convertBits'\n";
        return false;
    }

    if (hrp == "note")
        parsed.type = NOSTR_BECH32_NOTE;
    else if (hrp == "npub")
        parsed.type = NOSTR_BECH32_NPUB;
    else if (hrp == "nsec")
        parsed.type = NOSTR_BECH32_NSEC;
    else if (hrp == "nprofile")
        parsed.type = NOSTR_BECH32_NPROFILE;
    else if (hrp == "nevent")
        parsed.type = NOSTR_BECH32_NEVENT;
    else if (hrp == "naddr")
        parsed.type = NOSTR_BECH32_NADDR;
    else
        goto unrecognized_prefix;

    switch (parsed.type)
    {
    case NOSTR_BECH32_NOTE:
        ret = parseNostrBech32Note(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Note'");
        break;
    case NOSTR_BECH32_NPUB:
        ret = parseNostrBech32Npub(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Npub'");
        break;
    case NOSTR_BECH32_NSEC:
        ret = parseNostrBech32Nsec(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Nsec'");
        break;

    case NOSTR_BECH32_NPROFILE:
        ret = parseNostrBech32Nprofile(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Nprofile'");
        break;
    case NOSTR_BECH32_NEVENT:
        ret = parseNostrBech32Nevent(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Nevent'");
        break;

    case NOSTR_BECH32_NADDR:
        ret = parseNostrBech32Naddr(unsquashed_data, parsed);
        if (!ret)
            throw std::runtime_error("Error: 'parseNostrBech32Naddr'");
        break;

    default:
        goto unrecognized_prefix;
        break;
    }

    return true;

unrecognized_prefix:
    throw std::invalid_argument("Unrecognized human readable prefix");
}

}
} // namespace name
