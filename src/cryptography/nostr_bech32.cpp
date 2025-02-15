#include <cryptography/nostr_bech32.hpp>
#include <stdio.h>
namespace nostr
{
namespace encoding
{

// if `std::string hex_string` has an even number character
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
        std::cerr << "String: '" << hex << "' is not a valid hex string\n";

    std::size_t arraySize = hex.size() / 2;
    for(int i=0; i<arraySize; i++)
    {
        array.push_back(std::stol(hex.substr(2*i, 2), nullptr, 16));
    }

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

    // include TLV for the relays
    if (input.data.naddr.relays.empty())
    {
        std::cerr << "Relays metadata field is not optional for naddr encoding\n";
        return false;
    }

    for (std::string relay : input.data.naddr.relays)
    {
        input_hex.push_back(TLV_RELAY);
        input_hex.push_back(relay.length());
        input_hex.insert(input_hex.end(), relay.begin(), relay.end());
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
        {
            std::cerr << "Error: 'encodeNostrBech32Note'\n";
            return false;
        }
        break;
    case NOSTR_BECH32_NPUB:
        ret = encodeNostrBech32Npub(input, encoding);
        if(!ret)
        {
            std::cerr << "Error: 'encodeNostrBech32Npub'\n";
            return false;
        }
        break;
    case NOSTR_BECH32_NPROFILE:
        ret = encodeNostrBech32Nprofile(input, encoding);
        if(!ret)
        {
            std::cerr << "Error: 'encodeNostrBech32Nprofile'\n";
            return false;
        }
        break;
    case NOSTR_BECH32_NEVENT:
        ret = encodeNostrBech32Nevent(input, encoding);
        if(!ret)
        {
            std::cerr << "Error: 'encodeNostrBech32Nevent'\n";
            return false;
        }
        break;

    case NOSTR_BECH32_NADDR:
        ret = encodeNostrBech32Naddr(input, encoding);
        if(!ret)
        {
            std::cerr << "Error: 'encodeNostrBech32Naddr'\n";
            return false;
        }
        break;
    case NOSTR_BECH32_NSEC:
        ret = encodeNostrBech32Nsec(input, encoding);
        if(!ret)
        {
            std::cerr << "Error: 'encodeNostrBech32Nsec'\n";
            return false;
        }
        break;
    default:
        std::cerr << "Error: unrecognized encoding\n";
        return false;
        break;
    }
    return true;
}


}
} // namespace name
