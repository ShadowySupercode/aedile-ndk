
#include <cryptography/bech32.hpp>

namespace nostr
{
namespace encoding
{
    static uint32_t bech32PolymodStep(uint32_t value) {
        uint8_t b = value >> 25;
        uint32_t ret = ((value & 0x1FFFFFF) << 5) ^
            (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
            (-((b >> 1) & 1) & 0x26508e6dUL) ^
            (-((b >> 2) & 1) & 0x1ea119faUL) ^
            (-((b >> 3) & 1) & 0x3d4233ddUL) ^
            (-((b >> 4) & 1) & 0x2a1462b3UL);
        return ret;
    }

    static uint32_t bech32FinalConstant(Bech32EncodingType enc) {
        if (enc == BECH32_ENCODING_BECH32) return 1;
        if (enc == BECH32_ENCODING_BECH32M) return 0x2bc830a3;
        assert(0);
    }

    int Bech32::segwitAddrEncode(
        std::string &output,
        const std::string hrp,
        int ver,
        const BytesArray &prog,
        SegwitProtocol protocol)
    {
        BytesArray data;
        std::size_t datalen = 0;
        Bech32EncodingType enc = BECH32_ENCODING_BECH32;
        if (ver > 16)
            return 0;
        if (ver == 0 && prog.size() != 20 && prog.size() != 32)
            return 0;
        if (prog.size() < 2 || prog.size() > 40)
            return 0;
        if (ver > 0)
            enc = BECH32_ENCODING_BECH32M;

        if (protocol >= SEGWIT_MAX) {
            fprintf(stderr, "There is no supported for protocol of number %d\n", protocol);
            return 0;
        }

        if (protocol == SEGWIT_BITCOIN) {
            data.push_back(ver);
            BytesArray data_no_ver = BytesArray(data.begin()+1, data.end());
            Bech32::convertBits(data_no_ver, TO_BITS, prog, FROM_BITS, 1);
            return Bech32::encode(output, hrp, data, MAX_INPUT_LENGTH, enc);
        }

        // for NOSTR, witver is not included in the data to be encoded
        if (protocol == SEGWIT_NOSTR) {
            Bech32::convertBits(data, TO_BITS, prog, FROM_BITS, 1);
            return Bech32::encode(output, hrp, data, MAX_INPUT_LENGTH, enc);
        }

        return 0;
    }

    int Bech32::segwitAddrDecode(
        std::shared_ptr<int> ver,
        BytesArray &prog,
        const std::string hrp,
        const std::string addr,
        SegwitProtocol protocol
    )
    {
        BytesArray data;
        std::string hrp_actual;
        Bech32EncodingType enc = Bech32::decode(hrp_actual, data, addr, 90);
        if (enc == BECH32_ENCODING_NONE)
            return 0;
        if (data.size() == 0 || data.size() > 65)
            return 0;
        if (hrp.compare(0, 84, hrp_actual) != 0)
            return 0;
        if (data[0] > 16)
            return 0;
        if (data[0] == 0 && enc != BECH32_ENCODING_BECH32)
            return 0;
        if (data[0] > 0 && enc != BECH32_ENCODING_BECH32M)
            return 0;
        if (protocol >= SEGWIT_MAX)
            return 0;


        if(!Bech32::convertBits(prog, FROM_BITS, data, TO_BITS, 0))
            return 0;
        if (prog.size() < 2 || prog.size() > 40)
            return 0;
        if (data[0] == 0 && prog.size() != 20 && prog.size() != 32)
            return 0;

        // include the witness version in the decoded data
        // in case this is segwit for bitcoin because ver
        // could be something other than 1.
        if (protocol == SEGWIT_BITCOIN) {
            *ver = data[0];
        }

        return 1;
    }

    int Bech32::encode(
        std::string &output,
        const std::string hrp,
        const BytesArray &data,
        std::size_t max_input_len,
        Bech32EncodingType enc
    )
    {
        uint32_t chk = 1;
        std::size_t i = 0;
        for(const char &c : hrp)
        {
            if (c < 33 || c > 126)
                return 0;

            if (c >= 'A' && c <= 'Z')
                return 0;

            chk = bech32PolymodStep(chk) ^ (c >> 5);
            ++i;
        }
        if (i + 7 + data.size() > max_input_len)
            return 0;

        chk = bech32PolymodStep(chk);
        for(const char& c : hrp)
            chk = bech32PolymodStep(chk) ^ (c & 0x1f);

        output += hrp + "1";

        for (const uint8_t &d : data) {
            // guard against numbers that exceet 5 bits
            if (d >> TO_BITS)
                return 0;

            chk = bech32PolymodStep(chk) ^ d;
            output += bech32Charset[d];
        }
        for (i = 0; i < 6; i++)
            chk = bech32PolymodStep(chk);

        chk ^= bech32FinalConstant(enc);
        for (i = 0; i < 6; i++) {
            char current = bech32Charset[(chk >> (5 - i) * 5) & 0x1f];
            output += bech32Charset[(chk >> (5 - i) * 5) & 0x1f];
        }
        return 1;
    }

    Bech32EncodingType Bech32::decode(
        std::string &hrp,
        BytesArray &data,
        const std::string input,
        std::size_t max_input_len
    )
    {
        if (input.size() > max_input_len)
            return BECH32_ENCODING_NONE;

        return Bech32::decodeLen(hrp, data, input, input.size());
    }


    Bech32EncodingType Bech32::decodeLen(
        std::string &hrp,
        BytesArray &data,
        const std::string input,
        std::size_t max_input_len
    )
    {
        uint32_t chk = 1;
        std::size_t hrp_len;
        int have_lower = 0, have_upper = 0;
        if (input.size() < 8)
            return BECH32_ENCODING_NONE;

        hrp_len = input.find('1');
        if (hrp_len == std::string::npos)
            return BECH32_ENCODING_NONE;

        hrp = input.substr(0, hrp_len);

        for (char &c : hrp)
        {
            if (c < 33 || c > 126)
                return BECH32_ENCODING_NONE;
            if (c >= 'a' && c <= 'z')
                have_lower = 1;
            else if (c >= 'A' && c <= 'Z')
            {
                have_upper = 1;
                c = (c - 'A') + 'a';
            }
            chk = bech32PolymodStep(chk) ^ (c >> 5);
        }
        chk = bech32PolymodStep(chk);
        for (char &c : hrp)
            chk = bech32PolymodStep(chk) ^ (c & 0x1f);

        size_t i = 0;
        for (uint8_t byte : input.substr(hrp.size() + 1))
        {
            int v = (byte & 0x80) ? -1 : bech32CharsetRev[(int)byte];

            if (byte >= 'a' && byte <= 'z')
                have_lower = 1;
            if (byte >= 'A' && byte <= 'Z')
                 have_upper = 1;

            if (v == -1) {
                return BECH32_ENCODING_NONE;
            }
            chk = bech32PolymodStep(chk) ^ v;

            if(i + 6 < input.substr(hrp.size() + 1).size())
                data.push_back(v);
            ++i;
        }
        if (have_lower && have_upper)
        {
            return BECH32_ENCODING_NONE;
        }
        if (chk == bech32FinalConstant(BECH32_ENCODING_BECH32))
            return BECH32_ENCODING_BECH32;
        else if (chk == bech32FinalConstant(BECH32_ENCODING_BECH32M))
        {
            return BECH32_ENCODING_BECH32M;
        }
        else
        {
            printf("HERE\n");
            return BECH32_ENCODING_NONE;
        }
    }


    int Bech32::convertBits(BytesArray &out, int outbits,
                const BytesArray &in, int inbits,
                int pad)
    {
        uint32_t val = 0;
        int bits = 0;
        uint32_t maxv = (((uint32_t)1) << outbits) - 1;
        for (const uint8_t i : in)
        {
            val = (val << inbits) | i;
            bits += inbits;
            while (bits >= outbits) {
                bits -= outbits;
                out.push_back((val >> bits) & maxv);
            }
        }
        if (pad)
            if (bits)
                out.push_back((val << (outbits - bits)) & maxv);

        else if (((val << (outbits - bits)) & maxv) || bits >= inbits)
            return 0;

        return 1;
    }
}
}