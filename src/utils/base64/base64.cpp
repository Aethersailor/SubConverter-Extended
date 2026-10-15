#include <array>
#include <string>

#include "utils/string.h"

static constexpr char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static const std::string base64_chars = base64_alphabet;

std::string base64Encode(const std::string &string_to_encode)
{
    char const* bytes_to_encode = string_to_encode.data();
    unsigned int in_len = string_to_encode.size();

    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        int j;
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string base64Decode(const std::string &encoded_string, bool accept_urlsafe)
{
    string_size in_len = encoded_string.size();
    const char *encoded_data = encoded_string.data();
    string_size i = 0;
    string_size in_ = 0;
    unsigned char char_array_4[4], char_array_3[3], uchar;
    struct DecodeTables {
        std::array<unsigned char, 256> valid{};
        std::array<unsigned char, 256> decode{};
    };
    // Constant initialization keeps concurrent first calls read-only.
    constexpr auto make_tables = [] {
        DecodeTables value;
        for (string_size k = 0; k < sizeof(base64_alphabet) - 1; ++k) {
            const unsigned char ch = base64_alphabet[k];
            value.decode[ch] = static_cast<unsigned char>(k);
            value.valid[ch] = 1;
        }
        value.decode['-'] = value.decode['+']; value.valid['-'] = 2;
        value.decode['_'] = value.decode['/']; value.valid['_'] = 2;
        return value;
    };
    static constexpr auto dtable = make_tables().decode;
    static constexpr auto itable = make_tables().valid;
    std::string ret;

    while (in_len-- && (encoded_data[in_] != '='))
    {
        uchar = encoded_data[in_]; // make compiler happy
        if (!(accept_urlsafe ? itable[uchar] : (itable[uchar] == 1))) // break away from the while condition
        {
            ret += uchar; // not base64 encoded data, copy to result
            in_++;
            i = 0;
            continue;
        }
        char_array_4[i++] = uchar;
        in_++;
        if (i == 4)
        {
            for (string_size j = 0; j < 4; j++)
                char_array_4[j] = dtable[char_array_4[j]];

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (string_size j = i; j <4; j++)
            char_array_4[j] = 0;

        for (string_size j = 0; j <4; j++)
            char_array_4[j] = dtable[char_array_4[j]];

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (string_size j = 0; (j < i - 1); j++)
            ret += char_array_3[j];
    }

    return ret;
}

std::string urlSafeBase64Reverse(const std::string &encoded_string)
{
    return replaceAllDistinct(replaceAllDistinct(encoded_string, "-", "+"), "_", "/");
}

std::string urlSafeBase64Apply(const std::string &encoded_string)
{
    return replaceAllDistinct(replaceAllDistinct(replaceAllDistinct(encoded_string, "+", "-"), "/", "_"), "=", "");
}

std::string urlSafeBase64Decode(const std::string &encoded_string)
{
    return base64Decode(encoded_string, true);
}

std::string urlSafeBase64Encode(const std::string &string_to_encode)
{
    return urlSafeBase64Apply(base64Encode(string_to_encode));
}
