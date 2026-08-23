#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include <string>
#include <string_view>

namespace hashing
{
std::string sha256Hex(std::string_view input);
}

#endif // SHA256_H_INCLUDED
