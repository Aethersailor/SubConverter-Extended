#pragma once

#include <algorithm>
#include <string>
#include <string_view>

inline constexpr size_t kProviderUserAgentMaxLen = 512;

// This is a URI component, not form data: '+' is literal and decoding is
// performed exactly once. Reject invalid bytes instead of repairing headers.
inline bool parseProxyProviderUserAgent(std::string_view input,
                                        std::string &result) {
  if (input.empty() || input.size() > kProviderUserAgentMaxLen * 3)
    return false;
  auto hex = [](unsigned char ch) -> int {
    if (ch >= '0' && ch <= '9')
      return ch - '0';
    if (ch >= 'a' && ch <= 'f')
      return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
      return ch - 'A' + 10;
    return -1;
  };
  result.clear();
  result.reserve(std::min(input.size(), kProviderUserAgentMaxLen));
  for (size_t index = 0; index < input.size(); ++index) {
    unsigned char ch = input[index];
    if (ch == '%') {
      if (index + 2 >= input.size())
        return false;
      const int high = hex(input[index + 1]), low = hex(input[index + 2]);
      if (high < 0 || low < 0)
        return false;
      ch = static_cast<unsigned char>(high * 16 + low);
      index += 2;
    }
    if (ch < 0x20 || ch > 0x7e || result.size() == kProviderUserAgentMaxLen)
      return false;
    result += static_cast<char>(ch);
  }
  const size_t begin = result.find_first_not_of(' ');
  if (begin == std::string::npos)
    return false;
  result.erase(result.find_last_not_of(' ') + 1);
  result.erase(0, begin);
  return true;
}
