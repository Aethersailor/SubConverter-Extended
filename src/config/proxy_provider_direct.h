#pragma once

#include <cctype>
#include <string>
#include <string_view>

inline constexpr bool kDefaultProxyProviderDirect = true;

inline bool parseProxyProviderDirect(std::string_view value, bool &result) {
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.front())))
    value.remove_prefix(1);
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back())))
    value.remove_suffix(1);

  std::string normalized(value);
  for (char &ch : normalized)
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  if (normalized == "true" || normalized == "1") {
    result = true;
    return true;
  }
  if (normalized == "false" || normalized == "0") {
    result = false;
    return true;
  }
  return false;
}
