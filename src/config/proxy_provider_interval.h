#ifndef PROXY_PROVIDER_INTERVAL_H_INCLUDED
#define PROXY_PROVIDER_INTERVAL_H_INCLUDED

#include <charconv>
#include <cctype>
#include <string_view>

inline constexpr int kDefaultProxyProviderInterval = 3600;

inline bool parseProxyProviderInterval(std::string_view input, int &result) {
  while (!input.empty() &&
         std::isspace(static_cast<unsigned char>(input.front())))
    input.remove_prefix(1);
  while (!input.empty() &&
         std::isspace(static_cast<unsigned char>(input.back())))
    input.remove_suffix(1);
  if (input.empty())
    return false;

  for (unsigned char ch : input) {
    if (!std::isdigit(ch))
      return false;
  }

  int value = 0;
  const auto [end, error] =
      std::from_chars(input.data(), input.data() + input.size(), value);
  if (error != std::errc() || end != input.data() + input.size())
    return false;
  result = value;
  return true;
}

#endif // PROXY_PROVIDER_INTERVAL_H_INCLUDED
