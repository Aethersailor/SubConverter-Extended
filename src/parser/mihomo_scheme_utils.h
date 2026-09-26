#pragma once

#include <algorithm>
#include <cctype>
#include <string>

#include "mihomo_schemes.h"

namespace mihomo {

inline std::string normalizeScheme(std::string scheme) {
  std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return scheme;
}

inline std::string extractHierarchicalScheme(const std::string &link) {
  size_t pos = link.find("://");
  if (pos == std::string::npos)
    return "";
  return normalizeScheme(link.substr(0, pos));
}

inline bool isHttpScheme(const std::string &scheme) {
  return scheme == "http" || scheme == "https";
}

inline bool isHttpSchemeLink(const std::string &link) {
  return isHttpScheme(extractHierarchicalScheme(link));
}

// An explicit node marker avoids guessing whether an HTTP URL is a proxy or a
// subscription. Keep this URI deliberately narrow: Mihomo ignores HTTP proxy
// URI paths and queries, and its userinfo decoder can lose complex passwords.
inline bool isExplicitHttpNodeUri(const std::string &uri) {
  if (!isHttpSchemeLink(uri) || uri.find("!!import:") != std::string::npos)
    return false;

  const size_t authority_start = uri.find("://") + 3;
  const size_t authority_end = uri.find_first_of("/?#", authority_start);
  if (authority_end != std::string::npos && uri[authority_end] != '#')
    return false;
  const std::string authority = uri.substr(
      authority_start, authority_end == std::string::npos
                           ? std::string::npos
                           : authority_end - authority_start);
  if (authority.empty() || authority.find('@') != std::string::npos ||
      authority.find('%') != std::string::npos ||
      std::any_of(authority.begin(), authority.end(), [](unsigned char ch) {
        return std::isspace(ch) || ch < 0x20 || ch == 0x7f;
      }))
    return false;

  size_t port_start;
  if (authority.front() == '[') {
    const size_t bracket_end = authority.find(']');
    if (bracket_end == std::string::npos || bracket_end == 1 ||
        bracket_end + 1 >= authority.size() || authority[bracket_end + 1] != ':')
      return false;
    port_start = bracket_end + 2;
  } else {
    const size_t colon = authority.rfind(':');
    if (colon == std::string::npos || colon == 0 ||
        authority.find(':') != colon)
      return false;
    port_start = colon + 1;
  }
  if (port_start == authority.size())
    return false;
  unsigned port = 0;
  for (size_t i = port_start; i < authority.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(authority[i]);
    if (ch < '0' || ch > '9')
      return false;
    port = port * 10 + (ch - '0');
    if (port > 65535)
      return false;
  }
  if (port == 0)
    return false;

  for (size_t i = authority_start; i < uri.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(uri[i]);
    if (ch < 0x20 || ch == 0x7f)
      return false;
    if (ch != '%')
      continue;
    if (i + 2 >= uri.size() || !std::isxdigit(static_cast<unsigned char>(uri[i + 1])) ||
        !std::isxdigit(static_cast<unsigned char>(uri[i + 2])))
      return false;
    const auto hex = [](unsigned char digit) {
      return digit <= '9' ? digit - '0'
                          : static_cast<unsigned>(std::tolower(digit) - 'a' + 10);
    };
    const unsigned decoded =
        hex(static_cast<unsigned char>(uri[i + 1])) * 16 +
        hex(static_cast<unsigned char>(uri[i + 2]));
    if (decoded < 0x20 || decoded == 0x7f)
      return false;
    i += 2;
  }
  return true;
}

inline bool isSupportedSchemeName(const std::string &scheme) {
  std::string normalized = normalizeScheme(scheme);
  // The bridge expands the official binary Mieru client configuration into
  // Mihomo's supported mierus:// projection before conversion. Keep this
  // bridge-native scheme outside the generated upstream Mihomo manifest.
  if (normalized == "mieru")
    return true;
  return std::find(SUPPORTED_SCHEMES.begin(), SUPPORTED_SCHEMES.end(),
                   normalized) != SUPPORTED_SCHEMES.end();
}

inline bool isSupportedSchemeLink(const std::string &link) {
  std::string scheme = extractHierarchicalScheme(link);
  return !scheme.empty() && isSupportedSchemeName(scheme);
}

inline bool isSupportedNonHttpSchemeLink(const std::string &link) {
  std::string scheme = extractHierarchicalScheme(link);
  return !scheme.empty() && !isHttpScheme(scheme) &&
         isSupportedSchemeName(scheme);
}

} // namespace mihomo
