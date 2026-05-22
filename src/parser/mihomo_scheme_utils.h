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

inline bool isSupportedSchemeName(const std::string &scheme) {
  std::string normalized = normalizeScheme(scheme);
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
