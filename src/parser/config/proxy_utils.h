#ifndef PROXY_UTILS_H_INCLUDED
#define PROXY_UTILS_H_INCLUDED

#include "proxy.h"
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>


inline ProxyType getProxyTypeFromString(const std::string &typeStr) {
  static const std::vector<ProxyType> all_types = {
      ProxyType::Shadowsocks, ProxyType::ShadowsocksR, ProxyType::VMess,
      ProxyType::Trojan,      ProxyType::Snell,        ProxyType::HTTP,
      ProxyType::HTTPS,       ProxyType::SOCKS5,       ProxyType::WireGuard,
      ProxyType::VLESS,       ProxyType::Hysteria,     ProxyType::Hysteria2,
      ProxyType::TUIC,        ProxyType::AnyTLS,       ProxyType::Naive,
      ProxyType::Mieru};

  std::string lowerTypeStr = typeStr;
  std::transform(lowerTypeStr.begin(), lowerTypeStr.end(), lowerTypeStr.begin(),
                 ::tolower);

  for (const auto &type : all_types) {
    std::string typeName = getProxyTypeName(type);
    std::string lowerTypeName = typeName;
    std::transform(lowerTypeName.begin(), lowerTypeName.end(),
                   lowerTypeName.begin(), ::tolower);

    if (lowerTypeStr == lowerTypeName) {
      return type;
    }
  }

  return ProxyType::Unknown;
}

#endif // PROXY_UTILS_H_INCLUDED
