#include "server/client_ip.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

#include "server/socket.h"

namespace client_ip {
namespace {

std::string trim(std::string_view value) {
  std::size_t first = 0;
  while (first < value.size() &&
         std::isspace(static_cast<unsigned char>(value[first])))
    ++first;
  std::size_t last = value.size();
  while (last > first &&
         std::isspace(static_cast<unsigned char>(value[last - 1])))
    --last;
  return std::string(value.substr(first, last - first));
}

std::string lower(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return result;
}

bool isMappedIpv4(const std::array<uint8_t, 16> &bytes) {
  for (std::size_t i = 0; i < 10; ++i) {
    if (bytes[i] != 0)
      return false;
  }
  return bytes[10] == 0xff && bytes[11] == 0xff;
}

bool isTrusted(const Address &address, const Policy &policy) {
  return std::any_of(policy.trusted_proxy_cidrs.begin(),
                     policy.trusted_proxy_cidrs.end(),
                     [&](const Cidr &cidr) { return cidr.contains(address); });
}

bool parsePort(std::string_view value) {
  if (value.empty())
    return false;
  unsigned int port = 0;
  for (char ch : value) {
    if (ch < '0' || ch > '9')
      return false;
    port = port * 10 + static_cast<unsigned int>(ch - '0');
    if (port > 65535)
      return false;
  }
  return port != 0;
}

bool unquote(std::string_view value, std::string &result) {
  if (value.size() < 2 || value.front() != '"' || value.back() != '"') {
    result.assign(value);
    return value.find('"') == std::string_view::npos;
  }
  result.clear();
  for (std::size_t i = 1; i + 1 < value.size(); ++i) {
    char ch = value[i];
    if (ch == '\\') {
      if (++i + 1 >= value.size())
        return false;
      ch = value[i];
    } else if (ch == '"') {
      return false;
    }
    result.push_back(ch);
  }
  return true;
}

bool splitQuoted(std::string_view input, char delimiter,
                 std::vector<std::string> &parts) {
  parts.clear();
  bool quoted = false;
  bool escaped = false;
  std::size_t start = 0;
  for (std::size_t i = 0; i < input.size(); ++i) {
    char ch = input[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && ch == delimiter) {
      parts.emplace_back(trim(input.substr(start, i - start)));
      start = i + 1;
    }
  }
  if (quoted || escaped)
    return false;
  parts.emplace_back(trim(input.substr(start)));
  return true;
}

Address parseForwardedNode(std::string_view raw) {
  std::string value;
  if (!unquote(trim(raw), value) || value.empty() || value[0] == '_' ||
      lower(value) == "unknown")
    return {};

  if (value.front() == '[') {
    const std::size_t close = value.find(']');
    if (close == std::string::npos)
      return {};
    if (close + 1 < value.size() &&
        (value[close + 1] != ':' ||
         !parsePort(std::string_view(value).substr(close + 2))))
      return {};
    return parseAddress(std::string_view(value).substr(1, close - 1));
  }

  Address direct = parseAddress(value);
  if (direct.valid())
    return direct;

  const std::size_t colon = value.rfind(':');
  if (colon == std::string::npos || value.find(':') != colon ||
      !parsePort(std::string_view(value).substr(colon + 1)))
    return {};
  return parseAddress(std::string_view(value).substr(0, colon));
}

bool parseForwarded(std::string_view value, std::vector<Address> &addresses) {
  std::vector<std::string> elements;
  if (!splitQuoted(value, ',', elements) || elements.empty() ||
      elements.size() > kMaxForwardedHops)
    return false;

  addresses.clear();
  for (const std::string &element : elements) {
    if (element.empty())
      return false;
    std::vector<std::string> parameters;
    if (!splitQuoted(element, ';', parameters))
      return false;
    Address address;
    bool found = false;
    for (const std::string &parameter : parameters) {
      const std::size_t equal = parameter.find('=');
      if (equal == std::string::npos)
        return false;
      if (lower(trim(std::string_view(parameter).substr(0, equal))) != "for")
        continue;
      if (found)
        return false;
      address = parseForwardedNode(
          std::string_view(parameter).substr(equal + 1));
      if (!address.valid())
        return false;
      found = true;
    }
    if (!found)
      return false;
    addresses.push_back(address);
  }
  return true;
}

bool parseXForwardedFor(std::string_view value,
                        std::vector<Address> &addresses) {
  addresses.clear();
  std::size_t start = 0;
  while (start <= value.size()) {
    const std::size_t comma = value.find(',', start);
    const std::size_t end =
        comma == std::string_view::npos ? value.size() : comma;
    Address address = parseAddress(value.substr(start, end - start));
    if (!address.valid())
      return false;
    addresses.push_back(address);
    if (addresses.size() > kMaxForwardedHops)
      return false;
    if (comma == std::string_view::npos)
      break;
    start = comma + 1;
  }
  return !addresses.empty();
}

} // namespace

std::size_t AddressHash::operator()(const Address &address) const noexcept {
  std::size_t result = static_cast<std::size_t>(address.family);
  for (uint8_t byte : address.bytes)
    result = (result * 131) ^ byte;
  return result;
}

Address parseAddress(std::string_view raw) {
  const std::string value = trim(raw);
  if (value.empty() || value.size() > 45 || value.find('%') != std::string::npos)
    return {};

  Address result;
  in_addr ipv4{};
  if (inet_pton(AF_INET, value.c_str(), &ipv4) == 1) {
    result.family = Family::IPv4;
    std::memcpy(result.bytes.data(), &ipv4, 4);
    return result;
  }

  in6_addr ipv6{};
  if (inet_pton(AF_INET6, value.c_str(), &ipv6) != 1)
    return {};
  std::memcpy(result.bytes.data(), &ipv6, 16);
  if (isMappedIpv4(result.bytes)) {
    std::array<uint8_t, 16> mapped{};
    std::copy(result.bytes.begin() + 12, result.bytes.end(), mapped.begin());
    result.family = Family::IPv4;
    result.bytes = mapped;
  } else {
    result.family = Family::IPv6;
  }
  return result;
}

std::string toString(const Address &address) {
  char buffer[INET6_ADDRSTRLEN]{};
  if (address.family == Family::IPv4) {
    return inet_ntop(AF_INET, address.bytes.data(), buffer, sizeof(buffer))
               ? std::string(buffer)
               : std::string();
  }
  if (address.family == Family::IPv6) {
    return inet_ntop(AF_INET6, address.bytes.data(), buffer, sizeof(buffer))
               ? std::string(buffer)
               : std::string();
  }
  return "unknown";
}

bool Cidr::contains(const Address &address) const {
  if (!address.valid() || address.family != network.family)
    return false;
  const std::size_t bits = prefix_length;
  const std::size_t full_bytes = bits / 8;
  const uint8_t remaining = static_cast<uint8_t>(bits % 8);
  if (!std::equal(network.bytes.begin(), network.bytes.begin() + full_bytes,
                  address.bytes.begin()))
    return false;
  if (!remaining)
    return true;
  const uint8_t mask = static_cast<uint8_t>(0xff << (8 - remaining));
  return (network.bytes[full_bytes] & mask) ==
         (address.bytes[full_bytes] & mask);
}

Cidr parseCidr(std::string_view raw) {
  const std::string value = trim(raw);
  const std::size_t slash = value.find('/');
  if (slash == std::string::npos ||
      value.find('/', slash + 1) != std::string::npos)
    throw std::invalid_argument("trusted proxy must use CIDR notation: " + value);
  Cidr result;
  result.network = parseAddress(std::string_view(value).substr(0, slash));
  if (!result.network.valid())
    throw std::invalid_argument("invalid trusted proxy address: " + value);
  const std::string prefix = value.substr(slash + 1);
  if (prefix.empty() ||
      !std::all_of(prefix.begin(), prefix.end(),
                   [](unsigned char ch) { return std::isdigit(ch); }))
    throw std::invalid_argument("invalid trusted proxy prefix: " + value);
  unsigned int bits = 0;
  for (char ch : prefix) {
    bits = bits * 10 + static_cast<unsigned int>(ch - '0');
    if (bits > 128)
      break;
  }
  const unsigned int maximum =
      result.network.family == Family::IPv4 ? 32 : 128;
  if (bits == 0 || bits > maximum)
    throw std::invalid_argument(
        "trusted proxy CIDR must not be /0 and must fit its address family: " +
        value);
  result.prefix_length = static_cast<uint8_t>(bits);
  const std::size_t full_bytes = bits / 8;
  const uint8_t remaining = static_cast<uint8_t>(bits % 8);
  if (remaining) {
    result.network.bytes[full_bytes] &=
        static_cast<uint8_t>(0xff << (8 - remaining));
  }
  const std::size_t byte_count =
      result.network.family == Family::IPv4 ? 4 : 16;
  const std::size_t clear_from = full_bytes + (remaining ? 1 : 0);
  std::fill(result.network.bytes.begin() + clear_from,
            result.network.bytes.begin() + byte_count, 0);
  return result;
}

Header parseHeader(std::string_view raw) {
  const std::string value = lower(trim(raw));
  if (value.empty() || value == "none")
    return Header::None;
  if (value == "x-forwarded-for")
    return Header::XForwardedFor;
  if (value == "forwarded")
    return Header::Forwarded;
  if (value == "x-real-ip")
    return Header::XRealIp;
  if (value == "cf-connecting-ip")
    return Header::CfConnectingIp;
  if (value == "true-client-ip")
    return Header::TrueClientIp;
  throw std::invalid_argument("unsupported dashboard client IP header: " + value);
}

const char *headerName(Header header) {
  switch (header) {
  case Header::XForwardedFor:
    return "X-Forwarded-For";
  case Header::Forwarded:
    return "Forwarded";
  case Header::XRealIp:
    return "X-Real-IP";
  case Header::CfConnectingIp:
    return "CF-Connecting-IP";
  case Header::TrueClientIp:
    return "True-Client-IP";
  case Header::None:
  default:
    return "";
  }
}

const char *headerSettingName(Header header) {
  switch (header) {
  case Header::XForwardedFor:
    return "x-forwarded-for";
  case Header::Forwarded:
    return "forwarded";
  case Header::XRealIp:
    return "x-real-ip";
  case Header::CfConnectingIp:
    return "cf-connecting-ip";
  case Header::TrueClientIp:
    return "true-client-ip";
  case Header::None:
  default:
    return "none";
  }
}

Policy makePolicy(std::string_view header,
                  const std::vector<std::string> &trusted_proxy_cidrs) {
  if (trusted_proxy_cidrs.size() > kMaxTrustedProxyCidrs)
    throw std::invalid_argument("too many dashboard trusted proxy CIDRs");
  Policy result;
  result.header = parseHeader(header);
  result.trusted_proxy_cidrs.reserve(trusted_proxy_cidrs.size());
  for (const std::string &cidr : trusted_proxy_cidrs)
    result.trusted_proxy_cidrs.push_back(parseCidr(cidr));
  if (result.header == Header::None || result.trusted_proxy_cidrs.empty()) {
    result.header = Header::None;
    result.trusted_proxy_cidrs.clear();
  }
  return result;
}

Resolution resolve(const Address &peer,
                   const std::vector<std::string> &selected_header_values,
                   const Policy &policy) {
  Resolution fallback{peer, false};
  if (!peer.valid() || !policy.enabled() || !isTrusted(peer, policy))
    return fallback;
  if (selected_header_values.size() != 1 ||
      selected_header_values.front().size() > kMaxSelectedHeaderBytes)
    return fallback;

  std::vector<Address> chain;
  bool valid = false;
  if (policy.header == Header::XForwardedFor) {
    valid = parseXForwardedFor(selected_header_values.front(), chain);
  } else if (policy.header == Header::Forwarded) {
    valid = parseForwarded(selected_header_values.front(), chain);
  } else {
    Address address = parseAddress(selected_header_values.front());
    if (address.valid()) {
      chain.push_back(address);
      valid = true;
    }
  }
  if (!valid)
    return fallback;

  if (policy.header == Header::XForwardedFor ||
      policy.header == Header::Forwarded) {
    for (auto iter = chain.rbegin(); iter != chain.rend(); ++iter) {
      if (!isTrusted(*iter, policy))
        return {*iter, true};
    }
    return fallback;
  }
  return {chain.front(), true};
}

} // namespace client_ip
