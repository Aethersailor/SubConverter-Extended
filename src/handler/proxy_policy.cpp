#include <algorithm>
#include <charconv>
#include <cctype>
#include <stdexcept>
#include <system_error>

#include "utils/string.h"
#include "utils/system.h"
#include "proxy_policy.h"

namespace {

constexpr size_t kMaxProxyBypassCustomRules = 64;

bool hasControlCharacter(const std::string &value) {
  for (unsigned char character : value) {
    if (std::iscntrl(character))
      return true;
  }
  return false;
}

int hexDigitValue(unsigned char character) {
  if (character >= '0' && character <= '9')
    return character - '0';
  character = static_cast<unsigned char>(std::tolower(character));
  return character >= 'a' && character <= 'f' ? character - 'a' + 10 : -1;
}

bool hasUnsafePercentEncoding(const std::string &value) {
  for (size_t index = 0; index < value.size(); ++index) {
    if (value[index] != '%')
      continue;
    if (index + 2 >= value.size())
      return true;
    const int high = hexDigitValue(value[index + 1]);
    const int low = hexDigitValue(value[index + 2]);
    if (high < 0 || low < 0)
      return true;
    const int decoded = (high << 4) | low;
    if (decoded < 0x20 || decoded == 0x7f)
      return true;
    index += 2;
  }
  return false;
}

bool validPort(const std::string &port) {
  if (port.empty())
    return false;

  unsigned int value = 0;
  const auto [end, error] =
      std::from_chars(port.data(), port.data() + port.size(), value);
  return error == std::errc() && end == port.data() + port.size() &&
         value > 0 && value <= 65535;
}

bool validProxyEndpoint(const std::string &endpoint, bool cors,
                        std::string &error) {
  if (endpoint.empty() || hasControlCharacter(endpoint) ||
      hasUnsafePercentEncoding(endpoint)) {
    error = "proxy URI is empty or contains unsafe encoding";
    return false;
  }

  const std::string::size_type scheme_end = endpoint.find("://");
  if (scheme_end == std::string::npos || scheme_end == 0) {
    error = "proxy URI must include a scheme";
    return false;
  }

  const std::string scheme = toLower(endpoint.substr(0, scheme_end));
  const bool supported =
      cors ? (scheme == "http" || scheme == "https")
           : (scheme == "http" || scheme == "https" ||
              scheme == "socks4" || scheme == "socks4a" ||
              scheme == "socks5" || scheme == "socks5h");
  if (!supported) {
    error = cors ? "CORS endpoint must use http or https"
                 : "unsupported proxy URI scheme";
    return false;
  }

  const std::string authority_and_path = endpoint.substr(scheme_end + 3);
  const std::string::size_type authority_end =
      authority_and_path.find_first_of("/?#");
  std::string authority = authority_and_path.substr(0, authority_end);
  const std::string::size_type at = authority.rfind('@');
  if (at != std::string::npos)
    authority.erase(0, at + 1);
  if (authority.empty()) {
    error = "proxy URI is missing a host";
    return false;
  }

  std::string port;
  bool has_explicit_port = false;
  if (authority.front() == '[') {
    const std::string::size_type close = authority.find(']');
    if (close == std::string::npos) {
      error = "proxy URI has an invalid IPv6 host";
      return false;
    }
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') {
        error = "proxy URI has an invalid IPv6 host and port";
        return false;
      }
      port = authority.substr(close + 2);
      has_explicit_port = true;
    }
  } else {
    const std::string::size_type colon = authority.rfind(':');
    if (colon == 0) {
      error = "proxy URI is missing a host";
      return false;
    }
    if (colon != std::string::npos) {
      port = authority.substr(colon + 1);
      has_explicit_port = true;
    }
  }

  // Historical cors: examples use standard HTTP(S) ports implicitly. Keep
  // that compatibility, while ordinary libcurl proxies require a port.
  if (cors && !has_explicit_port)
    return true;
  if (!has_explicit_port || !validPort(port)) {
    error = "proxy URI has an invalid port";
    return false;
  }
  return true;
}

std::string redactEndpoint(const std::string &endpoint) {
  const std::string::size_type scheme_end = endpoint.find("://");
  if (scheme_end == std::string::npos)
    return "<invalid>";

  const std::string::size_type authority_start = scheme_end + 3;
  const std::string::size_type authority_end =
      endpoint.find_first_of("/?#", authority_start);
  const std::string authority = endpoint.substr(
      authority_start, authority_end == std::string::npos
                           ? std::string::npos
                           : authority_end - authority_start);
  const std::string::size_type at = authority.rfind('@');
  const std::string host_port =
      at == std::string::npos ? authority : authority.substr(at + 1);
  return endpoint.substr(0, scheme_end + 3) + host_port;
}

std::string normalizeSystemEndpoint(std::string endpoint) {
  // Windows ProxyServer can be either a single host:port value or a
  // semicolon-separated protocol map such as "http=...;https=...".  Libcurl
  // needs one concrete proxy URI for the request.
  if (endpoint.find("=") != std::string::npos) {
    string_array entries = split(endpoint, ";");
    std::string fallback;
    for (const std::string &entry : entries) {
      const std::string::size_type separator = entry.find('=');
      if (separator == std::string::npos)
        continue;
      const std::string scheme =
          toLower(trimWhitespace(entry.substr(0, separator), true, true));
      const std::string value =
          trimWhitespace(entry.substr(separator + 1), true, true);
      if (value.empty())
        continue;
      if (scheme == "https" || scheme == "http")
        return value.find("://") == std::string::npos ? "http://" + value
                                                        : value;
      if (fallback.empty())
        fallback = value;
    }
    endpoint = fallback;
  }
  if (!endpoint.empty() && endpoint.find("://") == std::string::npos)
    endpoint = "http://" + endpoint;
  return endpoint;
}

bool matchesDomain(const std::string &host, const std::string &domain) {
  return host == domain ||
         (host.size() > domain.size() &&
          host.compare(host.size() - domain.size(), domain.size(), domain) ==
              0 &&
          host[host.size() - domain.size() - 1] == '.');
}

bool validBypassDomain(const std::string &domain) {
  if (domain.empty() || domain.size() > 253 || domain.front() == '.' ||
      domain.back() == '.' ||
      domain.find('*') != std::string::npos)
    return false;
  size_t label_start = 0;
  while (label_start < domain.size()) {
    const size_t label_end = domain.find('.', label_start);
    const size_t length =
        (label_end == std::string::npos ? domain.size() : label_end) -
        label_start;
    if (length == 0 || length > 63 || domain[label_start] == '-' ||
        domain[label_start + length - 1] == '-')
      return false;
    for (size_t index = label_start; index < label_start + length; ++index) {
      const unsigned char character = domain[index];
      const bool ascii_letter =
          (character >= 'a' && character <= 'z') ||
          (character >= 'A' && character <= 'Z');
      const bool digit = character >= '0' && character <= '9';
      if (!ascii_letter && !digit && character != '-')
        return false;
    }
    if (label_end == std::string::npos)
      break;
    label_start = label_end + 1;
  }
  return true;
}

std::string normalizeBypassDomain(std::string value) {
  value = toLower(trimWhitespace(value, true, true));
  if (!value.empty() && value.front() == '.')
    value.erase(value.begin());
  if (!value.empty() && value.back() == '.')
    value.pop_back();
  return value;
}

bool isLoopback(const client_ip::Address &address) {
  if (address.family == client_ip::Family::IPv4)
    return address.bytes[0] == 127;
  if (address.family != client_ip::Family::IPv6 || address.bytes[15] != 1)
    return false;
  return std::all_of(address.bytes.begin(), address.bytes.begin() + 15,
                     [](uint8_t byte) { return byte == 0; });
}

bool isPrivate(const client_ip::Address &address) {
  if (address.family == client_ip::Family::IPv4) {
    return address.bytes[0] == 10 ||
           (address.bytes[0] == 172 && address.bytes[1] >= 16 &&
            address.bytes[1] <= 31) ||
           (address.bytes[0] == 192 && address.bytes[1] == 168);
  }
  return address.family == client_ip::Family::IPv6 &&
         (address.bytes[0] & 0xfe) == 0xfc;
}

bool isLinkLocal(const client_ip::Address &address) {
  if (address.family == client_ip::Family::IPv4)
    return address.bytes[0] == 169 && address.bytes[1] == 254;
  return address.family == client_ip::Family::IPv6 &&
         address.bytes[0] == 0xfe && (address.bytes[1] & 0xc0) == 0x80;
}

bool isCgnat(const client_ip::Address &address) {
  return address.family == client_ip::Family::IPv4 &&
         address.bytes[0] == 100 && address.bytes[1] >= 64 &&
         address.bytes[1] <= 127;
}

std::string canonicalCidrName(const client_ip::Cidr &cidr) {
  return client_ip::toString(cidr.network) + "/" +
         std::to_string(static_cast<unsigned int>(cidr.prefix_length));
}

void sortUnique(std::vector<std::string> &values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

} // namespace

ProxyBypassPolicy ProxyBypassPolicy::parse(const std::string &source) {
  ProxyBypassPolicy policy;
  const std::string value = trimWhitespace(source, true, true);
  if (value.empty())
    return policy;

  size_t start = 0;
  size_t custom_rule_count = 0;
  while (start <= value.size()) {
    const size_t comma = value.find(',', start);
    const std::string token = trimWhitespace(
        value.substr(start, comma == std::string::npos
                                ? std::string::npos
                                : comma - start),
        true, true);
    if (token.empty()) {
      policy.valid = false;
      policy.error = "proxy_bypass contains an empty rule";
      return policy;
    }

    const std::string keyword = toUpper(token);
    if (keyword == "LOOPBACK") {
      // Loopback is always enabled, so this token is intentionally idempotent.
    } else if (keyword == "PRIVATE") {
      policy.privateNetworks = true;
    } else if (keyword == "LAN") {
      policy.privateNetworks = true;
      policy.linkLocal = true;
      policy.localNames = true;
    } else if (keyword == "CGNAT") {
      policy.cgnat = true;
    } else if (startsWith(keyword, "CIDR:")) {
      if (++custom_rule_count > kMaxProxyBypassCustomRules) {
        policy.valid = false;
        policy.error = "proxy_bypass exceeds 64 custom rules";
        return policy;
      }
      const std::string raw_cidr =
          trimWhitespace(token.substr(5), true, true);
      try {
        const client_ip::Cidr cidr = client_ip::parseCidr(raw_cidr);
        policy.customCidrs.push_back(cidr);
        policy.customCidrNames.push_back(canonicalCidrName(cidr));
      } catch (const std::invalid_argument &) {
        policy.valid = false;
        policy.error = "proxy_bypass has an invalid CIDR rule";
        return policy;
      }
    } else if (startsWith(keyword, "DOMAIN:")) {
      if (++custom_rule_count > kMaxProxyBypassCustomRules) {
        policy.valid = false;
        policy.error = "proxy_bypass exceeds 64 custom rules";
        return policy;
      }
      const std::string domain = normalizeBypassDomain(token.substr(7));
      if (!validBypassDomain(domain)) {
        policy.valid = false;
        policy.error = "proxy_bypass has an invalid DOMAIN rule";
        return policy;
      }
      policy.customDomains.push_back(domain);
    } else {
      policy.valid = false;
      policy.error = "proxy_bypass has an unsupported rule";
      return policy;
    }

    if (comma == std::string::npos)
      break;
    start = comma + 1;
  }

  sortUnique(policy.customCidrNames);
  sortUnique(policy.customDomains);
  policy.customCidrs.clear();
  for (const std::string &cidr : policy.customCidrNames)
    policy.customCidrs.push_back(client_ip::parseCidr(cidr));
  return policy;
}

ProxyBypassMatch ProxyBypassPolicy::matchHost(const std::string &raw_host) const {
  if (!valid)
    return {};
  std::string host = toLower(trimWhitespace(raw_host, true, true));
  if (host.size() > 1 && host.back() == '.' &&
      host[host.size() - 2] != '.')
    host.pop_back();

  // CURLOPT_NOPROXY is a comma-separated grammar. Only a validated DNS name
  // may reach a hostname pattern; URL reg-name punctuation must not become a
  // second, unintended bypass entry.
  if (validBypassDomain(host)) {
    if (loopback &&
        (host == "localhost" || matchesDomain(host, "localhost")))
      return {true, "LOOPBACK"};
    if (localNames &&
        (matchesDomain(host, "local") || matchesDomain(host, "home.arpa")))
      return {true, "LAN"};
    for (const std::string &domain : customDomains) {
      if (matchesDomain(host, domain))
        return {true, "DOMAIN"};
    }
  }

  const client_ip::Address address = client_ip::parseAddress(host);
  if (!address.valid())
    return {};
  if (loopback && isLoopback(address))
    return {true, "LOOPBACK"};
  if (privateNetworks && isPrivate(address))
    return {true, "PRIVATE"};
  if (linkLocal && isLinkLocal(address))
    return {true, "LAN"};
  if (cgnat && isCgnat(address))
    return {true, "CGNAT"};
  for (size_t index = 0; index < customCidrs.size(); ++index) {
    if (customCidrs[index].contains(address))
      return {true, "CIDR"};
  }
  return {};
}

std::string ProxyBypassPolicy::cacheIdentity() const {
  std::string identity = valid ? "valid" : "invalid:" + error;
  identity += "\nloopback=1\nprivate=" +
              std::string(privateNetworks ? "1" : "0") +
              "\nlinklocal=" + std::string(linkLocal ? "1" : "0") +
              "\nlocalnames=" + std::string(localNames ? "1" : "0") +
              "\ncgnat=" + std::string(cgnat ? "1" : "0");
  for (const std::string &cidr : customCidrNames)
    identity += "\ncidr=" + cidr;
  for (const std::string &domain : customDomains)
    identity += "\ndomain=" + domain;
  return identity;
}

std::string ProxyBypassPolicy::describe() const {
  if (!valid)
    return "invalid";
  std::string description = "LOOPBACK";
  if (privateNetworks && linkLocal && localNames)
    description += ",LAN";
  else if (privateNetworks)
    description += ",PRIVATE";
  if (cgnat)
    description += ",CGNAT";
  if (!customCidrs.empty())
    description += ",CIDR(" + std::to_string(customCidrs.size()) + ")";
  if (!customDomains.empty())
    description += ",DOMAIN(" + std::to_string(customDomains.size()) + ")";
  return description;
}

ProxyPolicy ProxyPolicy::direct() { return {}; }

ProxyPolicy ProxyPolicy::parse(const std::string &source,
                               const std::string &bypassSource) {
  const ProxyBypassPolicy bypass = ProxyBypassPolicy::parse(bypassSource);
  const std::string value = trimWhitespace(source, true, true);
  const std::string keyword = toUpper(value);
  ProxyPolicy policy;
  policy.bypass = bypass;
  if (!bypass.valid) {
    policy.valid = false;
    policy.error = bypass.error;
  }
  if (value.empty() || keyword == "NONE")
    return policy;
  if (keyword == "SYSTEM") {
    policy.mode = ProxyMode::System;
    return policy;
  }

  if (startsWith(toLower(value), "cors:")) {
    policy.mode = ProxyMode::Cors;
    policy.endpoint = value.substr(5);
    std::string endpoint_error;
    const bool endpoint_valid =
        validProxyEndpoint(policy.endpoint, true, endpoint_error);
    if (!endpoint_valid) {
      policy.valid = false;
      policy.error = endpoint_error;
    }
    return policy;
  }

  policy.mode = ProxyMode::Explicit;
  policy.endpoint = value;
  std::string endpoint_error;
  const bool endpoint_valid =
      validProxyEndpoint(policy.endpoint, false, endpoint_error);
  if (!endpoint_valid) {
    policy.valid = false;
    policy.error = endpoint_error;
  }
  return policy;
}

ResolvedProxyPolicy ProxyPolicy::snapshot() const {
  ResolvedProxyPolicy result {mode, endpoint, valid, error, bypass};
  if (result.mode != ProxyMode::System)
    return result;

  result.endpoint = normalizeSystemEndpoint(
      trimWhitespace(getSystemProxy(), true, true));
  if (result.endpoint.empty())
    return result;

  std::string validation_error;
  if (!validProxyEndpoint(result.endpoint, false, validation_error)) {
    result.valid = false;
    result.error = "system proxy is invalid: " + validation_error;
  }
  return result;
}

ProxyPolicy ProxyPolicy::resolved() const {
  const ResolvedProxyPolicy effective = snapshot();
  return {effective.mode, effective.endpoint, effective.valid, effective.error,
          effective.bypass};
}

std::string ResolvedProxyPolicy::cacheIdentity() const {
  return std::string(proxyModeName(mode)) + "\n" + endpoint + "\n" +
         (valid ? "valid" : "invalid") + "\nbypass=" +
         bypass.cacheIdentity();
}

std::string ResolvedProxyPolicy::describe() const {
  std::string description = proxyModeName(mode);
  if (!valid)
    return description + " (invalid)";
  if (!endpoint.empty())
    description += " " + redactEndpoint(endpoint);
  else if (mode == ProxyMode::System)
    description += " (no system proxy configured)";
  return description;
}

std::string ProxyPolicy::cacheIdentity() const {
  return snapshot().cacheIdentity();
}

std::string ProxyPolicy::describe() const { return snapshot().describe(); }

ProxyPolicy parseProxy(const std::string &source,
                       const std::string &bypassSource) {
  return ProxyPolicy::parse(source, bypassSource);
}

const char *proxyModeName(ProxyMode mode) {
  switch (mode) {
  case ProxyMode::Direct:
    return "Direct";
  case ProxyMode::System:
    return "System";
  case ProxyMode::Explicit:
    return "Explicit";
  case ProxyMode::Cors:
    return "Cors";
  }
  return "Unknown";
}
