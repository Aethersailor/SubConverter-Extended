#include <charconv>
#include <cctype>
#include <system_error>

#include "utils/string.h"
#include "utils/system.h"
#include "proxy_policy.h"

namespace {

bool hasControlCharacter(const std::string &value) {
  for (unsigned char character : value) {
    if (std::iscntrl(character))
      return true;
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
  if (endpoint.empty() || hasControlCharacter(endpoint)) {
    error = "proxy URI is empty or contains a control character";
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

} // namespace

ProxyPolicy ProxyPolicy::direct() { return {}; }

ProxyPolicy ProxyPolicy::parse(const std::string &source) {
  const std::string value = trimWhitespace(source, true, true);
  const std::string keyword = toUpper(value);
  if (value.empty() || keyword == "NONE")
    return direct();
  if (keyword == "SYSTEM")
    return {ProxyMode::System, "", true, ""};

  if (startsWith(toLower(value), "cors:")) {
    ProxyPolicy policy {ProxyMode::Cors, value.substr(5), true, ""};
    policy.valid = validProxyEndpoint(policy.endpoint, true, policy.error);
    return policy;
  }

  ProxyPolicy policy {ProxyMode::Explicit, value, true, ""};
  policy.valid = validProxyEndpoint(policy.endpoint, false, policy.error);
  return policy;
}

ProxyPolicy ProxyPolicy::resolved() const {
  ProxyPolicy result = *this;
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

std::string ProxyPolicy::cacheIdentity() const {
  const ProxyPolicy effective = resolved();
  return std::string(proxyModeName(effective.mode)) + "\n" +
         effective.endpoint + "\n" + (effective.valid ? "valid" : "invalid");
}

std::string ProxyPolicy::describe() const {
  const ProxyPolicy effective = resolved();
  std::string description = proxyModeName(effective.mode);
  if (!effective.valid)
    return description + " (invalid)";
  if (!effective.endpoint.empty())
    description += " " + redactEndpoint(effective.endpoint);
  else if (effective.mode == ProxyMode::System)
    description += " (no system proxy configured)";
  return description;
}

ProxyPolicy parseProxy(const std::string &source) {
  return ProxyPolicy::parse(source);
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
