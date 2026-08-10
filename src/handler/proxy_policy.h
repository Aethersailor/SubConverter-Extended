#ifndef PROXY_POLICY_H_INCLUDED
#define PROXY_POLICY_H_INCLUDED

#include <string>
#include <vector>

#include "server/client_ip.h"

// A missing proxy_bypass setting must remain upgrade-compatible while keeping
// loopback and ordinary private networks off the explicit proxy path.
inline constexpr char kDefaultProxyBypass[] = "PRIVATE";

// Keep the user's proxy intent until the request reaches libcurl.  An empty
// string is deliberately Direct, not an implicit request to read curl's
// environment variables.
enum class ProxyMode {
  Direct,
  System,
  Explicit,
  Cors,
};

struct ProxyBypassMatch {
  bool matched = false;
  std::string rule;
};

// A parsed, canonical policy shared by every explicit outbound proxy setting.
// Built-in presets are additive and loopback is always retained as the safe
// compatibility baseline established for issue #89.
struct ProxyBypassPolicy {
  bool valid = true;
  std::string error;

  static ProxyBypassPolicy parse(const std::string &source);
  ProxyBypassMatch matchHost(const std::string &host) const;
  std::string cacheIdentity() const;
  std::string describe() const;

private:
  bool loopback = true;
  bool privateNetworks = false;
  bool linkLocal = false;
  bool localNames = false;
  bool cgnat = false;
  std::vector<client_ip::Cidr> customCidrs;
  std::vector<std::string> customCidrNames;
  std::vector<std::string> customDomains;
};

// An immutable view of the proxy source used by one top-level fetch.  SYSTEM
// is resolved once so cache identity, diagnostics, redirects, and transport
// cannot observe different platform settings during the same request.
struct ResolvedProxyPolicy {
  ProxyMode mode = ProxyMode::Direct;
  std::string endpoint;
  bool valid = true;
  std::string error;
  ProxyBypassPolicy bypass;

  std::string cacheIdentity() const;
  std::string describe() const;
};

struct ProxyPolicy {
  ProxyMode mode = ProxyMode::Direct;
  std::string endpoint;
  bool valid = true;
  std::string error;
  ProxyBypassPolicy bypass;

  static ProxyPolicy direct();
  static ProxyPolicy parse(const std::string &source,
                           const std::string &bypassSource =
                               kDefaultProxyBypass);

  ResolvedProxyPolicy snapshot() const;

  // Resolve the deterministic System source without changing its mode.  The
  // empty endpoint means that the configured system source has no proxy.
  ProxyPolicy resolved() const;

  // Suitable for cache identities, never for logs.  It intentionally retains
  // credentials so two authenticated proxy endpoints cannot share a cache.
  std::string cacheIdentity() const;
  std::string describe() const;
};

// Compatibility name used by the existing settings call sites.  Unlike the
// historical helper it returns a policy, not an ambiguous string.
ProxyPolicy parseProxy(const std::string &source,
                       const std::string &bypassSource = kDefaultProxyBypass);

const char *proxyModeName(ProxyMode mode);

#endif // PROXY_POLICY_H_INCLUDED
