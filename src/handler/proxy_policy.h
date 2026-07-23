#ifndef PROXY_POLICY_H_INCLUDED
#define PROXY_POLICY_H_INCLUDED

#include <string>

// Keep the user's proxy intent until the request reaches libcurl.  An empty
// string is deliberately Direct, not an implicit request to read curl's
// environment variables.
enum class ProxyMode {
  Direct,
  System,
  Explicit,
  Cors,
};

struct ProxyPolicy {
  ProxyMode mode = ProxyMode::Direct;
  std::string endpoint;
  bool valid = true;
  std::string error;

  static ProxyPolicy direct();
  static ProxyPolicy parse(const std::string &source);

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
ProxyPolicy parseProxy(const std::string &source);

const char *proxyModeName(ProxyMode mode);

#endif // PROXY_POLICY_H_INCLUDED
