#include <cassert>
#include <string>

#include "handler/proxy_policy.h"
#include "utils/redact.h"

int main() {
  assert(parseProxy("").mode == ProxyMode::Direct);
  assert(parseProxy("  NONE  ").mode == ProxyMode::Direct);
  assert(parseProxy("none").mode == ProxyMode::Direct);
  assert(parseProxy(" system ").mode == ProxyMode::System);

  const ProxyPolicy socks5h =
      parseProxy("socks5h://proxy.example.test:1080");
  assert(socks5h.mode == ProxyMode::Explicit && socks5h.valid);
  assert(socks5h.describe() == "Explicit socks5h://proxy.example.test:1080");

  const ProxyPolicy authenticated =
      parseProxy("socks5h://user:secret@proxy.example.test:1080");
  assert(authenticated.valid);
  assert(authenticated.describe().find("secret") == std::string::npos);
  assert(authenticated.describe().find("user") == std::string::npos);

  const ProxyPolicy cors = parseProxy("cors:https://cors.example.test:8443/");
  assert(cors.mode == ProxyMode::Cors && cors.valid);
  assert(parseProxy("cors:https://cors.example.test/").valid);
  assert(!parseProxy("proxy.example.test:1080").valid);
  assert(!parseProxy("socks5://proxy.example.test").valid);
  assert(!parseProxy("ftp://proxy.example.test:21").valid);

  const ProxyPolicy direct = parseProxy("NONE");
  const ProxyPolicy system = parseProxy("SYSTEM");
  const ProxyPolicy explicit_one = parseProxy("socks5://one.example.test:1080");
  const ProxyPolicy explicit_two = parseProxy("socks5://two.example.test:1080");
  assert(direct.cacheIdentity() != system.cacheIdentity());
  assert(explicit_one.cacheIdentity() != explicit_two.cacheIdentity());
  assert(direct.cacheIdentity() != explicit_one.cacheIdentity());

  const std::string redacted = redactSensitiveLogText(
      "CURL 请求头：> Authorization: Bearer private-token\n"
      "proxy=socks5h://user:secret@proxy.example.test:1080 "
      "url=https://example.test/sub?token=private-key");
  assert(redacted.find("private-token") == std::string::npos);
  assert(redacted.find("user:secret") == std::string::npos);
  assert(redacted.find("private-key") == std::string::npos);

  const std::string credential_url = redactSensitiveLogText(
      "proxy=socks5h://fixture-user:fixture-password@proxy.example.test:1080");
  assert(credential_url.find("fixture-user") == std::string::npos);
  assert(credential_url.find("fixture-password") == std::string::npos);
  assert(credential_url.find("proxy.example.test:1080") != std::string::npos);

  const std::string query_url = redactSensitiveLogText(
      "url=https://example.test/sub?token=fixture-token&mode=clash&api_key="
      "fixture-api-key");
  assert(query_url.find("fixture-token") == std::string::npos);
  assert(query_url.find("fixture-api-key") == std::string::npos);
  assert(query_url.find("mode=clash") != std::string::npos);

  const std::string header = redactSensitiveLogText(
      "Proxy-Authorization: Basic fixture-proxy-secret");
  assert(header.find("fixture-proxy-secret") == std::string::npos);
  return 0;
}
