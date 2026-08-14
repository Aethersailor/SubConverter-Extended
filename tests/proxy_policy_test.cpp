#ifdef NDEBUG
#undef NDEBUG
#endif
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
  const ResolvedProxyPolicy authenticated_snapshot = authenticated.snapshot();
  assert(authenticated_snapshot.mode == ProxyMode::Explicit);
  assert(authenticated_snapshot.describe().find("secret") ==
         std::string::npos);
  assert(authenticated_snapshot.cacheIdentity().find("secret") !=
         std::string::npos);

  const ProxyPolicy cors = parseProxy("cors:https://cors.example.test:8443/");
  assert(cors.mode == ProxyMode::Cors && cors.valid);
  assert(parseProxy("cors:https://cors.example.test/").valid);
  assert(parseProxy("http://user%27tail:secret@proxy.example.test:8080")
             .valid);
  assert(!parseProxy(
              "http://user%0D%0Atail:secret@proxy.example.test:8080")
              .valid);
  assert(!parseProxy("http://user%0Gtail:secret@proxy.example.test:8080")
              .valid);
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
  assert(explicit_one.bypass.describe() == "LOOPBACK,PRIVATE");
  assert(explicit_one.bypass.matchHost("127.0.0.1").matched);
  assert(explicit_one.bypass.matchHost("10.0.0.1").matched);
  assert(explicit_one.bypass.matchHost("172.31.255.255").matched);
  assert(explicit_one.bypass.matchHost("192.168.255.255").matched);
  assert(explicit_one.bypass.matchHost("fd12:3456::1").matched);

  const ProxyPolicy explicit_loopback =
      parseProxy("socks5://loopback.example.test:1080", "LOOPBACK");
  assert(explicit_loopback.bypass.describe() == "LOOPBACK");
  assert(!explicit_loopback.bypass.matchHost("192.168.1.1").matched);

  const ProxyBypassPolicy loopback = ProxyBypassPolicy::parse("LOOPBACK");
  assert(loopback.valid);
  assert(loopback.cacheIdentity() ==
         ProxyBypassPolicy::parse("").cacheIdentity());
  assert(loopback.matchHost("localhost").matched);
  assert(loopback.matchHost("api.localhost.").matched);
  assert(!loopback.matchHost("localhost..").matched);
  assert(loopback.matchHost("127.31.2.9").matched);
  assert(loopback.matchHost("::1").matched);
  assert(loopback.matchHost("::ffff:127.0.0.1").matched);
  assert(!loopback.matchHost("192.168.1.1").matched);
  assert(!loopback.matchHost("printer.local").matched);

  const ProxyBypassPolicy private_policy =
      ProxyBypassPolicy::parse("PRIVATE");
  assert(private_policy.valid);
  assert(private_policy.matchHost("10.255.1.2").matched);
  assert(private_policy.matchHost("172.16.0.1").matched);
  assert(private_policy.matchHost("172.31.255.255").matched);
  assert(!private_policy.matchHost("172.32.0.1").matched);
  assert(private_policy.matchHost("192.168.200.1").matched);
  assert(!private_policy.matchHost("192.169.0.1").matched);
  assert(private_policy.matchHost("fd12:3456::1").matched);
  assert(!private_policy.matchHost("fbff::1").matched);
  assert(!private_policy.matchHost("169.254.1.1").matched);

  const ProxyBypassPolicy lan = ProxyBypassPolicy::parse("LAN,CGNAT");
  assert(lan.valid);
  assert(lan.matchHost("169.254.20.1").matched);
  assert(lan.matchHost("fe80::1").matched);
  assert(lan.matchHost("printer.local").matched);
  assert(lan.matchHost("router.home.arpa").matched);
  assert(!lan.matchHost("printer.evillocal").matched);
  assert(!lan.matchHost("router.evilhome.arpa").matched);
  assert(!lan.matchHost("evil,.local").matched);
  assert(lan.matchHost("100.64.0.1").matched);
  assert(lan.matchHost("100.127.255.254").matched);
  assert(!lan.matchHost("100.63.255.255").matched);
  assert(!lan.matchHost("100.128.0.1").matched);
  assert(!lan.matchHost("198.18.0.1").matched);

  const ProxyBypassPolicy custom = ProxyBypassPolicy::parse(
      "DOMAIN:Corp.Example.,CIDR:10.200.23.7/16,CIDR:fd42::9/48");
  assert(custom.valid);
  assert(custom.matchHost("corp.example").matched);
  assert(custom.matchHost("api.corp.example").matched);
  assert(!custom.matchHost("notcorp.example").matched);
  assert(custom.matchHost("10.200.255.1").matched);
  assert(!custom.matchHost("10.201.0.1").matched);
  assert(custom.matchHost("fd42::abcd").matched);
  assert(custom.cacheIdentity().find("10.200.0.0/16") != std::string::npos);
  assert(custom.cacheIdentity().find("fd42::/48") != std::string::npos);
  const ProxyBypassPolicy custom_reordered = ProxyBypassPolicy::parse(
      "CIDR:fd42::/48,DOMAIN:corp.example,CIDR:10.200.0.0/16");
  assert(custom.cacheIdentity() == custom_reordered.cacheIdentity());

  assert(!ProxyBypassPolicy::parse("LAN,").valid);
  assert(!ProxyBypassPolicy::parse("ALL").valid);
  assert(!ProxyBypassPolicy::parse("CIDR:0.0.0.0/0").valid);
  assert(!ProxyBypassPolicy::parse("CIDR:10.0.0.1").valid);
  assert(!ProxyBypassPolicy::parse("DOMAIN:*.example.test").valid);
  assert(!ProxyBypassPolicy::parse("DOMAIN:-bad.example").valid);
  assert(!ProxyBypassPolicy::parse("DOMAIN:bad_name.example").valid);
  assert(!ProxyBypassPolicy::parse("DOMAIN:..example.test").valid);
  assert(!ProxyBypassPolicy::parse("DOMAIN:example.test..").valid);

  const ProxyPolicy explicit_lan =
      parseProxy("http://proxy.example.test:8080", "LAN,CGNAT");
  assert(explicit_lan.valid);
  assert(explicit_lan.bypass.matchHost("192.168.1.1").matched);
  assert(explicit_lan.cacheIdentity() != explicit_one.cacheIdentity());
  const ProxyPolicy invalid_bypass =
      parseProxy("http://proxy.example.test:8080", "LAN,ALL");
  assert(!invalid_bypass.valid);

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
  assert(query_url.find("url=<redacted>") != std::string::npos);

  const std::string nested_request = redactSensitiveLogText(
      "/sub?target=clash&url=https%3A%2F%2Fexample.test%2Fprivate-path%3F"
      "token%3Dnested-secret&config=data%3A%2Cconfig-secret&userinfo="
      "userinfo-secret&profile_data=profile-secret");
  assert(nested_request.find("nested-secret") == std::string::npos);
  assert(nested_request.find("config-secret") == std::string::npos);
  assert(nested_request.find("userinfo-secret") == std::string::npos);
  assert(nested_request.find("profile-secret") == std::string::npos);
  assert(nested_request.find("target=clash") != std::string::npos);

  const std::string node_uri = redactSensitiveLogText(
      "node=vless://fixture-uuid@node.example.test:443?type=ws&path="
      "/fixture-secret#Fixture");
  assert(node_uri.find("fixture-uuid") == std::string::npos);
  assert(node_uri.find("fixture-secret") == std::string::npos);
  assert(node_uri.find("vless://<redacted>") != std::string::npos);

  const std::string data_uri =
      redactSensitiveLogText("source=data:text/plain,fixture-data-secret");
  assert(data_uri.find("fixture-data-secret") == std::string::npos);

  const std::string http_path = redactSensitiveLogText(
      "source=https://example.test/private-path-token?mode=clash");
  assert(http_path.find("private-path-token") == std::string::npos);
  assert(http_path.find("example.test") != std::string::npos);

  const std::string summary = summarizeUrlForLog(
      "https://fixture-user:fixture-password@example.test/private-token");
  assert(summary.find("fixture-user") == std::string::npos);
  assert(summary.find("fixture-password") == std::string::npos);
  assert(summary.find("private-token") == std::string::npos);
  assert(summary.find("host=example.test") != std::string::npos);
  const std::string injected_summary =
      summarizeUrlForLog("https://example.test\nforged-log/private-token");
  assert(injected_summary.find("forged-log") == std::string::npos);

  const std::string header = redactSensitiveLogText(
      "Proxy-Authorization: Basic fixture-proxy-secret");
  assert(header.find("fixture-proxy-secret") == std::string::npos);

  const std::string curl_proxy_auth = redactSensitiveLogText(
      "Proxy auth using Basic with user 'fixture-proxy-user'");
  assert(curl_proxy_auth.find("fixture-proxy-user") == std::string::npos);
  assert(curl_proxy_auth.find("with user '<redacted>'") !=
         std::string::npos);
  const std::string quoted_curl_proxy_auth = redactSensitiveLogText(
      "Proxy auth using Basic with user 'fixture'user'tail'");
  assert(quoted_curl_proxy_auth.find("fixture") == std::string::npos);
  assert(quoted_curl_proxy_auth.find("tail") == std::string::npos);
  const std::string truncated_curl_proxy_auth = redactSensitiveLogText(
      "Proxy auth using Basic with user 'fixture-unclosed");
  assert(truncated_curl_proxy_auth.find("fixture-unclosed") ==
         std::string::npos);
  const std::string multiline_server_auth = redactSensitiveLogText(
      "Server auth using Basic with user 'fixture\r\ntail'");
  assert(multiline_server_auth.find("fixture") == std::string::npos);
  assert(multiline_server_auth.find("tail") == std::string::npos);

  const std::string multiline_headers = redactSensitiveLogText(
      "request headers:\r\n"
      "Authorization: Bearer authorization-secret\r\n"
      "pRoXy-AuThOrIzAtIoN: Basic proxy-authorization-secret\n"
      "Cookie: session=cookie-secret; preference=dark\n"
      "Authorization: Bearer folded-secret\r\n"
      "  folded-continuation-secret\r\n"
      "set-cookie: session=set-cookie-secret; HttpOnly\r\n"
      "X-Diagnostic: retained-value\r\n"
      "next=retained-parameter");
  for (const char *secret : {"authorization-secret",
                             "proxy-authorization-secret", "cookie-secret",
                             "folded-secret", "folded-continuation-secret",
                             "set-cookie-secret"})
    assert(multiline_headers.find(secret) == std::string::npos);
  assert(multiline_headers.find("Authorization: <redacted>") !=
         std::string::npos);
  assert(multiline_headers.find("pRoXy-AuThOrIzAtIoN: <redacted>") !=
         std::string::npos);
  assert(multiline_headers.find("Cookie: <redacted>") != std::string::npos);
  assert(multiline_headers.find("set-cookie: <redacted>") !=
         std::string::npos);
  assert(multiline_headers.find("X-Diagnostic: retained-value") !=
         std::string::npos);
  assert(multiline_headers.find("next=retained-parameter") !=
         std::string::npos);

  const std::string cookie_parameter = redactSensitiveLogText(
      "cookie=session-cookie-parameter&set-cookie=response-cookie-parameter"
      "&mode=clash");
  assert(cookie_parameter.find("session-cookie-parameter") ==
         std::string::npos);
  assert(cookie_parameter.find("response-cookie-parameter") ==
         std::string::npos);
  assert(cookie_parameter.find("mode=clash") != std::string::npos);

  const std::string yaml_fields = redactSensitiveLogText(
      "ToKeN: yaml-token-secret\n"
      "mode: clash\n"
      "authorization: 'yaml-authorization-secret'\n"
      "token_count: 2\n"
      "safe: retained-yaml-value");
  assert(yaml_fields.find("yaml-token-secret") == std::string::npos);
  assert(yaml_fields.find("yaml-authorization-secret") == std::string::npos);
  assert(yaml_fields.find("mode: clash") != std::string::npos);
  assert(yaml_fields.find("token_count: 2") != std::string::npos);
  assert(yaml_fields.find("safe: retained-yaml-value") != std::string::npos);

  const std::string json_fields = redactSensitiveLogText(
      R"({"authorization": "json-authorization-secret", "mode": "clash", "TOKEN":"json-token-secret", "safe":"retained-json-value"})");
  assert(json_fields.find("json-authorization-secret") == std::string::npos);
  assert(json_fields.find("json-token-secret") == std::string::npos);
  assert(json_fields.find(R"("mode": "clash")") != std::string::npos);
  assert(json_fields.find(R"("safe":"retained-json-value")") !=
         std::string::npos);

  const std::string protocol_auth_fields = redactSensitiveLogText(
      R"({"Auth":"hysteria-auth-secret","auth-str":"hysteria-auth-string-secret","psk":"snell-psk-secret","ShadowTLSPassword":"shadow-tls-secret","SnellMode":"unshaped"})");
  assert(protocol_auth_fields.find("hysteria-auth-secret") ==
         std::string::npos);
  assert(protocol_auth_fields.find("hysteria-auth-string-secret") ==
         std::string::npos);
  assert(protocol_auth_fields.find("snell-psk-secret") == std::string::npos);
  assert(protocol_auth_fields.find("shadow-tls-secret") == std::string::npos);
  assert(protocol_auth_fields.find(R"("SnellMode":"unshaped")") !=
         std::string::npos);

  const std::string composite_json = redactSensitiveLogText(
      R"({"config":{"token":"nested-json-secret","mode":"inside"},"safe":"retained-after-composite"})");
  assert(composite_json.find("nested-json-secret") == std::string::npos);
  assert(composite_json.find("retained-after-composite") != std::string::npos);

  const std::string inline_yaml = redactSensitiveLogText(
      "{ token: inline-yaml-secret, mode: rule, token_count: 7 }");
  assert(inline_yaml.find("inline-yaml-secret") == std::string::npos);
  assert(inline_yaml.find("mode: rule") != std::string::npos);
  assert(inline_yaml.find("token_count: 7") != std::string::npos);

  const std::string inline_header_names = redactSensitiveLogText(
      "{ authorization: inline-authorization-secret, mode: direct, "
      "cookie: inline-cookie-secret, safe: retained-inline-safe }");
  assert(inline_header_names.find("inline-authorization-secret") ==
         std::string::npos);
  assert(inline_header_names.find("inline-cookie-secret") == std::string::npos);
  assert(inline_header_names.find("mode: direct") != std::string::npos);
  assert(inline_header_names.find("safe: retained-inline-safe") !=
         std::string::npos);

  const std::string yaml_block = redactSensitiveLogText(
      "password: |-\n"
      "  first-block-secret\n"
      "  second-block-secret\n"
      "safe_after: retained-after-block\n");
  assert(yaml_block.find("first-block-secret") == std::string::npos);
  assert(yaml_block.find("second-block-secret") == std::string::npos);
  assert(yaml_block.find("safe_after: retained-after-block") !=
         std::string::npos);

  const std::string nested_yaml_block = redactSensitiveLogText(
      "items:\r\n"
      "- password: >\r\n"
      "    nested-block-secret\r\n"
      "\r\n"
      "  safe: retained-nested-sibling\r\n"
      "after: retained-root-sibling\r\n");
  assert(nested_yaml_block.find("nested-block-secret") == std::string::npos);
  assert(nested_yaml_block.find("safe: retained-nested-sibling") !=
         std::string::npos);
  assert(nested_yaml_block.find("after: retained-root-sibling") !=
         std::string::npos);

  const std::string parser_summary = summarizeSensitiveTextForLog(
      "parser rejected token: raw-parser-secret at line 4");
  assert(parser_summary.find("raw-parser-secret") == std::string::npos);
  assert(parser_summary.find("length=") != std::string::npos);
  assert(parser_summary.find("hash=") == std::string::npos);

  std::string forged_line =
      "event=retained private_api_key=private-api-secret\r\n"
      "[FATL] forged\t";
  forged_line.push_back('\x1b');
  forged_line += "[31m";
  forged_line.push_back('\0');
  forged_line += "中文诊断";
  const std::string sanitized = sanitizeLogLine(forged_line);
  assert(sanitized.find("private-api-secret") == std::string::npos);
  assert(sanitized.find('\r') == std::string::npos);
  assert(sanitized.find('\n') == std::string::npos);
  assert(sanitized.find('\t') == std::string::npos);
  assert(sanitized.find('\x1b') == std::string::npos);
  assert(sanitized.find('\0') == std::string::npos);
  assert(sanitized.find("\\r\\n") != std::string::npos);
  assert(sanitized.find("\\t") != std::string::npos);
  assert(sanitized.find("\\x1B") != std::string::npos);
  assert(sanitized.find("中文诊断") != std::string::npos);

  const std::string oversized = sanitizeLogLine(std::string(20000, 'x'));
  assert(oversized.size() <= 16 * 1024);
  assert(oversized.find("...[truncated original_bytes=20000]") !=
         std::string::npos);
  const std::string raw_oversized = sanitizeLogLine(std::string(70000, 's'));
  assert(raw_oversized ==
         "<redacted oversized_log_content original_bytes=70000>");
  const std::string oversized_script =
      sanitizeLogLine("SCRIPT_EXCEPTION " + std::string(70000, 's'));
  assert(oversized_script ==
         "SCRIPT_EXCEPTION <redacted oversized_log_content "
         "original_bytes=70017>");

  const std::string known_field_aliases = sanitizeLogLine(
      R"(SCRIPT_EXCEPTION detail={"PrivateKey":"private-key-secret","PreSharedKey":"pre-shared-key-secret","QUICSecret":"quic-secret","UserId":"user-id-secret"} X-API-Key: api-key-secret x-auth-token=auth-token-secret)");
  for (const char *secret :
       {"private-key-secret", "pre-shared-key-secret", "quic-secret",
        "user-id-secret", "api-key-secret", "auth-token-secret"})
    assert(known_field_aliases.find(secret) == std::string::npos);
  assert(known_field_aliases.find("PrivateKey") != std::string::npos);
  assert(known_field_aliases.find("X-API-Key") != std::string::npos);
  return 0;
}
