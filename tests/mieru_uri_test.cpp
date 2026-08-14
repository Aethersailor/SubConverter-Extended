#include <cassert>
#include <string>
#include <vector>

#include "parser/mieru_uri.h"

namespace {

constexpr const char *kOfficialSimpleUri =
    "mierus://baozi:manlianpenfen@1.2.3.4?"
    "handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&"
    "multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&"
    "port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&"
    "protocol=UDP&protocol=UDP&"
    "traffic-pattern=CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3";

void expectInvalid(const std::string &uri) {
  MieruSimpleConfig config;
  assert(!parseMieruSimpleUri(uri, config));
}

} // namespace

int main() {
  MieruSimpleConfig official;
  assert(parseMieruSimpleUri(kOfficialSimpleUri, official));
  assert(official.username == "baozi");
  assert(official.password == "manlianpenfen");
  assert(official.host == "1.2.3.4");
  assert(official.profile == "default");
  assert(official.mtu == 1400);
  assert(official.multiplexing == "MULTIPLEXING_HIGH");
  assert(official.handshake_mode == "HANDSHAKE_NO_WAIT");
  assert(official.port_bindings.size() == 4);
  assert(official.port_bindings[0].port == "6666");
  assert(!official.port_bindings[0].is_range);
  assert(official.port_bindings[1].port == "9998-9999");
  assert(official.port_bindings[1].is_range);
  assert(official.port_bindings[2].protocol == "UDP");
  std::string rebuilt;
  assert(buildMieruSimpleUri(official, rebuilt));
  MieruSimpleConfig rebuilt_official;
  assert(parseMieruSimpleUri(rebuilt, rebuilt_official));
  assert(rebuilt_official.username == official.username);
  assert(rebuilt_official.password == official.password);
  assert(rebuilt_official.host == official.host);
  assert(rebuilt_official.profile == official.profile);
  assert(rebuilt_official.mtu == official.mtu);
  assert(rebuilt_official.multiplexing == official.multiplexing);
  assert(rebuilt_official.handshake_mode == official.handshake_mode);
  assert(rebuilt_official.traffic_pattern == official.traffic_pattern);
  assert(rebuilt_official.port_bindings.size() ==
         official.port_bindings.size());

  MieruSimpleConfig ipv6;
  assert(parseMieruSimpleUri(
      "mierus://user%2Bname:p%40ss%2Bword@[2001:db8::20]?"
      "profile=IPv6%20Profile&port=0443&protocol=TCP&"
      "traffic-pattern=CgE%2B#IPv6%20Mieru",
      ipv6));
  assert(ipv6.username == "user+name");
  assert(ipv6.password == "p@ss+word");
  assert(ipv6.host == "2001:db8::20");
  assert(ipv6.profile == "IPv6 Profile");
  assert(ipv6.remark == "IPv6 Mieru");
  assert(ipv6.port_bindings.size() == 1);
  assert(ipv6.port_bindings[0].port == "443");
  assert(ipv6.traffic_pattern == "CgE+");
  assert(buildMieruSimpleUri(ipv6, rebuilt));
  assert(rebuilt.find("user%2Bname:p%40ss%2Bword@[2001:db8::20]") !=
         std::string::npos);
  assert(rebuilt.find("traffic-pattern=CgE%2B") != std::string::npos);

  MieruSimpleConfig defaults;
  assert(parseMieruSimpleUri(
      "mierus://user:pass@example.test?profile=default&port=443&"
      "protocol=TCP&future-option=ignored",
      defaults));
  assert(defaults.mtu == 0);
  assert(defaults.multiplexing.empty());
  assert(defaults.handshake_mode.empty());
  assert(defaults.has_unknown_parameters);
  assert(!buildMieruSimpleUri(defaults, rebuilt));

  MieruPortBinding binding;
  assert(parseMieruPortBinding("1000-1000", "UDP", binding));
  assert(binding.port == "1000-1000");
  assert(binding.is_range);

  const std::vector<std::string> invalid = {
      "mieru://AQIDBA==",
      "mierus://user:pass@example.test?port=443&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&profile=b&port=443&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=443&port=444&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=0&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=65536&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=184467440737095516160&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=9000-8000&protocol=TCP",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=tcp",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=QUIC",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&mtu=1279",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&mtu=1401",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&multiplexing=HIGH",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&handshake-mode=NO_WAIT",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&traffic-pattern=not_base64",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP&traffic-pattern=AAAA",
      "mierus://user:pass@example.test?profile=a&port=443&protocol=TCP%0A",
      "mierus://user:pass@bad%2Fhost?profile=a&port=443&protocol=TCP",
  };
  for (const std::string &uri : invalid)
    expectInvalid(uri);

  return 0;
}
