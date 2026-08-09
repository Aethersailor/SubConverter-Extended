#include "server/client_ip.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;

void require(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

client_ip::Policy policy(const std::string &header,
                         std::vector<std::string> cidrs = {"10.0.0.0/8"}) {
  return client_ip::makePolicy(header, cidrs);
}

void requireAddress(const client_ip::Address &address,
                    const std::string &expected,
                    const std::string &message) {
  require(client_ip::toString(address) == expected,
          message + ": got " + client_ip::toString(address));
}

void parsingAndCanonicalization() {
  requireAddress(client_ip::parseAddress(" 192.0.2.1 "), "192.0.2.1",
                 "IPv4 is parsed");
  requireAddress(client_ip::parseAddress("2001:0db8:0:0:0:0:0:1"),
                 "2001:db8::1", "IPv6 is canonicalized");
  require(client_ip::parseAddress("::ffff:192.0.2.1") ==
              client_ip::parseAddress("192.0.2.1"),
          "IPv4-mapped IPv6 collapses to IPv4");
  for (const std::string &invalid : std::vector<std::string>{
           "192.0.2.1:443", "[2001:db8::1]", "2001:db8::1%eth0",
           "999.1.1.1", std::string(100, '1')}) {
    require(!client_ip::parseAddress(invalid).valid(),
            "invalid address is rejected: " + invalid);
  }
  require(client_ip::parseHeader("X-FoRwArDeD-FoR") ==
              client_ip::Header::XForwardedFor,
          "header setting is case-insensitive");
}

void cidrValidation() {
  const client_ip::Cidr cidr = client_ip::parseCidr("192.0.2.129/24");
  require(cidr.contains(client_ip::parseAddress("192.0.2.42")),
          "CIDR host bits are masked");
  require(!cidr.contains(client_ip::parseAddress("192.0.3.42")),
          "CIDR excludes other networks");
  for (const std::string invalid : {"0.0.0.0/0", "::/0", "10.0.0.1",
                                    "10.0.0.1/33", "bad/24"}) {
    try {
      (void)client_ip::parseCidr(invalid);
      require(false, "invalid CIDR accepted: " + invalid);
    } catch (const std::invalid_argument &) {
    }
  }
}

void trustBoundary() {
  const client_ip::Address direct = client_ip::parseAddress("198.51.100.20");
  const client_ip::Policy trusted = policy("cf-connecting-ip");
  requireAddress(client_ip::resolve(direct, {"203.0.113.7"}, trusted).address,
                 "198.51.100.20", "untrusted peer cannot spoof selected header");
  requireAddress(client_ip::resolve(direct, {"203.0.113.7"}, policy("none"))
                     .address,
                 "198.51.100.20", "default policy uses socket peer");

  const client_ip::Address proxy = client_ip::parseAddress("10.0.0.1");
  for (const std::string header : {"x-real-ip", "cf-connecting-ip",
                                   "true-client-ip"}) {
    const auto result = client_ip::resolve(proxy, {"203.0.113.7"}, policy(header));
    requireAddress(result.address, "203.0.113.7",
                   "trusted proxy resolves " + header);
    require(result.used_forwarded_header, header + " marks header usage");
  }
  requireAddress(client_ip::resolve(proxy,
                                    {"203.0.113.7", "198.51.100.2"}, trusted)
                     .address,
                 "10.0.0.1", "duplicate selected headers fail closed to peer");
  requireAddress(client_ip::resolve(proxy, {"203.0.113.7:443"}, trusted).address,
                 "10.0.0.1", "port in single-IP header fails closed");
  requireAddress(client_ip::resolve(proxy, {std::string(2049, '1')}, trusted)
                     .address,
                 "10.0.0.1", "oversized selected header fails closed");

  const client_ip::Address mapped_peer =
      client_ip::parseAddress("::ffff:192.0.2.9");
  requireAddress(client_ip::resolve(
                     mapped_peer, {"203.0.113.8"},
                     policy("x-real-ip", {"192.0.2.0/24"}))
                     .address,
                 "203.0.113.8",
                 "IPv4-mapped peer matches canonical IPv4 trusted CIDR");
}

void forwardedChains() {
  const client_ip::Address proxy = client_ip::parseAddress("10.0.0.1");
  const client_ip::Policy xff = policy("x-forwarded-for");
  requireAddress(client_ip::resolve(
                     proxy, {"203.0.113.99, 198.51.100.8, 10.0.0.2"}, xff)
                     .address,
                 "198.51.100.8",
                 "XFF selects first untrusted hop scanning right to left");
  requireAddress(client_ip::resolve(proxy, {"10.0.0.2, 10.0.0.3"}, xff)
                     .address,
                 "10.0.0.1", "all-trusted XFF falls back to peer");
  requireAddress(client_ip::resolve(proxy, {"198.51.100.8, invalid"}, xff)
                     .address,
                 "10.0.0.1", "invalid XFF chain fails closed");
  requireAddress(client_ip::resolve(proxy, {"198.51.100.8:443"}, xff).address,
                 "10.0.0.1", "XFF ports are rejected");

  std::string too_many;
  for (std::size_t i = 0; i <= client_ip::kMaxForwardedHops; ++i) {
    if (!too_many.empty())
      too_many += ',';
    too_many += "10.0.0.2";
  }
  requireAddress(client_ip::resolve(proxy, {too_many}, xff).address,
                 "10.0.0.1", "overlong XFF chain fails closed");

  const client_ip::Policy forwarded = policy("forwarded");
  requireAddress(client_ip::resolve(
                     proxy,
                     {"for=203.0.113.99;proto=https, for=\"[2001:db8::7]:443\""},
                     forwarded)
                     .address,
                 "2001:db8::7", "Forwarded parses quoted IPv6 and port");
  requireAddress(client_ip::resolve(proxy, {"for=_hidden"}, forwarded).address,
                 "10.0.0.1", "obfuscated Forwarded node fails closed");
  requireAddress(client_ip::resolve(proxy, {"by=10.0.0.2"}, forwarded).address,
                 "10.0.0.1", "Forwarded element without for fails closed");
}

void incompleteConfiguration() {
  require(!client_ip::makePolicy("x-forwarded-for", {}).enabled(),
          "header without CIDR safely disables forwarding");
  require(!client_ip::makePolicy("none", {"10.0.0.0/8"}).enabled(),
          "CIDR without header safely disables forwarding");
  try {
    (void)client_ip::makePolicy("x-client-ip", {"10.0.0.0/8"});
    require(false, "unsupported X-Client-IP setting accepted");
  } catch (const std::invalid_argument &) {
  }
  try {
    std::vector<std::string> cidrs(client_ip::kMaxTrustedProxyCidrs + 1,
                                   "10.0.0.0/8");
    (void)client_ip::makePolicy("x-forwarded-for", cidrs);
    require(false, "CIDR count limit was not enforced");
  } catch (const std::invalid_argument &) {
  }
}

} // namespace

int main() {
  parsingAndCanonicalization();
  cidrValidation();
  trustBoundary();
  forwardedChains();
  incompleteConfiguration();
  if (failures != 0)
    return 1;
  std::cout << "client IP policy tests passed\n";
  return 0;
}
