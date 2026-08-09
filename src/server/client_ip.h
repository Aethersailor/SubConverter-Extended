#ifndef CLIENT_IP_H_INCLUDED
#define CLIENT_IP_H_INCLUDED

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace client_ip {

constexpr std::size_t kMaxTrustedProxyCidrs = 64;
constexpr std::size_t kMaxForwardedHops = 16;
constexpr std::size_t kMaxSelectedHeaderBytes = 2048;

enum class Family : uint8_t { Unknown = 0, IPv4 = 4, IPv6 = 6 };

struct Address {
  Family family = Family::Unknown;
  std::array<uint8_t, 16> bytes{};

  bool valid() const { return family != Family::Unknown; }
  bool operator==(const Address &other) const {
    return family == other.family && bytes == other.bytes;
  }
};

struct AddressHash {
  std::size_t operator()(const Address &address) const noexcept;
};

enum class Header {
  None,
  XForwardedFor,
  Forwarded,
  XRealIp,
  CfConnectingIp,
  TrueClientIp,
};

struct Cidr {
  Address network;
  uint8_t prefix_length = 0;

  bool contains(const Address &address) const;
};

struct Policy {
  Header header = Header::None;
  std::vector<Cidr> trusted_proxy_cidrs;

  bool enabled() const {
    return header != Header::None && !trusted_proxy_cidrs.empty();
  }
};

struct Resolution {
  Address address;
  bool used_forwarded_header = false;
};

Address parseAddress(std::string_view value);
std::string toString(const Address &address);
Cidr parseCidr(std::string_view value);
Header parseHeader(std::string_view value);
const char *headerName(Header header);
const char *headerSettingName(Header header);
Policy makePolicy(std::string_view header,
                  const std::vector<std::string> &trusted_proxy_cidrs);
Resolution resolve(const Address &peer,
                   const std::vector<std::string> &selected_header_values,
                   const Policy &policy);

} // namespace client_ip

#endif // CLIENT_IP_H_INCLUDED
