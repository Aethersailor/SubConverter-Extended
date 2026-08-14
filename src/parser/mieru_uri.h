#ifndef MIERU_URI_H_INCLUDED
#define MIERU_URI_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

struct MieruPortBinding {
  std::string port;
  std::string protocol;
  bool is_range = false;
};

struct MieruSimpleConfig {
  std::string username;
  std::string password;
  std::string host;
  std::string profile;
  std::string multiplexing;
  std::string handshake_mode;
  std::string traffic_pattern;
  std::string remark;
  uint16_t mtu = 0;
  bool has_unknown_parameters = false;
  std::vector<MieruPortBinding> port_bindings;
};

// Parses the official human-readable mierus:// format. The binary protobuf
// mieru:// format deliberately remains outside the Legacy parser.
bool parseMieruSimpleUri(const std::string &uri, MieruSimpleConfig &config);

// Serializes the portable subset defined by the official human-readable
// mierus:// format. Unknown source parameters deliberately fail closed.
bool buildMieruSimpleUri(const MieruSimpleConfig &config, std::string &uri);

// Validates one Mihomo/Mieru port or port-range plus transport pair.
bool parseMieruPortBinding(const std::string &port,
                           const std::string &protocol,
                           MieruPortBinding &binding);

bool isValidMieruMultiplexing(const std::string &value);
bool isValidMieruHandshakeMode(const std::string &value);
bool isValidMieruTrafficPattern(const std::string &value);

#endif // MIERU_URI_H_INCLUDED
