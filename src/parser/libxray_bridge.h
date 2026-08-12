#ifndef LIBXRAY_BRIDGE_H
#define LIBXRAY_BRIDGE_H

#include <string>
#include <vector>

namespace libxray {

struct ProxyNode {
  std::string name;
  std::string protocol;
  std::string server;
  int port = 0;
  // Build-validated Xray outbound JSON with libXray's temporary display-name
  // metadata removed. It is deliberately separate from Mihomo's
  // CanonicalProxyJson because the two kernels have different schemas.
  std::string xray_outbound_json;
};

struct ParserInfo {
  bool available = false;
  std::string library;
  std::string release;
  std::string module_version;
  std::string source_revision;
  int routed_targets = 0;
};

// Parse only. This function never starts an Xray runtime or performs network
// I/O. No production target calls it in the foundation phase.
std::vector<ProxyNode> parseSubscription(const std::string &subscription);

ParserInfo parserInfo();

} // namespace libxray

#endif // LIBXRAY_BRIDGE_H
