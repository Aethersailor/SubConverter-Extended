#ifndef CLASH_PROXY_H_INCLUDED
#define CLASH_PROXY_H_INCLUDED

#include <string>

#include <yaml-cpp/yaml.h>

#include "parser/config/proxy.h"

struct ClashProxyOverlay {
  tribool udp;
  tribool skip_cert_verify;
  tribool tfo;
  tribool xudp;
};

// Build one Clash proxy mapping from Mihomo's complete type-preserving JSON
// result. Only compatibility-visible identity fields and explicitly requested
// global overlays are changed.
YAML::Node buildCanonicalClashProxy(const Proxy &proxy,
                                    const ClashProxyOverlay &overlay);

// Serialize Clash YAML while preserving the scalar types carried by Mihomo's
// canonical JSON. This is the only supported dump path for YAML that may
// contain nodes returned by buildCanonicalClashProxy().
std::string dumpCanonicalClashYaml(const YAML::Node &node);

// Finalize an already serialized Clash document. This is used by output paths
// that compose independently dumped top-level fields.
std::string finalizeCanonicalClashYaml(const std::string &yaml);

#endif // CLASH_PROXY_H_INCLUDED
