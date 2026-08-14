#ifndef PROXY_H_INCLUDED
#define PROXY_H_INCLUDED

#include <string>
#include <utility>
#include <vector>

#include "utils/tribool.h"

using String = std::string;
using StringArray = std::vector<String>;

enum class ProxyType {
  Unknown,
  Shadowsocks,
  ShadowsocksR,
  VMess,
  Trojan,
  Snell,
  HTTP,
  HTTPS,
  SOCKS5,
  WireGuard,
  VLESS,
  Hysteria,
  Hysteria2,
  TUIC,
  AnyTLS,
  Naive,
  Mieru
};

struct WireGuardPeer {
  String Hostname;
  uint16_t Port = 0;
  String PublicKey;
  String PreSharedKey;
  String AllowedIPs = "0.0.0.0/0, ::/0";
  String Reserved;
  uint16_t KeepAlive = 0;
};

inline String getProxyTypeName(ProxyType type) {
  switch (type) {
  case ProxyType::Shadowsocks:
    return "SS";
  case ProxyType::ShadowsocksR:
    return "SSR";
  case ProxyType::VMess:
    return "VMess";
  case ProxyType::Trojan:
    return "Trojan";
  case ProxyType::Snell:
    return "Snell";
  case ProxyType::HTTP:
    return "HTTP";
  case ProxyType::HTTPS:
    return "HTTPS";
  case ProxyType::SOCKS5:
    return "SOCKS5";
  case ProxyType::WireGuard:
    return "WireGuard";
  case ProxyType::VLESS:
    return "Vless";
  case ProxyType::Hysteria:
    return "Hysteria";
  case ProxyType::Hysteria2:
    return "Hysteria2";
  case ProxyType::TUIC:
    return "Tuic";
  case ProxyType::AnyTLS:
    return "AnyTLS";
  case ProxyType::Naive:
    return "Naive";
  case ProxyType::Mieru:
    return "Mieru";
  default:
    return "Unknown";
  }
}

struct Proxy {
  ProxyType Type = ProxyType::Unknown;
  uint32_t Id = 0;
  uint32_t GroupId = 0;
  String Group;
  String Remark;
  String Hostname;
  uint16_t Port = 0;
  String CongestionControl;
  String Username;
  String Password;
  String EncryptMethod;
  String Plugin;
  String PluginOption;
  String Protocol;
  String ProtocolParam;
  String OBFS;
  String OBFSParam;
  String UserId;
  uint16_t AlterId = 0;
  String TransferProtocol;
  String FakeType;
  String AuthStr;
  uint16_t IdleSessionCheckInterval = 30;
  uint16_t IdleSessionTimeout = 30;
  uint16_t MinIdleSession = 0;
  uint32_t NaiveInsecureConcurrency = 0;
  tribool NaiveQuic;
  tribool NaiveUot;
  String TLSStr;
  bool TLSSecure = false;

  String Host;
  String Path;
  String Edge;

  String QUICSecure;
  String QUICSecret;

  tribool UDP;
  tribool XUDP;
  tribool TCPFastOpen;
  tribool AllowInsecure;
  tribool TLS13;

  uint16_t SnellVersion = 0;
  tribool SnellReuse;
  String SnellUserKey;
  // Empty means both TCP and UDP; otherwise sing-box accepts tcp or udp.
  String SnellNetwork;
  String SnellMode;
  uint16_t SnellUDPPort = 0;
  String ShadowTLSPassword;
  String ShadowTLSSNI;
  uint16_t ShadowTLSVersion = 0;
  String ServerName;

  String SelfIP;
  String SelfIPv6;
  String PublicKey;
  String PrivateKey;
  String PreSharedKey;
  StringArray DnsServers;
  uint16_t Mtu = 0;
  String AllowedIPs = "0.0.0.0/0, ::/0";
  uint16_t KeepAlive = 0;
  String TestUrl;
  String ClientId;
  // WireGuard historically projected only one peer into the fields above.
  // Keep that projection for existing scripts and generators, while retaining
  // the complete structured configuration for multi-peer targets.
  std::vector<WireGuardPeer> WireGuardPeers;
  StringArray WireGuardLocalAddresses;
  String WireGuardInterfaceName;
  tribool WireGuardSystem;
  uint16_t WireGuardListenPort = 0;
  uint16_t WireGuardWorkers = 0;
  String Ports;
  String Auth;
  String Alpn;
  String UpMbps;
  String DownMbps;
  String HysteriaHopInterval;
  String Insecure;
  String Fingerprint;
  String OBFSPassword;
  String Hysteria2RealmUrl;
  String Hysteria2GeckoMinPacketSize;
  String Hysteria2GeckoMaxPacketSize;
  // Hysteria 2 URI-only ECH config. It is preserved for standards-compliant
  // single-link round trips and is not projected into clients whose legacy
  // generators cannot represent it safely.
  String Hysteria2ECH;
  // URI port hopping stores the first port in Port and the remaining ranges in
  // Ports. Native config imports generally store the complete range in Ports.
  bool Hysteria2PortsAreAdditional = false;
  String GRPCServiceName;
  String GRPCMode;
  String ShortId;
  String Flow;
  String Encryption;
  bool FlowShow = false;
  tribool DisableSni;
  uint32_t UpSpeed;
  uint32_t DownSpeed;
  String SNI;
  tribool ReduceRtt;
  String UdpRelayMode = "native";
  uint16_t RequestTimeout = 15000;
  String token;
  String UnderlyingProxy;
  std::vector<String> AlpnList;
  String PacketEncoding;
  String Multiplexing;
  // Metadata from one official mierus:// resource. Legacy parsing expands
  // every port/protocol binding into a Proxy, while Shadowrocket needs the
  // original resource boundary to emit one lossless sharing link again.
  String MieruProfile;
  String MieruSourceId;
  String MieruSourceRemark;
  uint32_t MieruBindingIndex = 0;
  bool MieruHasUnknownParameters = false;
  String MieruHandshakeMode;
  String MieruTrafficPattern;
  tribool V2rayHttpUpgrade;

  // Recognized Xray share-link options that do not yet have a portable field
  // in every legacy target generator. They are kept as decoded key/value
  // pairs so single-link targets can round-trip the official URI without
  // coupling the generic proxy model to every Xray release.
  std::vector<std::pair<String, String>> XrayLinkOptions;

  // Complete type-preserving mapping returned by Mihomo. Clash output treats
  // this JSON document as the canonical representation; the fields above are
  // a compatibility projection for legacy target generators and scripts.
  String CanonicalProxyJson;
};

#define SS_DEFAULT_GROUP "SSProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define HTTP_DEFAULT_GROUP "HTTPProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define SNELL_DEFAULT_GROUP "SnellProvider"
#define WG_DEFAULT_GROUP "WireGuardProvider"
#define XRAY_DEFAULT_GROUP "XRayProvider"
#define HYSTERIA_DEFAULT_GROUP "HysteriaProvider"
#define HYSTERIA2_DEFAULT_GROUP "Hysteria2Provider"
#define TUIC_DEFAULT_GROUP "TuicProvider"
#define ANYTLS_DEFAULT_GROUP "AnyTLSProvider"
#define NAIVE_DEFAULT_GROUP "NaiveProvider"
#define MIERU_DEFAULT_GROUP "MieruProvider"
#endif // PROXY_H_INCLUDED
