#include <algorithm>
#include <cctype>
#include <climits>
#include <cmath>
#include <functional>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "config/regmatch.h"
#include "external_rules.h"
#include "generator/config/clash_proxy.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "handler/settings_view.h"
#include "nodemanip.h"
#include "parser/config/proxy.h"
#include "parser/mieru_uri.h"
#include "ruleconvert.h"
#include "script/script_quickjs.h"
#include "utils/bitwise.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/redact.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/time_compat.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"

extern string_array ss_ciphers, ssr_ciphers;

static bool splitRenameGroupRule(const std::string &match,
                                 std::string &group_pattern,
                                 std::string &name_pattern);
static bool parseProviderGroupIdMatcher(const std::string &rule,
                                        std::string &target,
                                        std::string &real_rule);

namespace {

std::vector<WireGuardPeer> wireGuardPeers(const Proxy &node);
std::vector<std::string> wireGuardLocalAddresses(const Proxy &node);
std::string wireGuardAddressWithoutPrefix(std::string address);
std::string wireGuardAddressWithDefaultPrefix(std::string address);
std::string wireGuardEndpoint(const WireGuardPeer &peer);
std::string generatePeer(const WireGuardPeer &peer,
                         bool client_id_as_reserved = false);
std::string generateLoonWireGuardPeer(const WireGuardPeer &peer);
bool wireGuardStructuredConfigIsSafe(const Proxy &node);

class TargetNodeGenerationTracker {
public:
  TargetNodeGenerationTracker(TargetGenerationStats &stats, ProxyType type)
      : stats_(stats), type_(type) {}
  ~TargetNodeGenerationTracker() {
    if (emitted_)
      stats_.emitted_nodes++;
    else
      stats_.unsupported_by_type[type_]++;
  }
  void markEmitted() { emitted_ = true; }

private:
  TargetGenerationStats &stats_;
  ProxyType type_;
  bool emitted_ = false;
};

class TargetGenerationStatsMirror {
public:
  TargetGenerationStatsMirror(TargetGenerationStats &source,
                              TargetGenerationStats &destination)
      : source_(source), destination_(destination) {}
  ~TargetGenerationStatsMirror() { destination_ = source_; }

private:
  TargetGenerationStats &source_;
  TargetGenerationStats &destination_;
};

template <typename Resource> struct PolicyPathSelector {
  const Resource *resource = nullptr;
  std::string policy_pattern;
};

template <typename Resource>
PolicyPathSelector<Resource> policyPathSelectorForGroup(
    const ProxyGroupConfig &group,
    const std::vector<Resource> &resources) {
  PolicyPathSelector<Resource> selector;
  if (resources.size() != 1)
    return selector;

  const Resource &resource = resources.front();
  if (!group.UsingProvider.empty()) {
    const bool selected =
        std::find(group.UsingProvider.begin(), group.UsingProvider.end(),
                  resource.requested_name) != group.UsingProvider.end();
    if (selected) {
      selector.resource = &resource;
      selector.policy_pattern = ".*";
    }
    return selector;
  }

  for (const std::string &rule : group.Proxies) {
    if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
      continue;

    std::string target, policy_pattern;
    if (parseProviderGroupIdMatcher(rule, target, policy_pattern)) {
      if (matchRange(target, resource.group_id)) {
        selector.resource = &resource;
        selector.policy_pattern =
            policy_pattern.empty() ? ".*" : policy_pattern;
      }
    } else if (splitRenameGroupRule(rule, target, policy_pattern)) {
      if (!resource.source_tag.empty() && regFind(resource.source_tag, target)) {
        selector.resource = &resource;
        selector.policy_pattern =
            policy_pattern.empty() ? ".*" : policy_pattern;
      }
    } else if (!startsWith(rule, "!!") && !startsWith(rule, "script:")) {
      selector.resource = &resource;
      selector.policy_pattern = rule;
    }
    break;
  }
  return selector;
}

std::string safePolicyPathUrl(const std::string &url) {
  return replaceAllDistinct(url, ",", "%2C");
}

std::string surfboardPolicyPattern(const std::string &pattern) {
  if (pattern == ".*")
    return pattern;
  return ".*(?:" + pattern + ").*";
}

} // namespace

static bool splitRenameGroupRule(const std::string &match,
                                 std::string &group_pattern,
                                 std::string &name_pattern) {
  static const std::string group_regex = R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
  if (!startsWith(match, "!!GROUP="))
    return false;
  regGetMatch(match, group_regex, 3, 0, &group_pattern, &name_pattern);
  return true;
}

static YAML::Node buildProviderProxyNameOverride(const ProxyProvider &provider,
                                                 const extra_settings &ext) {
  YAML::Node proxy_name_node(YAML::NodeType::Sequence);
  if (!ext.rename_for_providers || ext.rename_array.empty())
    return proxy_name_node;

  for (const RegexMatchConfig &rule : ext.rename_array) {
    if (!rule.Script.empty() || rule.Match.empty())
      continue;

    std::string group_pattern, name_pattern;
    if (splitRenameGroupRule(rule.Match, group_pattern, name_pattern)) {
      if (group_pattern.empty() || name_pattern.empty())
        continue;
      if (!provider.tag.empty() && regFind(provider.tag, group_pattern)) {
        YAML::Node item;
        item["pattern"] = name_pattern;
        item["target"] = rule.Replace;
        proxy_name_node.push_back(item);
      }
      continue;
    }

    if (startsWith(rule.Match, "!!"))
      continue;

    YAML::Node item;
    item["pattern"] = rule.Match;
    item["target"] = rule.Replace;
    proxy_name_node.push_back(item);
  }

  return proxy_name_node;
}

// Helper function to insert proxy-providers before proxy-groups
static void insertProxyProvidersBeforeGroups(std::string &yaml_str,
                                             const std::string &providers_yaml,
                                             bool new_field_name) {
  std::string providers_content = providers_yaml;
  if (providers_content.find("---") == 0) {
    size_t newline_pos = providers_content.find('\n');
    if (newline_pos != std::string::npos) {
      providers_content = providers_content.substr(newline_pos + 1);
    }
  }

  // 为每一行添加2个空格的缩进（YAML格式要求）
  std::string indented_content;
  std::istringstream stream(providers_content);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty()) {
      indented_content += "  " + line + "\n"; // 添加2个空格缩进
    } else {
      indented_content += "\n";
    }
  }

  std::string providers_str = "proxy-providers:\n" + indented_content;
  // 确保末尾有换行符，避免与 proxy-groups 连在一起
  if (!providers_str.empty() && providers_str.back() != '\n') {
    providers_str += "\n";
  }
  std::string groups_key = new_field_name ? "proxy-groups:" : "Proxy Group:";

  size_t groups_pos = yaml_str.find(groups_key);
  if (groups_pos != std::string::npos) {
    yaml_str.insert(groups_pos, providers_str);
  }
}

// Helper function to insert proxies before proxy-groups
static void insertProxiesBeforeTarget(std::string &yaml_str,
                                      const std::string &proxies_yaml,
                                      bool new_field_name) {
  std::string proxies_content = proxies_yaml;
  // 移除 YAML 文档分隔符 "---"
  if (proxies_content.find("---") == 0) {
    size_t newline_pos = proxies_content.find('\n');
    if (newline_pos != std::string::npos) {
      proxies_content = proxies_content.substr(newline_pos + 1);
    }
  }

  // 为每一行添加2个空格的缩进（YAML格式要求）
  std::string indented_content;
  std::istringstream stream(proxies_content);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty()) {
      indented_content += "  " + line + "\n";
    } else {
      indented_content += "\n";
    }
  }

  // 构建完整的 proxies 字符串
  std::string proxies_key = new_field_name ? "proxies" : "Proxy";
  std::string proxies_str = proxies_key + ":\n" + indented_content;

  // 确保末尾有换行符
  if (!proxies_str.empty() && proxies_str.back() != '\n') {
    proxies_str += "\n";
  }

  // 始终在 proxy-groups 之前插入
  // 这样顺序是：proxy-providers → proxies → proxy-groups
  std::string target_key = new_field_name ? "proxy-groups:" : "Proxy Group:";

  size_t target_pos = yaml_str.find(target_key);
  if (target_pos != std::string::npos) {
    yaml_str.insert(target_pos, proxies_str);
  }
}

const string_array clashr_protocols = {"origin",          "auth_sha1_v4",
                                       "auth_aes128_md5", "auth_aes128_sha1",
                                       "auth_chain_a",    "auth_chain_b"};
const string_array clashr_obfs = {
    "plain",       "http_simple",        "http_post",
    "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"};
const string_array clash_ssr_ciphers = {
    "rc4-md5",     "aes-128-ctr", "aes-192-ctr",   "aes-256-ctr", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20",   "none"};
bool isNumeric(const std::string &str) {
  for (char c : str) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

static bool parseMbpsValue(std::string value, int &result) {
  value = trim(value);
  for (const char *suffix : {" Mbps", "Mbps"}) {
    const size_t suffix_length = std::char_traits<char>::length(suffix);
    if (value.size() >= suffix_length &&
        value.compare(value.size() - suffix_length, suffix_length, suffix) == 0) {
      value.erase(value.size() - suffix_length);
      value = trim(value);
      break;
    }
  }
  if (!isNumeric(value) || value.empty())
    return false;
  try {
    const long long parsed = std::stoll(value);
    if (parsed < 0 || parsed > INT_MAX)
      return false;
    result = static_cast<int>(parsed);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

static bool parseSingBoxBandwidth(std::string value, bool &use_mbps,
                                  int &mbps, std::string &bandwidth) {
  value = trim(value);
  if (parseMbpsValue(value, mbps)) {
    use_mbps = true;
    return mbps > 0;
  }

  const size_t space = value.find(' ');
  if (space == std::string::npos || space == 0 ||
      value.find(' ', space + 1) != std::string::npos)
    return false;
  const std::string amount = value.substr(0, space);
  const std::string unit = value.substr(space + 1);
  static const string_array supported_units = {
      "bps", "Bps", "Kbps", "KBps", "Mbps", "MBps",
      "Gbps", "GBps", "Tbps", "TBps"};
  if (!isNumeric(amount) || amount.empty() || amount == "0" ||
      std::find(supported_units.begin(), supported_units.end(), unit) ==
          supported_units.end())
    return false;
  try {
    if (std::stoull(amount) == 0)
      return false;
  } catch (const std::exception &) {
    return false;
  }
  use_mbps = false;
  bandwidth = value;
  return true;
}

static bool surgeProxyScalarIsSafe(const std::string &value) {
  return value.find_first_of(",\r\n") == std::string::npos;
}

static bool quanxProxyScalarIsSafe(const std::string &value) {
  if (value.empty())
    return true;
  if (trim(value) != value)
    return false;
  for (const unsigned char character : value) {
    if (character == ',' || character < 0x20 || character == 0x7f)
      return false;
  }
  return true;
}

static bool quanxPlainXrayTransportIsSafe(const Proxy &proxy) {
  return proxy.Edge.empty() && proxy.GRPCServiceName.empty() &&
         proxy.GRPCMode.empty() && proxy.QUICSecure.empty() &&
         proxy.QUICSecret.empty() && proxy.XrayLinkOptions.empty() &&
         proxy.UnderlyingProxy.empty() && !proxy.V2rayHttpUpgrade;
}

static bool quanxRealityPublicKeyIsValid(const std::string &public_key) {
  if (public_key.size() != 43 ||
      !std::all_of(public_key.begin(), public_key.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_';
      }))
    return false;
  const std::string decoded = urlSafeBase64Decode(public_key);
  return decoded.size() == 32 && urlSafeBase64Encode(decoded) == public_key;
}

static bool quanxRealityShortIdIsValid(const std::string &short_id) {
  return short_id.empty() ||
         (short_id.size() <= 16 && short_id.size() % 2 == 0 &&
          std::all_of(short_id.begin(), short_id.end(), [](unsigned char c) {
            return std::isxdigit(c);
          }));
}

static bool appendQuanXRealityFields(const Proxy &proxy,
                                     std::string &output) {
  if (!quanxRealityPublicKeyIsValid(proxy.PublicKey) ||
      !quanxRealityShortIdIsValid(proxy.ShortId))
    return false;
  output += ", reality-base64-pubkey=" + proxy.PublicKey;
  if (!proxy.ShortId.empty())
    output += ", reality-hex-shortid=" + proxy.ShortId;
  return true;
}

static bool quanxTlsAlpnHex(const std::vector<String> &alpn_list,
                            std::string &output) {
  static constexpr char hex_digits[] = "0123456789abcdef";
  output.clear();
  size_t encoded_bytes = 0;
  for (const std::string &alpn : alpn_list) {
    if (alpn.empty() || alpn.size() > 255 ||
        encoded_bytes > 65535 - alpn.size() - 1)
      return false;
    const unsigned char length = static_cast<unsigned char>(alpn.size());
    output += hex_digits[length >> 4];
    output += hex_digits[length & 0x0f];
    for (const unsigned char byte : alpn) {
      output += hex_digits[byte >> 4];
      output += hex_digits[byte & 0x0f];
    }
    encoded_bytes += alpn.size() + 1;
  }
  return true;
}

static bool appendQuanXXrayTransport(const Proxy &proxy, bool reality,
                                     bool tls_active, std::string &output) {
  const std::string &transport = proxy.TransferProtocol;
  const bool fake_http = proxy.FakeType == "http";
  if (transport == "tcp") {
    if (fake_http) {
      if (tls_active || !quanxProxyScalarIsSafe(proxy.Host) ||
          !quanxProxyScalarIsSafe(proxy.Path))
        return false;
      output += ", obfs=http";
      if (!proxy.Host.empty())
        output += ", obfs-host=" + proxy.Host;
      if (!proxy.Path.empty())
        output += ", obfs-uri=" + proxy.Path;
      return true;
    }
    if (!proxy.FakeType.empty() && proxy.FakeType != "none")
      return false;
    if (!tls_active)
      return true;
    if (reality && proxy.ServerName.empty())
      return false;
    if (!quanxProxyScalarIsSafe(proxy.ServerName))
      return false;
    output += ", obfs=over-tls";
    if (!proxy.ServerName.empty())
      output += ", obfs-host=" + proxy.ServerName;
    return true;
  }

  if (transport != "ws" ||
      (!proxy.FakeType.empty() && proxy.FakeType != "none") ||
      !quanxProxyScalarIsSafe(proxy.Host) ||
      !quanxProxyScalarIsSafe(proxy.Path))
    return false;

  if (tls_active) {
    const std::string http_host =
        proxy.Host.empty() ? proxy.Hostname : proxy.Host;
    const std::string tls_host =
        proxy.ServerName.empty() ? proxy.Hostname : proxy.ServerName;
    if (!quanxProxyScalarIsSafe(http_host) ||
        !quanxProxyScalarIsSafe(tls_host) ||
        toLower(http_host) != toLower(tls_host))
      return false;
    output += ", obfs=wss";
    if (!http_host.empty())
      output += ", obfs-host=" + http_host;
  } else {
    output += ", obfs=ws";
    if (!proxy.Host.empty())
      output += ", obfs-host=" + proxy.Host;
  }
  if (!proxy.Path.empty())
    output += ", obfs-uri=" + proxy.Path;
  return true;
}

static bool loonProxyScalarIsSafe(const std::string &value) {
  return value.find_first_of(",\"\r\n") == std::string::npos;
}

static bool loonQuotedScalarIsSafe(const std::string &value) {
  // Loon documents double-quoted positional values, but does not document an
  // escaping convention. Reject ambiguous input instead of producing a node
  // whose credentials may be parsed differently by the client.
  return value.find_first_of("\\\"\r\n") == std::string::npos;
}

static bool loonPlainXrayTransportIsSafe(const Proxy &proxy) {
  return proxy.Edge.empty() && proxy.GRPCServiceName.empty() &&
         proxy.GRPCMode.empty() && proxy.QUICSecure.empty() &&
         proxy.QUICSecret.empty() && proxy.XrayLinkOptions.empty() &&
         proxy.UnderlyingProxy.empty() && !proxy.V2rayHttpUpgrade;
}

static std::string xrayLinkOption(const Proxy &proxy, const std::string &key) {
  const auto found = std::find_if(
      proxy.XrayLinkOptions.begin(), proxy.XrayLinkOptions.end(),
      [&](const auto &item) { return item.first == key; });
  return found == proxy.XrayLinkOptions.end() ? std::string() : found->second;
}

static std::string shareLinkHost(const std::string &host) {
  return host.find(':') == std::string::npos ? host : "[" + host + "]";
}

static bool isShadowsocks2022Method(const std::string &method) {
  return startsWith(method, "2022-");
}

static std::string shadowsocksShareLink(const Proxy &proxy,
                                        bool include_group,
                                        bool include_remark = true) {
  std::string userinfo;
  if (isShadowsocks2022Method(proxy.EncryptMethod)) {
    userinfo = urlEncode(proxy.EncryptMethod) + ":" + urlEncode(proxy.Password);
  } else {
    userinfo = urlSafeBase64Encode(proxy.EncryptMethod + ":" + proxy.Password);
  }

  std::vector<std::string> query;
  if (!proxy.Plugin.empty()) {
    std::string plugin = proxy.Plugin;
    if (!proxy.PluginOption.empty())
      plugin += ";" + proxy.PluginOption;
    query.emplace_back("plugin=" + urlEncode(plugin));
  }
  if (include_group && !proxy.Group.empty())
    query.emplace_back("group=" + urlSafeBase64Encode(proxy.Group));

  std::string result = "ss://" + userinfo + "@" +
                       shareLinkHost(proxy.Hostname) + ":" +
                       std::to_string(proxy.Port);
  if (!query.empty())
    result += "/?" + join(query, "&");
  if (include_remark && !proxy.Remark.empty())
    result += "#" + urlEncode(proxy.Remark);
  return result;
}

static std::string shadowsocksRShareLink(const Proxy &proxy) {
  return "ssr://" +
         urlSafeBase64Encode(
             shareLinkHost(proxy.Hostname) + ":" +
             std::to_string(proxy.Port) + ":" + proxy.Protocol + ":" +
             proxy.EncryptMethod + ":" + proxy.OBFS + ":" +
             urlSafeBase64Encode(proxy.Password) + "/?group=" +
             urlSafeBase64Encode(proxy.Group) + "&remarks=" +
             urlSafeBase64Encode(proxy.Remark) + "&obfsparam=" +
             urlSafeBase64Encode(proxy.OBFSParam) + "&protoparam=" +
             urlSafeBase64Encode(proxy.ProtocolParam));
}

static std::string hysteria2PortSpec(const Proxy &proxy) {
  if (proxy.Ports.empty())
    return std::to_string(proxy.Port);
  return proxy.Hysteria2PortsAreAdditional
             ? std::to_string(proxy.Port) + "," + proxy.Ports
             : proxy.Ports;
}

static std::string singBoxHysteria2PortSpec(const Proxy &proxy) {
  string_array ranges;
  for (std::string token : split(hysteria2PortSpec(proxy), ",")) {
    token = trim(token);
    const size_t separator = token.find('-');
    if (separator == std::string::npos)
      token += ":" + token;
    else
      token[separator] = ':';
    ranges.emplace_back(std::move(token));
  }
  return join(ranges, ",");
}

static bool generatorPortIsValid(const std::string &value) {
  if (value.empty() || !isNumeric(value))
    return false;
  try {
    const unsigned long port = std::stoul(value);
    return port > 0 && port <= 65535;
  } catch (const std::exception &) {
    return false;
  }
}

static bool singBoxHysteriaPortSpec(const Proxy &proxy,
                                    std::string &port_spec) {
  string_array ranges;
  for (std::string token : split(proxy.Ports, ",")) {
    token = trim(token);
    if (token.empty())
      return false;
    const size_t separator = token.find('-');
    if (separator == std::string::npos) {
      if (!generatorPortIsValid(token))
        return false;
      token += ":" + token;
    } else {
      if (token.find('-', separator + 1) != std::string::npos ||
          !generatorPortIsValid(token.substr(0, separator)) ||
          !generatorPortIsValid(token.substr(separator + 1)) ||
          std::stoul(token.substr(0, separator)) >
              std::stoul(token.substr(separator + 1)))
        return false;
      token[separator] = ':';
    }
    ranges.emplace_back(std::move(token));
  }
  if (ranges.empty())
    return false;
  port_spec = join(ranges, ",");
  return true;
}

static void appendShareQuery(std::vector<std::string> &query,
                             const std::string &key,
                             const std::string &value) {
  if (!value.empty())
    query.emplace_back(key + "=" + urlEncode(value));
}

static std::string joinShareQuery(const std::vector<std::string> &query) {
  return query.empty() ? std::string() : "?" + join(query, "&");
}

static bool hysteriaShareLinkFields(const Proxy &proxy,
                                    std::string &protocol,
                                    std::string &alpn,
                                    std::string &obfs_mode,
                                    std::string &up_mbps,
                                    std::string &down_mbps,
                                    bool &allow_insecure) {
  protocol = toLower(trim(proxy.FakeType));
  if (protocol.empty())
    protocol = "udp";
  int normalized_up = 0, normalized_down = 0;
  if ((protocol != "udp" && protocol != "wechat-video" &&
       protocol != "faketcp") ||
      !parseMbpsValue(proxy.UpMbps, normalized_up) || normalized_up <= 0 ||
      !parseMbpsValue(proxy.DownMbps, normalized_down) ||
      normalized_down <= 0 || !proxy.Auth.empty() ||
      !proxy.Ports.empty() || !proxy.HysteriaHopInterval.empty() ||
      !proxy.TransferProtocol.empty() || !proxy.UnderlyingProxy.empty() ||
      !proxy.Fingerprint.empty() || !proxy.PublicKey.empty() ||
      !proxy.ShortId.empty() || !proxy.TCPFastOpen.is_undef() ||
      !proxy.UDP.is_undef() || !proxy.TLS13.is_undef())
    return false;
  up_mbps = std::to_string(normalized_up);
  down_mbps = std::to_string(normalized_down);

  alpn = proxy.Alpn;
  if (!proxy.AlpnList.empty()) {
    if (proxy.AlpnList.size() != 1 ||
        (!alpn.empty() && alpn != proxy.AlpnList.front()))
      return false;
    alpn = proxy.AlpnList.front();
  }

  obfs_mode = toLower(trim(proxy.OBFS));
  if (!obfs_mode.empty() && obfs_mode != "xplus")
    return false;
  if (obfs_mode.empty() && !proxy.OBFSParam.empty())
    obfs_mode = "xplus";

  const std::string insecure = toLower(trim(proxy.Insecure));
  if (!insecure.empty() && insecure != "0" && insecure != "1" &&
      insecure != "false" && insecure != "true")
    return false;
  const bool insecure_text = insecure == "1" || insecure == "true";
  if (!proxy.AllowInsecure.is_undef() &&
      proxy.AllowInsecure.get() != insecure_text && !insecure.empty())
    return false;
  allow_insecure = insecure_text ||
                   (!proxy.AllowInsecure.is_undef() &&
                    proxy.AllowInsecure.get());
  return true;
}

static bool anyTlsShareLinkFields(const Proxy &proxy, std::string &sni,
                                  bool &allow_insecure) {
  sni = proxy.ServerName.empty() ? proxy.SNI : proxy.ServerName;
  if (!proxy.ServerName.empty() && !proxy.SNI.empty() &&
      proxy.ServerName != proxy.SNI)
    return false;
  const std::string tls = toLower(trim(proxy.TLSStr));
  if (proxy.Password.empty() || (!tls.empty() && tls != "tls") ||
      !proxy.PublicKey.empty() || !proxy.ShortId.empty() ||
      !proxy.Alpn.empty() || !proxy.AlpnList.empty() ||
      !proxy.Fingerprint.empty() || proxy.IdleSessionCheckInterval != 30 ||
      proxy.IdleSessionTimeout != 30 || proxy.MinIdleSession != 0 ||
      !proxy.UnderlyingProxy.empty() || !proxy.TCPFastOpen.is_undef() ||
      !proxy.UDP.is_undef() || !proxy.XUDP.is_undef() ||
      !proxy.TLS13.is_undef() ||
      (!proxy.Host.empty() && proxy.Host != proxy.Hostname))
    return false;
  allow_insecure = !proxy.AllowInsecure.is_undef() &&
                   proxy.AllowInsecure.get();
  return true;
}

std::string vmessLinkConstruct(const Proxy &proxy) {
  const std::string port = std::to_string(proxy.Port);
  const std::string alter_id = std::to_string(proxy.AlterId);
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  writer.StartObject();
  writer.Key("v");
  writer.String("2");
  writer.Key("ps");
  writer.String(proxy.Remark.data());
  writer.Key("add");
  writer.String(proxy.Hostname.data());
  writer.Key("port");
  writer.String(port.data());
  writer.Key("type");
  const std::string transport_type =
      (proxy.TransferProtocol == "grpc" || proxy.TransferProtocol == "xhttp")
          ? proxy.GRPCMode
          : proxy.FakeType;
  writer.String(transport_type.empty() ? "none" : transport_type.data());
  writer.Key("id");
  writer.String(proxy.UserId.data());
  writer.Key("aid");
  writer.String(alter_id.data());
  writer.Key("scy");
  writer.String(proxy.EncryptMethod.empty() ? "auto"
                                             : proxy.EncryptMethod.data());
  writer.Key("net");
  writer.String(proxy.TransferProtocol.empty() ? "tcp"
                                                : proxy.TransferProtocol.data());
  writer.Key("path");
  const std::string &transport_path =
      proxy.TransferProtocol == "quic"
          ? proxy.QUICSecret
          : (proxy.TransferProtocol == "grpc" &&
                     !proxy.GRPCServiceName.empty()
                 ? proxy.GRPCServiceName
                 : proxy.Path);
  writer.String(transport_path.data());
  writer.Key("host");
  writer.String((proxy.TransferProtocol == "quic" ? proxy.QUICSecure
                                                    : proxy.Host)
                    .data());
  writer.Key("tls");
  writer.String(proxy.TLSSecure
                    ? (proxy.TLSStr.empty() ? "tls" : proxy.TLSStr.data())
                    : "");
  if (!proxy.ServerName.empty()) {
    writer.Key("sni");
    writer.String(proxy.ServerName.data());
  }
  if (!proxy.AlpnList.empty()) {
    writer.Key("alpn");
    writer.String(join(proxy.AlpnList, ",").data());
  }
  if (!proxy.Fingerprint.empty()) {
    writer.Key("fp");
    writer.String(proxy.Fingerprint.data());
  }
  if (!proxy.PublicKey.empty()) {
    writer.Key("pbk");
    writer.String(proxy.PublicKey.data());
  }
  if (!proxy.ShortId.empty()) {
    writer.Key("sid");
    writer.String(proxy.ShortId.data());
  }
  for (const char *key : {"authority", "extra", "fm"}) {
    const std::string value = xrayLinkOption(proxy, key);
    if (!value.empty()) {
      writer.Key(key);
      writer.String(value.data());
    }
  }
  writer.EndObject();
  return sb.GetString();
}

namespace {

class PreparedRangeMatcher {
public:
  explicit PreparedRangeMatcher(const std::string &range) {
    const string_array values = split(range, ",");
    std::string range_begin_str, range_end_str;
    static const std::string reg_num = "-?\\d+",
                             reg_range = "(\\d+)-(\\d+)",
                             reg_not = "\\!-?(\\d+)",
                             reg_not_range = "\\!(\\d+)-(\\d+)",
                             reg_less = "(\\d+)-",
                             reg_more = "(\\d+)\\+";
    for (const std::string &value : values) {
      if (regMatch(value, reg_num)) {
        terms_.push_back({TermKind::Equal, to_int(value, INT_MAX), 0});
      } else if (regMatch(value, reg_range)) {
        regGetMatch(value, reg_range, 3,
                    static_cast<std::string *>(nullptr), &range_begin_str,
                    &range_end_str);
        terms_.push_back({TermKind::Range,
                          to_int(range_begin_str, INT_MAX),
                          to_int(range_end_str, INT_MIN)});
      } else if (regMatch(value, reg_not)) {
        terms_.push_back({TermKind::NotEqual,
                          to_int(regReplace(value, reg_not, "$1"), INT_MAX),
                          0});
      } else if (regMatch(value, reg_not_range)) {
        // Preserve the historical two-step parse and ordered overwrite
        // behavior instead of redefining the range grammar in this change.
        regGetMatch(value, reg_range, 3,
                    static_cast<std::string *>(nullptr), &range_begin_str,
                    &range_end_str);
        terms_.push_back({TermKind::NotRange,
                          to_int(range_begin_str, INT_MAX),
                          to_int(range_end_str, INT_MIN)});
      } else if (regMatch(value, reg_less)) {
        terms_.push_back({TermKind::LessOrEqual,
                          to_int(regReplace(value, reg_less, "$1"), INT_MAX),
                          0});
      } else if (regMatch(value, reg_more)) {
        terms_.push_back({TermKind::GreaterOrEqual,
                          to_int(regReplace(value, reg_more, "$1"), INT_MIN),
                          0});
      }
    }
  }

  bool matches(int target) const {
    bool match = false;
    for (const Term &term : terms_) {
      switch (term.kind) {
      case TermKind::Equal:
        if (term.first == target)
          match = true;
        break;
      case TermKind::Range:
        if (target >= term.first && target <= term.second)
          match = true;
        break;
      case TermKind::NotEqual:
        match = term.first != target;
        break;
      case TermKind::NotRange:
        match = !(target >= term.first && target <= term.second);
        break;
      case TermKind::LessOrEqual:
        if (term.first >= target)
          match = true;
        break;
      case TermKind::GreaterOrEqual:
        if (term.first <= target)
          match = true;
        break;
      }
    }
    return match;
  }

private:
  enum class TermKind {
    Equal,
    Range,
    NotEqual,
    NotRange,
    LessOrEqual,
    GreaterOrEqual,
  };

  struct Term {
    TermKind kind;
    int first;
    int second;
  };

  std::vector<Term> terms_;
};

class PreparedGroupRule {
public:
  explicit PreparedGroupRule(const std::string &rule) {
    std::string target;
    static const std::string groupid_regex =
        R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)";
    static const std::string group_regex =
        R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
    static const std::string type_regex =
        R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)";
    static const std::string port_regex =
        R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)";
    static const std::string server_regex =
        R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";

    if (startsWith(rule, "!!GROUP=")) {
      kind_ = Kind::Group;
      regGetMatch(rule, group_regex, 3,
                  static_cast<std::string *>(nullptr), &target, &real_rule_);
      selector_regex_.emplace(target, CompiledRegexMode::Search);
    } else if (startsWith(rule, "!!GROUPID=") ||
               startsWith(rule, "!!INSERT=")) {
      kind_ = startsWith(rule, "!!INSERT=") ? Kind::Insert : Kind::GroupId;
      regGetMatch(rule, groupid_regex, 3,
                  static_cast<std::string *>(nullptr), &target, &real_rule_);
      range_matcher_.emplace(target);
    } else if (startsWith(rule, "!!TYPE=")) {
      kind_ = Kind::Type;
      regGetMatch(rule, type_regex, 3,
                  static_cast<std::string *>(nullptr), &target, &real_rule_);
      selector_regex_.emplace(target, CompiledRegexMode::FullMatch);
    } else if (startsWith(rule, "!!PORT=")) {
      kind_ = Kind::Port;
      regGetMatch(rule, port_regex, 3,
                  static_cast<std::string *>(nullptr), &target, &real_rule_);
      range_matcher_.emplace(target);
    } else if (startsWith(rule, "!!SERVER=")) {
      kind_ = Kind::Server;
      regGetMatch(rule, server_regex, 3,
                  static_cast<std::string *>(nullptr), &target, &real_rule_);
      selector_regex_.emplace(target, CompiledRegexMode::Search);
    } else {
      real_rule_ = rule;
    }
  }

  bool matches(const Proxy &node) {
    if (!matchesSelector(node))
      return false;
    if (real_rule_.empty())
      return true;
    if (!remark_regex_)
      remark_regex_.emplace(real_rule_, CompiledRegexMode::Search);
    return remark_regex_->matches(node.Remark);
  }

private:
  enum class Kind { Plain, Group, GroupId, Insert, Type, Port, Server };

  bool matchesSelector(const Proxy &node) {
    static const std::map<ProxyType, const char *> types = {
        {ProxyType::Shadowsocks, "SS"},      {ProxyType::ShadowsocksR, "SSR"},
        {ProxyType::VMess, "VMESS"},         {ProxyType::Trojan, "TROJAN"},
        {ProxyType::Snell, "SNELL"},         {ProxyType::HTTP, "HTTP"},
        {ProxyType::HTTPS, "HTTPS"},         {ProxyType::SOCKS5, "SOCKS5"},
        {ProxyType::WireGuard, "WIREGUARD"}, {ProxyType::VLESS, "VLESS"},
        {ProxyType::Hysteria, "HYSTERIA"},   {ProxyType::Hysteria2, "HYSTERIA2"},
        {ProxyType::TUIC, "TUIC"},           {ProxyType::AnyTLS, "ANYTLS"},
        {ProxyType::Naive, "NAIVE"},         {ProxyType::Mieru, "MIERU"}};

    switch (kind_) {
    case Kind::Plain:
      return true;
    case Kind::Group:
      return selector_regex_ && selector_regex_->matches(node.Group);
    case Kind::GroupId:
      return range_matcher_ && range_matcher_->matches(node.GroupId);
    case Kind::Insert:
      return range_matcher_ && range_matcher_->matches(-node.GroupId);
    case Kind::Type:
      return node.Type != ProxyType::Unknown && selector_regex_ &&
             selector_regex_->matches(types.at(node.Type));
    case Kind::Port:
      return range_matcher_ && range_matcher_->matches(node.Port);
    case Kind::Server:
      return selector_regex_ && selector_regex_->matches(node.Hostname);
    }
    return false;
  }

  Kind kind_ = Kind::Plain;
  std::string real_rule_;
  std::optional<CompiledRegex> selector_regex_;
  std::optional<PreparedRangeMatcher> range_matcher_;
  std::optional<CompiledRegex> remark_regex_;
};

} // namespace

bool matchRange(const std::string &range, int target) {
  string_array vArray = split(range, ",");
  bool match = false;
  std::string range_begin_str, range_end_str;
  int range_begin, range_end;
  static const std::string reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)",
                           reg_not = "\\!-?(\\d+)",
                           reg_not_range = "\\!(\\d+)-(\\d+)",
                           reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
  for (std::string &x : vArray) {
    if (regMatch(x, reg_num)) {
      if (to_int(x, INT_MAX) == target)
        match = true;
    } else if (regMatch(x, reg_range)) {
      regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
      range_begin = to_int(range_begin_str, INT_MAX);
      range_end = to_int(range_end_str, INT_MIN);
      if (target >= range_begin && target <= range_end)
        match = true;
    } else if (regMatch(x, reg_not)) {
      match = true;
      if (to_int(regReplace(x, reg_not, "$1"), INT_MAX) == target)
        match = false;
    } else if (regMatch(x, reg_not_range)) {
      match = true;
      regGetMatch(x, reg_range, 3, 0, &range_begin_str, &range_end_str);
      range_begin = to_int(range_begin_str, INT_MAX);
      range_end = to_int(range_end_str, INT_MIN);
      if (target >= range_begin && target <= range_end)
        match = false;
    } else if (regMatch(x, reg_less)) {
      if (to_int(regReplace(x, reg_less, "$1"), INT_MAX) >= target)
        match = true;
    } else if (regMatch(x, reg_more)) {
      if (to_int(regReplace(x, reg_more, "$1"), INT_MIN) <= target)
        match = true;
    }
  }
  return match;
}

bool applyMatcher(const std::string &rule, std::string &real_rule,
                  const Proxy &node) {
  std::string target, ret_real_rule;
  static const std::string
      groupid_regex = R"(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)",
      group_regex = R"(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)";
  static const std::string type_regex = R"(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)",
                           port_regex = R"(^!!(?:PORT)=(.+?)(?:!!(.*))?$)",
                           server_regex = R"(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)";
  static const std::map<ProxyType, const char *> types = {
      {ProxyType::Shadowsocks, "SS"},      {ProxyType::ShadowsocksR, "SSR"},
      {ProxyType::VMess, "VMESS"},         {ProxyType::Trojan, "TROJAN"},
      {ProxyType::Snell, "SNELL"},         {ProxyType::HTTP, "HTTP"},
      {ProxyType::HTTPS, "HTTPS"},         {ProxyType::SOCKS5, "SOCKS5"},
      {ProxyType::WireGuard, "WIREGUARD"}, {ProxyType::VLESS, "VLESS"},
      {ProxyType::Hysteria, "HYSTERIA"},   {ProxyType::Hysteria2, "HYSTERIA2"},
      {ProxyType::TUIC, "TUIC"},           {ProxyType::AnyTLS, "ANYTLS"},
      {ProxyType::Naive, "NAIVE"},         {ProxyType::Mieru, "MIERU"}};
  if (startsWith(rule, "!!GROUP=")) {
    regGetMatch(rule, group_regex, 3, 0, &target, &ret_real_rule);
    real_rule = ret_real_rule;
    return regFind(node.Group, target);
  } else if (startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT=")) {
    int dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
    regGetMatch(rule, groupid_regex, 3, 0, &target, &ret_real_rule);
    real_rule = ret_real_rule;
    return matchRange(target, dir * node.GroupId);
  } else if (startsWith(rule, "!!TYPE=")) {
    regGetMatch(rule, type_regex, 3, 0, &target, &ret_real_rule);
    real_rule = ret_real_rule;
    if (node.Type == ProxyType::Unknown)
      return false;
    return regMatch(types.at(node.Type), target);
  } else if (startsWith(rule, "!!PORT=")) {
    regGetMatch(rule, port_regex, 3, 0, &target, &ret_real_rule);
    real_rule = ret_real_rule;
    return matchRange(target, node.Port);
  } else if (startsWith(rule, "!!SERVER=")) {
    regGetMatch(rule, server_regex, 3, 0, &target, &ret_real_rule);
    real_rule = ret_real_rule;
    return regFind(node.Hostname, target);
  } else
    real_rule = rule;
  return true;
}

static bool parseProviderGroupIdMatcher(const std::string &rule,
                                        std::string &target,
                                        std::string &real_rule) {
  static const std::string groupid_regex =
      R"(^!!GROUPID=([\d\-+!,]+)(?:!!(.*))?$)";
  if (!startsWith(rule, "!!GROUPID="))
    return false;
  target.clear();
  real_rule.clear();
  return regGetMatch(rule, groupid_regex, 3,
                     static_cast<std::string *>(nullptr), &target,
                     &real_rule) == 0 &&
         !target.empty();
}

static bool isProviderRegexRule(const std::string &rule) {
  return !rule.empty() && rule[0] != '[' && rule != "DIRECT" &&
         rule != "REJECT";
}

static YAML::Node providersMatchingGroupId(
    const std::string &target, const std::vector<ProxyProvider> &providers) {
  YAML::Node use_node(YAML::NodeType::Sequence);
  for (const ProxyProvider &p : providers) {
    if (p.groupId >= 0 && matchRange(target, p.groupId))
      use_node.push_back(p.name);
  }
  return use_node;
}

static YAML::Node providersMatchingGroupTag(
    const std::string &target, const std::vector<ProxyProvider> &providers) {
  YAML::Node use_node(YAML::NodeType::Sequence);
  for (const ProxyProvider &p : providers) {
    if (!p.tag.empty() && regFind(p.tag, target))
      use_node.push_back(p.name);
  }
  return use_node;
}

using RemarkSet = std::unordered_set<std::string_view>;

void processRemark(std::string &remark, const RemarkSet &used_remarks,
                   bool proc_comma = true) {
  // Replace every '=' with '-' in the remark string to avoid parse errors from
  // the clients.
  //     Surge is tested to yield an error when handling '=' in the remark
  //     string, not sure if other clients have the same problem.
  std::replace(remark.begin(), remark.end(), '=', '-');

  if (proc_comma) {
    if (remark.find(',') != std::string::npos) {
      remark.insert(0, "\"");
      remark.append("\"");
    }
  }
  std::string tempRemark = remark;
  int cnt = 2;
  while (used_remarks.find(tempRemark) != used_remarks.end()) {
    tempRemark = remark + " " + std::to_string(cnt);
    cnt++;
  }
  remark = tempRemark;
}

void groupGenerate(const std::string &rule, std::vector<Proxy> &nodelist,
                   string_array &filtered_nodelist, bool add_direct,
                   extra_settings &ext) {
  if (startsWith(rule, "[]") && add_direct) {
    filtered_nodelist.emplace_back(rule.substr(2));
  }
#ifndef NO_JS_RUNTIME
  else if (startsWith(rule, "script:") && ext.authorized) {
    script_safe_runner(
        ext.js_runtime, ext.js_context,
        [&](qjs::Context &ctx) {
          std::string script = fileGet(rule.substr(7), true);
          try {
            ctx.eval(script);
            auto filter =
                (std::function<std::string(const std::vector<Proxy> &)>)
                    ctx.eval("filter");
            std::string result_list = filter(nodelist);
            filtered_nodelist = split(regTrim(result_list), "\n");
          } catch (qjs::exception) {
            script_print_stack(ctx);
          }
        },
        effectiveSettings().scriptCleanContext);
  }
#endif // NO_JS_RUNTIME
  else {
    PreparedGroupRule prepared(rule);
    std::unordered_set<std::string> seen(filtered_nodelist.begin(),
                                         filtered_nodelist.end());
    for (Proxy &x : nodelist) {
      if (prepared.matches(x) && seen.insert(x.Remark).second)
        filtered_nodelist.emplace_back(x.Remark);
    }
  }
}

void proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode,
                  const ProxyGroupConfigs &extra_proxy_group, bool clashR,
                  extra_settings &ext) {
  YAML::Node proxies, original_groups;
  std::vector<Proxy> nodelist;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());
  /// proxies style

  bool proxy_block = false, proxy_compact = false, group_block = false,
       group_compact = false;
  switch (hash_(ext.clash_proxies_style)) {
  case "block"_hash:
    proxy_block = true;
    break;
  default:
  case "flow"_hash:
    break;
  case "compact"_hash:
    proxy_compact = true;
    break;
  }
  switch (hash_(ext.clash_proxy_groups_style)) {
  case "block"_hash:
    group_block = true;
    break;
  default:
  case "flow"_hash:
    break;
  case "compact"_hash:
    group_compact = true;
    break;
  }

  for (Proxy &x : nodes) {
    YAML::Node singleproxy;

    std::string type = getProxyTypeName(x.Type);
    std::string pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
    if (ext.append_proxy_type)
      x.Remark = "[" + type + "] " + x.Remark;

    processRemark(x.Remark, used_remarks, false);

    tribool udp = ext.udp;
    tribool xudp = ext.xudp;
    tribool scv = ext.skip_cert_verify;
    tribool tfo = ext.tfo;
    udp.define(x.UDP);
    xudp.define(x.XUDP);
    scv.define(x.AllowInsecure);
    tfo.define(x.TCPFastOpen);
    singleproxy["name"] = x.Remark;
    singleproxy["server"] = x.Hostname;
    singleproxy["port"] = x.Port;

    // Mihomo-produced nodes keep one complete typed mapping. Clash output is
    // derived from that canonical document, while legacy target generators
    // continue to use the compatibility projection in Proxy.
    if (!x.CanonicalProxyJson.empty()) {
      try {
        singleproxy = buildCanonicalClashProxy(
            x, ClashProxyOverlay{udp, scv, tfo, xudp});
      } catch (const std::exception &e) {
        writeLog(LOG_LEVEL_ERROR, "MIHOMO_CANONICAL_PROXY_INVALID detail=" +
                        summarizeSensitiveTextForLog(e.what()));
        continue;
      }

      // Preserve the existing compact representation for Mihomo-parsed nodes.
      singleproxy.SetStyle(YAML::EmitterStyle::Flow);
      proxies.push_back(singleproxy);
      nodelist.emplace_back(x);
      used_remarks.emplace(x.Remark);

      continue;
    }

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      // latest clash core removed support for chacha20 encryption
      if (ext.filter_deprecated && x.EncryptMethod == "chacha20")
        continue;
      singleproxy["type"] = "ss";
      singleproxy["cipher"] = x.EncryptMethod;
      singleproxy["password"] = x.Password;
      if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) &&
          !x.Password.empty())
        singleproxy["password"].SetTag("str");
      switch (hash_(x.Plugin)) {
      case "simple-obfs"_hash:
      case "obfs-local"_hash:
        singleproxy["plugin"] = "obfs";
        singleproxy["plugin-opts"]["mode"] =
            urlDecode(getUrlArg(pluginopts, "obfs"));
        singleproxy["plugin-opts"]["host"] =
            urlDecode(getUrlArg(pluginopts, "obfs-host"));
        break;
      case "v2ray-plugin"_hash:
        singleproxy["plugin"] = "v2ray-plugin";
        singleproxy["plugin-opts"]["mode"] = getUrlArg(pluginopts, "mode");
        singleproxy["plugin-opts"]["host"] = getUrlArg(pluginopts, "host");
        singleproxy["plugin-opts"]["path"] = getUrlArg(pluginopts, "path");
        singleproxy["plugin-opts"]["tls"] =
            pluginopts.find("tls") != std::string::npos;
        singleproxy["plugin-opts"]["mux"] =
            pluginopts.find("mux") != std::string::npos;
        if (!scv.is_undef())
          singleproxy["plugin-opts"]["skip-cert-verify"] = scv.get();
        break;
      }
      break;
    case ProxyType::VMess:
      singleproxy["type"] = "vmess";
      singleproxy["uuid"] = x.UserId;
      singleproxy["alterId"] = x.AlterId;
      singleproxy["cipher"] = x.EncryptMethod;
      singleproxy["tls"] = x.TLSSecure;
      if (!x.AlpnList.empty()) {
        for (auto &item : x.AlpnList) {
          singleproxy["alpn"].push_back(item);
        }
      } else if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (!x.ServerName.empty())
        singleproxy["servername"] = x.ServerName;
      switch (hash_(x.TransferProtocol)) {
      case "tcp"_hash:
        break;
      case "ws"_hash:
        singleproxy["network"] = x.TransferProtocol;
        if (ext.clash_new_field_name) {
          singleproxy["ws-opts"]["path"] = x.Path;
          if (!x.Host.empty())
            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
          if (!x.Edge.empty())
            singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
        } else {
          singleproxy["ws-path"] = x.Path;
          if (!x.Host.empty())
            singleproxy["ws-headers"]["Host"] = x.Host;
          if (!x.Edge.empty())
            singleproxy["ws-headers"]["Edge"] = x.Edge;
        }
        break;
      case "http"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["http-opts"]["method"] = "GET";
        singleproxy["http-opts"]["path"].push_back(x.Path);
        if (!x.Host.empty())
          singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
        if (!x.Edge.empty())
          singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
        break;
      case "h2"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["h2-opts"]["path"] = x.Path;
        if (!x.Host.empty())
          singleproxy["h2-opts"]["host"].push_back(x.Host);
        break;
      case "grpc"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["servername"] = x.Host;
        singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
        break;
      default:
        continue;
      }
      break;
    case ProxyType::ShadowsocksR:
      // ignoring all nodes with unsupported obfs, protocols and encryption
      if (ext.filter_deprecated) {
        if (!clashR &&
            std::find(clash_ssr_ciphers.cbegin(), clash_ssr_ciphers.cend(),
                      x.EncryptMethod) == clash_ssr_ciphers.cend())
          continue;
        if (std::find(clashr_protocols.cbegin(), clashr_protocols.cend(),
                      x.Protocol) == clashr_protocols.cend())
          continue;
        if (std::find(clashr_obfs.cbegin(), clashr_obfs.cend(), x.OBFS) ==
            clashr_obfs.cend())
          continue;
      }

      singleproxy["type"] = "ssr";
      singleproxy["cipher"] =
          x.EncryptMethod == "none" ? "dummy" : x.EncryptMethod;
      singleproxy["password"] = x.Password;
      if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) &&
          !x.Password.empty())
        singleproxy["password"].SetTag("str");
      singleproxy["protocol"] = x.Protocol;
      singleproxy["obfs"] = x.OBFS;
      if (clashR) {
        singleproxy["protocolparam"] = x.ProtocolParam;
        singleproxy["obfsparam"] = x.OBFSParam;
      } else {
        singleproxy["protocol-param"] = x.ProtocolParam;
        singleproxy["obfs-param"] = x.OBFSParam;
      }
      break;
    case ProxyType::SOCKS5:
      singleproxy["type"] = "socks5";
      if (!x.Username.empty())
        singleproxy["username"] = x.Username;
      if (!x.Password.empty()) {
        singleproxy["password"] = x.Password;
        if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
          singleproxy["password"].SetTag("str");
      }
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      break;
    case ProxyType::HTTP:
    case ProxyType::HTTPS:
      singleproxy["type"] = "http";
      if (!x.Username.empty())
        singleproxy["username"] = x.Username;
      if (!x.Password.empty()) {
        singleproxy["password"] = x.Password;
        if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit))
          singleproxy["password"].SetTag("str");
      }
      singleproxy["tls"] = x.TLSSecure;
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      break;
    case ProxyType::Trojan:
      singleproxy["type"] = "trojan";
      singleproxy["password"] = x.Password;
      if (!x.ServerName.empty())
        singleproxy["sni"] = x.ServerName;
      else if (!x.Host.empty()) {
        singleproxy["sni"] = x.Host;
      }
      if (!x.AlpnList.empty()) {
        for (auto &item : x.AlpnList) {
          singleproxy["alpn"].push_back(item);
        }
      } else if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) &&
          !x.Password.empty()) {
        singleproxy["password"].SetTag("str");
      }
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      switch (hash_(x.TransferProtocol)) {
      case "tcp"_hash:
        break;
      case "grpc"_hash:
        singleproxy["network"] = x.TransferProtocol;
        if (!x.Path.empty())
          singleproxy["grpc-opts"]["grpc-service-name"] = x.Path;
        break;
      case "ws"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["ws-opts"]["path"] = x.Path;
        if (!x.Host.empty())
          singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
        break;
      }
      break;
    case ProxyType::Snell:
      if ((clashR && x.SnellVersion >= 4) || x.SnellVersion > 5 ||
          !x.Path.empty() || !x.SnellMode.empty() || x.SnellUDPPort != 0 ||
          !x.SnellUserKey.empty() || !x.SnellNetwork.empty() ||
          (!x.SnellReuse.is_undef() && x.SnellVersion != 4 &&
           x.SnellVersion != 5))
        continue;
      singleproxy["type"] = "snell";
      singleproxy["psk"] = x.Password;
      if (x.SnellVersion != 0)
        singleproxy["version"] = x.SnellVersion;
      if (!x.SnellReuse.is_undef())
        singleproxy["reuse"] = x.SnellReuse.get();
      if (udp && x.SnellVersion >= 3 && x.SnellVersion <= 5)
        singleproxy["udp"] = true;
      {
        const std::string snell_obfs =
            !x.ShadowTLSPassword.empty() ? "shadow-tls" : x.OBFS;
        if (!snell_obfs.empty()) {
          singleproxy["obfs-opts"]["mode"] = snell_obfs;
          const std::string &snell_host = x.ShadowTLSSNI.empty()
                                              ? x.Host
                                              : x.ShadowTLSSNI;
          if (!snell_host.empty())
            singleproxy["obfs-opts"]["host"] = snell_host;
        }
        if (snell_obfs == "shadow-tls") {
          if (!x.ShadowTLSPassword.empty())
            singleproxy["obfs-opts"]["password"] = x.ShadowTLSPassword;
          if (x.ShadowTLSVersion > 0)
            singleproxy["obfs-opts"]["version"] = x.ShadowTLSVersion;
          if (!x.AlpnList.empty())
            singleproxy["obfs-opts"]["alpn"] = x.AlpnList;
        }
      }
      if (!x.Fingerprint.empty())
        singleproxy["client-fingerprint"] = x.Fingerprint;
      if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) &&
          !x.Password.empty())
        singleproxy["psk"].SetTag("str");
      break;
    case ProxyType::WireGuard:
      if (!wireGuardStructuredConfigIsSafe(x))
        continue;
      singleproxy["type"] = "wireguard";
      singleproxy["private-key"] = x.PrivateKey;
      {
        const auto addresses = wireGuardLocalAddresses(x);
        for (const std::string &address : addresses) {
          const std::string bare = wireGuardAddressWithoutPrefix(address);
          if (singleproxy["ip"].IsDefined() || !isIPv4(bare)) {
            if (!singleproxy["ipv6"].IsDefined() && isIPv6(bare))
              singleproxy["ipv6"] = bare;
          } else {
            singleproxy["ip"] = bare;
          }
        }
      }
      {
        const auto peers = wireGuardPeers(x);
        if (peers.size() == 1) {
          const WireGuardPeer &peer = peers.front();
          singleproxy["server"] = peer.Hostname;
          singleproxy["port"] = peer.Port;
          singleproxy["public-key"] = peer.PublicKey;
          if (!peer.PreSharedKey.empty())
            singleproxy["pre-shared-key"] = peer.PreSharedKey;
          if (!peer.Reserved.empty())
            for (const std::string &value : split(peer.Reserved, ","))
              singleproxy["reserved"].push_back(to_int(trim(value), 0));
        } else {
          singleproxy.remove("server");
          singleproxy.remove("port");
          for (const WireGuardPeer &peer : peers) {
            YAML::Node yaml_peer;
            yaml_peer["server"] = peer.Hostname;
            yaml_peer["port"] = peer.Port;
            yaml_peer["public-key"] = peer.PublicKey;
            if (!peer.PreSharedKey.empty())
              yaml_peer["pre-shared-key"] = peer.PreSharedKey;
            if (!peer.AllowedIPs.empty())
              for (const std::string &allowed : split(peer.AllowedIPs, ","))
                yaml_peer["allowed-ips"].push_back(trim(allowed));
            if (!peer.Reserved.empty())
              for (const std::string &value : split(peer.Reserved, ","))
                yaml_peer["reserved"].push_back(to_int(trim(value), 0));
            if (peer.KeepAlive > 0)
              yaml_peer["persistent-keepalive"] = peer.KeepAlive;
            singleproxy["peers"].push_back(yaml_peer);
          }
        }
      }
      if (!x.DnsServers.empty())
        singleproxy["dns"] = x.DnsServers;
      if (x.Mtu > 0)
        singleproxy["mtu"] = x.Mtu;
      break;
    case ProxyType::Hysteria:
      if (x.AuthStr.empty() && !x.Auth.empty())
        continue;
      if (x.UpMbps.empty() || x.DownMbps.empty() ||
          !x.TransferProtocol.empty() || !x.HysteriaHopInterval.empty())
        continue;
      singleproxy["type"] = "hysteria";
      if (!x.AuthStr.empty())
        singleproxy["auth-str"] = x.AuthStr;
      singleproxy["up"] = x.UpMbps;
      singleproxy["down"] = x.DownMbps;
      if (!x.Ports.empty()) {
        singleproxy["ports"] = x.Ports;
      }
      if (!tfo.is_undef()) {
        singleproxy["fast-open"] = tfo.get();
      }
      if (!x.FakeType.empty())
        singleproxy["protocol"] = x.FakeType;
      if (!x.ServerName.empty())
        singleproxy["sni"] = x.ServerName;
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (x.Insecure == "1")
        singleproxy["skip-cert-verify"] = true;
      if (!x.AlpnList.empty())
        singleproxy["alpn"] = x.AlpnList;
      else if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      if (!x.OBFSParam.empty())
        singleproxy["obfs"] = x.OBFSParam;
      break;
    case ProxyType::Hysteria2:
      if (!x.Hysteria2RealmUrl.empty() ||
          !x.Hysteria2GeckoMinPacketSize.empty() ||
          !x.Hysteria2GeckoMaxPacketSize.empty())
        continue;
      singleproxy["type"] = "hysteria2";
      singleproxy["password"] = x.Password;
      singleproxy["auth"] = x.Password;
      if (!x.PublicKey.empty()) {
        singleproxy["ca-str"] = x.PublicKey;
      }
      if (!x.Fingerprint.empty())
        singleproxy["fingerprint"] = x.Fingerprint;
      if (!x.ServerName.empty()) {
        singleproxy["sni"] = x.ServerName;
      }
      if (!x.UpMbps.empty())
        singleproxy["up"] = x.UpMbps;
      if (!x.DownMbps.empty())
        singleproxy["down"] = x.DownMbps;
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      if (!x.OBFSParam.empty())
        singleproxy["obfs"] = x.OBFSParam;
      if (!x.OBFSPassword.empty())
        singleproxy["obfs-password"] = x.OBFSPassword;
      if (!x.Ports.empty())
        singleproxy["ports"] = hysteria2PortSpec(x);
      break;
    case ProxyType::TUIC:
      singleproxy["type"] = "tuic";
      if (!x.Password.empty()) {
        singleproxy["password"] = x.Password;
      }
      if (!x.UserId.empty()) {
        singleproxy["uuid"] = x.UserId;
      }
      if (!x.token.empty()) {
        singleproxy["token"] = x.token;
      }
      if (!x.ServerName.empty()) {
        singleproxy["sni"] = x.ServerName;
      }
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      singleproxy["disable-sni"] = x.DisableSni.get();
      singleproxy["reduce-rtt"] = x.ReduceRtt.get();
      singleproxy["request-timeout"] = x.RequestTimeout;
      if (!x.UdpRelayMode.empty()) {
        if (x.UdpRelayMode == "native" || x.UdpRelayMode == "quic") {
          singleproxy["udp-relay-mode"] = x.UdpRelayMode;
        }
      }
      if (!x.CongestionControl.empty()) {
        singleproxy["congestion-controller"] = x.CongestionControl;
      }
      break;
    case ProxyType::AnyTLS:
      singleproxy["type"] = "anytls";
      if (!x.Password.empty()) {
        singleproxy["password"] = x.Password;
      }
      if (!x.Fingerprint.empty()) {
        singleproxy["client-fingerprint"] = x.Fingerprint;
      }
      if (!udp.is_undef()) {
        singleproxy["udp"] = udp.get();
      }
      if (!x.ServerName.empty()) {
        singleproxy["sni"] = x.SNI;
      }
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (!x.AlpnList.empty()) {
        for (auto &item : x.AlpnList) {
          singleproxy["alpn"].push_back(item);
        }
      }
      if (x.IdleSessionCheckInterval != 30)
        singleproxy["idle-session-check-interval"] =
            x.IdleSessionCheckInterval;
      if (x.IdleSessionTimeout != 30)
        singleproxy["idle-session-timeout"] = x.IdleSessionTimeout;
      if (x.MinIdleSession != 0)
        singleproxy["min-idle-session"] = x.MinIdleSession;
      break;
    case ProxyType::Mieru:
      // Mihomo has no per-proxy Mieru MTU field. Do not silently emit a node
      // whose explicit simple-link MTU would be lost.
      if (x.Mtu > 0)
        continue;
      singleproxy["type"] = "mieru";
      if (!x.Password.empty()) {
        singleproxy["password"] = x.Password;
      }
      if (!x.Username.empty()) {
        singleproxy["username"] = x.Username;
      }
      if (!x.Multiplexing.empty()) {
        singleproxy["multiplexing"] = x.Multiplexing;
      }
      if (!x.TransferProtocol.empty()) {
        singleproxy["transport"] = x.TransferProtocol;
      }
      if (!x.MieruHandshakeMode.empty()) {
        singleproxy["handshake-mode"] = x.MieruHandshakeMode;
      }
      if (!x.MieruTrafficPattern.empty()) {
        singleproxy["traffic-pattern"] = x.MieruTrafficPattern;
      }
      if (!x.Ports.empty()) {
        singleproxy["port-range"] = x.Ports;
        singleproxy.remove("port");
      }
      break;
    case ProxyType::VLESS:
      singleproxy["type"] = "vless";
      singleproxy["uuid"] = x.UserId;
      singleproxy["tls"] = x.TLSSecure;
      if (!x.AlpnList.empty()) {
        for (auto &item : x.AlpnList) {
          singleproxy["alpn"].push_back(item);
        }
      }
      if (!tfo.is_undef())
        singleproxy["tfo"] = tfo.get();
      if (xudp && udp)
        singleproxy["xudp"] = true;
      if (!x.PacketEncoding.empty()) {
        singleproxy["packet-encoding"] = x.PacketEncoding;
      }
      if (!x.Flow.empty())
        singleproxy["flow"] = x.Flow;
      if (!scv.is_undef())
        singleproxy["skip-cert-verify"] = scv.get();
      if (!x.PublicKey.empty()) {
        singleproxy["reality-opts"]["public-key"] = x.PublicKey;
      }
      if (!x.ServerName.empty())
        singleproxy["servername"] = x.ServerName;
      if (!x.ShortId.empty()) {
        singleproxy["reality-opts"]["short-id"] = "" + x.ShortId;
      }
      if (!x.PublicKey.empty() || x.Flow == "xtls-rprx-vision") {
        singleproxy["client-fingerprint"] = "chrome";
      }
      if (!x.Fingerprint.empty()) {
        singleproxy["client-fingerprint"] = x.Fingerprint;
      }
      switch (hash_(x.TransferProtocol)) {
      case "tcp"_hash:
        singleproxy["network"] = x.TransferProtocol;
        break;
      case "ws"_hash:
        singleproxy["network"] = x.TransferProtocol;
        if (ext.clash_new_field_name) {
          singleproxy["ws-opts"]["path"] = x.Path;
          if (!x.Host.empty())
            singleproxy["ws-opts"]["headers"]["Host"] = x.Host;
          if (!x.Edge.empty())
            singleproxy["ws-opts"]["headers"]["Edge"] = x.Edge;
          if (!x.V2rayHttpUpgrade.is_undef()) {
            singleproxy["ws-opts"]["v2ray-http-upgrade"] =
                x.V2rayHttpUpgrade.get();
          }
        } else {
          singleproxy["ws-path"] = x.Path;
          if (!x.Host.empty())
            singleproxy["ws-headers"]["Host"] = x.Host;
          if (!x.Edge.empty())
            singleproxy["ws-headers"]["Edge"] = x.Edge;
        }
        break;
      case "http"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["http-opts"]["method"] = "GET";
        singleproxy["http-opts"]["path"].push_back(x.Path);
        if (!x.Host.empty())
          singleproxy["http-opts"]["headers"]["Host"].push_back(x.Host);
        if (!x.Edge.empty())
          singleproxy["http-opts"]["headers"]["Edge"].push_back(x.Edge);
        break;
      case "h2"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["h2-opts"]["path"] = x.Path;
        if (!x.Host.empty())
          singleproxy["h2-opts"]["host"].push_back(x.Host);
        break;
      case "grpc"_hash:
        singleproxy["network"] = x.TransferProtocol;
        singleproxy["grpc-opts"]["grpc-mode"] = x.GRPCMode;
        singleproxy["grpc-opts"]["grpc-service-name"] = x.GRPCServiceName;
        break;
      default:
        continue;
      }
      break;
    default:
      continue;
    }

    // UDP is not supported yet in clash using snell
    // sees in
    // https://dreamacro.github.io/clash/configuration/outbound.html#snell
    if (udp && x.Type != ProxyType::Snell && x.Type != ProxyType::TUIC)
      singleproxy["udp"] = true;
    if (proxy_block)
      singleproxy.SetStyle(YAML::EmitterStyle::Block);
    else
      singleproxy.SetStyle(YAML::EmitterStyle::Flow);
    proxies.push_back(singleproxy);
    used_remarks.emplace(x.Remark);
    nodelist.emplace_back(x);
  }

  if (proxy_compact)
    proxies.SetStyle(YAML::EmitterStyle::Flow);

  if (ext.nodelist) {
    YAML::Node provider;
    provider["proxies"] = proxies;
    yamlnode.reset(provider);
    return;
  }

  // 只有当存在节点时才写入 proxies 字段
  // 纯 proxy-provider 模式下不生成 proxies 字段（模板中已移除占位符）
  if (!nodes.empty() || proxies.size() > 0) {
    if (ext.clash_new_field_name)
      yamlnode["proxies"] = proxies;
    else
      yamlnode["Proxy"] = proxies;
  }

  // 立即生成 proxy-providers 配置段（在 proxy-groups 之前）
  if (ext.use_proxy_provider && !ext.providers.empty()) {
    YAML::Node provider_node;

    for (const ProxyProvider &p : ext.providers) {
      YAML::Node single_provider;
      single_provider["type"] = "http";
      single_provider["url"] = p.url;
      single_provider["interval"] = p.interval;
      if (p.proxy_direct)
        single_provider["proxy"] = "DIRECT";
      single_provider["path"] = p.path;

      // 添加过滤器
      if (!p.filter.empty()) {
        single_provider["filter"] = p.filter;
      }
      if (!p.exclude_filter.empty()) {
        single_provider["exclude-filter"] = p.exclude_filter;
      }

      if (!p.user_agent.empty()) {
        single_provider["header"]["User-Agent"].push_back(p.user_agent);
      }
      for (const auto &[name, value] : p.headers) {
        single_provider["header"][name].push_back(value);
      }

      // 健康检查配置
      single_provider["health-check"]["enable"] = true;
      single_provider["health-check"]["url"] =
          "https://cp.cloudflare.com/generate_204";
      single_provider["health-check"]["interval"] = 300;

      // 添加 override 配置（如果用户指定了 udp 或 scv 参数）
      bool has_override = false;
      YAML::Node override_node;

      if (!ext.skip_cert_verify.is_undef()) {
        override_node["skip-cert-verify"] = ext.skip_cert_verify.get();
        has_override = true;
      }

      if (!ext.udp.is_undef()) {
        override_node["udp"] = ext.udp.get();
        has_override = true;
      }

      YAML::Node proxy_name_node = buildProviderProxyNameOverride(p, ext);
      if (proxy_name_node.size() > 0) {
        override_node["proxy-name"] = proxy_name_node;
        has_override = true;
      }

      if (has_override) {
        single_provider["override"] = override_node;
      }

      provider_node[p.name] = single_provider;
    }

    yamlnode["proxy-providers"] = provider_node;
    writeLog(LOG_LEVEL_INFO,
             "已生成 " + std::to_string(ext.providers.size()) +
                 " 个 proxy provider。");
  }

  for (const ProxyGroupConfig &x : extra_proxy_group) {
    YAML::Node singlegroup;
    string_array filtered_nodelist;

    singlegroup["name"] = x.Name;
    if (x.Type == ProxyGroupType::Smart)
      singlegroup["type"] = "url-test";
    else
      singlegroup["type"] = x.TypeStr();

    switch (x.Type) {
    case ProxyGroupType::Select:
      if (!x.Url.empty())
        singlegroup["url"] = x.Url;
      break;
    case ProxyGroupType::Relay:
      break;
    case ProxyGroupType::LoadBalance:
      singlegroup["strategy"] = x.StrategyStr();
      [[fallthrough]];
    case ProxyGroupType::Smart:
      [[fallthrough]];
    case ProxyGroupType::URLTest:
      if (!x.Lazy.is_undef())
        singlegroup["lazy"] = x.Lazy.get();
      [[fallthrough]];
    case ProxyGroupType::Fallback:
      singlegroup["url"] = x.Url;
      if (x.Interval > 0)
        singlegroup["interval"] = x.Interval;
      if (x.Tolerance > 0)
        singlegroup["tolerance"] = x.Tolerance;
      break;
    default:
      continue;
    }
    if (!x.DisableUdp.is_undef())
      singlegroup["disable-udp"] = x.DisableUdp.get();

    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, true, ext);

    // 对于 proxy-provider 模式的处理
    if (ext.use_proxy_provider && !ext.providers.empty()) {
      // 检查策略组是否包含正则表达式（用于匹配节点）
      bool has_regex = false;
      std::string regex_pattern;
      bool has_provider_match = false;
      YAML::Node provider_use_node(YAML::NodeType::Sequence);

      for (const auto &proxy : x.Proxies) {
        // 如果不是以 [] 开头，则认为是正则表达式
        if (isProviderRegexRule(proxy)) {
          std::string groupid_target, groupid_filter;
          if (parseProviderGroupIdMatcher(proxy, groupid_target,
                                          groupid_filter)) {
            YAML::Node matched_providers =
                providersMatchingGroupId(groupid_target, ext.providers);
            if (matched_providers.size() > 0) {
              has_provider_match = true;
              provider_use_node = matched_providers;
              regex_pattern = groupid_filter;
              has_regex = !regex_pattern.empty();
              break;
            }
          }

          std::string group_target, group_filter;
          if (splitRenameGroupRule(proxy, group_target, group_filter)) {
            YAML::Node matched_providers =
                providersMatchingGroupTag(group_target, ext.providers);
            if (matched_providers.size() > 0) {
              has_provider_match = true;
              provider_use_node = matched_providers;
              regex_pattern = group_filter;
              has_regex = !regex_pattern.empty();
              break;
            }
          }

          has_regex = true;
          regex_pattern = proxy;
          break; // 找到第一个正则就够了
        }
      }

      if (has_provider_match) {
        singlegroup["use"] = provider_use_node;
        if (has_regex)
          singlegroup["filter"] = regex_pattern;
      } else if (has_regex && !regex_pattern.empty()) {
        // 只有包含正则表达式的策略组才引用 provider
        // 不包含正则的策略组只引用其他策略组，不需要 provider
        // 添加 use 字段引用所有原始 provider
        YAML::Node use_node(YAML::NodeType::Sequence);
        for (const ProxyProvider &p : ext.providers) {
          // groupId >= 0 表示这是原始订阅的 provider
          if (p.groupId >= 0) {
            use_node.push_back(p.name);
          }
        }
        if (use_node.size() > 0) {
          singlegroup["use"] = use_node;
        }

        // 添加 filter 字段
        singlegroup["filter"] = regex_pattern;
      }
    }

    if (!x.UsingProvider.empty())
      singlegroup["use"] = x.UsingProvider;
    else {
      // 在 proxy-provider 模式下，不自动添加 DIRECT
      // 策略组应该只引用 provider 或其他策略组
      if (filtered_nodelist.empty() && !ext.use_proxy_provider)
        filtered_nodelist.emplace_back("DIRECT");
    }
    if (!filtered_nodelist.empty())
      singlegroup["proxies"] = filtered_nodelist;
    if (group_block)
      singlegroup.SetStyle(YAML::EmitterStyle::Block);
    else
      singlegroup.SetStyle(YAML::EmitterStyle::Flow);

    bool replace_flag = false;
    for (auto &&original_group : original_groups) {
      if (original_group["name"].as<std::string>() == x.Name) {
        original_group.reset(singlegroup);
        replace_flag = true;
        break;
      }
    }
    if (!replace_flag)
      original_groups.push_back(singlegroup);
  }
  if (group_compact)
    original_groups.SetStyle(YAML::EmitterStyle::Flow);

  // 生成 proxy-groups 配置段
  if (ext.clash_new_field_name)
    yamlnode["proxy-groups"] = original_groups;
  else
    yamlnode["Proxy Group"] = original_groups;
}

std::string proxyToClash(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         bool clashR, extra_settings &ext) {
  const size_t max_allowed_rules = effectiveSettings().maxAllowedRules;
  YAML::Node yamlnode;

  try {
    yamlnode = YAML::Load(base_conf);
  } catch (std::exception &e) {
    writeLog(LOG_LEVEL_ERROR, "CLASH_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(e.what()));
    return "";
  }

  proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

  // 关键修复：在所有早期返回之前提取 proxy-providers
  // 这样所有返回路径都会使用正确的顺序
  std::string proxy_providers_yaml;
  if (yamlnode["proxy-providers"].IsDefined()) {
    YAML::Node providers_node = yamlnode["proxy-providers"];
    proxy_providers_yaml = YAML::Dump(providers_node);
    yamlnode.remove("proxy-providers"); // 从 yamlnode 中移除
  }

  // 提取 proxies 字段，用于手动控制输出顺序
  std::string proxies_yaml;
  std::string proxies_field_name =
      ext.clash_new_field_name ? "proxies" : "Proxy";
  if (yamlnode[proxies_field_name].IsDefined()) {
    YAML::Node proxies_node = yamlnode[proxies_field_name];
    proxies_yaml = dumpCanonicalClashYaml(proxies_node);
    yamlnode.remove(proxies_field_name); // 从 yamlnode 中移除
  }

  auto dump_with_extracted_fields = [&]() {
    std::string result = YAML::Dump(yamlnode);
    if (!proxy_providers_yaml.empty()) {
      insertProxyProvidersBeforeGroups(result, proxy_providers_yaml,
                                       ext.clash_new_field_name);
    }
    if (!proxies_yaml.empty()) {
      insertProxiesBeforeTarget(result, proxies_yaml,
                                ext.clash_new_field_name);
    }
    return finalizeCanonicalClashYaml(result);
  };

  const bool has_external_rules =
      !ext.rule_prepend.empty() || !ext.rule_append.empty();
  const std::string rules_field_name =
      ext.clash_new_field_name ? "rules" : "Rule";
  string_array original_rules;
  if (has_external_rules &&
      yamlnode[rules_field_name].IsDefined() &&
      yamlnode[rules_field_name].IsSequence()) {
    original_rules = safe_as<string_array>(yamlnode[rules_field_name]);
  }

  auto merge_external_rules = [&](const string_array &generated_rules) {
    const string_array kept_original =
        ext.overwrite_original_rules ? string_array{} : original_rules;
    string_array merged;
    if (!mergeClashRulesWithinLimit(
            ext.rule_prepend, kept_original, generated_rules,
            ext.rule_append, max_allowed_rules, merged)) {
      ext.external_rule_error =
          "Invalid request: the final Clash rule count exceeds "
          "max_allowed_rules (" +
          std::to_string(max_allowed_rules) +
          ").\n"
          "无效请求：最终 Clash 规则数量超过 max_allowed_rules 限制（" +
          std::to_string(max_allowed_rules) + "）。";
      return false;
    }
    yamlnode[rules_field_name] = std::move(merged);
    return true;
  };

  if (ext.nodelist) {
    return dump_with_extracted_fields();
  }

  /*
  if(ext.enable_rule_generator)
      rulesetToClash(yamlnode, ruleset_content_array,
  ext.overwrite_original_rules, ext.clash_new_field_name, ext.rule_stats);

  return YAML::Dump(yamlnode);
  */
  if (!ext.enable_rule_generator) {
    if (has_external_rules) {
      yamlnode.remove(rules_field_name);
      if (!merge_external_rules({}))
        return "";
    }
    return dump_with_extracted_fields();
  }

  if (!ext.managed_config_prefix.empty() || ext.clash_script) {
    if (yamlnode["mode"].IsDefined()) {
      if (ext.clash_new_field_name)
        yamlnode["mode"] = ext.clash_script ? "script" : "rule";
      else
        yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
    }

    if (has_external_rules)
      yamlnode.remove(rules_field_name);
    renderClashScript(
        yamlnode, ruleset_content_array, ext.managed_config_prefix,
        ext.clash_script,
        has_external_rules ? true : ext.overwrite_original_rules,
        ext.clash_classical_ruleset, ext.rule_stats);
    if (has_external_rules) {
      string_array generated_rules;
      if (yamlnode[rules_field_name].IsDefined() &&
          yamlnode[rules_field_name].IsSequence())
        generated_rules = safe_as<string_array>(yamlnode[rules_field_name]);
      yamlnode.remove(rules_field_name);
      if (!merge_external_rules(generated_rules))
        return "";
    }
    return dump_with_extracted_fields();
  }

  if (has_external_rules) {
    yamlnode.remove(rules_field_name);
    rulesetToClash(yamlnode, ruleset_content_array, true,
                   ext.clash_new_field_name, ext.rule_stats);
    string_array generated_rules;
    if (yamlnode[rules_field_name].IsDefined() &&
        yamlnode[rules_field_name].IsSequence())
      generated_rules = safe_as<string_array>(yamlnode[rules_field_name]);
    yamlnode.remove(rules_field_name);
    if (!merge_external_rules(generated_rules))
      return "";
    return dump_with_extracted_fields();
  }

  std::string output_content =
      rulesetToClashStr(yamlnode, ruleset_content_array,
                        ext.overwrite_original_rules, ext.clash_new_field_name,
                        ext.rule_stats);

  // 提取 proxy-providers，手动控制输出顺序
  // 使用之前在 998-1002 行已提取的 proxy_providers_yaml
  std::string proxy_providers_str;
  if (!proxy_providers_yaml.empty()) {
    writeLog(LOG_LEVEL_INFO, "正在使用先前提取的 proxy-providers");

    // proxy_providers_yaml 已经是 YAML::Dump 的结果
    // 需要移除可能的文档分隔符 "---"
    std::string content = proxy_providers_yaml;
    size_t start_pos = 0;
    if (content.find("---") == 0) {
      size_t newline_pos = content.find('\n');
      if (newline_pos != std::string::npos) {
        start_pos = newline_pos + 1;
      }
    }

    if (start_pos < content.length()) {
      content = content.substr(start_pos);

      // 为每一行添加 2 个空格的缩进（YAML 格式要求）
      std::string indented_content;
      std::istringstream stream(content);
      std::string line;
      while (std::getline(stream, line)) {
        if (!line.empty()) {
          indented_content += "  " + line + "\n"; // 添加 2 个空格缩进
        } else {
          indented_content += "\n";
        }
      }

      proxy_providers_str = "proxy-providers:\n" + indented_content;

      // 确保末尾有换行符，避免与 proxy-groups 连在一起
      if (!proxy_providers_str.empty() && proxy_providers_str.back() != '\n') {
        proxy_providers_str += "\n";
      }

      writeLog(LOG_LEVEL_INFO,
               "已准备待插入的 proxy-providers，长度：" +
                   std::to_string(proxy_providers_str.length()));
    }
  } else {
    writeLog(LOG_LEVEL_INFO, "没有需要插入的 proxy-providers");
  }

  std::string yamlnode_str = YAML::Dump(yamlnode);

  // 在 proxy-groups 之前插入 proxy-providers
  if (!proxy_providers_str.empty()) {
    writeLog(LOG_LEVEL_INFO,
        "正在尝试将 proxy-providers 插入到 proxy-groups 前，大小：" +
            std::to_string(proxy_providers_str.length()));

    std::string proxy_groups_key =
        ext.clash_new_field_name ? "proxy-groups:" : "Proxy Group:";
    size_t groups_pos = yamlnode_str.find(proxy_groups_key);

    if (groups_pos != std::string::npos) {
      writeLog(LOG_LEVEL_INFO,
               "已在位置 " + std::to_string(groups_pos) + " 找到 proxy-groups");
      // 在 proxy-groups: 这一行之前插入
      yamlnode_str.insert(groups_pos, proxy_providers_str);
      writeLog(LOG_LEVEL_INFO, "已将 proxy-providers 插入到 proxy-groups 前");
    } else {
      writeLog(LOG_LEVEL_WARNING, "未找到 proxy-groups，将追加到末尾");
      // 如果找不到 proxy-groups，尝试在文件末尾插入
      yamlnode_str += proxy_providers_str;
    }
  } else {
    writeLog(LOG_LEVEL_WARNING, "proxy-providers 内容为空，没有内容需要插入");
  }

  // 插入 proxies 字段（在 proxy-groups 之前）
  if (!proxies_yaml.empty()) {
    insertProxiesBeforeTarget(yamlnode_str, proxies_yaml,
                              ext.clash_new_field_name);
  }

  output_content.insert(0, yamlnode_str);
  replaceAll(output_content, "!<str> ", "");
  return finalizeCanonicalClashYaml(output_content);
}

void replaceAll(std::string &input, const std::string &search,
                const std::string &replace) {
  size_t pos = 0;
  while ((pos = input.find(search, pos)) != std::string::npos) {
    input.replace(pos, search.length(), replace);
    pos += replace.length();
  }
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=,
// allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408,
// client-id = 139/184/125),(public-key =
// bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint =
// engage.cloudflareclient.com:2408)
namespace {

std::vector<WireGuardPeer> wireGuardPeers(const Proxy &node) {
  if (!node.WireGuardPeers.empty())
    return node.WireGuardPeers;
  WireGuardPeer peer;
  peer.Hostname = node.Hostname;
  peer.Port = node.Port;
  peer.PublicKey = node.PublicKey;
  peer.PreSharedKey = node.PreSharedKey;
  peer.AllowedIPs = node.AllowedIPs;
  peer.Reserved = node.ClientId;
  peer.KeepAlive = node.KeepAlive;
  return {peer};
}

std::vector<std::string> wireGuardLocalAddresses(const Proxy &node) {
  if (!node.WireGuardLocalAddresses.empty())
    return node.WireGuardLocalAddresses;
  std::vector<std::string> addresses;
  if (!node.SelfIP.empty())
    addresses.emplace_back(node.SelfIP);
  if (!node.SelfIPv6.empty())
    addresses.emplace_back(node.SelfIPv6);
  return addresses;
}

std::string wireGuardAddressWithoutPrefix(std::string address) {
  address = trim(address);
  const size_t slash = address.find('/');
  return slash == std::string::npos ? address : address.substr(0, slash);
}

std::string wireGuardAddressWithDefaultPrefix(std::string address) {
  address = trim(address);
  if (address.find('/') != std::string::npos)
    return address;
  return address + (isIPv6(address) ? "/128" : "/32");
}

std::string wireGuardEndpoint(const WireGuardPeer &peer) {
  const std::string host = isIPv6(peer.Hostname) ? "[" + peer.Hostname + "]"
                                                 : peer.Hostname;
  return host + ":" + std::to_string(peer.Port);
}

std::string generatePeer(const WireGuardPeer &peer,
                         bool client_id_as_reserved) {
  std::string result;
  result += "public-key = " + peer.PublicKey;
  result += ", endpoint = " + wireGuardEndpoint(peer);
  if (!peer.AllowedIPs.empty())
    result += ", allowed-ips = \"" + peer.AllowedIPs + "\"";
  if (!peer.Reserved.empty()) {
    if (client_id_as_reserved)
      result += ", reserved = [" +
                replaceAllDistinct(peer.Reserved, "/", ",") + "]";
    else
      result += ", client-id = " +
                replaceAllDistinct(peer.Reserved, ",", "/");
  }
  if (!peer.PreSharedKey.empty())
    result += client_id_as_reserved
                  ? ", preshared-key = \"" + peer.PreSharedKey + "\""
                  : ", preshared-key = " + peer.PreSharedKey;
  if (peer.KeepAlive > 0 && !client_id_as_reserved)
    result += ", keepalive = " + std::to_string(peer.KeepAlive);
  return result;
}

std::string generateLoonWireGuardPeer(const WireGuardPeer &peer) {
  std::string result = "public-key=\"" + peer.PublicKey + "\"";
  if (!peer.PreSharedKey.empty())
    result += ",preshared-key=\"" + peer.PreSharedKey + "\"";
  if (!peer.Reserved.empty())
    result += ",reserved=[" +
              replaceAllDistinct(peer.Reserved, "/", ",") + "]";
  if (!peer.AllowedIPs.empty())
    result += ",allowed-ips=\"" + peer.AllowedIPs + "\"";
  result += ",endpoint=" + wireGuardEndpoint(peer);
  return result;
}

bool wireGuardStructuredConfigIsSafe(const Proxy &node) {
  auto safe_scalar = [](const std::string &value) {
    return !value.empty() && value.find_first_of(",\"'\r\n(){}[]") == std::string::npos;
  };
  auto safe_list = [](const std::string &value) {
    return value.find_first_of("\"'\r\n{}[]") == std::string::npos;
  };
  auto valid_network = [](const std::string &value, bool require_prefix) {
    const std::string network = trim(value);
    const size_t slash = network.find('/');
    if (require_prefix && slash == std::string::npos)
      return false;
    const std::string address = slash == std::string::npos
                                    ? network
                                    : network.substr(0, slash);
    const bool ipv4 = isIPv4(address), ipv6 = isIPv6(address);
    if (!ipv4 && !ipv6)
      return false;
    if (slash == std::string::npos)
      return true;
    const std::string prefix = network.substr(slash + 1);
    if (prefix.empty() ||
        !std::all_of(prefix.begin(), prefix.end(), [](unsigned char ch) {
          return std::isdigit(ch) != 0;
        }))
      return false;
    const int bits = to_int(prefix, -1);
    return bits >= 0 && bits <= (ipv6 ? 128 : 32);
  };
  const auto addresses = wireGuardLocalAddresses(node);
  const auto peers = wireGuardPeers(node);
  if (!safe_scalar(node.PrivateKey) || addresses.empty() || peers.empty())
    return false;
  for (const std::string &address : addresses)
    if (!safe_scalar(address) || !valid_network(address, false))
      return false;
  for (const std::string &dns : node.DnsServers)
    if (!safe_scalar(dns))
      return false;
  for (const WireGuardPeer &peer : peers) {
    if (!safe_scalar(peer.Hostname) || peer.Port == 0 ||
        !safe_scalar(peer.PublicKey) ||
        (!peer.PreSharedKey.empty() && !safe_scalar(peer.PreSharedKey)) ||
        peer.AllowedIPs.empty() || !safe_list(peer.AllowedIPs) ||
        (!peer.Reserved.empty() &&
         !std::all_of(peer.Reserved.begin(), peer.Reserved.end(), [](unsigned char ch) {
           return std::isdigit(ch) != 0 || ch == ',';
         })))
      return false;
    const string_array allowed_ips = split(peer.AllowedIPs, ",");
    if (std::any_of(allowed_ips.begin(), allowed_ips.end(),
                    [&](const std::string &network) {
                      return !valid_network(network, true);
                    }))
      return false;
    if (!peer.Reserved.empty()) {
      const string_array reserved = split(peer.Reserved, ",");
      if (std::any_of(reserved.begin(), reserved.end(),
                      [](const std::string &value) {
                        const int byte = to_int(trim(value), -1);
                        return byte < 0 || byte > 255;
                      }))
        return false;
    }
  }
  return true;
}

bool stashNodeHasUnsupportedSharedFields(const Proxy &node) {
  return !node.UnderlyingProxy.empty() || !node.Edge.empty() ||
         !node.QUICSecure.empty() || !node.QUICSecret.empty() ||
         !node.ShadowTLSPassword.empty() || !node.ShadowTLSSNI.empty() ||
         node.ShadowTLSVersion != 0 || !node.XrayLinkOptions.empty() ||
         node.V2rayHttpUpgrade.get(false) || node.XUDP.get(false) ||
         node.TLS13.get(false);
}

void addStashTlsFields(YAML::Node &out, const Proxy &node, tribool insecure,
                       bool emit_tls, bool inherent_tls = false,
                       bool use_servername_key = false) {
  const std::string tls_state = toLower(trim(node.TLSStr));
  const bool tls_active = inherent_tls || node.TLSSecure ||
                          tls_state == "tls" || tls_state == "reality" ||
                          tls_state == "xtls" || !node.PublicKey.empty();
  if (emit_tls && tls_active)
    out["tls"] = true;
  if (tls_active && !insecure.is_undef())
    out["skip-cert-verify"] = insecure.get();
  const std::string &sni = !node.ServerName.empty() ? node.ServerName : node.SNI;
  if (tls_active && !sni.empty())
    out[use_servername_key ? "servername" : "sni"] = sni;
  if (tls_active && !node.AlpnList.empty())
    out["alpn"] = node.AlpnList;
  else if (tls_active && !node.Alpn.empty())
    out["alpn"].push_back(node.Alpn);
}

bool addStashV2RayTransport(YAML::Node &out, const Proxy &node,
                           bool allow_http, bool allow_h2, bool allow_grpc,
                           bool allow_xhttp = false) {
  const std::string network = toLower(node.TransferProtocol);
  if (network.empty() || network == "tcp")
    return node.FakeType.empty() || node.FakeType == "none";
  if (network == "ws") {
    out["network"] = "ws";
    if (!node.Path.empty())
      out["ws-opts"]["path"] = node.Path;
    if (!node.Host.empty())
      out["ws-opts"]["headers"]["Host"] = node.Host;
    return true;
  }
  if (network == "http" && allow_http) {
    out["network"] = "http";
    out["http-opts"]["method"] = "GET";
    if (!node.Path.empty())
      out["http-opts"]["path"].push_back(node.Path);
    if (!node.Host.empty())
      out["http-opts"]["headers"]["Host"].push_back(node.Host);
    return true;
  }
  if (network == "h2" && allow_h2) {
    out["network"] = "h2";
    if (!node.Path.empty())
      out["h2-opts"]["path"] = node.Path;
    if (!node.Host.empty())
      out["h2-opts"]["host"].push_back(node.Host);
    return true;
  }
  if (network == "grpc" && allow_grpc &&
      (node.GRPCMode.empty() || node.GRPCMode == "gun")) {
    out["network"] = "grpc";
    if (!node.GRPCServiceName.empty())
      out["grpc-opts"]["grpc-service-name"] = node.GRPCServiceName;
    return true;
  }
  if (network == "xhttp" && allow_xhttp) {
    static const std::unordered_set<std::string> modes = {
        "auto", "stream-one", "stream-up", "packet-up"};
    const std::string mode =
        node.GRPCMode.empty() ? std::string("auto") : node.GRPCMode;
    if (modes.find(mode) == modes.end())
      return false;
    out["network"] = "xhttp";
    out["xhttp-opts"]["mode"] = mode;
    if (!node.Path.empty())
      out["xhttp-opts"]["path"] = node.Path;
    if (!node.Host.empty())
      out["xhttp-opts"]["host"] = node.Host;
    return true;
  }
  return false;
}

bool stashStringIn(const std::string &value,
                   const std::unordered_set<std::string> &allowed) {
  return allowed.find(toLower(trim(value))) != allowed.end();
}

bool stashTlsStateIsValid(const Proxy &node, bool allow_reality,
                          bool allow_xtls = false) {
  const std::string declared = toLower(trim(node.TLSStr));
  if (declared.empty())
    return allow_reality || node.PublicKey.empty();
  if (declared == "none")
    return !node.TLSSecure && node.PublicKey.empty();
  if (declared == "tls")
    return node.PublicKey.empty() || allow_reality;
  if (declared == "xtls")
    return allow_xtls && node.PublicKey.empty();
  if (declared == "reality")
    return allow_reality && !node.PublicKey.empty();
  return false;
}

bool stashPortSpecIsValid(const std::string &spec) {
  if (spec.empty())
    return true;
  for (std::string token : split(spec, ",")) {
    token = trim(token);
    const size_t dash = token.find('-');
    if (dash == std::string::npos) {
      if (!generatorPortIsValid(token))
        return false;
      continue;
    }
    if (dash == 0 || dash + 1 >= token.size() ||
        token.find('-', dash + 1) != std::string::npos ||
        !generatorPortIsValid(token.substr(0, dash)) ||
        !generatorPortIsValid(token.substr(dash + 1)) ||
        std::stoul(token.substr(0, dash)) >
            std::stoul(token.substr(dash + 1)))
      return false;
  }
  return true;
}

bool stashSinglePortRangeIsValid(const std::string &range) {
  if (range.empty() || range.find(',') != std::string::npos)
    return false;
  const size_t dash = range.find('-');
  return dash != std::string::npos && dash > 0 && dash + 1 < range.size() &&
         range.find('-', dash + 1) == std::string::npos &&
         generatorPortIsValid(range.substr(0, dash)) &&
         generatorPortIsValid(range.substr(dash + 1)) &&
         std::stoul(range.substr(0, dash)) <=
             std::stoul(range.substr(dash + 1));
}

bool stashBase64ValueIsValid(const std::string &value) {
  return !value.empty() && value.size() % 4 == 0 &&
         regMatch(value, R"(^[A-Za-z0-9+/]+={0,2}$)");
}

bool stashHopIntervalSeconds(const std::string &value, int &seconds) {
  seconds = 0;
  if (value.empty())
    return true;
  if (isNumeric(value)) {
    try {
      const unsigned long parsed = std::stoul(value);
      if (parsed == 0 || parsed > static_cast<unsigned long>(INT_MAX))
        return false;
      seconds = static_cast<int>(parsed);
      return true;
    } catch (const std::exception &) {
      return false;
    }
  }

  uint64_t total_nanoseconds = 0;
  size_t position = 0;
  while (position < value.size()) {
    const size_t number_start = position;
    while (position < value.size() &&
           std::isdigit(static_cast<unsigned char>(value[position])))
      ++position;
    if (number_start == position)
      return false;
    uint64_t amount = 0;
    try {
      amount = std::stoull(value.substr(number_start, position - number_start));
    } catch (const std::exception &) {
      return false;
    }
    uint64_t multiplier = 0;
    if (value.compare(position, 2, "ns") == 0) {
      multiplier = 1;
      position += 2;
    } else if (value.compare(position, 2, "us") == 0) {
      multiplier = 1000;
      position += 2;
    } else if (value.compare(position, 2, "ms") == 0) {
      multiplier = 1000000;
      position += 2;
    } else if (position < value.size() && value[position] == 's') {
      multiplier = 1000000000ULL;
      ++position;
    } else if (position < value.size() && value[position] == 'm') {
      multiplier = 60ULL * 1000000000ULL;
      ++position;
    } else if (position < value.size() && value[position] == 'h') {
      multiplier = 3600ULL * 1000000000ULL;
      ++position;
    } else {
      return false;
    }
    if (amount > (std::numeric_limits<uint64_t>::max() - total_nanoseconds) /
                     multiplier)
      return false;
    total_nanoseconds += amount * multiplier;
  }
  constexpr uint64_t nanoseconds_per_second = 1000000000ULL;
  if (total_nanoseconds == 0 ||
      total_nanoseconds % nanoseconds_per_second != 0 ||
      total_nanoseconds / nanoseconds_per_second >
          static_cast<uint64_t>(INT_MAX))
    return false;
  seconds = static_cast<int>(total_nanoseconds / nanoseconds_per_second);
  return true;
}

std::string stashHysteriaPorts(const Proxy &node) {
  if (node.Ports.empty())
    return "";
  if (node.Hysteria2PortsAreAdditional)
    return std::to_string(node.Port) + "," + node.Ports;
  return node.Ports;
}

bool buildStashNode(const Proxy &node, YAML::Node &out, tribool udp,
                    tribool tfo, tribool insecure, tribool tls13) {
  const bool mieru_port_range =
      node.Type == ProxyType::Mieru && node.Port == 0 && !node.Ports.empty();
  if (node.Hostname.empty() || (node.Port == 0 && !mieru_port_range) ||
      node.Remark.empty() || tls13.get(false) ||
      std::any_of(node.AlpnList.begin(), node.AlpnList.end(),
                  [](const std::string &alpn) { return alpn.empty(); }) ||
      stashNodeHasUnsupportedSharedFields(node))
    return false;

  out["name"] = node.Remark;
  out["server"] = node.Hostname;
  if (node.Port != 0)
    out["port"] = node.Port;

  switch (node.Type) {
  case ProxyType::Shadowsocks: {
    static const std::unordered_set<std::string> ciphers = {
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb",
        "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
        "aes-256-ctr", "rc4-md5", "chacha20", "chacha20-ietf",
        "xchacha20", "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm"};
    std::string cipher = toLower(trim(node.EncryptMethod));
    if (cipher == "aead_chacha20_poly1305")
      cipher = "chacha20-ietf-poly1305";
    if (node.Password.empty() || !stashStringIn(cipher, ciphers) ||
        (!node.Plugin.empty() && node.PluginOption.empty()))
      return false;
    out["type"] = "ss";
    out["cipher"] = cipher;
    out["password"] = node.Password;
    if (!node.Plugin.empty()) {
      const std::string options =
          replaceAllDistinct(node.PluginOption, ";", "&");
      const std::string plugin = toLower(node.Plugin);
      std::unordered_map<std::string, std::string> parsed_options;
      for (const std::string &raw_option : split(options, "&")) {
        if (raw_option.empty())
          continue;
        const size_t equals = raw_option.find('=');
        const std::string key =
            toLower(trim(raw_option.substr(0, equals)));
        const std::string value =
            equals == std::string::npos ? std::string()
                                        : raw_option.substr(equals + 1);
        if (key.empty() || !parsed_options.emplace(key, value).second)
          return false;
      }
      auto flag_value = [&](const std::string &key, bool &present,
                            bool &value) {
        const auto found = parsed_options.find(key);
        present = found != parsed_options.end();
        if (!present)
          return true;
        const std::string normalized = toLower(trim(found->second));
        if (normalized.empty() || normalized == "true" || normalized == "1") {
          value = true;
          return true;
        }
        if (normalized == "false" || normalized == "0") {
          value = false;
          return true;
        }
        return false;
      };
      if (plugin == "simple-obfs" || plugin == "obfs-local") {
        if (std::any_of(parsed_options.begin(), parsed_options.end(),
                        [](const auto &option) {
                          return option.first != "obfs" &&
                                 option.first != "obfs-host";
                        }))
          return false;
        const std::string mode =
            urlDecode(parsed_options.count("obfs") ? parsed_options["obfs"]
                                                    : std::string());
        if (mode != "http" && mode != "tls")
          return false;
        out["plugin"] = "obfs";
        out["plugin-opts"]["mode"] = mode;
        const std::string host =
            urlDecode(parsed_options.count("obfs-host")
                          ? parsed_options["obfs-host"]
                          : std::string());
        if (!host.empty())
          out["plugin-opts"]["host"] = host;
      } else if (plugin == "v2ray-plugin") {
        if (std::any_of(parsed_options.begin(), parsed_options.end(),
                        [](const auto &option) {
                          return option.first != "mode" &&
                                 option.first != "host" &&
                                 option.first != "path" &&
                                 option.first != "tls" &&
                                 option.first != "skip-cert-verify";
                        }))
          return false;
        const std::string mode = parsed_options["mode"];
        if (!mode.empty() && mode != "websocket")
          return false;
        bool tls_present = false, tls_enabled = false;
        bool scv_present = false, scv_enabled = false;
        if (!flag_value("tls", tls_present, tls_enabled) ||
            !flag_value("skip-cert-verify", scv_present, scv_enabled))
          return false;
        if (!insecure.is_undef()) {
          if (scv_present && insecure.get() != scv_enabled)
            return false;
          scv_present = true;
          scv_enabled = insecure.get();
        }
        out["plugin"] = "v2ray-plugin";
        out["plugin-opts"]["mode"] = "websocket";
        const std::string host = parsed_options["host"];
        const std::string path = parsed_options["path"];
        if (!host.empty())
          out["plugin-opts"]["host"] = host;
        if (!path.empty())
          out["plugin-opts"]["path"] = path;
        if (tls_present)
          out["plugin-opts"]["tls"] = tls_enabled;
        if (scv_present)
          out["plugin-opts"]["skip-cert-verify"] = scv_enabled;
        if (tls_present && tls_enabled)
          out["plugin-opts"]["tls"] = true;
      } else {
        return false;
      }
    } else if (!node.PluginOption.empty() || insecure.get(false))
      return false;
    break;
  }
  case ProxyType::ShadowsocksR: {
    static const std::unordered_set<std::string> ciphers = {
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb",
        "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
        "aes-256-ctr", "rc4-md5", "chacha20", "chacha20-ietf",
        "xchacha20", "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm"};
    static const std::unordered_set<std::string> protocols = {
        "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
        "auth_chain_a", "auth_chain_b"};
    static const std::unordered_set<std::string> obfs_values = {
        "plain", "http_simple", "http_post", "random_head",
        "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"};
    std::string cipher = toLower(trim(node.EncryptMethod));
    if (cipher == "aead_chacha20_poly1305")
      cipher = "chacha20-ietf-poly1305";
    const std::string protocol = toLower(trim(node.Protocol));
    const std::string obfs = toLower(trim(node.OBFS));
    if (node.Password.empty() || !stashStringIn(cipher, ciphers) ||
        (!protocol.empty() && !stashStringIn(protocol, protocols)) ||
        (!obfs.empty() && !stashStringIn(obfs, obfs_values)) ||
        insecure.get(false))
      return false;
    out["type"] = "ssr";
    out["cipher"] = cipher;
    out["password"] = node.Password;
    out["protocol"] = protocol;
    out["obfs"] = obfs;
    if (!node.ProtocolParam.empty())
      out["protocol-param"] = node.ProtocolParam;
    if (!node.OBFSParam.empty())
      out["obfs-param"] = node.OBFSParam;
    break;
  }
  case ProxyType::HTTP:
  case ProxyType::HTTPS:
    out["type"] = "http";
    if (!node.Username.empty())
      out["username"] = node.Username;
    if (!node.Password.empty())
      out["password"] = node.Password;
    if (node.Type == ProxyType::HTTPS || node.TLSSecure)
      out["tls"] = true;
    if (!stashTlsStateIsValid(node, false))
      return false;
    addStashTlsFields(out, node, insecure, true,
                      node.Type == ProxyType::HTTPS);
    break;
  case ProxyType::SOCKS5:
    out["type"] = "socks5";
    if (!node.Username.empty())
      out["username"] = node.Username;
    if (!node.Password.empty())
      out["password"] = node.Password;
    if (!stashTlsStateIsValid(node, false))
      return false;
    addStashTlsFields(out, node, insecure, true);
    break;
  case ProxyType::VMess: {
    static const std::unordered_set<std::string> ciphers = {
        "auto", "aes-128-gcm", "chacha20-poly1305", "none"};
    const std::string cipher = node.EncryptMethod.empty()
                                   ? std::string("auto")
                                   : toLower(trim(node.EncryptMethod));
    if (node.UserId.empty() || !node.PublicKey.empty() || !node.Flow.empty() ||
        !node.ShortId.empty() || !node.Fingerprint.empty() ||
        !node.Encryption.empty() || !stashStringIn(cipher, ciphers) ||
        !stashTlsStateIsValid(node, false) ||
        (!node.PacketEncoding.empty() && node.PacketEncoding != "none") ||
        !addStashV2RayTransport(out, node, true, true, true))
      return false;
    out["type"] = "vmess";
    out["uuid"] = node.UserId;
    out["alterId"] = node.AlterId;
    out["cipher"] = cipher;
    addStashTlsFields(out, node, insecure, true, false, true);
    break;
  }
  case ProxyType::Trojan:
    if (node.Password.empty() || !node.PublicKey.empty() || !node.Flow.empty() ||
        !node.ShortId.empty() || !node.Fingerprint.empty() ||
        !node.Encryption.empty() || !node.PacketEncoding.empty() ||
        !stashTlsStateIsValid(node, false) ||
        toLower(trim(node.TLSStr)) == "none" ||
        !addStashV2RayTransport(out, node, false, false, true))
      return false;
    out["type"] = "trojan";
    out["password"] = node.Password;
    addStashTlsFields(out, node, insecure, false, true);
    break;
  case ProxyType::VLESS: {
    static const std::unordered_set<std::string> flows = {
        "xtls-rprx-origin", "xtls-rprx-direct", "xtls-rprx-splice",
        "xtls-rprx-vision"};
    const std::string network = toLower(node.TransferProtocol);
    const std::string flow = toLower(trim(node.Flow));
    const std::string tls_state = toLower(trim(node.TLSStr));
    const bool tls_active = node.TLSSecure || !node.PublicKey.empty() ||
                            tls_state == "tls" || tls_state == "xtls" ||
                            tls_state == "reality";
    if (node.UserId.empty() ||
        (!node.Encryption.empty() && node.Encryption != "none") ||
        (!node.PacketEncoding.empty() && node.PacketEncoding != "none") ||
        (!flow.empty() &&
         (!stashStringIn(flow, flows) ||
          (!network.empty() && network != "tcp") ||
           !tls_active)) ||
        !stashTlsStateIsValid(node, true, true) ||
        !addStashV2RayTransport(out, node, true, true, true, true))
      return false;
    out["type"] = "vless";
    out["uuid"] = node.UserId;
    if (!flow.empty())
      out["flow"] = flow;
    addStashTlsFields(out, node, insecure, true);
    if (!node.PublicKey.empty()) {
      out["tls"] = true;
      out["reality-opts"]["public-key"] = node.PublicKey;
      if (!node.ShortId.empty())
        out["reality-opts"]["short-id"] = node.ShortId;
    } else if (!node.ShortId.empty()) {
      return false;
    }
    if (!node.Fingerprint.empty()) {
      if (!tls_active)
        return false;
      out["client-fingerprint"] = node.Fingerprint;
    }
    break;
  }
  case ProxyType::Snell:
    if (node.Password.empty() || node.SnellVersion == 0 ||
        node.SnellVersion > 5 ||
        !node.SnellReuse.is_undef() || !node.SnellUserKey.empty() ||
        !node.SnellNetwork.empty() || !node.SnellMode.empty() ||
        node.SnellUDPPort != 0 || !node.Path.empty())
      return false;
    out["type"] = "snell";
    out["psk"] = node.Password;
    out["version"] = node.SnellVersion;
    if (!node.OBFS.empty() && node.OBFS != "none") {
      if (node.OBFS != "http" && node.OBFS != "tls")
        return false;
      out["obfs-opts"]["mode"] = node.OBFS;
      if (!node.Host.empty())
        out["obfs-opts"]["host"] = node.Host;
    }
    if (udp.get(false) && node.SnellVersion < 3)
      return false;
    break;
  case ProxyType::AnyTLS:
    if (node.Password.empty() || !node.PublicKey.empty() ||
        !node.ShortId.empty() || !node.Fingerprint.empty() ||
        !node.Flow.empty() || !node.Encryption.empty() ||
        !node.PacketEncoding.empty() ||
        (!node.TransferProtocol.empty() &&
         toLower(node.TransferProtocol) != "tcp") ||
        !node.FakeType.empty() || !node.Path.empty() ||
        !node.GRPCServiceName.empty() || !node.GRPCMode.empty() ||
        node.IdleSessionCheckInterval != 30 ||
        node.IdleSessionTimeout != 30 || node.MinIdleSession != 0 ||
        (!node.TLSStr.empty() && node.TLSStr != "tls"))
      return false;
    out["type"] = "anytls";
    out["password"] = node.Password;
    addStashTlsFields(out, node, insecure, false, true);
    break;
  case ProxyType::Hysteria: {
    int up = 0, down = 0;
    if (!parseMbpsValue(node.UpMbps, up) || !parseMbpsValue(node.DownMbps, down) ||
        up <= 0 || down <= 0 ||
        (!node.FakeType.empty() && node.FakeType != "udp" &&
         node.FakeType != "wechat-video") || !node.Fingerprint.empty() ||
        (!node.OBFS.empty() && node.OBFS != "xplus"))
      return false;
    out["type"] = "hysteria";
    out["up-speed"] = up;
    out["down-speed"] = down;
    if (!node.AuthStr.empty() && !node.Auth.empty())
      return false;
    if (!node.AuthStr.empty())
      out["auth-str"] = node.AuthStr;
    else if (!node.Auth.empty()) {
      if (!stashBase64ValueIsValid(node.Auth))
        return false;
      out["auth"] = node.Auth;
    }
    if (!node.FakeType.empty())
      out["protocol"] = node.FakeType;
    if (!node.OBFSParam.empty())
      out["obfs"] = node.OBFSParam;
    addStashTlsFields(out, node, insecure, false, true);
    const std::string ports = stashHysteriaPorts(node);
    int hop_interval = 0;
    if (!stashPortSpecIsValid(ports) ||
        !stashHopIntervalSeconds(node.HysteriaHopInterval, hop_interval) ||
        (!node.TLSStr.empty() && node.TLSStr != "tls"))
      return false;
    if (!ports.empty())
      out["ports"] = ports;
    if (hop_interval > 0)
      out["hop-interval"] = hop_interval;
    break;
  }
  case ProxyType::Hysteria2: {
    if (node.Password.empty() || !node.Hysteria2RealmUrl.empty() ||
        !node.Hysteria2ECH.empty() ||
        !node.Hysteria2GeckoMinPacketSize.empty() ||
        !node.Hysteria2GeckoMaxPacketSize.empty() ||
        !node.PublicKey.empty() || !node.Fingerprint.empty() ||
        (!node.OBFSParam.empty() && node.OBFSParam != "salamander" &&
         node.OBFSParam != "gecko") ||
        (node.OBFSParam.empty() != node.OBFSPassword.empty()))
      return false;
    out["type"] = "hysteria2";
    out["auth"] = node.Password;
    if (!node.OBFSParam.empty()) {
      out["obfs"] = node.OBFSParam;
      out["obfs-password"] = node.OBFSPassword;
    }
    int bandwidth = 0;
    if (!node.UpMbps.empty() &&
        (!parseMbpsValue(node.UpMbps, bandwidth) || bandwidth <= 0))
      return false;
    if (!node.UpMbps.empty())
      out["up-speed"] = bandwidth;
    if (!node.DownMbps.empty() &&
        (!parseMbpsValue(node.DownMbps, bandwidth) || bandwidth <= 0))
      return false;
    if (!node.DownMbps.empty())
      out["down-speed"] = bandwidth;
    addStashTlsFields(out, node, insecure, false, true);
    const std::string ports = stashHysteriaPorts(node);
    int hop_interval = 0;
    if (!stashPortSpecIsValid(ports) ||
        !stashHopIntervalSeconds(node.HysteriaHopInterval, hop_interval) ||
        (!node.TLSStr.empty() && node.TLSStr != "tls"))
      return false;
    if (!ports.empty())
      out["ports"] = ports;
    if (hop_interval > 0)
      out["hop-interval"] = hop_interval;
    break;
  }
  case ProxyType::TUIC: {
    const bool v4 = !node.token.empty() && node.UserId.empty() &&
                    node.Password.empty();
    const bool v5 = node.token.empty() && !node.UserId.empty() &&
                    !node.Password.empty();
    if (!v4 && !v5)
      return false;
    if ((!node.CongestionControl.empty() &&
         node.CongestionControl != "cubic") ||
        (!node.UdpRelayMode.empty() && node.UdpRelayMode != "native") ||
        node.ReduceRtt.get(false) || node.DisableSni.get(false) ||
        !node.PublicKey.empty() || !node.ShortId.empty() ||
        !node.Fingerprint.empty() ||
        node.RequestTimeout != 15000 ||
        (!node.TLSStr.empty() && node.TLSStr != "tls"))
      return false;
    out["type"] = "tuic";
    out["version"] = v4 ? 4 : 5;
    if (v4)
      out["token"] = node.token;
    else {
      out["uuid"] = node.UserId;
      out["password"] = node.Password;
    }
    addStashTlsFields(out, node, insecure, false, true);
    if (!out["alpn"].IsDefined())
      out["alpn"].push_back("h3");
    const std::string ports = stashHysteriaPorts(node);
    int hop_interval = 0;
    if (!stashPortSpecIsValid(ports) ||
        !stashHopIntervalSeconds(node.HysteriaHopInterval, hop_interval))
      return false;
    if (!ports.empty())
      out["ports"] = ports;
    if (hop_interval > 0)
      out["hop-interval"] = hop_interval;
    break;
  }
  case ProxyType::Mieru: {
    const std::string transport = toLower(trim(node.TransferProtocol));
    if (node.Username.empty() || node.Password.empty() ||
        (transport != "tcp" && transport != "udp") ||
        (!node.MieruProfile.empty() && node.MieruProfile != "default") ||
        node.Mtu != 0 ||
        (!node.Multiplexing.empty() &&
         node.Multiplexing != "MULTIPLEXING_LOW") ||
        !node.MieruHandshakeMode.empty() || !node.MieruTrafficPattern.empty() ||
        node.MieruHasUnknownParameters ||
        (node.Port == 0 && !stashSinglePortRangeIsValid(node.Ports)) ||
        (node.Port != 0 && !node.Ports.empty()))
      return false;
    out["type"] = "mieru";
    out["username"] = node.Username;
    out["password"] = node.Password;
    out["transport"] = transport;
    if (node.Port == 0)
      out["port-range"] = node.Ports;
    break;
  }
  case ProxyType::WireGuard: {
    if (!wireGuardStructuredConfigIsSafe(node) ||
        !node.WireGuardInterfaceName.empty() || node.WireGuardSystem.get(false) ||
        node.WireGuardListenPort != 0 || node.WireGuardWorkers != 0 ||
        (!node.ClientId.empty() && node.WireGuardPeers.size() == 1 &&
         node.ClientId != node.WireGuardPeers.front().Reserved))
      return false;
    const auto peers = wireGuardPeers(node);
    const auto addresses = wireGuardLocalAddresses(node);
    std::unordered_set<std::string> allowed_ips;
    for (std::string value : split(peers.empty() ? std::string()
                                                  : peers[0].AllowedIPs,
                                   ",")) {
      value = trim(value);
      if (!value.empty())
        allowed_ips.insert(value);
    }
    if (peers.size() != 1 || addresses.empty() || addresses.size() > 2 ||
        allowed_ips !=
            std::unordered_set<std::string>{"0.0.0.0/0", "::/0"})
      return false;
    out["type"] = "wireguard";
    out["server"] = peers[0].Hostname;
    out["port"] = peers[0].Port;
    out["private-key"] = node.PrivateKey;
    out["public-key"] = peers[0].PublicKey;
    if (!peers[0].PreSharedKey.empty())
      out["preshared-key"] = peers[0].PreSharedKey;
    size_t ipv4_count = 0, ipv6_count = 0;
    for (const std::string &address : addresses) {
      const std::string value = wireGuardAddressWithoutPrefix(address);
      if (isIPv4(value)) {
        if (++ipv4_count > 1)
          return false;
        out["ip"] = value;
      } else if (isIPv6(value)) {
        if (++ipv6_count > 1)
          return false;
        out["ipv6"] = value;
      } else
        return false;
    }
    if (ipv4_count != 1)
      return false;
    if (!node.DnsServers.empty())
      out["dns"] = node.DnsServers;
    if (node.Mtu > 0)
      out["mtu"] = node.Mtu;
    if (!peers[0].Reserved.empty()) {
      const string_array values = split(peers[0].Reserved, ",");
      if (values.size() != 3)
        return false;
      for (const std::string &value : values)
        out["reserved"].push_back(to_int(trim(value), -1));
    }
    if (peers[0].KeepAlive > 0)
      out["keepalive"] = peers[0].KeepAlive;
    break;
  }
  case ProxyType::Naive:
  case ProxyType::Unknown:
  default:
    return false;
  }

  if (!udp.is_undef()) {
    if (node.Type == ProxyType::Shadowsocks ||
        node.Type == ProxyType::SOCKS5 || node.Type == ProxyType::Snell ||
        node.Type == ProxyType::Trojan) {
      out["udp"] = udp.get();
    } else if (node.Type == ProxyType::HTTP || node.Type == ProxyType::HTTPS ||
               node.Type == ProxyType::AnyTLS) {
      if (udp.get())
        return false;
    } else if (node.Type == ProxyType::Mieru) {
      // Mieru's transport selects its carrier and is not an UDP-relay toggle.
      // Stash has no separate Mieru UDP override, so the generic preference is
      // intentionally not projected onto this protocol. A node-local false
      // value is nevertheless semantic and cannot be preserved.
      if (!udp.get())
        return false;
    } else if (!udp.get())
      return false;
  }
  if (!tfo.is_undef()) {
    if (node.Type == ProxyType::Hysteria2)
      out["fast-open"] = tfo.get();
    else if (tfo.get())
      return false;
  }
  if (insecure.get(false) &&
      (node.Type == ProxyType::Snell || node.Type == ProxyType::Mieru ||
       node.Type == ProxyType::WireGuard))
    return false;
  if (!node.TestUrl.empty())
    out["benchmark-url"] = node.TestUrl;
  return true;
}

struct StashGroupProviderSelection {
  std::vector<const StashProxyProvider *> providers;
  std::string filter;
  bool valid = true;
};

StashGroupProviderSelection stashProvidersForGroup(
    const ProxyGroupConfig &group,
    const std::vector<StashProxyProvider> &providers) {
  StashGroupProviderSelection selection;
  if (providers.empty())
    return selection;
  auto add_matching = [&](auto predicate) {
    for (const StashProxyProvider &provider : providers)
      if (predicate(provider) &&
          std::find(selection.providers.begin(), selection.providers.end(),
                    &provider) == selection.providers.end())
        selection.providers.push_back(&provider);
  };

  if (!group.UsingProvider.empty()) {
    add_matching([&](const StashProxyProvider &provider) {
      return std::any_of(group.UsingProvider.begin(), group.UsingProvider.end(),
                         [&](const std::string &requested) {
                           return requested == provider.name ||
                                  requested == provider.requested_name ||
                                  requested == provider.selection_name;
                         });
    });
    return selection;
  }

  bool saw_dynamic_selector = false;
  for (const std::string &rule : group.Proxies) {
    if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
      continue;
    {
      const std::string normalized_rule = toLower(rule);
      if (startsWith(normalized_rule, "http://") ||
          startsWith(normalized_rule, "https://"))
        continue;
    }
    std::string selector, server_pattern;
    bool matched_dynamic_selector = false;
    if (parseProviderGroupIdMatcher(rule, selector, server_pattern)) {
      matched_dynamic_selector = true;
      add_matching([&](const StashProxyProvider &provider) {
        return matchRange(selector, provider.group_id);
      });
    } else if (startsWith(rule, "!!GROUP=")) {
      static const std::string group_regex = R"(^!!GROUP=(.+?)(?:!!(.*))?$)";
      if (regGetMatch(rule, group_regex, 3,
                       static_cast<std::string *>(nullptr), &selector,
                       &server_pattern) == 0) {
        matched_dynamic_selector = true;
        add_matching([&](const StashProxyProvider &provider) {
          return !provider.source_tag.empty() &&
                 regFind(provider.source_tag, selector);
        });
      }
    } else if (!startsWith(rule, "!!") && !startsWith(rule, "script:")) {
      matched_dynamic_selector = true;
      add_matching([](const StashProxyProvider &) { return true; });
      server_pattern = rule;
    }
    if (!matched_dynamic_selector)
      continue;
    if (saw_dynamic_selector && selection.filter != server_pattern) {
      selection.valid = false;
      return selection;
    }
    saw_dynamic_selector = true;
    selection.filter = server_pattern;
  }
  return selection;
}

} // namespace

static std::string proxyToStashImpl(
    std::vector<Proxy> &nodes, const std::string &base_conf,
    std::vector<RulesetContent> &ruleset_content_array,
    const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext) {
  YAML::Node root;
  try {
    root = YAML::Load(base_conf);
  } catch (const std::exception &e) {
    writeLog(LOG_LEVEL_ERROR,
             "STASH_BASE_CONFIG_PARSE_FAILED detail=" +
                 summarizeSensitiveTextForLog(e.what()));
    ext.external_rule_error =
        "Invalid request: the selected Stash base template is not valid "
        "YAML.\n"
        "无效请求：所选 Stash 基础模板不是有效的 YAML。";
    return "";
  }
  if (!root.IsMap()) {
    ext.external_rule_error =
        "Invalid request: the selected Stash base template must be a YAML "
        "mapping.\n"
        "无效请求：所选 Stash 基础模板必须是 YAML 映射。";
    return "";
  }
  auto require_collection_type = [&](const char *key, YAML::NodeType::value type,
                                     const char *expected) {
    const YAML::Node value = root[key];
    if (!value.IsDefined() || value.IsNull() || value.Type() == type)
      return true;
    ext.external_rule_error =
        "Invalid request: Stash base field '" + std::string(key) +
        "' must be " + expected + ".\n无效请求：Stash 基础模板字段 '" +
        key + "' 的类型无效。";
    return false;
  };
  if (!require_collection_type("proxies", YAML::NodeType::Sequence,
                               "a YAML sequence") ||
      !require_collection_type("proxy-providers", YAML::NodeType::Map,
                               "a YAML mapping") ||
      !require_collection_type("proxy-groups", YAML::NodeType::Sequence,
                               "a YAML sequence") ||
      !require_collection_type("rules", YAML::NodeType::Sequence,
                               "a YAML sequence"))
    return "";

  TargetGenerationStats &stats = ext.target_generation_stats;
  stats = TargetGenerationStats{};
  stats.input_nodes = nodes.size();
  YAML::Node generated_nodes = root["proxies"].IsSequence()
                                   ? YAML::Clone(root["proxies"])
                                   : YAML::Node(YAML::NodeType::Sequence);
  generated_nodes.SetStyle(YAML::EmitterStyle::Block);
  if (!generated_nodes.IsSequence())
    generated_nodes = YAML::Node(YAML::NodeType::Sequence);
  YAML::Node base_groups = root["proxy-groups"].IsSequence()
                               ? YAML::Clone(root["proxy-groups"])
                               : YAML::Node(YAML::NodeType::Sequence);
  auto fail_base_schema = [&](const std::string &field) {
    ext.external_rule_error =
        "Invalid request: the selected Stash base has an invalid '" + field +
        "' entry.\n无效请求：所选 Stash 基础模板中的 '" + field +
        "' 条目无效。";
    return false;
  };
  if (root["rules"].IsSequence())
    for (const YAML::Node &rule : root["rules"])
      if (!rule.IsScalar())
        return fail_base_schema("rules"), std::string();
  if (root["sub-rules"].IsDefined() && !root["sub-rules"].IsNull()) {
    if (!root["sub-rules"].IsMap())
      return fail_base_schema("sub-rules"), std::string();
    for (const auto &sub_rule : root["sub-rules"]) {
      if (!sub_rule.first.IsScalar() || !sub_rule.second.IsSequence())
        return fail_base_schema("sub-rules"), std::string();
      for (const YAML::Node &rule : sub_rule.second)
        if (!rule.IsScalar())
          return fail_base_schema("sub-rules"), std::string();
    }
  }

  std::vector<std::string> base_remark_storage;
  base_remark_storage.reserve(generated_nodes.size() + base_groups.size());
  std::unordered_set<std::string> base_remark_keys;
  const std::unordered_set<std::string> built_in_policy_names = {
      "DIRECT", "REJECT", "REJECT-DROP", "PASS"};
  auto is_built_in_policy_name = [&](const std::string &name) {
    return built_in_policy_names.find(name) != built_in_policy_names.end();
  };
  for (const YAML::Node &item : generated_nodes) {
    if (!item.IsMap() || !item["name"].IsScalar())
      return fail_base_schema("proxies"), std::string();
    const std::string name = item["name"].as<std::string>();
    if (name.empty() || is_built_in_policy_name(name) ||
        !base_remark_keys.insert(name).second)
      return fail_base_schema("proxies.name"), std::string();
    base_remark_storage.push_back(name);
  }
  std::unordered_set<std::string> base_group_names;
  if (base_groups.IsSequence()) {
    for (const YAML::Node &group : base_groups) {
      if (!group.IsMap() || !group["name"].IsScalar() ||
          !group["type"].IsScalar() ||
          (group["proxies"].IsDefined() && !group["proxies"].IsNull() &&
           !group["proxies"].IsSequence()) ||
          (group["use"].IsDefined() && !group["use"].IsNull() &&
           !group["use"].IsSequence()))
        return fail_base_schema("proxy-groups"), std::string();
      const std::string name = group["name"].as<std::string>();
      if (name.empty() || is_built_in_policy_name(name) ||
          base_remark_keys.find(name) != base_remark_keys.end() ||
          !base_group_names.insert(name).second)
        return fail_base_schema("proxy-groups.name"), std::string();
      for (const char *member_key : {"proxies", "use"}) {
        const YAML::Node members = group[member_key];
        if (!members.IsDefined() || members.IsNull())
          continue;
        if (!members.IsSequence())
          return fail_base_schema("proxy-groups"), std::string();
        for (const YAML::Node &member : members)
          if (!member.IsScalar())
            return fail_base_schema("proxy-groups"), std::string();
      }
      base_remark_storage.push_back(name);
    }
  }
  std::unordered_set<std::string> planned_custom_group_names;
  for (const ProxyGroupConfig &group : extra_proxy_group) {
    if (group.Name.empty() || is_built_in_policy_name(group.Name) ||
        base_remark_keys.find(group.Name) != base_remark_keys.end() ||
        !planned_custom_group_names.insert(group.Name).second)
      return fail_base_schema("custom proxy-group name"), std::string();
    base_remark_storage.push_back(group.Name);
  }
  std::vector<Proxy> emitted_nodes;
  emitted_nodes.reserve(nodes.size());
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size() + base_remark_storage.size() +
                       built_in_policy_names.size());
  for (const std::string &name : built_in_policy_names)
    used_remarks.emplace(name);
  for (const std::string &name : base_remark_storage)
    used_remarks.emplace(name);

  for (const Proxy &original : nodes) {
    TargetNodeGenerationTracker tracker(stats, original.Type);
    Proxy node = original;
    if (ext.append_proxy_type)
      node.Remark = "[" + getProxyTypeName(node.Type) + "] " + node.Remark;
    processRemark(node.Remark, used_remarks, false);
    const bool stash_udp_field =
        node.Type == ProxyType::Shadowsocks ||
        node.Type == ProxyType::SOCKS5 || node.Type == ProxyType::Snell ||
        node.Type == ProxyType::Trojan;
    tribool udp = node.UDP;
    if (stash_udp_field) {
      udp = ext.udp;
      udp.define(node.UDP);
    } else if (!ext.stash_request_udp.is_undef()) {
      if (node.Type == ProxyType::Mieru)
        continue;
      udp = ext.stash_request_udp;
      udp.define(node.UDP);
    }
    tribool tfo = node.TCPFastOpen;
    if (node.Type == ProxyType::Hysteria2) {
      tfo = ext.tfo;
      tfo.define(node.TCPFastOpen);
    } else if (!ext.stash_request_tfo.is_undef()) {
      tfo = ext.stash_request_tfo;
      tfo.define(node.TCPFastOpen);
    }
    const bool stash_tls_capable =
        node.Type == ProxyType::HTTP || node.Type == ProxyType::HTTPS ||
        node.Type == ProxyType::SOCKS5 || node.Type == ProxyType::VMess ||
        node.Type == ProxyType::Trojan || node.Type == ProxyType::VLESS ||
        node.Type == ProxyType::AnyTLS || node.Type == ProxyType::Hysteria ||
        node.Type == ProxyType::Hysteria2 || node.Type == ProxyType::TUIC ||
        (node.Type == ProxyType::Shadowsocks &&
         toLower(node.Plugin) == "v2ray-plugin");
    tribool insecure = stash_tls_capable ? ext.skip_cert_verify
                                         : node.AllowInsecure;
    tribool tls13 = node.TLS13;
    if (!ext.stash_request_tls13.is_undef()) {
      tls13 = ext.stash_request_tls13;
      tls13.define(node.TLS13);
    }
    insecure.define(node.AllowInsecure);
    YAML::Node generated;
    generated.SetStyle(YAML::EmitterStyle::Block);
    if (!buildStashNode(node, generated, udp, tfo, insecure, tls13))
      continue;
    generated_nodes.push_back(generated);
    emitted_nodes.push_back(node);
    used_remarks.emplace(emitted_nodes.back().Remark);
    tracker.markEmitted();
  }
  root["proxies"] = generated_nodes;

  YAML::Node providers = root["proxy-providers"].IsMap()
                             ? YAML::Clone(root["proxy-providers"])
                             : YAML::Node(YAML::NodeType::Map);
  if (!providers.IsMap())
    providers = YAML::Node(YAML::NodeType::Map);
  providers.SetStyle(YAML::EmitterStyle::Block);
  std::unordered_set<std::string> provider_name_keys;
  std::unordered_set<std::string> provider_path_keys;
  for (const auto &entry : providers) {
    if (!entry.first.IsScalar() || !entry.second.IsMap())
      return fail_base_schema("proxy-providers"), std::string();
    const std::string name = entry.first.as<std::string>();
    if (name.empty() || !provider_name_keys.insert(toLower(name)).second)
      return fail_base_schema("proxy-providers.name"), std::string();
    const YAML::Node path = entry.second["path"];
    if (path.IsDefined() && !path.IsNull()) {
      if (!path.IsScalar())
        return fail_base_schema("proxy-providers.path"), std::string();
      const std::string normalized_path = toLower(path.as<std::string>());
      if (!normalized_path.empty() &&
          !provider_path_keys.insert(normalized_path).second)
        return fail_base_schema("proxy-providers.path"), std::string();
    }
  }
  for (const StashProxyProvider &provider : ext.stash_proxy_providers) {
    if (!provider_name_keys.insert(toLower(provider.name)).second ||
        !provider_path_keys.insert(toLower(provider.path)).second) {
      ext.external_rule_error =
          "Invalid request: a generated Stash proxy-provider name or path conflicts "
          "with the selected base template.\n"
          "无效请求：生成的 Stash proxy-provider 名称或路径与所选基础模板冲突。";
      return "";
    }
    YAML::Node item;
    item.SetStyle(YAML::EmitterStyle::Block);
    item["url"] = provider.url;
    item["path"] = provider.path;
    item["interval"] = provider.interval;
    if (!provider.headers.empty()) {
      YAML::Node headers(YAML::NodeType::Map);
      headers.SetStyle(YAML::EmitterStyle::Block);
      for (const auto &[name, value] : provider.headers)
        headers[name] = value;
      item["headers"] = headers;
    }
    providers[provider.name] = item;
  }
  root["proxy-providers"] = providers;

  YAML::Node groups(YAML::NodeType::Sequence);
  std::unordered_set<std::string> referenced_providers;
  std::unordered_set<std::string> generated_group_names;
  std::string preferred_entry_group;
  bool preferred_entry_has_provider = false;
  if (extra_proxy_group.empty() &&
      (!emitted_nodes.empty() || !ext.stash_proxy_providers.empty())) {
    bool attached = false;
    if (base_groups.IsSequence()) {
      for (YAML::Node group : base_groups) {
        if (!group["name"].IsDefined() ||
            group["name"].as<std::string>() != "Proxy")
          continue;
        if (group["type"].as<std::string>() != "select") {
          ext.external_rule_error =
              "Invalid request: the built-in Stash 'Proxy' group must be a "
              "select group before generated nodes or providers can be attached.\n"
              "无效请求：内置 Stash 'Proxy' 策略组必须是 select 类型，才能附加生成的节点或 provider。";
          return "";
        }
        std::unordered_set<std::string> existing_members;
        if (group["proxies"].IsSequence())
          for (const YAML::Node &member : group["proxies"])
            if (member.IsScalar())
              existing_members.insert(member.as<std::string>());
        for (const Proxy &node : emitted_nodes)
          if (existing_members.insert(node.Remark).second)
            group["proxies"].push_back(node.Remark);
        std::unordered_set<std::string> existing_uses;
        if (group["use"].IsSequence())
          for (const YAML::Node &use : group["use"])
            existing_uses.insert(use.as<std::string>());
        for (const StashProxyProvider &provider : ext.stash_proxy_providers)
          if (existing_uses.insert(provider.name).second) {
            group["use"].push_back(provider.name);
            referenced_providers.insert(provider.name);
          }
        attached = true;
        break;
      }
    }
    if (!attached) {
      YAML::Node group;
      group["name"] = "Proxy";
      group["type"] = "select";
      group["proxies"].push_back("DIRECT");
      for (const Proxy &node : emitted_nodes)
        group["proxies"].push_back(node.Remark);
      for (const StashProxyProvider &provider : ext.stash_proxy_providers) {
        group["use"].push_back(provider.name);
        referenced_providers.insert(provider.name);
      }
      base_groups.push_back(group);
    }
    root["proxy-groups"] = base_groups;
  }
  for (const ProxyGroupConfig &group : extra_proxy_group) {
    if (group.Type == ProxyGroupType::Smart ||
        group.Type == ProxyGroupType::SSID) {
      ext.external_rule_error =
          "Invalid request: the selected Stash target cannot represent a "
          "Smart or SSID custom proxy group without changing its semantics.\n"
          "无效请求：Stash 目标无法在不改变语义的前提下表示 Smart "
          "或 SSID 自定义策略组。";
      return "";
    }
    generated_group_names.insert(group.Name);
    if (group.DisableUdp.get(false) || group.Persistent.get(false) ||
        group.EvaluateBeforeUse.get(false)) {
      ext.external_rule_error =
          "Invalid request: the selected Stash target cannot represent one "
          "or more enabled custom proxy-group options.\n"
          "无效请求：Stash 目标无法表示一个或多个已启用的自定义策略组选项。";
      return "";
    }
    const StashGroupProviderSelection remote =
        stashProvidersForGroup(group, ext.stash_proxy_providers);
    if (!remote.valid) {
      ext.external_rule_error =
          "Invalid request: a Stash proxy group contains multiple remote "
          "selectors with different filters.\n"
          "无效请求：Stash 策略组包含筛选条件不同的多个远程选择器。";
      return "";
    }
    if (group.Type == ProxyGroupType::Relay && !remote.providers.empty()) {
      ext.external_rule_error =
          "Invalid request: a Stash relay group cannot preserve the order of "
          "a dynamic proxy-provider.\n"
          "无效请求：Stash relay 策略组无法保留动态 proxy-provider 的顺序。";
      return "";
    }

    YAML::Node item;
    item["name"] = group.Name;
    switch (group.Type) {
    case ProxyGroupType::Select:
      item["type"] = "select";
      break;
    case ProxyGroupType::URLTest:
      item["type"] = "url-test";
      break;
    case ProxyGroupType::Fallback:
      item["type"] = "fallback";
      break;
    case ProxyGroupType::LoadBalance:
      item["type"] = "load-balance";
      item["strategy"] = group.StrategyStr();
      break;
    case ProxyGroupType::Relay:
      item["type"] = "relay";
      if (!group.Url.empty())
        item["benchmark-url"] = group.Url;
      if (group.Timeout > 0)
        item["benchmark-timeout"] = group.Timeout;
      break;
    default:
      continue;
    }
    string_array local_members;
    for (const std::string &rule : group.Proxies)
      groupGenerate(rule, emitted_nodes, local_members, true, ext);
    if (local_members.empty() && remote.providers.empty())
      local_members.emplace_back("DIRECT");
    if (!local_members.empty())
      item["proxies"] = local_members;
    for (const StashProxyProvider *provider : remote.providers) {
      item["use"].push_back(provider->name);
      referenced_providers.insert(provider->name);
    }
    if (!remote.providers.empty() && !remote.filter.empty())
      item["filter"] = remote.filter;
    if (group.Interval != 0)
      item["interval"] = group.Interval;
    if (!group.Lazy.is_undef())
      item["lazy"] = group.Lazy.get();
    if (preferred_entry_group.empty() ||
        (!preferred_entry_has_provider && !remote.providers.empty())) {
      preferred_entry_group = group.Name;
      preferred_entry_has_provider = !remote.providers.empty();
    }
    groups.push_back(item);
  }
  if (groups.size() > 0 &&
      generated_group_names.find("Proxy") == generated_group_names.end()) {
    bool references_proxy = false;
    for (const ProxyGroupConfig &group : extra_proxy_group)
      if (std::find(group.Proxies.begin(), group.Proxies.end(), "[]Proxy") !=
          group.Proxies.end())
        references_proxy = true;
    if (references_proxy) {
      ext.external_rule_error =
          "Invalid request: adding the required Stash 'Proxy' entry group "
          "would create a proxy-group cycle.\n"
          "无效请求：补充必需的 Stash 'Proxy' 入口策略组会形成循环引用。";
      return "";
    }
    YAML::Node entry;
    entry["name"] = "Proxy";
    entry["type"] = "select";
    entry["proxies"].push_back(preferred_entry_group.empty()
                                   ? std::string("DIRECT")
                                   : preferred_entry_group);
    groups.push_back(entry);
  }
  if (groups.size() > 0) {
    const bool ignored_benchmark_tuning =
        std::any_of(extra_proxy_group.begin(), extra_proxy_group.end(),
                    [](const ProxyGroupConfig &group) {
                      return group.Type != ProxyGroupType::Relay &&
                             (!group.Url.empty() || group.Timeout != 0 ||
                              group.Tolerance != 0);
                    });
    if (ignored_benchmark_tuning)
      writeLog(LOG_LEVEL_WARNING,
               "STASH_GROUP_BENCHMARK_DEFAULTS client=stash reason="
               "unsupported-group-specific-url-timeout-tolerance");
    root["proxy-groups"] = groups;
  }
  stats.remote_references_emitted = referenced_providers.size();

  if (ext.enable_rule_generator) {
    std::string stash_rule_error;
    if (!rulesetToStash(root, ruleset_content_array,
                        ext.overwrite_original_rules, ext.stash_rule_stats,
                        ext.rule_stats, stash_rule_error)) {
      ext.external_rule_error = std::move(stash_rule_error);
      writeLog(LOG_LEVEL_WARNING,
               "STASH_RULE_GENERATION input=" +
                   std::to_string(ext.stash_rule_stats.input_sources) +
                   " inline=" +
                   std::to_string(ext.stash_rule_stats.inline_sources) +
                   " expanded=" +
                   std::to_string(ext.stash_rule_stats.expanded_sources) +
                   " providers=" +
                   std::to_string(ext.stash_rule_stats.providerized_sources) +
                   " unsupported=" +
                   std::to_string(ext.stash_rule_stats.unsupported_sources));
      return "";
    }
    writeLog(LOG_LEVEL_INFO,
             "STASH_RULE_GENERATION input=" +
                 std::to_string(ext.stash_rule_stats.input_sources) +
                 " inline=" +
                 std::to_string(ext.stash_rule_stats.inline_sources) +
                 " expanded=" +
                 std::to_string(ext.stash_rule_stats.expanded_sources) +
                 " providers=" +
                 std::to_string(ext.stash_rule_stats.providerized_sources) +
                 " emitted_rules=" +
                 std::to_string(ext.stash_rule_stats.emitted_rules) +
                 " unsupported=0");
  }
  if (!ext.rule_prepend.empty() || !ext.rule_append.empty()) {
    string_array current_rules;
    if (root["rules"].IsDefined() && root["rules"].IsSequence())
      current_rules = safe_as<string_array>(root["rules"]);
    string_array merged;
    if (!mergeClashRulesWithinLimit(
            ext.rule_prepend, {}, current_rules, ext.rule_append,
            effectiveSettings().maxAllowedRules, merged)) {
      ext.external_rule_error =
          "Invalid request: the final Stash rule count exceeds "
          "max_allowed_rules.\n"
          "无效请求：最终 Stash 规则数量超过 max_allowed_rules 限制。";
      return "";
    }
    root["rules"] = merged;
  }

  // A custom Stash base is deployment input. Validate the final reference
  // graph after every generated group/rule rewrite so a syntactically valid
  // YAML document cannot retain a dangling policy/provider or a group cycle.
  auto fail_reference_graph = [&]() {
    ext.external_rule_error =
        "Invalid request: the final Stash configuration contains a dangling "
        "or cyclic policy reference.\n"
        "无效请求：最终 Stash 配置包含悬空或循环的策略引用。";
    return std::string();
  };
  std::unordered_set<std::string> proxy_names = {"DIRECT", "REJECT",
                                                  "REJECT-DROP", "PASS"};
  if (root["proxies"].IsSequence()) {
    for (const YAML::Node &proxy : root["proxies"])
      if (!proxy.IsMap() || !proxy["name"].IsScalar())
        return fail_reference_graph();
      else
        proxy_names.insert(proxy["name"].as<std::string>());
  }

  std::unordered_set<std::string> provider_names;
  if (root["proxy-providers"].IsMap()) {
    for (const auto &provider : root["proxy-providers"])
      if (!provider.first.IsScalar())
        return fail_reference_graph();
      else
        provider_names.insert(provider.first.as<std::string>());
  }

  std::unordered_set<std::string> rule_provider_names;
  if (root["rule-providers"].IsDefined() &&
      !root["rule-providers"].IsNull()) {
    if (!root["rule-providers"].IsMap())
      return fail_reference_graph();
    for (const auto &provider : root["rule-providers"])
      if (!provider.first.IsScalar())
        return fail_reference_graph();
      else
        rule_provider_names.insert(provider.first.as<std::string>());
  }

  std::unordered_set<std::string> script_shortcut_names;
  YAML::Node script_shortcuts;
  if (root["script"].IsDefined() && !root["script"].IsNull()) {
    if (!root["script"].IsMap())
      return fail_reference_graph();
    script_shortcuts = root["script"]["shortcuts"];
  }
  if (script_shortcuts.IsDefined() && !script_shortcuts.IsNull()) {
    if (!script_shortcuts.IsMap())
      return fail_reference_graph();
    for (const auto &shortcut : script_shortcuts)
      if (!shortcut.first.IsScalar())
        return fail_reference_graph();
      else
        script_shortcut_names.insert(shortcut.first.as<std::string>());
  }

  std::unordered_set<std::string> group_names;
  if (root["proxy-groups"].IsSequence())
    for (const YAML::Node &group : root["proxy-groups"])
      if (!group.IsMap() || !group["name"].IsScalar() ||
          proxy_names.find(group["name"].as<std::string>()) !=
              proxy_names.end() ||
          !group_names.insert(group["name"].as<std::string>()).second)
        return fail_reference_graph();

  std::unordered_set<std::string> sub_rule_names;
  if (root["sub-rules"].IsDefined() && !root["sub-rules"].IsNull()) {
    if (!root["sub-rules"].IsMap())
      return fail_reference_graph();
    for (const auto &sub_rule : root["sub-rules"])
      if (!sub_rule.first.IsScalar() || !sub_rule.second.IsSequence())
        return fail_reference_graph();
      else
        sub_rule_names.insert(sub_rule.first.as<std::string>());
  }

  std::unordered_map<std::string, std::vector<std::string>> group_edges;
  if (root["proxy-groups"].IsSequence()) {
    for (const YAML::Node &group : root["proxy-groups"]) {
      const std::string name = group["name"].as<std::string>();
      if (group["proxies"].IsDefined() && !group["proxies"].IsNull()) {
        if (!group["proxies"].IsSequence())
          return fail_reference_graph();
        for (const YAML::Node &member_node : group["proxies"]) {
          if (!member_node.IsScalar())
            return fail_reference_graph();
          const std::string member = member_node.as<std::string>();
          if (proxy_names.find(member) == proxy_names.end() &&
              group_names.find(member) == group_names.end())
            return fail_reference_graph();
          if (group_names.find(member) != group_names.end())
            group_edges[name].push_back(member);
        }
      }
      if (group["use"].IsDefined() && !group["use"].IsNull()) {
        if (!group["use"].IsSequence())
          return fail_reference_graph();
        for (const YAML::Node &provider_node : group["use"])
          if (!provider_node.IsScalar() ||
              provider_names.find(provider_node.as<std::string>()) ==
                  provider_names.end())
            return fail_reference_graph();
      }
      if (group["ssid-policy"].IsDefined() &&
          !group["ssid-policy"].IsNull()) {
        if (!group["ssid-policy"].IsMap())
          return fail_reference_graph();
        for (const auto &mapping : group["ssid-policy"]) {
          if (!mapping.first.IsScalar() || !mapping.second.IsScalar())
            return fail_reference_graph();
          const std::string member = mapping.second.as<std::string>();
          if (proxy_names.find(member) == proxy_names.end() &&
              group_names.find(member) == group_names.end())
            return fail_reference_graph();
          if (group_names.find(member) != group_names.end())
            group_edges[name].push_back(member);
        }
      }
    }
  }

  std::unordered_map<std::string, unsigned char> visit_state;
  std::function<bool(const std::string &)> has_group_cycle =
      [&](const std::string &name) {
        unsigned char &state = visit_state[name];
        if (state == 1)
          return true;
        if (state == 2)
          return false;
        state = 1;
        for (const std::string &child : group_edges[name])
          if (has_group_cycle(child))
            return true;
        state = 2;
        return false;
      };
  for (const std::string &name : group_names)
    if (has_group_cycle(name))
      return fail_reference_graph();

  auto embedded_rule_references_are_closed =
      [&](const std::string &rule) {
        const string_array references = regGetAllMatch(
            rule,
            R"((?:^|\()\s*([A-Za-z-]+)\s*,\s*([^,()]+))",
            true);
        if (references.size() % 2 != 0)
          return false;
        for (size_t i = 0; i < references.size(); i += 2) {
          const std::string kind = toUpper(trim(references[i]));
          if (kind != "RULE-SET" && kind != "SCRIPT")
            continue;
          const std::string reference = trim(references[i + 1]);
          if (reference.empty())
            return false;
          if (kind == "RULE-SET" &&
              rule_provider_names.find(reference) == rule_provider_names.end())
            return false;
          if (kind == "SCRIPT" &&
              script_shortcut_names.find(reference) ==
                  script_shortcut_names.end())
            return false;
        }
        return true;
      };
  auto rule_sequence_is_closed = [&](const YAML::Node &rules) {
    if (!rules.IsSequence())
      return false;
    for (const YAML::Node &rule_node : rules) {
      if (!rule_node.IsScalar())
        return false;
      const std::string rule = rule_node.as<std::string>();
      if (!embedded_rule_references_are_closed(rule))
        return false;
      string_array fields = split(rule, ",");
      if (fields.size() < 2)
        return false;
      size_t policy_index = fields.size() - 1;
      while (policy_index > 0) {
        const std::string option = toLower(trim(fields[policy_index]));
        if (option != "no-resolve" && option != "no-track")
          break;
        --policy_index;
      }
      if (policy_index == 0)
        return false;
      const std::string rule_type = toUpper(trim(fields.front()));
      if (rule_type == "RULE-SET" &&
          (fields.size() < 3 ||
           rule_provider_names.find(trim(fields[1])) ==
               rule_provider_names.end()))
        return false;
      if (rule_type == "SCRIPT" &&
          (fields.size() < 3 ||
           script_shortcut_names.find(trim(fields[1])) ==
               script_shortcut_names.end()))
        return false;
      const std::string policy = trim(fields[policy_index]);
      const bool valid_sub_rule =
          rule_type == "SUB-RULE" &&
          sub_rule_names.find(policy) != sub_rule_names.end();
      if (!valid_sub_rule && proxy_names.find(policy) == proxy_names.end() &&
          group_names.find(policy) == group_names.end())
        return false;
    }
    return true;
  };
  if (root["rules"].IsDefined() && !root["rules"].IsNull() &&
      !rule_sequence_is_closed(root["rules"]))
    return fail_reference_graph();
  if (root["sub-rules"].IsMap()) {
    for (const auto &sub_rule : root["sub-rules"])
      if (!rule_sequence_is_closed(sub_rule.second))
        return fail_reference_graph();
  }
  ext.stash_rule_stats.final_provider_count = rule_provider_names.size();
  return finalizeCanonicalClashYaml(YAML::Dump(root));
}

std::string proxyToStash(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext) {
  try {
    return proxyToStashImpl(nodes, base_conf, ruleset_content_array,
                            extra_proxy_group, ext);
  } catch (const std::exception &e) {
    writeLog(LOG_LEVEL_ERROR,
             "STASH_CONFIG_GENERATION_FAILED detail=" +
                 summarizeSensitiveTextForLog(e.what()));
  } catch (...) {
    writeLog(LOG_LEVEL_ERROR,
             "STASH_CONFIG_GENERATION_FAILED detail=unknown-exception");
  }
  ext.external_rule_error =
      "Invalid request: the Stash configuration could not be generated from "
      "the selected inputs.\n"
      "无效请求：无法根据所选输入生成 Stash 配置。";
  return "";
}

std::string proxyToSurge(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         int surge_ver, extra_settings &ext) {
  const bool resolve_hostname = effectiveSettings().surgeResolveHostname;
  INIReader ini;
  std::string output_nodelist;
  std::vector<Proxy> nodelist;
  unsigned short local_port = 1080;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());
  const bool surfboard = surge_ver == -3;
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  TargetGenerationStatsMirror generation_stats_mirror(
      generation_stats, surfboard ? ext.surfboard_generation_stats
                                  : ext.surge_generation_stats);

  ini.store_any_line = true;
  // filter out sections that requires direct-save
  ini.add_direct_save_section("General");
  ini.add_direct_save_section("Replica");
  ini.add_direct_save_section("Rule");
  ini.add_direct_save_section("MITM");
  ini.add_direct_save_section("Script");
  ini.add_direct_save_section("Host");
  ini.add_direct_save_section("URL Rewrite");
  ini.add_direct_save_section("Header Rewrite");
  if (ini.parse(base_conf) != 0 && !ext.nodelist) {
    writeLog(LOG_LEVEL_ERROR, "SURGE_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return "";
  }

  ini.set_current_section("Proxy");
  ini.erase_section();
  ini.set("{NONAME}", "DIRECT = direct");

  for (Proxy &x : nodes) {
    bool supported = true;
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, &sni = x.ServerName,
                &username = x.Username, &password = x.Password,
                &method = x.EncryptMethod, &id = x.UserId,
                &transproto = x.TransferProtocol, &host = x.Host,
                &edge = x.Edge, &path = x.Path, &protocol = x.Protocol,
                &protoparam = x.ProtocolParam, &obfs = x.OBFS,
                &obfsparam = x.OBFSParam, &plugin = x.Plugin,
                &pluginopts = x.PluginOption,
                &underlying_proxy = x.UnderlyingProxy;
    std::string port = std::to_string(x.Port);
    ;
    bool &tlssecure = x.TLSSecure;

    tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify,
            tls13 = ext.tls13;
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);
    tls13.define(x.TLS13);

    std::string proxy, section, real_section;
    string_array args, headers;
    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (!surgeProxyScalarIsSafe(x.Remark) ||
          !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(method) ||
          !surgeProxyScalarIsSafe(password)) {
        supported = false;
        break;
      }
      if (surge_ver >= 3 || surge_ver == -3) {
        proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method +
                ", password=" + password;
      } else {
        proxy =
            "custom, " + hostname + ", " + port + ", " + method + ", " +
            password +
            ", "
            "https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
      }
      if (!plugin.empty()) {
        if (!surgeProxyScalarIsSafe(pluginopts)) {
          supported = false;
          break;
        }
        switch (hash_(plugin)) {
        case "simple-obfs"_hash:
        case "obfs-local"_hash:
          if (!pluginopts.empty())
            proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
          break;
        default:
          supported = false;
          break;
        }
      }
      break;
    case ProxyType::VMess:
      if (surge_ver < 4 && surge_ver != -3) {
        supported = false;
        break;
      }
      proxy = "vmess, " + hostname + ", " + port + ", username=" + id +
              ", tls=" + (tlssecure ? "true" : "false") +
              ", vmess-aead=" + (x.AlterId == 0 ? "true" : "false");
      if (tlssecure && !tls13.is_undef())
        proxy += ", tls13=" + std::string(tls13 ? "true" : "false");
      switch (hash_(transproto)) {
      case "tcp"_hash:
        break;
      case "ws"_hash:
        if (host.empty())
          proxy += ", ws=true, ws-path=" + path + ", sni=" + hostname;
        else
          proxy += ", ws=true, ws-path=" + path + ", sni=" + host;
        if (!host.empty())
          headers.push_back("Host:" + host);
        if (!edge.empty())
          headers.push_back("Edge:" + edge);
        if (!headers.empty())
          proxy += ", ws-headers=" + join(headers, "|");
        break;
      default:
        supported = false;
        break;
      }
      if (!scv.is_undef())
        proxy += ", skip-cert-verify=" + scv.get_str();
      break;
    case ProxyType::ShadowsocksR:
      if (ext.surge_ssr_path.empty() || surge_ver < 2) {
        supported = false;
        break;
      }
      proxy = "external, exec=\"" + ext.surge_ssr_path + "\", args=\"";
      args = {"-l", std::to_string(local_port),
              "-s", hostname,
              "-p", port,
              "-m", method,
              "-k", password,
              "-o", obfs,
              "-O", protocol};
      if (!obfsparam.empty()) {
        args.emplace_back("-g");
        args.emplace_back(std::move(obfsparam));
      }
      if (!protoparam.empty()) {
        args.emplace_back("-G");
        args.emplace_back(std::move(protoparam));
      }
      proxy += join(args, "\", args=\"");
      proxy += "\", local-port=" + std::to_string(local_port);
      if (isIPv4(hostname) || isIPv6(hostname))
        proxy += ", addresses=" + hostname;
      else if (resolve_hostname)
        proxy += ", addresses=" + hostnameToIPAddr(hostname);
      local_port++;
      break;
    case ProxyType::SOCKS5:
      proxy = "socks5, " + hostname + ", " + port;
      if (!username.empty())
        proxy += ", username=" + username;
      if (!password.empty())
        proxy += ", password=" + password;
      if (!scv.is_undef())
        proxy += ", skip-cert-verify=" + scv.get_str();
      break;
    case ProxyType::HTTPS:
      if (surge_ver == -3) {
        proxy = "https, " + hostname + ", " + port + ", " + username + ", " +
                password;
        if (!scv.is_undef())
          proxy += ", skip-cert-verify=" + scv.get_str();
        break;
      }
      [[fallthrough]];
    case ProxyType::HTTP:
      proxy = "http, " + hostname + ", " + port;
      if (!username.empty())
        proxy += ", username=" + username;
      if (!password.empty())
        proxy += ", password=" + password;
      proxy += std::string(", tls=") + (x.TLSSecure ? "true" : "false");
      if (!scv.is_undef())
        proxy += ", skip-cert-verify=" + scv.get_str();
      break;
    case ProxyType::Trojan:
      if (surge_ver < 4 && surge_ver != -3) {
        supported = false;
        break;
      }
      proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
      if (x.SnellVersion != 0)
        proxy += ", version=" + std::to_string(x.SnellVersion);
      if (!sni.empty()) {
        proxy += ", sni=" + sni;
      } else if (!host.empty()) {
        proxy += ", sni=" + host;
      }
      if (!scv.is_undef())
        proxy += ", skip-cert-verify=" + scv.get_str();
      break;
    case ProxyType::Snell: {
      const uint16_t snell_version =
          x.SnellVersion == 0 ? 1 : x.SnellVersion;
      if (surge_ver < 3 || surge_ver == -3 || snell_version > 6 ||
          x.Password.empty() ||
          !x.SnellUserKey.empty() || !x.SnellNetwork.empty() ||
          (snell_version == 6 &&
           (!x.OBFS.empty() || !x.Host.empty() || !x.Path.empty())) ||
          (!x.OBFS.empty() && x.OBFS != "http" &&
           x.OBFS != "tls" && x.OBFS != "shadow-tls") ||
          (snell_version >= 4 && x.OBFS == "tls") ||
          (!x.Path.empty() && x.OBFS != "http") ||
          (x.SnellUDPPort != 0 && snell_version < 3) ||
          (snell_version == 6
               ? (!x.SnellMode.empty() && x.SnellMode != "default" &&
                  x.SnellMode != "unshaped" &&
                  x.SnellMode != "unsafe-raw")
               : !x.SnellMode.empty()) ||
          ((!x.ShadowTLSPassword.empty() || !x.ShadowTLSSNI.empty() ||
            x.ShadowTLSVersion != 0) &&
           (x.ShadowTLSPassword.empty() ||
            (!x.OBFS.empty() && x.OBFS != "shadow-tls") ||
            (x.ShadowTLSVersion != 0 && x.ShadowTLSVersion != 2 &&
             x.ShadowTLSVersion != 3) ||
            (x.ShadowTLSVersion == 3 && x.ShadowTLSSNI.empty()))) ||
          !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(password) ||
          !surgeProxyScalarIsSafe(obfs) ||
          !surgeProxyScalarIsSafe(host) ||
          !surgeProxyScalarIsSafe(path) ||
          !surgeProxyScalarIsSafe(x.ShadowTLSPassword) ||
          !surgeProxyScalarIsSafe(x.ShadowTLSSNI)) {
        supported = false;
        break;
      }
      proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
      if (obfs == "http" || obfs == "tls") {
        proxy += ", obfs=" + obfs;
        if (!host.empty())
          proxy += ", obfs-host=" + host;
      }
      if (!path.empty())
        proxy += ", obfs-uri=" + path;
      proxy += ", version=" + std::to_string(snell_version);
      if (!x.SnellReuse.is_undef())
        proxy += ", reuse=" + x.SnellReuse.get_str();
      if (x.SnellUDPPort != 0)
        proxy += ", udp-port=" + std::to_string(x.SnellUDPPort);
      if (!x.SnellMode.empty())
        proxy += ", mode=" + x.SnellMode;
      if (!x.ShadowTLSPassword.empty())
        proxy += ", shadow-tls-password=" + x.ShadowTLSPassword;
      if (!x.ShadowTLSSNI.empty())
        proxy += ", shadow-tls-sni=" + x.ShadowTLSSNI;
      if (x.ShadowTLSVersion > 0)
        proxy += ", shadow-tls-version=" +
                 std::to_string(x.ShadowTLSVersion);
      break;
    }
    case ProxyType::Hysteria2:
      if (surge_ver < 4 || !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(password) ||
          !surgeProxyScalarIsSafe(x.ServerName) ||
          !surgeProxyScalarIsSafe(x.Fingerprint) ||
          !surgeProxyScalarIsSafe(x.OBFSPassword) ||
          !surgeProxyScalarIsSafe(x.Alpn) ||
          !x.Hysteria2RealmUrl.empty() ||
          !x.Hysteria2GeckoMinPacketSize.empty() ||
          !x.Hysteria2GeckoMaxPacketSize.empty()) {
        supported = false;
        break;
      }
      proxy = "hysteria2, " + hostname + ", " + port + ", password=" + password;
      {
        int download_bandwidth = 0;
        if (parseMbpsValue(x.DownMbps, download_bandwidth))
          proxy += ", download-bandwidth=" +
                   std::to_string(download_bandwidth);
      }

      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      if (!x.Fingerprint.empty())
        proxy += ",server-cert-fingerprint-sha256=" + x.Fingerprint;
      if (!x.ServerName.empty())
        proxy += ",sni=" + x.ServerName;
      if (!x.Alpn.empty())
        proxy += ",alpn=" + trim(split(x.Alpn, ",").front());
      if (!x.OBFSPassword.empty()) {
        if (x.OBFSParam == "salamander")
          proxy += ",salamander-password=" + x.OBFSPassword;
        else if (x.OBFSParam == "gecko")
          proxy += ",gecko-password=" + x.OBFSPassword;
      }
      if (!x.Ports.empty()) {
        proxy += ",port-hopping=" +
                 replaceAllDistinct(hysteria2PortSpec(x), ",", ";");
      }
      break;
    case ProxyType::TUIC:
      if (surge_ver < 4 || x.token.empty() ||
          !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(x.token) ||
          !surgeProxyScalarIsSafe(x.ServerName) ||
          !surgeProxyScalarIsSafe(x.Alpn)) {
        supported = false;
        break;
      }
      proxy = "tuic, " + hostname + ", " + port + ", token=" + x.token;
      if (!scv.is_undef())
        proxy += ",skip-cert-verify=" + scv.get_str();
      if (!x.ServerName.empty())
        proxy += ",sni=" + x.ServerName;
      if (!x.Alpn.empty())
        proxy += ",alpn=" + trim(split(x.Alpn, ",").front());
      if (!x.Ports.empty())
        proxy += ",port-hopping=" +
                 replaceAllDistinct(x.Ports, ",", ";");
      break;
    case ProxyType::AnyTLS:
      if (surge_ver < 4 || !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(password) ||
          !surgeProxyScalarIsSafe(x.ServerName) ||
          (!x.AlpnList.empty() &&
           !surgeProxyScalarIsSafe(x.AlpnList.front()))) {
        supported = false;
        break;
      }
      proxy = "anytls, " + hostname + ", " + port + ", password=" +
              password;
      if (!scv.is_undef())
        proxy += ",skip-cert-verify=" + scv.get_str();
      if (!x.ServerName.empty())
        proxy += ",sni=" + x.ServerName;
      if (!x.AlpnList.empty())
        proxy += ",alpn=" + x.AlpnList.front();
      break;
    case ProxyType::WireGuard:
      if (surge_ver < 4 && surge_ver != -3) {
        supported = false;
        break;
      }
      if (!wireGuardStructuredConfigIsSafe(x)) {
        supported = false;
        break;
      }
      section = randomStr(5);
      real_section = "WireGuard " + section;
      proxy = "wireguard, section-name=" + section;
      if (!x.TestUrl.empty())
        proxy += ", test-url=" + x.TestUrl;
      ini.set(real_section, "private-key", x.PrivateKey);
      for (const std::string &address : wireGuardLocalAddresses(x)) {
        const std::string bare = wireGuardAddressWithoutPrefix(address);
        if (isIPv4(bare))
          ini.set(real_section, "self-ip", bare);
        else if (isIPv6(bare))
          ini.set(real_section, "self-ip-v6", bare);
      }
      if (!x.DnsServers.empty())
        ini.set(real_section, "dns-server", join(x.DnsServers, ","));
      if (x.Mtu > 0)
        ini.set(real_section, "mtu", std::to_string(x.Mtu));
      {
        std::string peer_value;
        for (const WireGuardPeer &peer : wireGuardPeers(x)) {
          if (!peer_value.empty())
            peer_value += ",";
          peer_value += "(" + generatePeer(peer) + ")";
        }
        ini.set(real_section, "peer", peer_value);
      }
      break;
    default:
      supported = false;
      break;
    }

    if (!supported) {
      generation_stats.unsupported_by_type[x.Type]++;
      continue;
    }

    if (!tfo.is_undef())
      proxy += ", tfo=" + tfo.get_str();
    if (!udp.is_undef() && x.Type != ProxyType::AnyTLS)
      proxy += ", udp-relay=" + udp.get_str();
    if (underlying_proxy != "")
      proxy += ", underlying-proxy=" + underlying_proxy;
    if (ext.nodelist)
      output_nodelist += x.Remark + " = " + proxy + "\n";
    else {
      ini.set("{NONAME}", x.Remark + " = " + proxy);
      nodelist.emplace_back(x);
    }
    used_remarks.emplace(x.Remark);
    generation_stats.emitted_nodes++;
  }

  if (ext.nodelist)
    return output_nodelist;

  ini.set_current_section("Proxy Group");
  ini.erase_section();
  size_t surfboard_test_url_fallbacks = 0;
  for (const ProxyGroupConfig &x : extra_proxy_group) {
    string_array filtered_nodelist;
    std::string group;
    const auto surge_remote_selector =
        policyPathSelectorForGroup(x, ext.surge_policy_paths);
    const auto surfboard_remote_selector =
        policyPathSelectorForGroup(x, ext.surfboard_policy_paths);
    const bool has_remote_selector =
        surfboard ? surfboard_remote_selector.resource != nullptr
                  : surge_remote_selector.resource != nullptr;

    switch (x.Type) {
    case ProxyGroupType::Select:
    case ProxyGroupType::Smart:
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
      break;
    case ProxyGroupType::LoadBalance:
      if (surge_ver < 1 && surge_ver != -3)
        continue;
      break;
    case ProxyGroupType::SSID:
      group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
      group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
      ini.set("{NONAME}", x.Name + " = " + group); // insert order
      continue;
    default:
      continue;
    }

    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, true, ext);

    if (filtered_nodelist.empty() && !has_remote_selector)
      filtered_nodelist.emplace_back("DIRECT");

    if (filtered_nodelist.size() == 1 && !has_remote_selector) {
      group = toLower(filtered_nodelist[0]);
      switch (hash_(group)) {
      case "direct"_hash:
      case "reject"_hash:
      case "reject-tinygif"_hash:
        ini.set("Proxy", "{NONAME}", x.Name + " = " + group);
        continue;
      }
    }

    group = x.TypeStr();
    if (!filtered_nodelist.empty())
      group += "," + join(filtered_nodelist, ",");
    if (has_remote_selector) {
      if (surfboard) {
        const SurfboardPolicyPathResource &resource =
            *surfboard_remote_selector.resource;
        group += ",policy-path=" + safePolicyPathUrl(resource.url);
        group += ",policy-regex-filter=\"" +
                 surfboardPolicyPattern(
                     surfboard_remote_selector.policy_pattern) +
                 "\"";
      } else {
        const SurgePolicyPathResource &resource =
            *surge_remote_selector.resource;
        group += ",policy-path=" + safePolicyPathUrl(resource.url);
        if (resource.has_update_interval)
          group += ",update-interval=" +
                   std::to_string(resource.update_interval);
        group += ",policy-regex-filter=\"" +
                 surge_remote_selector.policy_pattern + "\"";
      }
      generation_stats.remote_references_emitted++;
    }
    if (x.Type == ProxyGroupType::URLTest ||
        x.Type == ProxyGroupType::Fallback ||
        (!surfboard && x.Type == ProxyGroupType::LoadBalance)) {
      std::string test_url = x.Url;
      if (surfboard && !test_url.empty() &&
          !startsWith(toLower(test_url), "http://")) {
        test_url = "http://www.gstatic.com/generate_204";
        surfboard_test_url_fallbacks++;
      }
      if (surfboard && !test_url.empty())
        group += ",url=" + test_url;
      else if (!surfboard)
        group += ",url=" + test_url;
      group += ",interval=" + std::to_string(x.Interval);
      if (x.Tolerance > 0 &&
          (!surfboard || x.Type == ProxyGroupType::URLTest))
        group += ",tolerance=" + std::to_string(x.Tolerance);
      if (x.Timeout > 0)
        group += ",timeout=" + std::to_string(x.Timeout);
      if (!surfboard && !x.Persistent.is_undef())
        group += ",persistent=" + x.Persistent.get_str();
      if (!surfboard && !x.EvaluateBeforeUse.is_undef())
        group += ",evaluate-before-use=" + x.EvaluateBeforeUse.get_str();
    }

    ini.set("{NONAME}", x.Name + " = " + group); // insert order
  }

  if (surfboard_test_url_fallbacks) {
    writeLog(LOG_LEVEL_WARNING,
             "SURFBOARD_TEST_URL_NORMALIZED count=" +
                 std::to_string(surfboard_test_url_fallbacks) +
                 " fallback=http://www.gstatic.com/generate_204");
  }

  if (ext.enable_rule_generator)
    rulesetToSurge(ini, ruleset_content_array, surge_ver,
                   ext.overwrite_original_rules, ext.managed_config_prefix,
                   ext.rule_stats);

  return ini.to_string();
}

namespace {

using V2RayProfileWriter =
    rapidjson::Writer<rapidjson::StringBuffer>;

void writeV2RayProfileString(V2RayProfileWriter &writer, const char *key,
                             const std::string &value) {
  if (value.empty())
    return;
  writer.Key(key);
  writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
}

bool isV2RayProfileUuid(const std::string &value) {
  static const std::string pattern =
      "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
      "[0-9a-f]{4}-[0-9a-f]{12}$";
  return regMatch(value, pattern);
}

bool v2rayProfileTransport(const Proxy &proxy, V2RayClientTarget target,
                           std::string &network) {
  network = toLower(trim(proxy.TransferProtocol));
  if (network.empty() || network == "tcp" || network == "none")
    network = "raw";
  else if (network == "mkcp")
    network = "kcp";
  else if (network == "gun")
    network = "grpc";
  else if (network == "splithttp")
    network = "xhttp";
  else if (network == "h2")
    network = "http";

  static const string_array desktop_networks = {
      "raw", "kcp", "ws", "httpupgrade", "xhttp", "grpc"};
  static const string_array android_networks = {
      "raw", "kcp", "ws", "httpupgrade", "xhttp", "http", "grpc"};
  const string_array &supported = target == V2RayClientTarget::V2RayN
                                      ? desktop_networks
                                      : android_networks;
  if (std::find(supported.begin(), supported.end(), network) ==
      supported.end())
    return false;
  if (proxy.V2rayHttpUpgrade.get(false) && network != "httpupgrade")
    return false;
  if (!proxy.Edge.empty() || !proxy.QUICSecure.empty() ||
      !proxy.QUICSecret.empty())
    return false;
  if (network == "raw" && !proxy.FakeType.empty() &&
      proxy.FakeType != "none" && proxy.FakeType != "http")
    return false;
  static const string_array kcp_header_types = {
      "none", "srtp", "utp", "wechat-video", "dtls", "wireguard",
      "dns"};
  if (network == "kcp") {
    const std::string header =
        proxy.FakeType.empty() ? std::string("none")
                               : toLower(trim(proxy.FakeType));
    if (std::find(kcp_header_types.begin(), kcp_header_types.end(), header) ==
        kcp_header_types.end())
      return false;
  }
  if (network == "grpc" && !proxy.GRPCMode.empty() &&
      proxy.GRPCMode != "gun" && proxy.GRPCMode != "multi")
    return false;
  static const string_array xhttp_modes = {
      "auto", "packet-up", "stream-up", "stream-one"};
  if (network == "xhttp" && !proxy.GRPCMode.empty() &&
      std::find(xhttp_modes.begin(), xhttp_modes.end(), proxy.GRPCMode) ==
          xhttp_modes.end())
    return false;
  return true;
}

bool v2rayProfileVmessSecurityIsSupported(const Proxy &proxy) {
  static const string_array securities = {
      "aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero"};
  const std::string security =
      proxy.EncryptMethod.empty() ? std::string("auto")
                                  : toLower(trim(proxy.EncryptMethod));
  return std::find(securities.begin(), securities.end(), security) !=
         securities.end();
}

bool v2rayProfileFlowIsSupported(const Proxy &proxy,
                                 const std::string &network,
                                 const std::string &security) {
  if (proxy.Flow.empty())
    return true;
  if (proxy.Flow != "xtls-rprx-vision" &&
      proxy.Flow != "xtls-rprx-vision-udp443")
    return false;
  return network == "raw" && (security == "tls" || security == "reality");
}

bool v2rayProfileSecurity(const Proxy &proxy, std::string &security) {
  if (!proxy.PublicKey.empty()) {
    if (proxy.Type != ProxyType::VLESS && proxy.Type != ProxyType::Trojan &&
        proxy.Type != ProxyType::TUIC && proxy.Type != ProxyType::AnyTLS &&
        proxy.Type != ProxyType::Naive)
      return false;
    const std::string declared_security = toLower(trim(proxy.TLSStr));
    if (!declared_security.empty() && declared_security != "tls" &&
        declared_security != "reality")
      return false;
    security = "reality";
    if (proxy.ServerName.empty())
      return false;
  } else {
    if (!proxy.ShortId.empty())
      return false;
    security = toLower(trim(proxy.TLSStr));
    if (security.empty() && proxy.TLSSecure)
      security = "tls";
    if (security == "none")
      security.clear();
    if (!security.empty() && security != "tls")
      return false;
  }
  return true;
}

bool v2rayProfileCommonIsSafe(const Proxy &proxy) {
  return !proxy.Hostname.empty() && proxy.Port > 0 &&
         proxy.UnderlyingProxy.empty();
}

bool v2rayProfileShadowsocksIsSupported(const Proxy &proxy,
                                        V2RayClientTarget target) {
  static const string_array xray_methods = {
      "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305",
      "chacha20-ietf-poly1305", "xchacha20-poly1305",
      "xchacha20-ietf-poly1305", "none", "plain",
      "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
      "2022-blake3-chacha20-poly1305"};
  static const string_array singbox_methods = {
      "aes-256-gcm", "aes-192-gcm", "aes-128-gcm",
      "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none",
      "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
      "2022-blake3-chacha20-poly1305", "aes-128-ctr", "aes-192-ctr",
      "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
      "rc4-md5", "chacha20-ietf", "xchacha20"};
  const std::string method = toLower(trim(proxy.EncryptMethod));
  const string_array &supported = target == V2RayClientTarget::V2RayN
                                      ? singbox_methods
                                      : xray_methods;
  return std::find(supported.begin(), supported.end(), method) !=
         supported.end();
}

void writeV2RayTlsProfile(V2RayProfileWriter &writer, const Proxy &proxy,
                          const extra_settings &ext,
                          const std::string &security) {
  writeV2RayProfileString(writer, "StreamSecurity", security);
  tribool allow_insecure = ext.skip_cert_verify;
  allow_insecure.define(proxy.AllowInsecure);
  if (!allow_insecure.is_undef())
    writeV2RayProfileString(writer, "AllowInsecure",
                            allow_insecure.get() ? "true" : "false");
  writeV2RayProfileString(writer, "Sni", proxy.ServerName);
  if (!proxy.AlpnList.empty())
    writeV2RayProfileString(writer, "Alpn", join(proxy.AlpnList, ","));
  else
    writeV2RayProfileString(writer, "Alpn", proxy.Alpn);
  writeV2RayProfileString(writer, "Fingerprint", proxy.Fingerprint);
  writeV2RayProfileString(writer, "PublicKey", proxy.PublicKey);
  writeV2RayProfileString(writer, "ShortId", proxy.ShortId);
  writeV2RayProfileString(writer, "SpiderX", xrayLinkOption(proxy, "spx"));
  writeV2RayProfileString(writer, "Mldsa65Verify",
                          xrayLinkOption(proxy, "pqv"));
  writeV2RayProfileString(writer, "CertSha", xrayLinkOption(proxy, "pcs"));
  writeV2RayProfileString(writer, "EchConfigList",
                          xrayLinkOption(proxy, "ech"));
  writeV2RayProfileString(writer, "VerifyPeerCertByName",
                          xrayLinkOption(proxy, "vcn"));
  writeV2RayProfileString(writer, "Finalmask", xrayLinkOption(proxy, "fm"));
}

void writeV2RayTransportProfile(V2RayProfileWriter &writer,
                                const Proxy &proxy,
                                const std::string &network) {
  writeV2RayProfileString(writer, "Network", network);
  writer.Key("TransportExtraObj");
  writer.StartObject();
  if (network == "raw") {
    writeV2RayProfileString(
        writer, "RawHeaderType",
        proxy.FakeType.empty() ? std::string("none") : proxy.FakeType);
    if (proxy.FakeType == "http") {
      writeV2RayProfileString(writer, "Host", proxy.Host);
      writeV2RayProfileString(writer, "Path", proxy.Path);
    }
  } else if (network == "kcp") {
    writeV2RayProfileString(
        writer, "KcpHeaderType",
        proxy.FakeType.empty() ? std::string("none") : proxy.FakeType);
    writeV2RayProfileString(writer, "KcpSeed", proxy.Path);
  } else if (network == "ws" || network == "httpupgrade" ||
             network == "http") {
    writeV2RayProfileString(writer, "Host", proxy.Host);
    writeV2RayProfileString(writer, "Path", proxy.Path);
  } else if (network == "grpc") {
    writeV2RayProfileString(writer, "GrpcAuthority",
                            xrayLinkOption(proxy, "authority"));
    writeV2RayProfileString(
        writer, "GrpcServiceName",
        proxy.GRPCServiceName.empty() ? proxy.Path : proxy.GRPCServiceName);
    writeV2RayProfileString(writer, "GrpcMode", proxy.GRPCMode);
  } else if (network == "xhttp") {
    writeV2RayProfileString(writer, "Host", proxy.Host);
    writeV2RayProfileString(writer, "Path", proxy.Path);
    writeV2RayProfileString(writer, "XhttpMode", proxy.GRPCMode);
    writeV2RayProfileString(writer, "XhttpExtra",
                            xrayLinkOption(proxy, "extra"));
  }
  writer.EndObject();
}

bool writeV2RayProfilePayload(const Proxy &proxy, V2RayClientTarget target,
                              const extra_settings &ext,
                              const WireGuardPeer *wireguard_peer,
                              std::string &scheme, std::string &payload) {
  if (!v2rayProfileCommonIsSafe(proxy) && !wireguard_peer)
    return false;

  int config_type = 0;
  std::string address = proxy.Hostname;
  uint16_t port = proxy.Port;
  std::string password = proxy.Password;
  std::string username = proxy.Username;
  std::string network;
  std::string security;
  bool xray_transport = false;

  switch (proxy.Type) {
  case ProxyType::VMess:
    if (!isV2RayProfileUuid(proxy.UserId) ||
        (target == V2RayClientTarget::V2RayNG && proxy.AlterId != 0) ||
        !v2rayProfileVmessSecurityIsSupported(proxy) ||
        !v2rayProfileTransport(proxy, target, network) ||
        !v2rayProfileSecurity(proxy, security))
      return false;
    config_type = 1;
    scheme = "vmess";
    password = proxy.UserId;
    xray_transport = true;
    break;
  case ProxyType::Shadowsocks:
    if (proxy.Password.empty() || proxy.EncryptMethod.empty() ||
        !proxy.Plugin.empty() || !proxy.PluginOption.empty() ||
        !v2rayProfileShadowsocksIsSupported(proxy, target))
      return false;
    config_type = 3;
    scheme = "shadowsocks";
    break;
  case ProxyType::SOCKS5:
    config_type = 4;
    scheme = "socks";
    break;
  case ProxyType::VLESS:
    if (proxy.UserId.empty() ||
        (!proxy.Encryption.empty() &&
         toLower(trim(proxy.Encryption)) != "none") ||
        (!proxy.PacketEncoding.empty() && proxy.PacketEncoding != "none") ||
        proxy.XUDP.get(false) ||
        !v2rayProfileTransport(proxy, target, network) ||
        !v2rayProfileSecurity(proxy, security) ||
        !v2rayProfileFlowIsSupported(proxy, network, security))
      return false;
    config_type = 5;
    scheme = "vless";
    password = proxy.UserId;
    xray_transport = true;
    break;
  case ProxyType::Trojan:
    if (proxy.Password.empty() ||
        (target == V2RayClientTarget::V2RayN && !proxy.Flow.empty()) ||
        !v2rayProfileTransport(proxy, target, network) ||
        !v2rayProfileSecurity(proxy, security) ||
        !v2rayProfileFlowIsSupported(proxy, network, security))
      return false;
    config_type = 6;
    scheme = "trojan";
    xray_transport = true;
    break;
  case ProxyType::Hysteria2:
    {
      const std::string obfs = toLower(trim(
          proxy.OBFSParam.empty() ? proxy.OBFS : proxy.OBFSParam));
      if (proxy.Password.empty() ||
          (!proxy.OBFS.empty() && !proxy.OBFSParam.empty() &&
           toLower(trim(proxy.OBFS)) != toLower(trim(proxy.OBFSParam))) ||
          (!obfs.empty() && obfs != "salamander" && obfs != "gecko") ||
          ((obfs == "salamander" || obfs == "gecko") !=
           !proxy.OBFSPassword.empty()) ||
          (!proxy.TLSStr.empty() && toLower(trim(proxy.TLSStr)) != "tls") ||
          (target == V2RayClientTarget::V2RayN &&
           (!proxy.Alpn.empty() || !proxy.AlpnList.empty())) ||
          (target == V2RayClientTarget::V2RayNG &&
           (!proxy.Hysteria2RealmUrl.empty() || obfs == "gecko" ||
            !proxy.PublicKey.empty())))
        return false;
      if (obfs == "gecko") {
        const std::string minimum =
            proxy.Hysteria2GeckoMinPacketSize.empty()
                ? std::string("512")
                : proxy.Hysteria2GeckoMinPacketSize;
        const std::string maximum =
            proxy.Hysteria2GeckoMaxPacketSize.empty()
                ? std::string("1200")
                : proxy.Hysteria2GeckoMaxPacketSize;
        if (!regMatch(minimum, "^[1-9][0-9]*$") ||
            !regMatch(maximum, "^[1-9][0-9]*$") || minimum.size() > 4 ||
            maximum.size() > 4 || to_int(minimum, 0) > to_int(maximum, 0) ||
            to_int(maximum, 0) > 2048)
          return false;
      } else if (!proxy.Hysteria2GeckoMinPacketSize.empty() ||
                 !proxy.Hysteria2GeckoMaxPacketSize.empty()) {
        return false;
      }
    }
    config_type = 7;
    scheme = "hysteria2";
    security = "tls";
    break;
  case ProxyType::TUIC:
  {
      static const string_array congestion_controls = {"cubic", "new_reno",
                                                       "bbr"};
      const std::string congestion =
          toLower(trim(proxy.CongestionControl));
      if (target != V2RayClientTarget::V2RayN ||
          !isV2RayProfileUuid(proxy.UserId) || proxy.Password.empty() ||
          !proxy.token.empty() ||
          (!proxy.UdpRelayMode.empty() &&
           toLower(trim(proxy.UdpRelayMode)) != "native") ||
          proxy.ReduceRtt.get(false) || proxy.DisableSni.get(false) ||
          !proxy.Fingerprint.empty() ||
          (!congestion.empty() &&
           std::find(congestion_controls.begin(), congestion_controls.end(),
                     congestion) == congestion_controls.end()) ||
          proxy.RequestTimeout != 15000 ||
          !v2rayProfileSecurity(proxy, security))
        return false;
  }
    config_type = 8;
    scheme = "tuic";
    username = proxy.UserId;
    break;
  case ProxyType::WireGuard:
    if (!wireguard_peer || proxy.PrivateKey.empty() ||
        !proxy.UnderlyingProxy.empty() ||
        wireGuardLocalAddresses(proxy).empty() ||
        wireguard_peer->Hostname.empty() || wireguard_peer->Port == 0 ||
        wireguard_peer->PublicKey.empty() ||
        (!wireguard_peer->AllowedIPs.empty() &&
         wireguard_peer->AllowedIPs != "0.0.0.0/0, ::/0") ||
        wireguard_peer->KeepAlive != 0 ||
        !proxy.WireGuardInterfaceName.empty() ||
        !proxy.WireGuardSystem.is_undef() || proxy.WireGuardListenPort != 0 ||
        proxy.WireGuardWorkers != 0)
      return false;
    config_type = 9;
    scheme = "wireguard";
    address = wireguard_peer->Hostname;
    port = wireguard_peer->Port;
    password = proxy.PrivateKey;
    break;
  case ProxyType::HTTP:
    config_type = 10;
    scheme = "http";
    break;
  case ProxyType::AnyTLS:
    if (target != V2RayClientTarget::V2RayN || proxy.Password.empty() ||
        proxy.IdleSessionCheckInterval != 30 ||
        proxy.IdleSessionTimeout != 30 || proxy.MinIdleSession != 0 ||
        !v2rayProfileSecurity(proxy, security))
      return false;
    config_type = 11;
    scheme = "anytls";
    break;
  case ProxyType::Naive:
  {
      static const string_array congestion_controls = {"bbr", "bbr2",
                                                       "cubic", "reno"};
      const std::string congestion =
          toLower(trim(proxy.CongestionControl));
      if (target != V2RayClientTarget::V2RayN || proxy.Password.empty() ||
          !proxy.AlpnList.empty() || !proxy.Alpn.empty() ||
          !proxy.Fingerprint.empty() || proxy.AllowInsecure.get(false) ||
          ext.skip_cert_verify.get(false) ||
          (!congestion.empty() &&
           std::find(congestion_controls.begin(), congestion_controls.end(),
                     congestion) == congestion_controls.end()) ||
          !v2rayProfileSecurity(proxy, security))
        return false;
  }
    config_type = 12;
    scheme = "naive";
    break;
  default:
    return false;
  }

  if (address.empty() || port == 0)
    return false;

  rapidjson::StringBuffer buffer;
  V2RayProfileWriter writer(buffer);
  writer.StartObject();
  writer.Key("ConfigType");
  writer.Int(config_type);
  writer.Key("ConfigVersion");
  writer.Int(4);
  if (target == V2RayClientTarget::V2RayN &&
      (proxy.Type == ProxyType::Shadowsocks ||
       proxy.Type == ProxyType::TUIC || proxy.Type == ProxyType::AnyTLS ||
       proxy.Type == ProxyType::Naive ||
       (proxy.Type == ProxyType::Hysteria2 &&
        (!proxy.Hysteria2RealmUrl.empty() ||
         toLower(trim(proxy.OBFSParam.empty() ? proxy.OBFS
                                              : proxy.OBFSParam)) ==
             "gecko")))) {
    writer.Key("CoreType");
    writer.Int(24);
  }
  writeV2RayProfileString(writer, "Remarks", proxy.Remark);
  writeV2RayProfileString(writer, "Address", address);
  writer.Key("Port");
  writer.Uint(port);
  writeV2RayProfileString(writer, "Password", password);
  writeV2RayProfileString(writer, "Username", username);
  // v2rayNG's current V2rayNShareItem DTO declares WgPublicKey but does not
  // copy it into ProfileItem. Its WireGuard outbound consumes the top-level
  // PublicKey property instead, so emit that compatibility projection only
  // for the Android target while retaining the canonical nested field below.
  if (target == V2RayClientTarget::V2RayNG &&
      proxy.Type == ProxyType::WireGuard)
    writeV2RayProfileString(writer, "PublicKey",
                            wireguard_peer->PublicKey);

  if (xray_transport) {
    writeV2RayTransportProfile(writer, proxy, network);
    writeV2RayTlsProfile(writer, proxy, ext, security);
  } else if (proxy.Type == ProxyType::Hysteria2) {
    writeV2RayProfileString(writer, "StreamSecurity", security);
    tribool allow_insecure = ext.skip_cert_verify;
    allow_insecure.define(proxy.AllowInsecure);
    if (!allow_insecure.is_undef())
      writeV2RayProfileString(writer, "AllowInsecure",
                              allow_insecure.get() ? "true" : "false");
    writeV2RayProfileString(writer, "Sni", proxy.ServerName);
    if (!proxy.AlpnList.empty())
      writeV2RayProfileString(writer, "Alpn", join(proxy.AlpnList, ","));
    else
      writeV2RayProfileString(writer, "Alpn", proxy.Alpn);
    if (target == V2RayClientTarget::V2RayN)
      writeV2RayProfileString(writer, "Cert", proxy.PublicKey);
    writeV2RayProfileString(writer, "CertSha", proxy.Fingerprint);
    writeV2RayProfileString(writer, "EchConfigList", proxy.Hysteria2ECH);
  } else if (proxy.Type == ProxyType::TUIC ||
             proxy.Type == ProxyType::AnyTLS ||
             proxy.Type == ProxyType::Naive) {
    writeV2RayTlsProfile(writer, proxy, ext, security);
  }

  writer.Key("ProtoExtraObj");
  writer.StartObject();
  switch (proxy.Type) {
  case ProxyType::VMess:
    writer.Key("AlterId");
    if (target == V2RayClientTarget::V2RayN) {
      const std::string alter_id = std::to_string(proxy.AlterId);
      writer.String(alter_id.data(),
                    static_cast<rapidjson::SizeType>(alter_id.size()));
    } else {
      writer.Uint(proxy.AlterId);
    }
    writeV2RayProfileString(
        writer, "VmessSecurity",
        proxy.EncryptMethod.empty() ? std::string("auto")
                                    : proxy.EncryptMethod);
    break;
  case ProxyType::Shadowsocks:
    writeV2RayProfileString(writer, "SsMethod", proxy.EncryptMethod);
    break;
  case ProxyType::VLESS:
    writeV2RayProfileString(writer, "Flow", proxy.Flow);
    writeV2RayProfileString(
        writer, "VlessEncryption",
        "none");
    break;
  case ProxyType::Trojan:
    writeV2RayProfileString(writer, "Flow", proxy.Flow);
    break;
  case ProxyType::Hysteria2: {
    writeV2RayProfileString(writer, "SalamanderPass", proxy.OBFSPassword);
    writeV2RayProfileString(writer, "Hy2RealmUrl",
                            proxy.Hysteria2RealmUrl);
    if (toLower(trim(proxy.OBFSParam.empty() ? proxy.OBFS
                                             : proxy.OBFSParam)) == "gecko") {
      writeV2RayProfileString(
          writer, "GeckoMinPacketSize",
          proxy.Hysteria2GeckoMinPacketSize.empty()
              ? std::string("512")
              : proxy.Hysteria2GeckoMinPacketSize);
      writeV2RayProfileString(
          writer, "GeckoMaxPacketSize",
          proxy.Hysteria2GeckoMaxPacketSize.empty()
              ? std::string("1200")
              : proxy.Hysteria2GeckoMaxPacketSize);
    }
    int up_mbps = 0;
    int down_mbps = 0;
    if ((!proxy.UpMbps.empty() && !parseMbpsValue(proxy.UpMbps, up_mbps)) ||
        (!proxy.DownMbps.empty() &&
         !parseMbpsValue(proxy.DownMbps, down_mbps))) {
      writer.EndObject();
      writer.EndObject();
      return false;
    }
    if (up_mbps > 0) {
      writer.Key("UpMbps");
      writer.Int(up_mbps);
    }
    if (down_mbps > 0) {
      writer.Key("DownMbps");
      writer.Int(down_mbps);
    }
    if (!proxy.Ports.empty())
      writeV2RayProfileString(writer, "Ports", hysteria2PortSpec(proxy));
    writeV2RayProfileString(writer, "HopInterval",
                            proxy.HysteriaHopInterval);
    break;
  }
  case ProxyType::TUIC:
    writeV2RayProfileString(writer, "CongestionControl",
                            toLower(trim(proxy.CongestionControl)));
    break;
  case ProxyType::WireGuard: {
    writeV2RayProfileString(writer, "WgPublicKey",
                            wireguard_peer->PublicKey);
    writeV2RayProfileString(writer, "WgPresharedKey",
                            wireguard_peer->PreSharedKey);
    writeV2RayProfileString(writer, "WgInterfaceAddress",
                            join(wireGuardLocalAddresses(proxy), ","));
    const std::string reserved = wireguard_peer->Reserved.empty()
                                     ? proxy.ClientId
                                     : wireguard_peer->Reserved;
    writeV2RayProfileString(writer, "WgReserved", reserved);
    if (proxy.Mtu > 0) {
      writer.Key("WgMtu");
      writer.Uint(proxy.Mtu);
    }
    break;
  }
  case ProxyType::Naive:
    writeV2RayProfileString(writer, "CongestionControl",
                            toLower(trim(proxy.CongestionControl)));
    if (proxy.NaiveInsecureConcurrency > 0) {
      writer.Key("InsecureConcurrency");
      writer.Uint(proxy.NaiveInsecureConcurrency);
    }
    if (!proxy.NaiveQuic.is_undef()) {
      writer.Key("NaiveQuic");
      writer.Bool(proxy.NaiveQuic.get());
    }
    if (!proxy.NaiveUot.is_undef()) {
      writer.Key("Uot");
      writer.Bool(proxy.NaiveUot.get());
    }
    break;
  default:
    break;
  }
  writer.EndObject();
  writer.EndObject();
  payload.assign(buffer.GetString(), buffer.GetSize());
  return true;
}

} // namespace

std::string proxyToV2RayClient(std::vector<Proxy> &nodes,
                               V2RayClientTarget target,
                               extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  std::string all_links;

  for (const Proxy &proxy : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats,
                                                   proxy.Type);
    bool emitted = false;
    std::string node_links;
    const std::vector<WireGuardPeer> peers =
        proxy.Type == ProxyType::WireGuard ? wireGuardPeers(proxy)
                                           : std::vector<WireGuardPeer>{};
    const size_t profile_count =
        proxy.Type == ProxyType::WireGuard ? peers.size() : 1;
    for (size_t index = 0; index < profile_count; ++index) {
      const WireGuardPeer *peer =
          proxy.Type == ProxyType::WireGuard ? &peers[index] : nullptr;
      Proxy profile_proxy = proxy;
      if (proxy.Type == ProxyType::WireGuard && peers.size() > 1)
        profile_proxy.Remark += " [Peer " + std::to_string(index + 1) + "]";
      std::string scheme;
      std::string payload;
      if (!writeV2RayProfilePayload(profile_proxy, target, ext, peer, scheme,
                                    payload)) {
        emitted = false;
        break;
      }
      node_links += "v2rayn://" + scheme + "/" +
                    urlSafeBase64Encode(payload) + "\n";
      emitted = true;
    }
    if (emitted) {
      all_links += node_links;
      generation_tracker.markEmitted();
    }
  }

  if (ext.nodelist)
    return all_links;
  return base64Encode(all_links);
}

namespace {

enum class SingleLinkDialect { Legacy, Shadowrocket };

struct SingleLinkProfile {
  bool shadowsocks;
  bool shadowsocksr;
  bool vmess;
  bool trojan;
  bool hysteria2;
  bool vless;
  SingleLinkDialect dialect;
};

static SingleLinkProfile legacySingleLinkProfile(SingleLinkTypes types) {
  return {
      (types & SingleLinkType::Shadowsocks) != 0,
      (types & SingleLinkType::ShadowsocksR) != 0,
      (types & SingleLinkType::VMess) != 0,
      (types & SingleLinkType::Trojan) != 0,
      (types & SingleLinkType::Hysteria2) != 0,
      (types & SingleLinkType::VLESS) != 0,
      SingleLinkDialect::Legacy,
  };
}

static constexpr SingleLinkProfile kShadowrocketSingleLinkProfile = {
    true, true, true, true, true, true, SingleLinkDialect::Shadowrocket,
};

struct ShadowrocketMieruGroup {
  std::vector<const Proxy *> members;
  bool built = false;
  bool valid = false;
  bool written = false;
  std::string link;
};

static std::string mieruBindingSpec(const Proxy &node) {
  return node.Ports.empty() ? std::to_string(node.Port) : node.Ports;
}

static bool shadowrocketMieruNodeIsPortable(const Proxy &node) {
  if (node.Type != ProxyType::Mieru || node.MieruSourceId.empty() ||
      node.MieruProfile.empty() || node.MieruHasUnknownParameters ||
      node.Username.empty() || node.Password.empty() || node.Hostname.empty() ||
      !node.UnderlyingProxy.empty() || node.TCPFastOpen.get() ||
      node.AllowInsecure.get() || node.TLS13.get() || node.XUDP.get() ||
      !node.UDP.get() ||
      (node.Mtu != 0 && (node.Mtu < 1280 || node.Mtu > 1400)) ||
      !isValidMieruMultiplexing(node.Multiplexing) ||
      !isValidMieruHandshakeMode(node.MieruHandshakeMode) ||
      !isValidMieruTrafficPattern(node.MieruTrafficPattern))
    return false;
  MieruPortBinding binding;
  return parseMieruPortBinding(mieruBindingSpec(node),
                               node.TransferProtocol, binding);
}

static bool sameMieruResource(const Proxy &left, const Proxy &right) {
  return left.Username == right.Username &&
         left.Password == right.Password &&
         left.Hostname == right.Hostname &&
         left.Mtu == right.Mtu &&
         left.Multiplexing == right.Multiplexing &&
         left.MieruProfile == right.MieruProfile &&
         left.MieruSourceRemark == right.MieruSourceRemark &&
         left.MieruHasUnknownParameters == right.MieruHasUnknownParameters &&
         left.MieruHandshakeMode == right.MieruHandshakeMode &&
         left.MieruTrafficPattern == right.MieruTrafficPattern;
}

static bool buildShadowrocketMieruGroup(std::vector<const Proxy *> &members,
                                        std::string &link) {
  if (members.empty())
    return false;
  std::sort(members.begin(), members.end(), [](const Proxy *left,
                                                const Proxy *right) {
    return left->MieruBindingIndex < right->MieruBindingIndex;
  });

  const Proxy &first = *members.front();
  if (!shadowrocketMieruNodeIsPortable(first))
    return false;
  MieruSimpleConfig config;
  config.username = first.Username;
  config.password = first.Password;
  config.host = first.Hostname;
  config.profile = first.MieruProfile;
  config.mtu = first.Mtu;
  config.multiplexing = first.Multiplexing;
  config.handshake_mode = first.MieruHandshakeMode;
  config.traffic_pattern = first.MieruTrafficPattern;
  config.has_unknown_parameters = first.MieruHasUnknownParameters;

  std::string effective_remark;
  bool has_effective_remark = false;
  uint32_t previous_index = 0;
  bool has_previous_index = false;
  for (const Proxy *member : members) {
    if (!shadowrocketMieruNodeIsPortable(*member) ||
        !sameMieruResource(first, *member) ||
        (has_previous_index &&
         member->MieruBindingIndex == previous_index))
      return false;
    previous_index = member->MieruBindingIndex;
    has_previous_index = true;

    MieruPortBinding binding;
    if (!parseMieruPortBinding(mieruBindingSpec(*member),
                               member->TransferProtocol, binding))
      return false;
    const std::string suffix =
        ":" + binding.port + "/" + binding.protocol;
    std::string member_remark = member->Remark;
    if (endsWith(member_remark, suffix))
      member_remark.erase(member_remark.size() - suffix.size());
    if (!has_effective_remark) {
      effective_remark = std::move(member_remark);
      has_effective_remark = true;
    } else if (effective_remark != member_remark) {
      return false;
    }
    config.port_bindings.emplace_back(std::move(binding));
  }

  const std::string source_base = first.MieruSourceRemark.empty()
                                      ? first.MieruProfile
                                      : first.MieruSourceRemark;
  config.remark = effective_remark == source_base
                      ? first.MieruSourceRemark
                      : effective_remark;
  return buildMieruSimpleUri(config, link);
}

static std::string proxyToSingleProfile(const std::vector<Proxy> &nodes,
                                        const SingleLinkProfile &profile,
                                        extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  std::string proxyStr, allLinks;
  const bool ss = profile.shadowsocks;
  const bool ssr = profile.shadowsocksr;
  const bool vmess = profile.vmess;
  const bool trojan = profile.trojan;
  const bool hysteria2 = profile.hysteria2;
  const bool vless = profile.vless;
  const bool shadowrocket = profile.dialect == SingleLinkDialect::Shadowrocket;
  std::unordered_map<std::string, ShadowrocketMieruGroup> mieru_groups;
  if (shadowrocket) {
    for (const Proxy &node : nodes) {
      if (node.Type == ProxyType::Mieru && !node.MieruSourceId.empty())
        mieru_groups[node.MieruSourceId].members.push_back(&node);
    }
  }

  for (const Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    proxyStr.clear();
    const std::string &remark = x.Remark, &hostname = x.Hostname,
                      &sni = x.ServerName, &password = x.Password,
                      &method = x.EncryptMethod, &plugin = x.Plugin,
                      &protocol = x.Protocol, &flow = x.Flow,
                      &pbk = x.PublicKey, &sid = x.ShortId,
                      &fp = x.Fingerprint,
                      &packet_encoding = x.PacketEncoding,
                      &fake_type = x.FakeType, &mode = x.GRPCMode,
                      &obfs = x.OBFS, &obfsparam = x.OBFSParam,
                      &obfsPassword = x.OBFSPassword, &id = x.UserId,
                      &transproto = x.TransferProtocol, &host = x.Host,
                      &tls = x.TLSStr, &path = x.Path;
    const std::vector<string> &alpns = x.AlpnList;
    std::string port = std::to_string(x.Port);
    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (ss) {
        proxyStr = shadowsocksShareLink(x, false);
      } else if (ssr) {
        if (std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) !=
                ssr_ciphers.end() &&
            plugin.empty()) {
          Proxy converted = x;
          converted.Protocol = "origin";
          converted.OBFS = "plain";
          proxyStr = shadowsocksRShareLink(converted);
        } else {
          continue;
        }
      } else
        continue;
      break;
    case ProxyType::ShadowsocksR:
      if (ssr) {
        proxyStr = shadowsocksRShareLink(x);
      } else if (ss) {
        if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) !=
                ss_ciphers.end() &&
            protocol == "origin" && obfs == "plain") {
          Proxy converted = x;
          converted.Plugin.clear();
          converted.PluginOption.clear();
          proxyStr = shadowsocksShareLink(converted, false);
        } else {
          continue;
        }
      } else
        continue;
      break;
    case ProxyType::VMess:
      if (!vmess)
        continue;
      proxyStr = "vmess://" + base64Encode(vmessLinkConstruct(x));
      break;
    case ProxyType::Hysteria2:
      if (!hysteria2)
        continue;
      {
        std::vector<std::string> query;
        appendShareQuery(query, "insecure",
                         x.AllowInsecure.get() ? "1" : "0");
        appendShareQuery(query, "obfs", obfsparam);
        appendShareQuery(query, "obfs-password", obfsPassword);
        appendShareQuery(query, "sni", sni);
        appendShareQuery(query, "pinSHA256", x.Fingerprint);
        appendShareQuery(query, "ech", x.Hysteria2ECH);
        appendShareQuery(query, "minPacketSize",
                         x.Hysteria2GeckoMinPacketSize);
        appendShareQuery(query, "maxPacketSize",
                         x.Hysteria2GeckoMaxPacketSize);
        if (!x.Hysteria2RealmUrl.empty()) {
          appendShareQuery(query, "auth", password);
          proxyStr = "hysteria2+" + x.Hysteria2RealmUrl;
          const std::string query_string = joinShareQuery(query);
          if (!query_string.empty())
            proxyStr += (proxyStr.find('?') == std::string::npos ? "?" : "&") +
                        query_string.substr(1);
          proxyStr += "#" + urlEncode(remark);
        } else {
          const std::string port_spec = hysteria2PortSpec(x);
          proxyStr = "hysteria2://" +
                     (password.empty() ? std::string()
                                       : urlEncode(password) + "@") +
                     shareLinkHost(hostname) + ":" + port_spec + "/" +
                     joinShareQuery(query) + "#" + urlEncode(remark);
        }
      }
      break;
    case ProxyType::Hysteria:
      if (!shadowrocket)
        continue;
      {
        std::string hysteria_protocol, hysteria_alpn, hysteria_obfs,
            hysteria_up, hysteria_down;
        bool allow_insecure = false;
        if (!hysteriaShareLinkFields(x, hysteria_protocol, hysteria_alpn,
                                     hysteria_obfs, hysteria_up,
                                     hysteria_down, allow_insecure))
          continue;
        std::vector<std::string> query;
        appendShareQuery(query, "protocol", hysteria_protocol);
        appendShareQuery(query, "auth", x.AuthStr);
        appendShareQuery(query, "peer", sni);
        if (allow_insecure)
          appendShareQuery(query, "insecure", "1");
        appendShareQuery(query, "upmbps", hysteria_up);
        appendShareQuery(query, "downmbps", hysteria_down);
        appendShareQuery(query, "alpn", hysteria_alpn);
        appendShareQuery(query, "obfs", hysteria_obfs);
        appendShareQuery(query, "obfsParam", x.OBFSParam);
        proxyStr = "hysteria://" + shareLinkHost(hostname) + ":" + port +
                   joinShareQuery(query) + "#" + urlEncode(remark);
      }
      break;
    case ProxyType::AnyTLS:
      if (!shadowrocket)
        continue;
      {
        std::string anytls_sni;
        bool allow_insecure = false;
        if (!anyTlsShareLinkFields(x, anytls_sni, allow_insecure))
          continue;
        std::vector<std::string> query;
        appendShareQuery(query, "sni", anytls_sni);
        if (allow_insecure)
          appendShareQuery(query, "insecure", "1");
        proxyStr = "anytls://" + urlEncode(password) + "@" +
                   shareLinkHost(hostname) + ":" + port + "/" +
                   joinShareQuery(query) + "#" + urlEncode(remark);
      }
      break;
    case ProxyType::Mieru:
      if (!shadowrocket || x.MieruSourceId.empty())
        continue;
      {
        auto group_it = mieru_groups.find(x.MieruSourceId);
        if (group_it == mieru_groups.end())
          continue;
        ShadowrocketMieruGroup &group = group_it->second;
        if (!group.built) {
          group.built = true;
          group.valid =
              buildShadowrocketMieruGroup(group.members, group.link);
        }
        if (!group.valid)
          continue;
        generation_tracker.markEmitted();
        if (group.written)
          continue;
        group.written = true;
        proxyStr = group.link;
      }
      break;
    case ProxyType::VLESS:
      if (!vless)
        continue;
      {
        std::vector<std::string> query;
        appendShareQuery(query, "encryption",
                         x.Encryption.empty() ? "none" : x.Encryption);
        appendShareQuery(query, "security",
                         !pbk.empty() ? "reality" : tls);
        appendShareQuery(query, "flow", flow);
        appendShareQuery(query, "pbk", pbk);
        appendShareQuery(query, "sid", sid);
        appendShareQuery(query, "fp", fp);
        appendShareQuery(query, "packet-encoding", packet_encoding);
        if (x.AllowInsecure.get())
          appendShareQuery(query, "insecure", "1");
        if (!alpns.empty())
          appendShareQuery(query, "alpn", join(alpns, ","));
        appendShareQuery(query, "sni", sni);
        appendShareQuery(query, "type", transproto);
        switch (hash_(transproto)) {
        case "tcp"_hash:
          appendShareQuery(query, "headerType", fake_type);
          if (fake_type == "http") {
            appendShareQuery(query, "host", host);
            appendShareQuery(query, "path", path.empty() ? "/" : path);
          }
          break;
        case "kcp"_hash:
          appendShareQuery(query, "headerType", fake_type);
          appendShareQuery(query, "seed", path);
          break;
        case "ws"_hash:
        case "http"_hash:
        case "httpupgrade"_hash:
          appendShareQuery(query, "headerType", fake_type);
          appendShareQuery(query, "host", host);
          appendShareQuery(query, "path", path.empty() ? "/" : path);
          break;
        case "grpc"_hash:
          appendShareQuery(query, "serviceName", x.GRPCServiceName);
          appendShareQuery(query, "mode", mode);
          appendShareQuery(query, "authority", xrayLinkOption(x, "authority"));
          break;
        case "xhttp"_hash:
          appendShareQuery(query, "host", host);
          appendShareQuery(query, "path", path.empty() ? "/" : path);
          appendShareQuery(query, "mode", mode);
          appendShareQuery(query, "extra", xrayLinkOption(x, "extra"));
          break;
        case "quic"_hash:
          appendShareQuery(query, "headerType", fake_type);
          appendShareQuery(query, "quicSecurity", host.empty() ? sni : host);
          appendShareQuery(query, "key", x.QUICSecret);
          break;
        default:
          break;
        }
        for (const char *key : {"fm", "ech", "pcs", "vcn", "pqv", "spx"})
          appendShareQuery(query, key, xrayLinkOption(x, key));
        proxyStr = "vless://" +
                   (id.empty() ? "00000000-0000-0000-0000-000000000000" : id) +
                   "@" + shareLinkHost(hostname) + ":" + port +
                   joinShareQuery(query) + "#" + urlEncode(remark);
      }
      break;
    case ProxyType::Trojan:
      if (!trojan)
        continue;
      {
        std::vector<std::string> query;
        appendShareQuery(query, "security", tls.empty() ? "tls" : tls);
        appendShareQuery(query, "allowInsecure",
                         x.AllowInsecure.get() ? "1" : "0");
        if (x.AllowInsecure.get())
          appendShareQuery(query, "insecure", "1");
        appendShareQuery(query, "sni", !sni.empty() ? sni : host);
        appendShareQuery(query, "fp", fp);
        appendShareQuery(query, "pbk", x.PublicKey);
        appendShareQuery(query, "sid", x.ShortId);
        if (!alpns.empty())
          appendShareQuery(query, "alpn", join(alpns, ","));
        appendShareQuery(query, "type", transproto);
        if (transproto == "tcp") {
          appendShareQuery(query, "headerType", fake_type);
          if (fake_type == "http") {
            appendShareQuery(query, "host", host);
            appendShareQuery(query, "path", path.empty() ? "/" : path);
          }
        } else if (transproto == "kcp") {
          appendShareQuery(query, "headerType", fake_type);
          appendShareQuery(query, "seed", path);
        } else if (transproto == "ws" || transproto == "http" ||
                   transproto == "httpupgrade") {
          appendShareQuery(query, "host", host);
          appendShareQuery(query, "path", path.empty() ? "/" : path);
        } else if (transproto == "grpc") {
          appendShareQuery(query, "serviceName", path);
          appendShareQuery(query, "mode", mode);
          appendShareQuery(query, "authority", xrayLinkOption(x, "authority"));
        } else if (transproto == "xhttp") {
          appendShareQuery(query, "host", host);
          appendShareQuery(query, "path", path.empty() ? "/" : path);
          appendShareQuery(query, "mode", mode);
          appendShareQuery(query, "extra", xrayLinkOption(x, "extra"));
        } else if (transproto == "quic") {
          appendShareQuery(query, "headerType", fake_type);
          appendShareQuery(query, "quicSecurity", host);
          appendShareQuery(query, "key", path);
        }
        for (const char *key : {"fm", "ech", "pcs", "vcn"})
          appendShareQuery(query, key, xrayLinkOption(x, key));
        proxyStr = "trojan://" + urlEncode(password) + "@" +
                   shareLinkHost(hostname) + ":" + port +
                   joinShareQuery(query) + "#" + urlEncode(remark);
      }
      break;
    default:
      continue;
    }
    allLinks += proxyStr + "\n";
    generation_tracker.markEmitted();
  }

  if (ext.nodelist)
    return allLinks;
  return base64Encode(allLinks);
}

} // namespace

std::string proxyToSingle(const std::vector<Proxy> &nodes,
                          SingleLinkTypes types,
                          extra_settings &ext) {
  return proxyToSingleProfile(nodes, legacySingleLinkProfile(types), ext);
}

std::string proxyToShadowrocket(const std::vector<Proxy> &nodes,
                                extra_settings &ext) {
  return proxyToSingleProfile(nodes, kShadowrocketSingleLinkProfile, ext);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes,
                         extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  using namespace rapidjson_ext;
  rapidjson::Document base;

  auto &alloc = base.GetAllocator();

  base_conf = trimWhitespace(base_conf);
  if (base_conf.empty())
    base_conf = "{}";
  rapidjson::ParseResult result = base.Parse(base_conf.data());
  if (!result || !base.IsObject()) {
    writeLog(LOG_LEVEL_ERROR,
             std::string("SIP008 基础配置加载失败：") +
                 (result ? "root must be an object"
                         : rapidjson::GetParseError_En(result.Code())) +
                 " (" + std::to_string(result.Offset()) + ")");
    base.SetObject();
  }

  rapidjson::Value proxies(rapidjson::kArrayType);
  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    std::string &remark = x.Remark;
    std::string &hostname = x.Hostname;
    std::string &password = x.Password;
    std::string &method = x.EncryptMethod;
    std::string &plugin = x.Plugin;
    std::string &pluginopts = x.PluginOption;
    std::string &protocol = x.Protocol;
    std::string &obfs = x.OBFS;

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (plugin == "simple-obfs")
        plugin = "obfs-local";
      break;
    case ProxyType::ShadowsocksR:
      if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) ==
              ss_ciphers.end() ||
          protocol != "origin" || obfs != "plain")
        continue;
      break;
    default:
      continue;
    }
    rapidjson::Value proxy(rapidjson::kObjectType);
    proxy.CopyFrom(base, alloc) |
        AddMemberOrReplace(
            "remarks", rapidjson::Value(remark.c_str(), remark.size()), alloc) |
        AddMemberOrReplace("server",
                           rapidjson::Value(hostname.c_str(), hostname.size()),
                           alloc) |
        AddMemberOrReplace("server_port", rapidjson::Value(x.Port), alloc) |
        AddMemberOrReplace(
            "method", rapidjson::Value(method.c_str(), method.size()), alloc) |
        AddMemberOrReplace("password",
                           rapidjson::Value(password.c_str(), password.size()),
                           alloc) |
        AddMemberOrReplace(
            "plugin", rapidjson::Value(plugin.c_str(), plugin.size()), alloc) |
        AddMemberOrReplace(
            "plugin_opts",
            rapidjson::Value(pluginopts.c_str(), pluginopts.size()), alloc);
    proxies.PushBack(proxy, alloc);
    generation_tracker.markEmitted();
  }
  return proxies | SerializeObject();
}

std::string proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext) {
  ext.target_generation_stats = TargetGenerationStats{};
  ext.target_generation_stats.input_nodes = nodes.size();
  INIReader ini;
  ini.store_any_line = true;
  if (!ext.nodelist && ini.parse(base_conf) != 0) {
    writeLog(LOG_LEVEL_ERROR, "QUANTUMULT_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return "";
  }

  proxyToQuan(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

  if (ext.nodelist) {
    string_array allnodes;
    std::string allLinks;
    ini.get_all("SERVER", "{NONAME}", allnodes);
    if (!allnodes.empty())
      allLinks = join(allnodes, "\n");
    return base64Encode(allLinks);
  }
  return ini.to_string();
}

void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini,
                 std::vector<RulesetContent> &ruleset_content_array,
                 const ProxyGroupConfigs &extra_proxy_group,
                 extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  std::string proxyStr;
  std::vector<Proxy> nodelist;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("SERVER");
  ini.erase_section();
  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, &method = x.EncryptMethod,
                &password = x.Password, &id = x.UserId,
                &transproto = x.TransferProtocol, &host = x.Host,
                &path = x.Path, &edge = x.Edge, &protocol = x.Protocol,
                &protoparam = x.ProtocolParam, &obfs = x.OBFS,
                &obfsparam = x.OBFSParam, &plugin = x.Plugin,
                &pluginopts = x.PluginOption, &username = x.Username;
    std::string port = std::to_string(x.Port);
    bool &tlssecure = x.TLSSecure;
    tribool scv;

    switch (x.Type) {
    case ProxyType::VMess:
      scv = ext.skip_cert_verify;
      scv.define(x.AllowInsecure);

      if (method == "auto")
        method = "chacha20-ietf-poly1305";
      proxyStr = x.Remark + " = vmess, " + hostname + ", " + port + ", " +
                 method + ", \"" + id + "\", group=" + x.Group;
      if (tlssecure) {
        proxyStr += ", over-tls=true, tls-host=" + host;
        if (!scv.is_undef())
          proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
      }
      if (transproto == "ws") {
        proxyStr += ", obfs=ws, obfs-path=\"" + path +
                    "\", obfs-header=\"Host: " + host;
        if (!edge.empty())
          proxyStr += "[Rr][Nn]Edge: " + edge;
        proxyStr += "\"";
      }

      if (ext.nodelist)
        proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
      break;
    case ProxyType::ShadowsocksR:
      if (ext.nodelist) {
        proxyStr = shadowsocksRShareLink(x);
      } else {
        proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port +
                   ", " + method + ", \"" + password + "\", group=" + x.Group +
                   ", protocol=" + protocol + ", obfs=" + obfs;
        if (!protoparam.empty())
          proxyStr += ", protocol_param=" + protoparam;
        if (!obfsparam.empty())
          proxyStr += ", obfs_param=" + obfsparam;
      }
      break;
    case ProxyType::Shadowsocks:
      if (ext.nodelist) {
        proxyStr = shadowsocksShareLink(x, true);
      } else {
        proxyStr = x.Remark + " = shadowsocks, " + hostname + ", " + port +
                   ", " + method + ", \"" + password + "\", group=" + x.Group;
        if (plugin == "obfs-local" && !pluginopts.empty()) {
          proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
        }
      }
      break;
    case ProxyType::HTTP:
    case ProxyType::HTTPS:
      proxyStr = x.Remark + " = http, upstream-proxy-address=" + hostname +
                 ", upstream-proxy-port=" + port + ", group=" + x.Group;
      if (!username.empty() && !password.empty())
        proxyStr +=
            ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
            ", upstream-proxy-password=" + password;
      else
        proxyStr += ", upstream-proxy-auth=false";

      if (tlssecure) {
        proxyStr += ", over-tls=true";
        if (!host.empty())
          proxyStr += ", tls-host=" + host;
        if (!scv.is_undef())
          proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
      }

      if (ext.nodelist)
        proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
      break;
    case ProxyType::SOCKS5:
      proxyStr = x.Remark + " = socks, upstream-proxy-address=" + hostname +
                 ", upstream-proxy-port=" + port + ", group=" + x.Group;
      if (!username.empty() && !password.empty())
        proxyStr +=
            ", upstream-proxy-auth=true, upstream-proxy-username=" + username +
            ", upstream-proxy-password=" + password;
      else
        proxyStr += ", upstream-proxy-auth=false";

      if (tlssecure) {
        proxyStr += ", over-tls=true";
        if (!host.empty())
          proxyStr += ", tls-host=" + host;
        if (!scv.is_undef())
          proxyStr += ", certificate=" + std::string(scv.get() ? "0" : "1");
      }

      if (ext.nodelist)
        proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
      break;
    default:
      continue;
    }

    ini.set("{NONAME}", proxyStr);
    used_remarks.emplace(x.Remark);
    nodelist.emplace_back(x);
    generation_tracker.markEmitted();
  }

  if (ext.nodelist)
    return;

  ini.set_current_section("POLICY");
  ini.erase_section();

  for (const ProxyGroupConfig &x : extra_proxy_group) {
    string_array filtered_nodelist;
    std::string type;
    std::string singlegroup;
    std::string name, proxies;

    switch (x.Type) {
    case ProxyGroupType::Select:
    case ProxyGroupType::Fallback:
      type = "static";
      break;
    case ProxyGroupType::URLTest:
      type = "auto";
      break;
    case ProxyGroupType::LoadBalance:
      type = "balance, round-robin";
      break;
    case ProxyGroupType::SSID: {
      singlegroup = x.Name + " : wifi = " + x.Proxies[0];
      std::string content, celluar,
          celluar_matcher = R"(^(.*?),?celluar\s?=\s?(.*?)(,.*)$)", rem_a,
          rem_b;
      for (auto iter = x.Proxies.begin() + 1; iter != x.Proxies.end(); iter++) {
        if (regGetMatch(*iter, celluar_matcher, 4, 0, &rem_a, &celluar,
                        &rem_b)) {
          content += *iter + "\n";
          continue;
        }
        content += rem_a + rem_b + "\n";
      }
      if (!celluar.empty())
        singlegroup += ", celluar = " + celluar;
      singlegroup += "\n" + replaceAllDistinct(trimOf(content, ','), ",", "\n");
      ini.set("{NONAME}", base64Encode(singlegroup)); // insert order
    }
      continue;
    default:
      continue;
    }

    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, true, ext);

    if (filtered_nodelist.empty())
      filtered_nodelist.emplace_back("direct");

    if (filtered_nodelist.size() < 2) // force groups with 1 node to be static
      type = "static";

    proxies = join(filtered_nodelist, "\n");

    singlegroup = x.Name + " : " + type;
    if (type == "static")
      singlegroup += ", " + filtered_nodelist[0];
    singlegroup += "\n" + proxies + "\n";
    ini.set("{NONAME}", base64Encode(singlegroup));
  }

  if (ext.enable_rule_generator)
    rulesetToSurge(ini, ruleset_content_array, -2, ext.overwrite_original_rules,
                   "", ext.rule_stats);
}

static std::string escapeQuanXRegexLiteral(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);
  for (char ch : value) {
    switch (ch) {
    case '\\':
    case '.':
    case '^':
    case '$':
    case '|':
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case '*':
    case '+':
    case '?':
      escaped.push_back('\\');
      break;
    default:
      break;
    }
    escaped.push_back(ch);
  }
  return escaped;
}

static std::string quanxResourceTagRegex(
    const std::vector<const QuanXServerRemote *> &resources) {
  string_array alternatives;
  alternatives.reserve(resources.size());
  for (const QuanXServerRemote *resource : resources)
    alternatives.emplace_back(escapeQuanXRegexLiteral(resource->resource_tag));
  if (alternatives.size() == 1)
    return "^" + alternatives.front() + "$";
  return "^(?:" + join(alternatives, "|") + ")$";
}

static bool parseQuanXSourceGroupRule(const std::string &rule,
                                      std::string &source_pattern,
                                      std::string &server_pattern) {
  static const std::string group_regex =
      R"(^!!GROUP=(.+?)(?:!!(.*))?$)";
  if (!startsWith(rule, "!!GROUP="))
    return false;
  source_pattern.clear();
  server_pattern.clear();
  return regGetMatch(rule, group_regex, 3,
                     static_cast<std::string *>(nullptr), &source_pattern,
                     &server_pattern) == 0 &&
         !source_pattern.empty();
}

struct QuanXRemoteSelector {
  std::vector<const QuanXServerRemote *> resources;
  std::string server_pattern;
};

static QuanXRemoteSelector quanxRemoteSelectorForGroup(
    const ProxyGroupConfig &group,
    const std::vector<QuanXServerRemote> &resources) {
  QuanXRemoteSelector selector;
  if (resources.empty() || group.Type == ProxyGroupType::SSID)
    return selector;

  for (const QuanXServerRemote &resource : resources)
    selector.resources.emplace_back(&resource);

  if (!group.UsingProvider.empty()) {
    selector.resources.erase(
        std::remove_if(selector.resources.begin(), selector.resources.end(),
                       [&](const QuanXServerRemote *resource) {
                         return std::find(group.UsingProvider.begin(),
                                          group.UsingProvider.end(),
                                          resource->resource_tag) ==
                                    group.UsingProvider.end() &&
                                std::find(group.UsingProvider.begin(),
                                          group.UsingProvider.end(),
                                          resource->requested_resource_tag) ==
                                    group.UsingProvider.end() &&
                                std::find(group.UsingProvider.begin(),
                                          group.UsingProvider.end(),
                                          resource->selection_resource_tag) ==
                                    group.UsingProvider.end();
                       }),
        selector.resources.end());
    selector.server_pattern = ".*";
  }

  for (const std::string &rule : group.Proxies) {
    if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
      continue;

    std::string target, server_pattern;
    if (parseProviderGroupIdMatcher(rule, target, server_pattern)) {
      selector.resources.erase(
          std::remove_if(selector.resources.begin(), selector.resources.end(),
                         [&](const QuanXServerRemote *resource) {
                           return !matchRange(target, resource->group_id);
                         }),
          selector.resources.end());
      selector.server_pattern =
          server_pattern.empty() ? ".*" : server_pattern;
    } else if (parseQuanXSourceGroupRule(rule, target, server_pattern)) {
      selector.resources.erase(
          std::remove_if(selector.resources.begin(), selector.resources.end(),
                         [&](const QuanXServerRemote *resource) {
                           return resource->source_tag.empty() ||
                                  !regFind(resource->source_tag, target);
                         }),
          selector.resources.end());
      selector.server_pattern =
          server_pattern.empty() ? ".*" : server_pattern;
    } else if (!startsWith(rule, "!!") && !startsWith(rule, "script:")) {
      selector.server_pattern = rule;
    }
    break;
  }

  if (selector.server_pattern.empty())
    selector.resources.clear();
  return selector;
}

static std::string quanxRemoteTagFromLine(const std::string &line) {
  std::string trimmed = trimWhitespace(line, true, true);
  if (trimmed.empty() || startsWith(trimmed, ";") ||
      startsWith(trimmed, "#") || startsWith(trimmed, "//"))
    return "";
  for (std::string item : split(trimmed, ",")) {
    item = trimWhitespace(item, true, true);
    std::string lower = toLower(item);
    if (startsWith(lower, "tag="))
      return trimWhitespace(item.substr(4), true, true);
  }
  return "";
}

static std::string clampQuanXResourceTag(const std::string &tag,
                                         size_t max_length) {
  if (tag.size() <= max_length)
    return tag;
  std::string result = tag.substr(0, max_length);
  while (!result.empty() && !isStrUTF8(result))
    result.pop_back();
  return result;
}

static void appendQuanXServerRemotes(INIReader &ini, extra_settings &ext) {
  if (ext.quanx_server_remotes.empty())
    return;

  std::unordered_set<std::string> used_tags;
  string_array existing_lines;
  ini.get_all("server_remote", "{NONAME}", existing_lines);
  for (const std::string &line : existing_lines) {
    std::string tag = quanxRemoteTagFromLine(line);
    if (!tag.empty())
      used_tags.emplace(std::move(tag));
  }

  ini.set_current_section("server_remote");
  for (QuanXServerRemote &remote : ext.quanx_server_remotes) {
    std::string base_tag = remote.resource_tag;
    std::string candidate = base_tag;
    int suffix_index = 1;
    while (!used_tags.insert(candidate).second) {
      const std::string suffix = "_" + std::to_string(suffix_index++);
      const size_t max_base = 64 > suffix.size() ? 64 - suffix.size() : 0;
      candidate = clampQuanXResourceTag(base_tag, max_base) + suffix;
    }
    if (candidate != remote.resource_tag) {
      remote.resource_tag = candidate;
      writeLog(LOG_LEVEL_INFO,
               "QUANX_REMOTE_TAG_RENAMED group_id=" +
                   std::to_string(remote.group_id));
    }

    std::string safe_url = replaceAllDistinct(remote.url, ",", "%2C");
    std::string line = safe_url + ", tag=" + remote.resource_tag;
    if (remote.has_update_interval) {
      const int interval =
          remote.update_interval == 0 ? -1 : remote.update_interval;
      line += ", update-interval=" + std::to_string(interval);
    }
    line += ", enabled=true";
    ini.set("{NONAME}", std::move(line));
  }
}

std::string proxyToQuanX(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext) {
  ext.target_generation_stats = TargetGenerationStats{};
  ext.target_generation_stats.input_nodes = nodes.size();
  INIReader ini;
  ini.store_any_line = true;
  ini.add_direct_save_section("general");
  ini.add_direct_save_section("dns");
  ini.add_direct_save_section("rewrite_remote");
  ini.add_direct_save_section("rewrite_local");
  ini.add_direct_save_section("task_local");
  ini.add_direct_save_section("mitm");
  ini.add_direct_save_section("server_remote");
  if (!ext.nodelist && ini.parse(base_conf) != 0) {
    writeLog(LOG_LEVEL_ERROR, "QUANTUMULT_X_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return "";
  }

  if (!ext.nodelist)
    appendQuanXServerRemotes(ini, ext);
  proxyToQuanX(nodes, ini, ruleset_content_array, extra_proxy_group, ext);
  if (!ext.nodelist)
    ext.target_generation_stats.remote_references_emitted =
        ext.quanx_server_remotes.size();

  if (ext.nodelist) {
    string_array allnodes;
    std::string allLinks;
    ini.get_all("server_local", "{NONAME}", allnodes);
    if (!allnodes.empty())
      allLinks = join(allnodes, "\n");
    return allLinks;
  }
  return ini.to_string();
}

void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini,
                  std::vector<RulesetContent> &ruleset_content_array,
                  const ProxyGroupConfigs &extra_proxy_group,
                  extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  std::string proxyStr;
  tribool udp, tfo, scv, tls13;
  std::vector<Proxy> nodelist;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("server_local");
  ini.erase_section();
  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    if (x.Port == 0 || x.Hostname.empty() || x.Remark.empty() ||
        !quanxProxyScalarIsSafe(x.Hostname) ||
        !quanxProxyScalarIsSafe(x.Remark))
      continue;

    std::string &hostname = x.Hostname, &method = x.EncryptMethod,
                &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &password = x.Password,
                &plugin = x.Plugin, &pluginopts = x.PluginOption,
                &protocol = x.Protocol, &protoparam = x.ProtocolParam,
                &obfs = x.OBFS, &obfsparam = x.OBFSParam,
                &username = x.Username;
    std::string port = std::to_string(x.Port);
    const std::string endpoint = shareLinkHost(hostname) + ":" + port;
    bool &tlssecure = x.TLSSecure;
    bool emit_tls_verification = false;
    bool force_disable_tfo = false;

    udp = ext.udp;
    tfo = ext.tfo;
    scv = ext.skip_cert_verify;
    tls13 = ext.tls13;
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);
    tls13.define(x.TLS13);

    switch (x.Type) {
    case ProxyType::VMess: {
      const bool reality = x.TLSStr == "reality" || !x.PublicKey.empty();
      const bool tls_active = reality || tlssecure;
      const std::string quanx_method =
          method == "auto" ? "chacha20-ietf-poly1305" : method;
      if (quanx_method.empty() || id.empty() ||
          !quanxProxyScalarIsSafe(quanx_method) ||
          !quanxProxyScalarIsSafe(id) ||
          !quanxPlainXrayTransportIsSafe(x) || !x.Flow.empty() ||
          !x.Encryption.empty() ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none") ||
          (!x.TLSStr.empty() && x.TLSStr != "none" && x.TLSStr != "tls" &&
           x.TLSStr != "reality") ||
          (x.TLSStr == "none" && tlssecure) ||
          (!x.ShortId.empty() && !reality))
        continue;
      proxyStr = "vmess = " + endpoint + ", method=" + quanx_method +
                 ", password=" + id;
      if (x.AlterId != 0)
        proxyStr += ", aead=false";
      if (!appendQuanXXrayTransport(x, reality, tls_active, proxyStr))
        continue;
      if (reality) {
        if (!appendQuanXRealityFields(x, proxyStr))
          continue;
        force_disable_tfo = true;
      } else if (tls_active) {
        std::string alpn_hex;
        if (!quanxTlsAlpnHex(x.AlpnList, alpn_hex))
          continue;
        if (!alpn_hex.empty())
          proxyStr += ", tls-alpn=" + alpn_hex;
        emit_tls_verification = true;
      } else if (!x.AlpnList.empty()) {
        continue;
      }
      break;
    }
    case ProxyType::VLESS: {
      const bool reality = x.TLSStr == "reality" || !x.PublicKey.empty();
      const bool tls_active = reality || tlssecure;
      const bool vision = x.Flow == "xtls-rprx-vision";
      if (id.empty() || !quanxProxyScalarIsSafe(id) ||
          !quanxPlainXrayTransportIsSafe(x) ||
          (!x.Encryption.empty() && x.Encryption != "none") ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none") ||
          (!x.Flow.empty() && !vision) ||
          (vision && (!reality || transproto != "tcp" ||
                      x.FakeType == "http")) ||
          (!x.TLSStr.empty() && x.TLSStr != "none" && x.TLSStr != "tls" &&
           x.TLSStr != "reality") ||
          (x.TLSStr == "none" && tlssecure) ||
          (!x.ShortId.empty() && !reality))
        continue;
      proxyStr =
          "vless = " + endpoint + ", method=none, password=" + id;
      if (!appendQuanXXrayTransport(x, reality, tls_active, proxyStr))
        continue;
      if (reality) {
        if (!appendQuanXRealityFields(x, proxyStr))
          continue;
        if (vision)
          proxyStr += ", vless-flow=xtls-rprx-vision";
        force_disable_tfo = true;
      } else if (tls_active) {
        std::string alpn_hex;
        if (!quanxTlsAlpnHex(x.AlpnList, alpn_hex))
          continue;
        if (!alpn_hex.empty())
          proxyStr += ", tls-alpn=" + alpn_hex;
        emit_tls_verification = true;
      } else if (!x.AlpnList.empty()) {
        continue;
      }
      break;
    }
    case ProxyType::Shadowsocks:
      proxyStr = "shadowsocks = " + endpoint +
                  ", method=" + method + ", password=" + password;
      if (!plugin.empty()) {
        switch (hash_(plugin)) {
        case "simple-obfs"_hash:
        case "obfs-local"_hash:
          if (!pluginopts.empty())
            proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
          break;
        case "v2ray-plugin"_hash:
          pluginopts = replaceAllDistinct(pluginopts, ";", "&");
          plugin = getUrlArg(pluginopts, "mode") == "websocket" ? "ws" : "";
          host = getUrlArg(pluginopts, "host");
          path = getUrlArg(pluginopts, "path");
          tlssecure = pluginopts.find("tls") != std::string::npos;
          if (tlssecure && plugin == "ws") {
            plugin += 's';
            if (!tls13.is_undef())
              proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
          }
          proxyStr += ", obfs=" + plugin;
          if (!host.empty())
            proxyStr += ", obfs-host=" + host;
          if (!path.empty())
            proxyStr += ", obfs-uri=" + path;
          break;
        default:
          continue;
        }
      }

      break;
    case ProxyType::ShadowsocksR:
      proxyStr = "shadowsocks = " + endpoint +
                  ", method=" + method + ", password=" + password +
                  ", ssr-protocol=" + protocol;
      if (!protoparam.empty())
        proxyStr += ", ssr-protocol-param=" + protoparam;
      proxyStr += ", obfs=" + obfs;
      if (!obfsparam.empty())
        proxyStr += ", obfs-host=" + obfsparam;
      break;
    case ProxyType::HTTP:
    case ProxyType::HTTPS:
      proxyStr = "http = " + endpoint +
                  ", username=" + (username.empty() ? "none" : username) +
                  ", password=" + (password.empty() ? "none" : password);
      if (tlssecure) {
        proxyStr += ", over-tls=true";
        emit_tls_verification = true;
        if (!tls13.is_undef())
          proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
      } else {
        proxyStr += ", over-tls=false";
      }
      break;
    case ProxyType::Trojan: {
      const bool reality = x.TLSStr == "reality" || !x.PublicKey.empty();
      const bool tls_active = reality || tlssecure;
      if (!tls_active || password.empty() ||
          !quanxProxyScalarIsSafe(password) ||
          !quanxPlainXrayTransportIsSafe(x) || !x.Flow.empty() ||
          !x.Encryption.empty() ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none") ||
          (!x.FakeType.empty() && x.FakeType != "none") ||
          (transproto != "tcp" && transproto != "ws") ||
          (!x.TLSStr.empty() && x.TLSStr != "tls" &&
           x.TLSStr != "reality") ||
          (!x.ShortId.empty() && !reality))
        continue;
      proxyStr = "trojan = " + endpoint + ", password=" + password;
      if (transproto == "tcp") {
        if (reality && x.ServerName.empty())
          continue;
        if (!quanxProxyScalarIsSafe(x.ServerName))
          continue;
        proxyStr += ", over-tls=true";
        if (!x.ServerName.empty())
          proxyStr += ", tls-host=" + x.ServerName;
      } else {
        const std::string http_host = host.empty() ? hostname : host;
        const std::string tls_host =
            x.ServerName.empty() ? hostname : x.ServerName;
        if (!quanxProxyScalarIsSafe(http_host) ||
            !quanxProxyScalarIsSafe(tls_host) ||
            !quanxProxyScalarIsSafe(path) ||
            toLower(http_host) != toLower(tls_host))
          continue;
        proxyStr += ", obfs=wss";
        if (!http_host.empty())
          proxyStr += ", obfs-host=" + http_host;
        if (!path.empty())
          proxyStr += ", obfs-uri=" + path;
      }
      if (reality) {
        if (!appendQuanXRealityFields(x, proxyStr))
          continue;
        force_disable_tfo = true;
      } else {
        std::string alpn_hex;
        if (!quanxTlsAlpnHex(x.AlpnList, alpn_hex))
          continue;
        if (!alpn_hex.empty())
          proxyStr += ", tls-alpn=" + alpn_hex;
        emit_tls_verification = true;
      }
      break;
    }
    case ProxyType::AnyTLS: {
      const bool reality = x.TLSStr == "reality" || !x.PublicKey.empty();
      if (password.empty() || !quanxProxyScalarIsSafe(password) ||
          !quanxPlainXrayTransportIsSafe(x) || !x.Flow.empty() ||
          !x.Encryption.empty() ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none") ||
          (!transproto.empty() && transproto != "tcp") ||
          (!x.FakeType.empty() && x.FakeType != "none") ||
          !x.Path.empty() ||
          (!x.TLSStr.empty() && x.TLSStr != "tls" &&
           x.TLSStr != "reality") ||
          !quanxProxyScalarIsSafe(x.ServerName) ||
          (!x.ShortId.empty() && !reality) ||
          (reality && x.ServerName.empty()))
        continue;
      proxyStr =
          "anytls = " + endpoint + ", password=" + password + ", over-tls=true";
      if (!x.ServerName.empty())
        proxyStr += ", tls-host=" + x.ServerName;
      if (reality) {
        if (!appendQuanXRealityFields(x, proxyStr))
          continue;
        force_disable_tfo = true;
      } else {
        std::string alpn_hex;
        if (!quanxTlsAlpnHex(x.AlpnList, alpn_hex))
          continue;
        if (!alpn_hex.empty())
          proxyStr += ", tls-alpn=" + alpn_hex;
        emit_tls_verification = true;
      }
      break;
    }
    case ProxyType::SOCKS5:
      proxyStr = "socks5 = " + endpoint;
      if (!username.empty() && !password.empty()) {
        proxyStr += ", username=" + username + ", password=" + password;
        if (tlssecure) {
          proxyStr += ", over-tls=true, tls-host=" + host;
          emit_tls_verification = true;
          if (!tls13.is_undef())
            proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
        } else {
          proxyStr += ", over-tls=false";
        }
      }
      break;
    default:
      continue;
    }
    if (force_disable_tfo)
      proxyStr += ", fast-open=false";
    else if (!tfo.is_undef())
      proxyStr += ", fast-open=" + tfo.get_str();
    if (!udp.is_undef())
      proxyStr += ", udp-relay=" + udp.get_str();
    if (emit_tls_verification && !scv.is_undef())
      proxyStr += ", tls-verification=" + scv.reverse().get_str();
    proxyStr += ", tag=" + x.Remark;

    ini.set("{NONAME}", proxyStr);
    used_remarks.emplace(x.Remark);
    nodelist.emplace_back(x);
    generation_tracker.markEmitted();
  }

  if (ext.nodelist)
    return;

  string_multimap original_groups;
  ini.set_current_section("policy");
  ini.get_items(original_groups);
  ini.erase_section();

  for (const ProxyGroupConfig &x : extra_proxy_group) {
    std::string type;
    string_array filtered_nodelist;
    bool has_remote_selector = false;

    switch (x.Type) {
    case ProxyGroupType::Select:
      type = "static";
      break;
    case ProxyGroupType::URLTest:
      type = "url-latency-benchmark";
      break;
    case ProxyGroupType::Fallback:
      type = "available";
      break;
    case ProxyGroupType::LoadBalance:
      type = "round-robin";
      break;
    case ProxyGroupType::SSID:
      type = "ssid";
      for (const auto &proxy : x.Proxies)
        filtered_nodelist.emplace_back(replaceAllDistinct(proxy, "=", ":"));
      break;
    default:
      continue;
    }

    if (x.Type != ProxyGroupType::SSID) {
      for (const auto &y : x.Proxies)
        groupGenerate(y, nodelist, filtered_nodelist, true, ext);

      QuanXRemoteSelector remote_selector =
          quanxRemoteSelectorForGroup(x, ext.quanx_server_remotes);
      if (!remote_selector.resources.empty()) {
        filtered_nodelist.emplace_back(
            "resource-tag-regex=" +
            quanxResourceTagRegex(remote_selector.resources));
        filtered_nodelist.emplace_back("server-tag-regex=" +
                                       remote_selector.server_pattern);
        has_remote_selector = true;
      }

      if (filtered_nodelist.empty() && !has_remote_selector)
        filtered_nodelist.emplace_back("direct");

      if (filtered_nodelist.size() < 2 &&
          !has_remote_selector) // force groups with 1 node to be static
        type = "static";
    }

    auto iter =
        std::find_if(original_groups.begin(), original_groups.end(),
                     [&](const string_multimap::value_type &n) {
                       std::string groupdata = n.second;
                       std::string::size_type cpos = groupdata.find(',');
                       if (cpos != std::string::npos)
                         return trim(groupdata.substr(0, cpos)) == x.Name;
                       else
                         return false;
                     });
    if (iter != original_groups.end()) {
      string_array vArray = split(iter->second, ",");
      if (vArray.size() > 1) {
        if (trim(vArray[vArray.size() - 1]).find("img-url") == 0)
          filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
      }
    }

    std::string proxies = join(filtered_nodelist, ", ");

    std::string singlegroup = type + "=" + x.Name + ", " + proxies;
    if (x.Type != ProxyGroupType::Select && x.Type != ProxyGroupType::SSID) {
      singlegroup += ", check-interval=" + std::to_string(x.Interval);
      if (x.Tolerance > 0)
        singlegroup += ", tolerance=" + std::to_string(x.Tolerance);
    }
    ini.set("{NONAME}", singlegroup);
  }

  if (ext.enable_rule_generator)
    rulesetToSurge(ini, ruleset_content_array, -1, ext.overwrite_original_rules,
                   ext.managed_config_prefix, ext.rule_stats);
}

std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group,
                       std::string &userinfo, extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  int index = 0;

  if (group.empty())
    group = "SSD";

  writer.StartObject();
  writer.Key("airport");
  writer.String(group.data());
  writer.Key("port");
  writer.Int(1);
  writer.Key("encryption");
  writer.String("aes-128-gcm");
  writer.Key("password");
  writer.String("password");
  if (!userinfo.empty()) {
    std::string data = replaceAllDistinct(userinfo, "; ", "&");
    std::string upload = getUrlArg(data, "upload"),
                download = getUrlArg(data, "download"),
                total = getUrlArg(data, "total"),
                expiry = getUrlArg(data, "expire");
    double used = (to_number(upload, 0.0) + to_number(download, 0.0)) /
                  std::pow(1024, 3) * 1.0,
           tot = to_number(total, 0.0) / std::pow(1024, 3) * 1.0;
    writer.Key("traffic_used");
    writer.Double(used);
    writer.Key("traffic_total");
    writer.Double(tot);
    if (!expiry.empty()) {
      const time_t rawtime = to_int(expiry);
      char buffer[30];
      struct tm dt;
      localtime_r(&rawtime, &dt);
      strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", &dt);
      writer.Key("expiry");
      writer.String(buffer);
    }
  }
  writer.Key("servers");
  writer.StartArray();

  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    std::string &hostname = x.Hostname, &password = x.Password,
                &method = x.EncryptMethod, &plugin = x.Plugin,
                &pluginopts = x.PluginOption, &protocol = x.Protocol,
                &obfs = x.OBFS;

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (plugin == "obfs-local")
        plugin = "simple-obfs";
      writer.StartObject();
      writer.Key("server");
      writer.String(hostname.data());
      writer.Key("port");
      writer.Int(x.Port);
      writer.Key("encryption");
      writer.String(method.data());
      writer.Key("password");
      writer.String(password.data());
      writer.Key("plugin");
      writer.String(plugin.data());
      writer.Key("plugin_options");
      writer.String(pluginopts.data());
      writer.Key("remarks");
      writer.String(x.Remark.data());
      writer.Key("id");
      writer.Int(index);
      writer.EndObject();
      break;
    case ProxyType::ShadowsocksR:
      if (std::count(ss_ciphers.begin(), ss_ciphers.end(), method) > 0 &&
          protocol == "origin" && obfs == "plain") {
        writer.StartObject();
        writer.Key("server");
        writer.String(hostname.data());
        writer.Key("port");
        writer.Int(x.Port);
        writer.Key("encryption");
        writer.String(method.data());
        writer.Key("password");
        writer.String(password.data());
        writer.Key("remarks");
        writer.String(x.Remark.data());
        writer.Key("id");
        writer.Int(index);
        writer.EndObject();
        break;
      } else
        continue;
    default:
      continue;
    }
    index++;
    generation_tracker.markEmitted();
  }
  writer.EndArray();
  writer.EndObject();
  return "ssd://" + base64Encode(sb.GetString());
}

std::string proxyToMellow(std::vector<Proxy> &nodes,
                          const std::string &base_conf,
                          std::vector<RulesetContent> &ruleset_content_array,
                          const ProxyGroupConfigs &extra_proxy_group,
                          extra_settings &ext) {
  ext.target_generation_stats = TargetGenerationStats{};
  ext.target_generation_stats.input_nodes = nodes.size();
  INIReader ini;
  ini.store_any_line = true;
  if (ini.parse(base_conf) != 0) {
    writeLog(LOG_LEVEL_ERROR, "MELLOW_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return "";
  }

  proxyToMellow(nodes, ini, ruleset_content_array, extra_proxy_group, ext);

  return ini.to_string();
}

void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini,
                   std::vector<RulesetContent> &ruleset_content_array,
                   const ProxyGroupConfigs &extra_proxy_group,
                   extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  std::string proxy;
  std::string url;
  tribool tfo, scv;
  std::vector<Proxy> nodelist;
  string_array vArray, remarks_list;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("Endpoint");

  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, &username = x.Username,
                &password = x.Password,
                &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path,
                &quicsecure = x.QUICSecure, &quicsecret = x.QUICSecret;
    std::string port = std::to_string(x.Port);
    const std::string tlssecure = x.TLSSecure ? "true" : "false";

    tfo = ext.tfo;
    scv = ext.skip_cert_verify;
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (!x.Plugin.empty())
        continue;
      if (!surgeProxyScalarIsSafe(x.Remark))
        continue;
      proxy = x.Remark + ", ss, " + shadowsocksShareLink(x, false, false);
      break;
    case ProxyType::VMess:
      proxy =
          x.Remark + ", vmess1, vmess1://" + id + "@" + hostname + ":" + port;
      if (!path.empty())
        proxy += path;
      proxy += "?network=" + transproto;
      switch (hash_(transproto)) {
      case "ws"_hash:
        proxy += "&ws.host=" + urlEncode(host);
        break;
      case "http"_hash:
        if (!host.empty())
          proxy += "&http.host=" + urlEncode(host);
        break;
      case "quic"_hash:
        if (!quicsecure.empty())
          proxy += "&quic.security=" + quicsecure + "&quic.key=" + quicsecret;
        break;
      case "kcp"_hash:
      case "tcp"_hash:
        break;
      }
      proxy += "&tls=" + tlssecure;
      if (tlssecure == "true") {
        if (!host.empty())
          proxy += "&tls.servername=" + urlEncode(host);
      }
      if (!scv.is_undef())
        proxy += "&tls.allowinsecure=" + scv.get_str();
      if (!tfo.is_undef())
        proxy += "&sockopt.tcpfastopen=" + tfo.get_str();
      break;
    case ProxyType::SOCKS5:
      if (!surgeProxyScalarIsSafe(x.Remark) ||
          !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(username) ||
          !surgeProxyScalarIsSafe(password))
        continue;
      proxy = x.Remark + ", builtin, socks, address=" + hostname +
              ", port=" + port + ", user=" + username + ", pass=" + password;
      break;
    case ProxyType::HTTP:
      if (!surgeProxyScalarIsSafe(x.Remark) ||
          !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(username) ||
          !surgeProxyScalarIsSafe(password))
        continue;
      proxy = x.Remark + ", builtin, http, address=" + hostname +
              ", port=" + port + ", user=" + username + ", pass=" + password;
      break;
    default:
      continue;
    }

    ini.set("{NONAME}", proxy);
    remarks_list.emplace_back(x.Remark);
    used_remarks.emplace(x.Remark);
    nodelist.emplace_back(x);
    generation_tracker.markEmitted();
  }

  ini.set_current_section("EndpointGroup");

  for (const ProxyGroupConfig &x : extra_proxy_group) {
    string_array filtered_nodelist;
    url.clear();
    proxy.clear();

    switch (x.Type) {
    case ProxyGroupType::Select:
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
    case ProxyGroupType::LoadBalance:
      break;
    default:
      continue;
    }

    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, false, ext);

    if (filtered_nodelist.empty()) {
      if (remarks_list.empty())
        filtered_nodelist.emplace_back("DIRECT");
      else
        filtered_nodelist = remarks_list;
    }

    // don't process these for now
    /*
    proxy = vArray[1];
    for(std::string &x : filtered_nodelist)
        proxy += "," + x;
    if(vArray[1] == "url-test" || vArray[1] == "fallback" || vArray[1] ==
    "load-balance") proxy += ",url=" + url;
    */

    proxy = x.Name + ", ";
    /*
    for(std::string &y : filtered_nodelist)
        proxy += y + ":";
    proxy = proxy.substr(0, proxy.size() - 1);
    */
    proxy += join(filtered_nodelist, ":");
    proxy +=
        ", latency, interval=300, timeout=6"; // use hard-coded values for now

    ini.set("{NONAME}", proxy); // insert order
  }

  if (ext.enable_rule_generator)
    rulesetToSurge(ini, ruleset_content_array, 0, ext.overwrite_original_rules,
                   "", ext.rule_stats);
}

static std::string clampLoonAlias(const std::string &alias,
                                  size_t max_length) {
  if (alias.size() <= max_length)
    return alias;
  std::string result = alias.substr(0, max_length);
  while (!result.empty() && !isStrUTF8(result))
    result.pop_back();
  return result;
}

static void collectLoonSectionNames(INIReader &ini, const std::string &section,
                                    std::unordered_set<std::string> &names) {
  string_multimap items;
  ini.set_current_section(section);
  ini.get_items(items);
  for (const auto &[name, value] : items) {
    (void)value;
    std::string normalized = trimWhitespace(name, true, true);
    if (!normalized.empty() && normalized != "{NONAME}")
      names.emplace(std::move(normalized));
  }
}

static std::string reserveLoonAlias(std::unordered_set<std::string> &used,
                                    const std::string &base,
                                    const std::string &fallback) {
  std::string normalized = clampLoonAlias(base, 64);
  if (normalized.empty())
    normalized = fallback;
  if (used.insert(normalized).second)
    return normalized;
  int suffix_index = 1;
  while (true) {
    const std::string suffix = "_" + std::to_string(suffix_index++);
    const size_t max_base = 64 > suffix.size() ? 64 - suffix.size() : 0;
    const std::string candidate =
        clampLoonAlias(normalized, max_base) + suffix;
    if (used.insert(candidate).second)
      return candidate;
  }
}

static bool loonRemoteMatchesProvider(const LoonRemoteProxyResource &remote,
                                      const std::string &provider) {
  return provider == remote.requested_name ||
         provider == remote.selection_name ||
         provider == remote.resource_name;
}

static std::vector<LoonRemoteProxyResource *>
loonResourcesForRule(const std::string &rule,
                     std::vector<LoonRemoteProxyResource> &remotes,
                     std::string &server_pattern) {
  std::vector<LoonRemoteProxyResource *> selected;
  selected.reserve(remotes.size());
  for (LoonRemoteProxyResource &remote : remotes)
    selected.emplace_back(&remote);

  std::string target;
  if (parseProviderGroupIdMatcher(rule, target, server_pattern)) {
    selected.erase(
        std::remove_if(selected.begin(), selected.end(), [&](const auto *item) {
          return !matchRange(target, item->group_id);
        }),
        selected.end());
  } else if (parseQuanXSourceGroupRule(rule, target, server_pattern)) {
    selected.erase(
        std::remove_if(selected.begin(), selected.end(), [&](const auto *item) {
          return item->source_tag.empty() ||
                 !regFind(item->source_tag, target);
        }),
        selected.end());
  } else if (!startsWith(rule, "!!") && !startsWith(rule, "script:")) {
    server_pattern = rule;
  } else {
    selected.clear();
  }
  if (server_pattern.empty())
    server_pattern = ".*";
  return selected;
}

static void appendLoonRemoteProxies(
    INIReader &ini, std::vector<Proxy> &nodes,
    const ProxyGroupConfigs &extra_proxy_group, extra_settings &ext,
    std::unordered_set<std::string> &used_aliases) {
  collectLoonSectionNames(ini, "Remote Proxy", used_aliases);
  collectLoonSectionNames(ini, "Remote Filter", used_aliases);
  collectLoonSectionNames(ini, "Proxy", used_aliases);
  collectLoonSectionNames(ini, "Proxy Group", used_aliases);
  for (const ProxyGroupConfig &group : extra_proxy_group)
    used_aliases.emplace(group.Name);
  for (const Proxy &node : nodes)
    used_aliases.emplace(node.Remark);

  ini.set_current_section("Remote Proxy");
  for (LoonRemoteProxyResource &remote : ext.loon_remote_proxies) {
    const std::string final_name = reserveLoonAlias(
        used_aliases, remote.resource_name, "SubConverter_Remote");
    if (final_name != remote.resource_name) {
      remote.resource_name = final_name;
      writeLog(LOG_LEVEL_INFO, "LOON_REMOTE_PROXY_RENAMED group_id=" +
                                   std::to_string(remote.group_id));
    }
    ini.set(remote.resource_name,
            replaceAllDistinct(remote.url, ",", "%2C"));
  }
}

std::string proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext) {
  INIReader ini;
  std::string output_nodelist;
  std::vector<Proxy> nodelist;
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  TargetGenerationStatsMirror generation_stats_mirror(
      generation_stats, ext.loon_generation_stats);

  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.store_any_line = true;
  ini.add_direct_save_section("Plugin");
  if (ini.parse(base_conf) != INIREADER_EXCEPTION_NONE && !ext.nodelist) {
    writeLog(LOG_LEVEL_ERROR, "LOON_BASE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return "";
  }

  std::unordered_set<std::string> used_remote_aliases;
  if (!ext.nodelist)
    appendLoonRemoteProxies(ini, nodes, extra_proxy_group, ext,
                            used_remote_aliases);

  ini.set_current_section("Proxy");
  ini.erase_section();

  for (Proxy &x : nodes) {
    if (!loonQuotedScalarIsSafe(x.Remark)) {
      generation_stats.unsupported_by_type[x.Type]++;
      continue;
    }
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, &username = x.Username,
                &password = x.Password, &method = x.EncryptMethod,
                &plugin = x.Plugin, &pluginopts = x.PluginOption,
                &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &protocol = x.Protocol,
                &protoparam = x.ProtocolParam, &obfs = x.OBFS,
                &obfsparam = x.OBFSParam, flow = x.Flow, pk = x.PublicKey,
                shortId = x.ShortId, sni = x.ServerName;
    std::string port = std::to_string(x.Port), aid = std::to_string(x.AlterId);
    bool &tlssecure = x.TLSSecure;

    tribool scv = ext.skip_cert_verify, udp = ext.udp, tfo = ext.tfo;
    scv.define(x.AllowInsecure);
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    std::string proxy;

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      proxy = "Shadowsocks," + hostname + "," + port + "," + method + ",\"" +
              password + "\"";
      if (plugin == "simple-obfs" || plugin == "obfs-local") {
        if (!pluginopts.empty())
          proxy += "," + replaceAllDistinct(
                             replaceAllDistinct(pluginopts, ";obfs-host=", ","),
                             "obfs=", "");
      } else if (!plugin.empty()) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      break;
    case ProxyType::VMess:
      if (x.Port == 0 || method.empty() || id.empty() ||
          !loonProxyScalarIsSafe(hostname) ||
          !loonProxyScalarIsSafe(method) || !loonQuotedScalarIsSafe(id) ||
          !loonPlainXrayTransportIsSafe(x) || !x.AlpnList.empty() ||
          !x.PacketEncoding.empty() ||
          !x.TLS13.is_undef() || x.XUDP ||
          (!x.TLSStr.empty() && x.TLSStr != "none" && x.TLSStr != "tls") ||
          (x.TLSStr == "none" && tlssecure) ||
          (x.TLSStr == "tls" && !tlssecure) ||
          (!x.FakeType.empty() && x.FakeType != "none") ||
          (!x.Fingerprint.empty() &&
           (!tlssecure || !loonProxyScalarIsSafe(x.Fingerprint))) ||
          (!sni.empty() && (!tlssecure || !loonProxyScalarIsSafe(sni)))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      if (transproto != "tcp" && transproto != "ws" && transproto != "http") {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      if ((transproto == "ws" || transproto == "http") &&
          (!loonProxyScalarIsSafe(path) || !loonProxyScalarIsSafe(host))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      proxy = "vmess," + hostname + "," + port + "," + method + ",\"" + id +
              "\",transport=" + transproto + ",alterId=" + aid;
      if (transproto == "ws" || transproto == "http")
        proxy += ",path=" + path + ",host=" + host;
      proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
      if (tlssecure && !sni.empty())
        proxy += ",sni=" + sni;
      if (tlssecure && !x.Fingerprint.empty())
        proxy += ",tls-profile=" + x.Fingerprint;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    case ProxyType::VLESS: {
      const bool reality = x.TLSStr == "reality";
      if (x.Port == 0 || id.empty() || !loonProxyScalarIsSafe(hostname) ||
          !loonQuotedScalarIsSafe(id) || !loonPlainXrayTransportIsSafe(x) ||
          !x.AlpnList.empty() ||
          (!x.Encryption.empty() && x.Encryption != "none") ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none") ||
          !x.TLS13.is_undef() || x.XUDP ||
          (x.TLSStr == "none" && tlssecure) ||
          (x.TLSStr == "tls" && !tlssecure) ||
          (!x.FakeType.empty() && x.FakeType != "none") ||
          (!x.Fingerprint.empty() &&
           (!tlssecure || !loonProxyScalarIsSafe(x.Fingerprint))) ||
          (!sni.empty() && (!tlssecure || !loonProxyScalarIsSafe(sni)))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      if (reality) {
        if (!tlssecure || transproto != "tcp" || flow != "xtls-rprx-vision" ||
            pk.empty() || sni.empty() || !loonQuotedScalarIsSafe(pk) ||
            !loonProxyScalarIsSafe(shortId)) {
          generation_stats.unsupported_by_type[x.Type]++;
          continue;
        }
        proxy = "VLESS," + hostname + "," + port + ",\"" + id +
                "\",transport=tcp,flow=xtls-rprx-vision,public-key=\"" + pk + "\"";
        if (!shortId.empty())
          proxy += ",short-id=" + shortId;
        proxy += ",over-tls=true,sni=" + sni;
      } else {
        if ((!x.TLSStr.empty() && x.TLSStr != "none" && x.TLSStr != "tls") ||
            !flow.empty() || !pk.empty() || !shortId.empty() ||
            (transproto != "tcp" && transproto != "ws" && transproto != "http") ||
            ((transproto == "ws" || transproto == "http") &&
             (!loonProxyScalarIsSafe(path) || !loonProxyScalarIsSafe(host)))) {
          generation_stats.unsupported_by_type[x.Type]++;
          continue;
        }
        proxy = "VLESS," + hostname + "," + port + ",\"" + id +
                "\",transport=" + transproto;
        if (transproto == "ws" || transproto == "http")
          proxy += ",path=" + path + ",host=" + host;
        proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
        if (tlssecure && !sni.empty())
          proxy += ",sni=" + sni;
      }
      if (tlssecure && !x.Fingerprint.empty())
        proxy += ",tls-profile=" + x.Fingerprint;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    }
    case ProxyType::ShadowsocksR:
      proxy = "ShadowsocksR," + hostname + "," + port + "," + method + ",\"" +
              password + "\",protocol=" + protocol +
              ",protocol-param=" + protoparam + ",obfs=" + obfs +
              ",obfs-param=" + obfsparam;
      break;
    case ProxyType::HTTP:
      proxy = "http," + hostname + "," + port + "," + username + ",\"" +
              password + "\"";
      break;
    case ProxyType::HTTPS:
      proxy = "https," + hostname + "," + port + "," + username + ",\"" +
              password + "\"";
      if (!host.empty())
        proxy += ",tls-name=" + host;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    case ProxyType::Trojan:
      if (x.Port == 0 || password.empty() || !tlssecure ||
          !loonProxyScalarIsSafe(hostname) ||
          !loonQuotedScalarIsSafe(password) ||
          !loonPlainXrayTransportIsSafe(x) ||
          (transproto != "tcp" && transproto != "ws" && transproto != "http") ||
          ((transproto == "ws" || transproto == "http") &&
           (!loonProxyScalarIsSafe(path) || !loonProxyScalarIsSafe(host))) ||
          x.AlpnList.size() > 1 || !x.PublicKey.empty() || !x.ShortId.empty() ||
          !x.Flow.empty() || !x.PacketEncoding.empty() ||
          !x.TLS13.is_undef() || x.XUDP ||
          (!x.TLSStr.empty() && x.TLSStr != "tls") ||
          (!x.FakeType.empty() && x.FakeType != "none") ||
          (!sni.empty() && !loonProxyScalarIsSafe(sni)) ||
          (!x.Fingerprint.empty() && !loonProxyScalarIsSafe(x.Fingerprint)) ||
          (!x.AlpnList.empty() &&
           !loonProxyScalarIsSafe(x.AlpnList.front()))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      proxy = "trojan," + hostname + "," + port + ",\"" + password + "\"";
      if (transproto == "ws" || transproto == "http")
        proxy += ",transport=" + transproto + ",path=" + path + ",host=" + host;
      if (!x.AlpnList.empty())
        proxy += ",alpn=" + x.AlpnList.front();
      if (!sni.empty())
        proxy += ",sni=" + sni;
      if (!x.Fingerprint.empty())
        proxy += ",tls-profile=" + x.Fingerprint;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    case ProxyType::AnyTLS:
      if (x.Port == 0 || password.empty() || !loonProxyScalarIsSafe(hostname) ||
          !loonQuotedScalarIsSafe(password) || !x.AlpnList.empty() ||
          !x.UnderlyingProxy.empty() || x.IdleSessionCheckInterval != 30 ||
          x.IdleSessionTimeout != 30 || x.MinIdleSession != 0 ||
          !x.TLS13.is_undef() ||
          (!x.SNI.empty() && x.SNI != sni) ||
          (!sni.empty() && !loonProxyScalarIsSafe(sni)) ||
          (!x.Fingerprint.empty() && !loonProxyScalarIsSafe(x.Fingerprint))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      proxy = "AnyTLS," + hostname + "," + port + ",\"" + password + "\"";
      if (!sni.empty())
        proxy += ",sni=" + sni;
      if (!x.Fingerprint.empty())
        proxy += ",tls-profile=" + x.Fingerprint;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      proxy += ",block-quic=false";
      break;
    case ProxyType::SOCKS5:
      proxy = "socks5," + hostname + "," + port;
      if (!username.empty() && !password.empty())
        proxy += "," + username + ",\"" + password + "\"";
      proxy += ",over-tls=" + std::string(tlssecure ? "true" : "false");
      if (tlssecure) {
        if (!host.empty())
          proxy += ",tls-name=" + host;
        if (!scv.is_undef())
          proxy +=
              ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      }
      break;
    case ProxyType::WireGuard:
      if (!wireGuardStructuredConfigIsSafe(x)) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      proxy = "wireguard";
      for (const std::string &address : wireGuardLocalAddresses(x)) {
        const std::string bare = wireGuardAddressWithoutPrefix(address);
        if (isIPv4(bare))
          proxy += ", interface-ip=" + bare;
        else if (isIPv6(bare))
          proxy += ", interface-ipV6=" + bare;
      }
      proxy += ", private-key=\"" + x.PrivateKey + "\"";
      for (const auto &y : x.DnsServers) {
        if (isIPv4(y))
          proxy += ", dns=" + y;
        else if (isIPv6(y))
          proxy += ", dnsV6=" + y;
      }
      if (x.Mtu > 0)
        proxy += ", mtu=" + std::to_string(x.Mtu);
      {
        const auto peers = wireGuardPeers(x);
        uint16_t common_keepalive = peers.empty() ? 0 : peers.front().KeepAlive;
        if (std::any_of(peers.begin(), peers.end(), [common_keepalive](const WireGuardPeer &peer) {
              return peer.KeepAlive != common_keepalive;
            })) {
          generation_stats.unsupported_by_type[x.Type]++;
          continue;
        }
        if (common_keepalive > 0)
          proxy += ", keepalive=" + std::to_string(common_keepalive);
        proxy += ", peers=[";
        for (size_t peer_index = 0; peer_index < peers.size(); ++peer_index) {
          if (peer_index > 0)
            proxy += ",";
          proxy += "{" + generateLoonWireGuardPeer(peers[peer_index]) + "}";
        }
        proxy += "]";
      }
      break;
    case ProxyType::Hysteria2: {
      const bool salamander = x.OBFSParam == "salamander";
      int download_bandwidth = 0;
      if (x.Port == 0 || password.empty() || !loonProxyScalarIsSafe(hostname) ||
          !loonQuotedScalarIsSafe(password) || !x.UpMbps.empty() ||
          !x.Ports.empty() || !x.Hysteria2ECH.empty() || !x.Alpn.empty() ||
          !x.AlpnList.empty() || !x.PublicKey.empty() || !x.OBFS.empty() ||
          !x.HysteriaHopInterval.empty() || !x.Hysteria2RealmUrl.empty() ||
          !x.Hysteria2GeckoMinPacketSize.empty() ||
          !x.Hysteria2GeckoMaxPacketSize.empty() ||
          (!x.ServerName.empty() &&
           !loonProxyScalarIsSafe(x.ServerName)) ||
          (!x.Fingerprint.empty() &&
           (!loonProxyScalarIsSafe(x.Fingerprint) ||
            (!scv.is_undef() && scv.get()))) ||
          ((!x.OBFSParam.empty() || !x.OBFSPassword.empty()) &&
           (!salamander || x.OBFSPassword.empty() ||
            !loonQuotedScalarIsSafe(x.OBFSPassword))) ||
          (!x.DownMbps.empty() &&
           (!parseMbpsValue(x.DownMbps, download_bandwidth) ||
            download_bandwidth <= 0))) {
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      proxy = "Hysteria2," + hostname + "," + port + ",\"" + password + "\"";
      if (!x.ServerName.empty()) {
        proxy += ",sni=" + x.ServerName;
      }
      if (!x.Fingerprint.empty())
        proxy += ",tls-cert-sha256=" + x.Fingerprint;
      if (!x.DownMbps.empty())
        proxy += ",download-bandwidth=" + std::to_string(download_bandwidth);
      if (salamander)
        proxy += ",salamander-password=\"" + x.OBFSPassword + "\"";
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    }
    default:
      generation_stats.unsupported_by_type[x.Type]++;
      continue;
    }

    if (!tfo.is_undef())
      proxy += ",fast-open=" + std::string(tfo.get() ? "true" : "false");
    if (!udp.is_undef())
      proxy += ",udp=" + std::string(udp.get() ? "true" : "false");

    if (ext.nodelist)
      output_nodelist += x.Remark + " = " + proxy + "\n";
    else {
      ini.set("{NONAME}", x.Remark + " = " + proxy);
      nodelist.emplace_back(x);
      used_remarks.emplace(x.Remark);
    }
    generation_stats.emitted_nodes++;
  }

  if (ext.nodelist)
    return output_nodelist;

  string_multimap original_groups;
  ini.set_current_section("Proxy Group");
  ini.get_items(original_groups);
  ini.erase_section();

  size_t loon_group_index = 0;
  size_t generated_remote_filters = 0;
  for (const ProxyGroupConfig &x : extra_proxy_group) {
    const size_t current_group_index = ++loon_group_index;
    string_array filtered_nodelist;
    std::string group, group_extra;

    switch (x.Type) {
    case ProxyGroupType::Select:
    case ProxyGroupType::LoadBalance:
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
      break;
    case ProxyGroupType::SSID:
      if (x.Proxies.size() < 2)
        continue;
      group = x.TypeStr() + ",default=" + x.Proxies[0] + ",";
      group += join(x.Proxies.begin() + 1, x.Proxies.end(), ",");
      ini.set("{NONAME}", x.Name + " = " + group); // insert order
      continue;
    default:
      continue;
    }

    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, true, ext);

    auto add_remote_member = [&](const std::string &member) {
      if (std::find(filtered_nodelist.begin(), filtered_nodelist.end(),
                    member) == filtered_nodelist.end()) {
        filtered_nodelist.emplace_back(member);
        generation_stats.remote_references_emitted++;
      }
    };

    for (const std::string &provider : x.UsingProvider) {
      for (const LoonRemoteProxyResource &remote : ext.loon_remote_proxies) {
        if (loonRemoteMatchesProvider(remote, provider))
          add_remote_member(remote.resource_name);
      }
    }

    size_t remote_rule_index = 0;
    for (const std::string &rule : x.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      {
        const std::string normalized_rule = toLower(rule);
        if (startsWith(normalized_rule, "http://") ||
            startsWith(normalized_rule, "https://"))
          continue;
      }
      std::string server_pattern;
      std::vector<LoonRemoteProxyResource *> selected =
          loonResourcesForRule(rule, ext.loon_remote_proxies, server_pattern);
      if (selected.empty())
        continue;
      if (server_pattern == ".*") {
        for (const LoonRemoteProxyResource *remote : selected)
          add_remote_member(remote->resource_name);
        continue;
      }

      const std::string filter_name = reserveLoonAlias(
          used_remote_aliases,
          "SubConverter_Filter_" + std::to_string(current_group_index) +
              "_" + std::to_string(++remote_rule_index),
          "SubConverter_Filter");
      string_array resource_names;
      resource_names.reserve(selected.size());
      for (const LoonRemoteProxyResource *remote : selected)
        resource_names.emplace_back(remote->resource_name);
      ini.set("Remote Filter", filter_name,
              "NameRegex," + join(resource_names, ",") +
                  ",FilterKey=\"" + server_pattern + "\"");
      generated_remote_filters++;
      add_remote_member(filter_name);
    }

    if (filtered_nodelist.empty())
      filtered_nodelist.emplace_back("DIRECT");

    auto iter = std::find_if(original_groups.begin(), original_groups.end(),
                             [&](const string_multimap::value_type &n) {
                               return trim(n.first) == x.Name;
                             });

    if (iter != original_groups.end()) {
      string_array vArray = split(iter->second, ",");
      if (vArray.size() > 1) {
        if (trim(vArray[vArray.size() - 1]).find("img-url") == 0)
          filtered_nodelist.emplace_back(trim(vArray[vArray.size() - 1]));
      }
    }

    group = x.TypeStr() + ",";
    /*
    for(std::string &y : filtered_nodelist)
        group += "," + y;
    */
    group += join(filtered_nodelist, ",");
    if (x.Type != ProxyGroupType::Select) {
      group += ",url=" + x.Url + ",interval=" + std::to_string(x.Interval);
      if (x.Type == ProxyGroupType::LoadBalance) {
        group += ",algorithm=" +
                 std::string(x.Strategy == BalanceStrategy::RoundRobin
                                 ? "round-robin"
                                 : "pcc");
        if (x.Timeout > 0)
          group += ",max-timeout=" + std::to_string(x.Timeout);
      }
      if (x.Type == ProxyGroupType::URLTest) {
        if (x.Tolerance > 0)
          group += ",tolerance=" + std::to_string(x.Tolerance);
      }
      if (x.Type == ProxyGroupType::Fallback)
        group += ",max-timeout=" + std::to_string(x.Timeout);
    }

    ini.set("{NONAME}", x.Name + " = " + group); // insert order
  }

  if (!ext.loon_remote_proxies.empty()) {
    writeLog(LOG_LEVEL_INFO,
             "LOON_REMOTE_FILTERS_GENERATED resources=" +
                 std::to_string(ext.loon_remote_proxies.size()) +
                 " filters=" + std::to_string(generated_remote_filters) +
                 " references=" +
                 std::to_string(generation_stats.remote_references_emitted));
  }

  if (ext.enable_rule_generator)
    rulesetToSurge(ini, ruleset_content_array, -4, ext.overwrite_original_rules,
                   ext.managed_config_prefix, ext.rule_stats);

  return ini.to_string();
}

static std::string formatSingBoxInterval(Integer interval) {
  std::string result;
  if (interval >= 3600) {
    result += std::to_string(interval / 3600) + "h";
    interval %= 3600;
  }
  if (interval >= 60) {
    result += std::to_string(interval / 60) + "m";
    interval %= 60;
  }
  if (interval > 0)
    result += std::to_string(interval) + "s";
  return result;
}

static rapidjson::Value
buildSingBoxTransport(const Proxy &proxy,
                      rapidjson::MemoryPoolAllocator<> &allocator) {
  rapidjson::Value transport(rapidjson::kObjectType);
  const std::string transport_type =
      proxy.TransferProtocol == "tcp" && proxy.FakeType == "http"
          ? "http"
          : proxy.TransferProtocol;
  switch (hash_(transport_type)) {
  case "http"_hash: {
    transport.AddMember("type", "http", allocator);
    if (!proxy.Host.empty()) {
      rapidjson::Value hosts(rapidjson::kArrayType);
      hosts.PushBack(rapidjson::StringRef(proxy.Host.c_str()), allocator);
      transport.AddMember("host", hosts, allocator);
    }
    transport.AddMember("path",
                        rapidjson::StringRef(proxy.Path.empty()
                                                 ? "/"
                                                 : proxy.Path.c_str()),
                        allocator);
    break;
  }
  case "ws"_hash: {
    transport.AddMember("type", "ws", allocator);
    if (proxy.Path.empty())
      transport.AddMember("path", "/", allocator);
    else
      transport.AddMember("path", rapidjson::StringRef(proxy.Path.c_str()),
                          allocator);

    rapidjson::Value headers(rapidjson::kObjectType);
    if (!proxy.Host.empty())
      headers.AddMember("Host", rapidjson::StringRef(proxy.Host.c_str()),
                        allocator);
    if (!proxy.Edge.empty())
      headers.AddMember("Edge", rapidjson::StringRef(proxy.Edge.c_str()),
                        allocator);
    transport.AddMember("headers", headers, allocator);
    break;
  }
  case "grpc"_hash: {
    transport.AddMember("type", "grpc", allocator);
    const std::string &service_name = proxy.GRPCServiceName.empty()
                                          ? proxy.Path
                                          : proxy.GRPCServiceName;
    if (!service_name.empty())
      transport.AddMember("service_name",
                          rapidjson::StringRef(service_name.c_str()), allocator);
    break;
  }
  case "httpupgrade"_hash: {
    transport.AddMember("type", "httpupgrade", allocator);
    transport.AddMember("host", rapidjson::StringRef(proxy.Host.c_str()),
                        allocator);
    transport.AddMember("path",
                        rapidjson::StringRef(proxy.Path.empty()
                                                 ? "/"
                                                 : proxy.Path.c_str()),
                        allocator);
    break;
  }
  default:
    break;
  }
  return transport;
}

static bool singBoxTransportSupported(const Proxy &proxy) {
  const std::string &network = proxy.TransferProtocol;
  return network.empty() || network == "tcp" || network == "ws" ||
         network == "http" || network == "grpc" ||
         network == "httpupgrade";
}

static void addSingBoxCommonMembers(
    rapidjson::Value &proxy, const Proxy &x,
    const rapidjson::GenericStringRef<rapidjson::Value::Ch> &type,
    rapidjson::MemoryPoolAllocator<> &allocator) {
  proxy.AddMember("type", type, allocator);
  proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
  proxy.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()),
                  allocator);
  proxy.AddMember("server_port", x.Port, allocator);
}

static rapidjson::Value
stringArrayToJsonArray(const std::string &array, const std::string &delimiter,
                       rapidjson::MemoryPoolAllocator<> &allocator) {
  rapidjson::Value result(rapidjson::kArrayType);
  string_array vArray = split(array, delimiter);
  for (const auto &x : vArray)
    result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
  return result;
}

static rapidjson::Value
vectorToJsonArray(const std::vector<std::string> &array,
                  rapidjson::MemoryPoolAllocator<> &allocator) {
  rapidjson::Value result(rapidjson::kArrayType);
  for (const auto &x : array)
    result.PushBack(rapidjson::Value(trim(x).c_str(), allocator), allocator);
  return result;
}

static rapidjson::Value wireGuardIntegerArray(
    const std::string &values, rapidjson::MemoryPoolAllocator<> &allocator) {
  rapidjson::Value result(rapidjson::kArrayType);
  for (const std::string &value : split(replaceAllDistinct(values, "/", ","), ",")) {
    const std::string item = trim(value);
    if (!item.empty())
      result.PushBack(to_int(item, 0), allocator);
  }
  return result;
}

static rapidjson::Value buildSingBoxWireGuardPeer(
    const WireGuardPeer &peer, bool endpoint_schema,
    rapidjson::MemoryPoolAllocator<> &allocator) {
  rapidjson::Value result(rapidjson::kObjectType);
  result.AddMember(rapidjson::Value(endpoint_schema ? "address" : "server", allocator),
                   rapidjson::Value(peer.Hostname.c_str(), allocator), allocator);
  if (endpoint_schema)
    result.AddMember("port", peer.Port, allocator);
  else
    result.AddMember("server_port", peer.Port, allocator);
  result.AddMember("public_key", rapidjson::Value(peer.PublicKey.c_str(), allocator), allocator);
  if (!peer.PreSharedKey.empty())
    result.AddMember("pre_shared_key",
                     rapidjson::Value(peer.PreSharedKey.c_str(), allocator), allocator);
  if (!peer.AllowedIPs.empty())
    result.AddMember("allowed_ips",
                     stringArrayToJsonArray(peer.AllowedIPs, ",", allocator), allocator);
  if (!peer.Reserved.empty())
    result.AddMember("reserved", wireGuardIntegerArray(peer.Reserved, allocator), allocator);
  if (endpoint_schema && peer.KeepAlive > 0) {
    result.AddMember("persistent_keepalive_interval",
                     peer.KeepAlive, allocator);
  }
  return result;
}

void proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json,
                    std::vector<RulesetContent> &ruleset_content_array,
                    const ProxyGroupConfigs &extra_proxy_group,
                    extra_settings &ext) {
  TargetGenerationStats &generation_stats = ext.target_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();
  const bool add_clash_modes = effectiveSettings().singBoxAddClashModes;
  const bool wireguard_endpoint = effectiveSettings().singBoxWireGuardEndpoint;
  const bool snell_outbound = effectiveSettings().singBoxSnellOutbound;
  using namespace rapidjson_ext;
  rapidjson::Document::AllocatorType &allocator = json.GetAllocator();
  rapidjson::Value outbounds(rapidjson::kArrayType),
      route(rapidjson::kArrayType);
  rapidjson::Value endpoints(rapidjson::kArrayType);
  if (wireguard_endpoint && json.IsObject() && json.HasMember("endpoints") &&
      json["endpoints"].IsArray())
    endpoints.CopyFrom(json["endpoints"], allocator);
  std::vector<Proxy> nodelist;
  string_array remarks_list;
  size_t wireguard_nodes_emitted = 0;
  size_t wireguard_peers_emitted = 0;
  size_t snell_nodes_input = 0;
  size_t snell_nodes_emitted = 0;
  size_t snell_v5_normalized = 0;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  if (!ext.nodelist) {
    auto direct = buildObject(allocator, "type", "direct", "tag", "DIRECT");
    outbounds.PushBack(direct, allocator);
    // 注释掉 REJECT 和 dns-out
    // auto reject = buildObject(allocator, "type", "block", "tag", "REJECT");
    // outbounds.PushBack(reject, allocator);
    // auto dns = buildObject(allocator, "type", "dns", "tag", "dns-out");
    // outbounds.PushBack(dns, allocator);
  }

  for (Proxy &x : nodes) {
    TargetNodeGenerationTracker generation_tracker(generation_stats, x.Type);
    std::string type = getProxyTypeName(x.Type);
    if (ext.append_proxy_type)
      x.Remark = "[" + type + "] " + x.Remark;

    processRemark(x.Remark, used_remarks, false);

    tribool udp = ext.udp, tfo = ext.tfo, scv = ext.skip_cert_verify,
            xudp = ext.xudp;
    udp.define(x.UDP);
    xudp.define(x.XUDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);

    rapidjson::Value proxy(rapidjson::kObjectType);
    switch (x.Type) {
    case ProxyType::Shadowsocks: {
      addSingBoxCommonMembers(proxy, x, "shadowsocks", allocator);
      proxy.AddMember("method", rapidjson::StringRef(x.EncryptMethod.c_str()),
                      allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      if (!x.Plugin.empty() && !x.PluginOption.empty()) {
        if (x.Plugin == "simple-obfs")
          x.Plugin = "obfs-local";
        if (x.Plugin != "obfs-local" && x.Plugin != "v2ray-plugin") {
          continue;
        }
        proxy.AddMember("plugin", rapidjson::StringRef(x.Plugin.c_str()),
                        allocator);
        proxy.AddMember("plugin_opts",
                        rapidjson::StringRef(x.PluginOption.c_str()),
                        allocator);
      }
      break;
    }
    //            case ProxyType::ShadowsocksR: {
    //                addSingBoxCommonMembers(proxy, x, "shadowsocksr",
    //                allocator); proxy.AddMember("method",
    //                rapidjson::StringRef(x.EncryptMethod.c_str()), allocator);
    //                proxy.AddMember("password",
    //                rapidjson::StringRef(x.Password.c_str()), allocator);
    //                proxy.AddMember("protocol",
    //                rapidjson::StringRef(x.Protocol.c_str()), allocator);
    //                proxy.AddMember("protocol_param",
    //                rapidjson::StringRef(x.ProtocolParam.c_str()), allocator);
    //                proxy.AddMember("obfs",
    //                rapidjson::StringRef(x.OBFS.c_str()), allocator);
    //                proxy.AddMember("obfs_param",
    //                rapidjson::StringRef(x.OBFSParam.c_str()), allocator);
    //                break;
    //            }
    case ProxyType::VMess: {
      if (!singBoxTransportSupported(x) ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none" &&
           x.PacketEncoding != "xudp"))
        continue;
      addSingBoxCommonMembers(proxy, x, "vmess", allocator);
      proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()),
                      allocator);
      proxy.AddMember("alter_id", x.AlterId, allocator);
      proxy.AddMember("security", rapidjson::StringRef(x.EncryptMethod.c_str()),
                      allocator);
      if (x.PacketEncoding == "xudp")
        proxy.AddMember("packet_encoding",
                        rapidjson::StringRef(x.PacketEncoding.c_str()),
                        allocator);

      auto transport = buildSingBoxTransport(x, allocator);
      if (!transport.ObjectEmpty())
        proxy.AddMember("transport", transport, allocator);
      break;
    }
    case ProxyType::VLESS: {
      if (!singBoxTransportSupported(x) ||
          (!x.PacketEncoding.empty() && x.PacketEncoding != "none" &&
           x.PacketEncoding != "xudp"))
        continue;
      addSingBoxCommonMembers(proxy, x, "vless", allocator);
      proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()),
                      allocator);
      const bool emit_xudp = x.PacketEncoding == "xudp" ||
                             (x.PacketEncoding.empty() && xudp && udp);
      if (emit_xudp)
        proxy.AddMember("packet_encoding", rapidjson::StringRef("xudp"),
                        allocator);
      if (!x.Flow.empty())
        proxy.AddMember("flow", rapidjson::StringRef(x.Flow.c_str()),
                        allocator);
      auto transport = buildSingBoxTransport(x, allocator);
      if (!transport.ObjectEmpty())
        proxy.AddMember("transport", transport, allocator);
      break;
    }
    case ProxyType::Trojan: {
      if (!singBoxTransportSupported(x))
        continue;
      addSingBoxCommonMembers(proxy, x, "trojan", allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);

      auto transport = buildSingBoxTransport(x, allocator);
      if (!transport.ObjectEmpty())
        proxy.AddMember("transport", transport, allocator);
      break;
    }
    case ProxyType::WireGuard: {
      if (!wireGuardStructuredConfigIsSafe(x))
        continue;
      const auto structured_peers = wireGuardPeers(x);
      wireguard_nodes_emitted++;
      wireguard_peers_emitted += structured_peers.size();
      rapidjson::Value addresses(rapidjson::kArrayType);
      for (const std::string &address : wireGuardLocalAddresses(x)) {
        const std::string prefixed = wireGuardAddressWithDefaultPrefix(address);
        addresses.PushBack(rapidjson::Value(prefixed.c_str(), allocator), allocator);
      }
      rapidjson::Value peers(rapidjson::kArrayType);
      for (const WireGuardPeer &peer : structured_peers)
        peers.PushBack(buildSingBoxWireGuardPeer(peer, wireguard_endpoint, allocator),
                       allocator);
      if (wireguard_endpoint) {
        rapidjson::Value endpoint(rapidjson::kObjectType);
        endpoint.AddMember("type", "wireguard", allocator);
        endpoint.AddMember("tag", rapidjson::Value(x.Remark.c_str(), allocator), allocator);
        if (!x.WireGuardSystem.is_undef())
          endpoint.AddMember("system", x.WireGuardSystem.get(), allocator);
        if (!x.WireGuardInterfaceName.empty())
          endpoint.AddMember("name",
                             rapidjson::Value(x.WireGuardInterfaceName.c_str(), allocator),
                             allocator);
        if (x.Mtu > 0)
          endpoint.AddMember("mtu", x.Mtu, allocator);
        endpoint.AddMember("address", addresses, allocator);
        endpoint.AddMember("private_key",
                           rapidjson::Value(x.PrivateKey.c_str(), allocator), allocator);
        if (x.WireGuardListenPort > 0)
          endpoint.AddMember("listen_port", x.WireGuardListenPort, allocator);
        endpoint.AddMember("peers", peers, allocator);
        if (x.WireGuardWorkers > 0)
          endpoint.AddMember("workers", x.WireGuardWorkers, allocator);
        endpoints.PushBack(endpoint, allocator);
        nodelist.push_back(x);
        remarks_list.emplace_back(x.Remark);
        used_remarks.emplace(x.Remark);
        generation_tracker.markEmitted();
        continue;
      }
      proxy.AddMember("type", "wireguard", allocator);
      proxy.AddMember("tag", rapidjson::Value(x.Remark.c_str(), allocator), allocator);
      proxy.AddMember("local_address", addresses, allocator);
      proxy.AddMember("private_key", rapidjson::Value(x.PrivateKey.c_str(), allocator), allocator);
      proxy.AddMember("peers", peers, allocator);
      if (!x.WireGuardSystem.is_undef())
        proxy.AddMember("system_interface", x.WireGuardSystem.get(), allocator);
      if (!x.WireGuardInterfaceName.empty())
        proxy.AddMember("interface_name",
                        rapidjson::Value(x.WireGuardInterfaceName.c_str(), allocator),
                        allocator);
      if (x.WireGuardWorkers > 0)
        proxy.AddMember("workers", x.WireGuardWorkers, allocator);
      if (x.Mtu > 0)
        proxy.AddMember("mtu", x.Mtu, allocator);
      break;
    }
    case ProxyType::HTTP:
    case ProxyType::HTTPS: {
      addSingBoxCommonMembers(proxy, x, "http", allocator);
      proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()),
                      allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      break;
    }
    case ProxyType::SOCKS5: {
      addSingBoxCommonMembers(proxy, x, "socks", allocator);
      proxy.AddMember("version", "5", allocator);
      proxy.AddMember("username", rapidjson::StringRef(x.Username.c_str()),
                      allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      break;
    }
    case ProxyType::Hysteria: {
      bool up_uses_mbps = false, down_uses_mbps = false;
      int up_mbps = 0, down_mbps = 0;
      std::string up_bandwidth, down_bandwidth, port_spec;
      if (!parseSingBoxBandwidth(x.UpMbps, up_uses_mbps, up_mbps,
                                 up_bandwidth) ||
          !parseSingBoxBandwidth(x.DownMbps, down_uses_mbps, down_mbps,
                                 down_bandwidth) ||
          (!x.FakeType.empty() && x.FakeType != "udp") ||
          (!x.TransferProtocol.empty() && x.TransferProtocol != "tcp" &&
           x.TransferProtocol != "udp") ||
          (!x.HysteriaHopInterval.empty() &&
           !regMatch(x.HysteriaHopInterval,
                     R"(^([1-9][0-9]*(?:ns|us|ms|s|m|h))+$)")) ||
          (x.Ports.empty() && x.Port == 0) ||
          (!x.Ports.empty() &&
           !singBoxHysteriaPortSpec(x, port_spec)))
        continue;
      addSingBoxCommonMembers(proxy, x, "hysteria", allocator);
      if (!x.Ports.empty()) {
        proxy.RemoveMember("server_port");
        auto server_ports = stringArrayToJsonArray(port_spec, ",", allocator);
        proxy.AddMember("server_ports", server_ports, allocator);
      }
      if (!x.HysteriaHopInterval.empty())
        proxy.AddMember(
            "hop_interval",
            rapidjson::StringRef(x.HysteriaHopInterval.c_str()), allocator);
      if (!x.AuthStr.empty())
        proxy.AddMember("auth_str",
                        rapidjson::StringRef(x.AuthStr.c_str()), allocator);
      else if (!x.Auth.empty())
        proxy.AddMember("auth", rapidjson::StringRef(x.Auth.c_str()),
                        allocator);
      if (up_uses_mbps)
        proxy.AddMember("up_mbps", up_mbps, allocator);
      else
        proxy.AddMember("up",
                        rapidjson::Value(up_bandwidth.c_str(), allocator),
                        allocator);
      if (down_uses_mbps)
        proxy.AddMember("down_mbps", down_mbps, allocator);
      else
        proxy.AddMember("down",
                        rapidjson::Value(down_bandwidth.c_str(), allocator),
                        allocator);
      rapidjson::Value tls(rapidjson::kObjectType);
      tls.AddMember("enabled", true, allocator);
      if (!x.AlpnList.empty()) {
        auto alpns = vectorToJsonArray(x.AlpnList, allocator);
        tls.AddMember("alpn", alpns, allocator);
      } else if (!x.Alpn.empty()) {
        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
        tls.AddMember("alpn", alpns, allocator);
      }
      if (!x.ServerName.empty())
        tls.AddMember("server_name",
                      rapidjson::StringRef(x.ServerName.c_str()), allocator);
      tls.AddMember("insecure", buildBooleanValue(scv), allocator);
      proxy.AddMember("tls", tls, allocator);
      if (!x.TransferProtocol.empty())
        proxy.AddMember(
            "network", rapidjson::StringRef(x.TransferProtocol.c_str()),
            allocator);
      if (!x.OBFSParam.empty())
        proxy.AddMember("obfs", rapidjson::StringRef(x.OBFSParam.c_str()),
                        allocator);
      break;
    }
    case ProxyType::Hysteria2: {
      if (!x.Hysteria2RealmUrl.empty() ||
          !x.Hysteria2GeckoMinPacketSize.empty() ||
          !x.Hysteria2GeckoMaxPacketSize.empty())
        continue;
      addSingBoxCommonMembers(proxy, x, "hysteria2", allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      if (!x.Ports.empty()) {
        const std::string port_spec = singBoxHysteria2PortSpec(x);
        proxy.RemoveMember("server_port");
        auto server_ports = stringArrayToJsonArray(port_spec, ",", allocator);
        proxy.AddMember("server_ports", server_ports, allocator);
      }
      if (!x.TLSSecure) {
        rapidjson::Value tls(rapidjson::kObjectType);
        tls.AddMember("enabled", true, allocator);
        if (!x.ServerName.empty())
          tls.AddMember("server_name",
                        rapidjson::StringRef(x.ServerName.c_str()), allocator);
        if (!x.Alpn.empty()) {
          auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
          tls.AddMember("alpn", alpns, allocator);
        }
        if (!x.PublicKey.empty()) {
          tls.AddMember("certificate",
                        rapidjson::StringRef(x.PublicKey.c_str()), allocator);
        }
        tls.AddMember("insecure", buildBooleanValue(scv), allocator);
        proxy.AddMember("tls", tls, allocator);
      }
      int bandwidth = 0;
      if (parseMbpsValue(x.UpMbps, bandwidth))
        proxy.AddMember("up_mbps", bandwidth, allocator);
      if (parseMbpsValue(x.DownMbps, bandwidth))
        proxy.AddMember("down_mbps", bandwidth, allocator);
      if (!x.OBFSParam.empty()) {
        rapidjson::Value obfs(rapidjson::kObjectType);
        obfs.AddMember("type", rapidjson::StringRef(x.OBFSParam.c_str()),
                       allocator);
        if (!x.OBFSPassword.empty()) {
          obfs.AddMember("password",
                         rapidjson::StringRef(x.OBFSPassword.c_str()),
                         allocator);
        }
        proxy.AddMember("obfs", obfs, allocator);
      }
      break;
    }
    case ProxyType::TUIC: {
      // sing-box implements TUIC v5, whose share links carry UUID/password.
      // TUIC v4 token links remain available to clients such as Surge but
      // cannot be represented by this outbound schema.
      if (x.UserId.empty() || x.Password.empty())
        continue;
      addSingBoxCommonMembers(proxy, x, "tuic", allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()),
                      allocator);
      if (!x.TLSSecure) {
        rapidjson::Value tls(rapidjson::kObjectType);
        tls.AddMember("enabled", true, allocator);
        if (!scv.is_undef()) {
          tls.AddMember("insecure", buildBooleanValue(scv), allocator);
        }
        if (!x.ServerName.empty())
          tls.AddMember("server_name",
                        rapidjson::StringRef(x.ServerName.c_str()), allocator);
        if (!x.Alpn.empty()) {
          auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
          tls.AddMember("alpn", alpns, allocator);
        }
        if (!x.DisableSni.is_undef()) {
          tls.AddMember("disable_sni", buildBooleanValue(x.DisableSni),
                        allocator);
        }
        proxy.AddMember("tls", tls, allocator);
      }
      if (!x.CongestionControl.empty()) {
        proxy.AddMember("congestion_control",
                        rapidjson::StringRef(x.CongestionControl.c_str()),
                        allocator);
      }
      if (!x.UdpRelayMode.empty()) {
        proxy.AddMember("udp_relay_mode",
                        rapidjson::StringRef(x.UdpRelayMode.c_str()),
                        allocator);
      }
      if (!x.ReduceRtt.is_undef()) {
        proxy.AddMember("zero_rtt_handshake", buildBooleanValue(x.ReduceRtt),
                        allocator);
      }
      break;
    }
    case ProxyType::AnyTLS: {
      addSingBoxCommonMembers(proxy, x, "anytls", allocator);
      proxy.AddMember("password", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      if (x.IdleSessionCheckInterval != 30) {
        const std::string value =
            std::to_string(x.IdleSessionCheckInterval) + "s";
        proxy.AddMember("idle_session_check_interval",
                        rapidjson::Value(value.c_str(), allocator), allocator);
      }
      if (x.IdleSessionTimeout != 30) {
        const std::string value = std::to_string(x.IdleSessionTimeout) + "s";
        proxy.AddMember("idle_session_timeout",
                        rapidjson::Value(value.c_str(), allocator), allocator);
      }
      if (x.MinIdleSession != 0)
        proxy.AddMember("min_idle_session", x.MinIdleSession, allocator);
      rapidjson::Value tls(rapidjson::kObjectType);
      tls.AddMember("enabled", true, allocator);
      if (!scv.is_undef()) {
        tls.AddMember("insecure", buildBooleanValue(scv), allocator);
      }
      if (!x.SNI.empty())
        tls.AddMember("server_name", rapidjson::StringRef(x.SNI.c_str()),
                      allocator);
      if (!x.AlpnList.empty()) {
        auto alpns = vectorToJsonArray(x.AlpnList, allocator);
        tls.AddMember("alpn", alpns, allocator);
      }
      if (!x.Fingerprint.empty()) {
        rapidjson::Value utls(rapidjson::kObjectType);
        utls.AddMember("enabled", true, allocator);
        utls.AddMember("fingerprint",
                       rapidjson::StringRef(x.Fingerprint.c_str()), allocator);
        tls.AddMember("utls", utls, allocator);
      }
      proxy.AddMember("tls", tls, allocator);
      break;
    }
    case ProxyType::Snell: {
      snell_nodes_input++;
      if (!snell_outbound || x.Password.empty() || x.Hostname.empty() ||
          x.Port == 0 || x.SnellUDPPort != 0 ||
          !x.ShadowTLSPassword.empty() || !x.ShadowTLSSNI.empty() ||
          x.ShadowTLSVersion != 0 || !x.Path.empty() ||
          !x.UnderlyingProxy.empty() || !x.TransferProtocol.empty() ||
          !x.TLSStr.empty() || x.TLSSecure || !x.PublicKey.empty() ||
          !x.PrivateKey.empty() || !x.PreSharedKey.empty() ||
          !x.ServerName.empty() || !x.SNI.empty() ||
          !x.Fingerprint.empty() || !x.Alpn.empty() ||
          !x.AlpnList.empty() || x.SnellUserKey.size() > 255 ||
          (!x.SnellNetwork.empty() && x.SnellNetwork != "tcp" &&
           x.SnellNetwork != "udp"))
        continue;

      const bool normalize_v5 = x.SnellVersion == 5;
      uint16_t output_version = normalize_v5 ? 4 : x.SnellVersion;
      if (output_version != 4 && output_version != 6)
        continue;

      if (output_version == 4) {
        if (!x.SnellMode.empty() ||
            (!x.OBFS.empty() && x.OBFS != "none" && x.OBFS != "http") ||
            (!x.Host.empty() && x.OBFS != "http") ||
            !x.OBFSParam.empty())
          continue;
      } else if (x.Password.size() < 12 || x.Password.size() > 255 ||
                 !x.OBFS.empty() || !x.OBFSParam.empty() ||
                 !x.Host.empty() ||
                 (!x.SnellMode.empty() && x.SnellMode != "default" &&
                  x.SnellMode != "unshaped" &&
                  x.SnellMode != "unsafe-raw")) {
        continue;
      }

      addSingBoxCommonMembers(proxy, x, "snell", allocator);
      proxy.AddMember("version", output_version, allocator);
      proxy.AddMember("psk", rapidjson::StringRef(x.Password.c_str()),
                      allocator);
      if (!x.SnellUserKey.empty())
        proxy.AddMember("userkey",
                        rapidjson::StringRef(x.SnellUserKey.c_str()),
                        allocator);
      if (!x.SnellReuse.is_undef())
        proxy.AddMember("reuse", buildBooleanValue(x.SnellReuse), allocator);

      std::string network;
      if (!ext.udp.is_undef())
        network = ext.udp ? std::string() : "tcp";
      else if (!x.SnellNetwork.empty())
        network = x.SnellNetwork;
      else if (!x.UDP.is_undef() && !x.UDP)
        network = "tcp";
      if (!network.empty())
        proxy.AddMember("network", rapidjson::Value(network.c_str(), allocator),
                        allocator);

      if (output_version == 4 && x.OBFS == "http") {
        proxy.AddMember("obfs_mode", "http", allocator);
        if (!x.Host.empty())
          proxy.AddMember("obfs_host",
                          rapidjson::StringRef(x.Host.c_str()), allocator);
      }
      if (output_version == 6 && !x.SnellMode.empty())
        proxy.AddMember("mode", rapidjson::StringRef(x.SnellMode.c_str()),
                        allocator);
      if (normalize_v5)
        snell_v5_normalized++;
      snell_nodes_emitted++;
      break;
    }
    default:
      continue;
    }
    // Hysteria v1 builds its mandatory TLS object in the protocol-specific
    // branch above. Adding the generic object as well would serialize a
    // duplicate `tls` key, leaving precedence up to the JSON consumer.
    if (x.TLSSecure && x.Type != ProxyType::Hysteria &&
        x.Type != ProxyType::Snell) {
      rapidjson::Value tls(rapidjson::kObjectType);
      tls.AddMember("enabled", true, allocator);
      if (!x.ServerName.empty())
        tls.AddMember("server_name", rapidjson::StringRef(x.ServerName.c_str()),
                      allocator);
      if (!x.AlpnList.empty()) {
        auto alpns = vectorToJsonArray(x.AlpnList, allocator);
        tls.AddMember("alpn", alpns, allocator);
      } else if (!x.Alpn.empty()) {
        auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
        tls.AddMember("alpn", alpns, allocator);
      }
      tls.AddMember("insecure", buildBooleanValue(scv), allocator);
      const bool has_reality = !x.PublicKey.empty() || !x.ShortId.empty();
      if (!x.Fingerprint.empty() && !has_reality) {
        rapidjson::Value utls(rapidjson::kObjectType);
        utls.AddMember("enabled", true, allocator);
        utls.AddMember("fingerprint",
                       rapidjson::StringRef(x.Fingerprint.c_str()), allocator);
        tls.AddMember("utls", utls, allocator);
      }
      if (has_reality) {
        rapidjson::Value reality(rapidjson::kObjectType);
        rapidjson::Value utls(rapidjson::kObjectType);
        utls.AddMember("enabled", true, allocator);
        utls.AddMember(
            "fingerprint",
            rapidjson::StringRef(x.Fingerprint.empty() ? "chrome"
                                                       : x.Fingerprint.c_str()),
            allocator);
        tls.AddMember("utls", utls, allocator);
        reality.AddMember("enabled", true, allocator);
        if (!x.PublicKey.empty()) {
          reality.AddMember("public_key",
                            rapidjson::StringRef(x.PublicKey.c_str()),
                            allocator);
        }
        reality.AddMember("short_id",
                          rapidjson::StringRef(x.ShortId.c_str()), allocator);
        tls.AddMember("reality", reality, allocator);
      }
      proxy.AddMember("tls", tls, allocator);
    }
    // AnyTLS is TCP-only and its sing-box outbound schema has no `network`
    // field. Other supported outbounds use this field to apply a TCP-only
    // override when UDP is disabled globally.
    if (!udp.is_undef() && !udp && x.Type != ProxyType::AnyTLS &&
        x.Type != ProxyType::Snell &&
        !(x.Type == ProxyType::Hysteria &&
          !x.TransferProtocol.empty())) {
      proxy.AddMember("network", "tcp", allocator);
    }
    if (!tfo.is_undef() && x.Type != ProxyType::AnyTLS) {
      proxy.AddMember("tcp_fast_open", buildBooleanValue(tfo), allocator);
    }
    nodelist.push_back(x);
    remarks_list.emplace_back(x.Remark);
    used_remarks.emplace(x.Remark);
    outbounds.PushBack(proxy, allocator);
    generation_tracker.markEmitted();
  }

  if (wireguard_nodes_emitted > 0) {
    writeLog(LOG_LEVEL_INFO,
             "SINGBOX_WIREGUARD_GENERATION schema=" +
                 std::string(wireguard_endpoint ? "endpoint" : "outbound") +
                 " nodes=" + std::to_string(wireguard_nodes_emitted) +
                 " peers=" + std::to_string(wireguard_peers_emitted));
  }

  if (snell_nodes_input > 0) {
    writeLog(LOG_LEVEL_INFO,
             "SINGBOX_SNELL_GENERATION enabled=" +
                 std::string(snell_outbound ? "true" : "false") +
                 " input=" + std::to_string(snell_nodes_input) +
                 " emitted=" + std::to_string(snell_nodes_emitted) +
                 " normalized_v5=" + std::to_string(snell_v5_normalized) +
                 " minimum_version=" +
                 std::string(snell_nodes_emitted > 0 ? "1.14.0" : "none"));
  }

  if (ext.nodelist) {
    json | AddMemberOrReplace("outbounds", outbounds, allocator);
    if (wireguard_endpoint)
      json | AddMemberOrReplace("endpoints", endpoints, allocator);
    return;
  }

  for (const ProxyGroupConfig &x : extra_proxy_group) {
    string_array filtered_nodelist;
    std::string type;
    switch (x.Type) {
    case ProxyGroupType::Select: {
      type = "selector";
      break;
    }
    case ProxyGroupType::URLTest:
    case ProxyGroupType::Fallback:
    case ProxyGroupType::LoadBalance: {
      type = "urltest";
      break;
    }
    default:
      continue;
    }
    for (const auto &y : x.Proxies)
      groupGenerate(y, nodelist, filtered_nodelist, true, ext);

    if (filtered_nodelist.empty())
      filtered_nodelist.emplace_back("DIRECT");

    rapidjson::Value group(rapidjson::kObjectType);

    group.AddMember("type", rapidjson::Value(type.c_str(), allocator),
                    allocator);
    group.AddMember("tag", rapidjson::Value(x.Name.c_str(), allocator),
                    allocator);

    rapidjson::Value group_outbounds(rapidjson::kArrayType);
    for (const std::string &y : filtered_nodelist) {
      group_outbounds.PushBack(rapidjson::Value(y.c_str(), allocator),
                               allocator);
    }
    group.AddMember("outbounds", group_outbounds, allocator);

    if (x.Type == ProxyGroupType::URLTest) {
      group.AddMember("url", rapidjson::Value(x.Url.c_str(), allocator),
                      allocator);
      group.AddMember("interval",
                      rapidjson::Value(
                          formatSingBoxInterval(x.Interval).c_str(), allocator),
                      allocator);
      if (x.Tolerance > 0)
        group.AddMember("tolerance", x.Tolerance, allocator);
    }
    outbounds.PushBack(group, allocator);
  }

  if (add_clash_modes) {
    auto global_group = rapidjson::Value(rapidjson::kObjectType);
    global_group.AddMember("type", "selector", allocator);
    global_group.AddMember("tag", "GLOBAL", allocator);
    global_group.AddMember("outbounds", rapidjson::Value(rapidjson::kArrayType),
                           allocator);
    global_group["outbounds"].PushBack("DIRECT", allocator);
    for (auto &x : remarks_list) {
      global_group["outbounds"].PushBack(rapidjson::Value(x.c_str(), allocator),
                                         allocator);
    }
    outbounds.PushBack(global_group, allocator);
  }

  json | AddMemberOrReplace("outbounds", outbounds, allocator);
  if (wireguard_endpoint)
    json | AddMemberOrReplace("endpoints", endpoints, allocator);
}

std::string proxyToSingBox(std::vector<Proxy> &nodes,
                           const std::string &base_conf,
                           std::vector<RulesetContent> &ruleset_content_array,
                           const ProxyGroupConfigs &extra_proxy_group,
                           extra_settings &ext) {
  ext.target_generation_stats = TargetGenerationStats{};
  ext.target_generation_stats.input_nodes = nodes.size();
  using namespace rapidjson_ext;
  rapidjson::Document json;

  if (!ext.nodelist) {
    json.Parse(base_conf.data());
    if (json.HasParseError()) {
      writeLog(LOG_LEVEL_ERROR,
          "sing-box 基础配置加载失败：" +
              std::string(rapidjson::GetParseError_En(json.GetParseError())));
      return "";
    }
  } else {
    json.SetObject();
  }

  proxyToSingBox(nodes, json, ruleset_content_array, extra_proxy_group, ext);

  if (ext.nodelist || !ext.enable_rule_generator)
    return json | SerializeObject();

  rulesetToSingBox(json, ruleset_content_array, ext.overwrite_original_rules,
                   ext.rule_stats);

  return json | SerializeObject();
}
