#include <algorithm>
#include <climits>
#include <cmath>
#include <iostream>
#include <numeric>
#include <string_view>
#include <unordered_set>

#include "config/regmatch.h"
#include "external_rules.h"
#include "generator/config/clash_proxy.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "handler/settings.h"
#include "handler/settings_view.h"
#include "nodemanip.h"
#include "parser/config/proxy.h"
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

static bool surgeProxyScalarIsSafe(const std::string &value) {
  return value.find_first_of(",\r\n") == std::string::npos;
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

static void appendShareQuery(std::vector<std::string> &query,
                             const std::string &key,
                             const std::string &value) {
  if (!value.empty())
    query.emplace_back(key + "=" + urlEncode(value));
}

static std::string joinShareQuery(const std::vector<std::string> &query) {
  return query.empty() ? std::string() : "?" + join(query, "&");
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
  writer.String((proxy.TransferProtocol == "quic" ? proxy.QUICSecret
                                                    : proxy.Path)
                    .data());
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
      {ProxyType::Hysteria, "HYSTERIA"},   {ProxyType::Hysteria2, "HYSTERIA2"}};
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
  std::string real_rule;
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
    std::unordered_set<std::string> seen(filtered_nodelist.begin(),
                                         filtered_nodelist.end());
    for (Proxy &x : nodelist) {
      if (applyMatcher(rule, real_rule, x) &&
          (real_rule.empty() || regFind(x.Remark, real_rule)) &&
          seen.insert(x.Remark).second)
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
      if (x.SnellVersion >= 4)
        continue;
      singleproxy["type"] = "snell";
      singleproxy["psk"] = x.Password;
      if (x.SnellVersion != 0)
        singleproxy["version"] = x.SnellVersion;
      if (!x.OBFS.empty()) {
        singleproxy["obfs-opts"]["mode"] = x.OBFS;
        if (!x.Host.empty())
          singleproxy["obfs-opts"]["host"] = x.Host;
      }
      if (std::all_of(x.Password.begin(), x.Password.end(), ::isdigit) &&
          !x.Password.empty())
        singleproxy["password"].SetTag("str");
      break;
    case ProxyType::WireGuard:
      singleproxy["type"] = "wireguard";
      singleproxy["public-key"] = x.PublicKey;
      singleproxy["private-key"] = x.PrivateKey;
      singleproxy["ip"] = x.SelfIP;
      if (!x.SelfIPv6.empty())
        singleproxy["ipv6"] = x.SelfIPv6;
      if (!x.PreSharedKey.empty())
        singleproxy["preshared-key"] = x.PreSharedKey;
      if (!x.DnsServers.empty())
        singleproxy["dns"] = x.DnsServers;
      if (x.Mtu > 0)
        singleproxy["mtu"] = x.Mtu;
      break;
    case ProxyType::Hysteria:
      singleproxy["type"] = "hysteria";
      singleproxy["auth_str"] = x.Auth;
      singleproxy["auth-str"] = x.Auth;
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
      if (!x.Alpn.empty())
        singleproxy["alpn"].push_back(x.Alpn);
      if (!x.OBFSParam.empty())
        singleproxy["obfs"] = x.OBFSParam;
      break;
    case ProxyType::Hysteria2:
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
      bool has_groupid_provider_match = false;
      YAML::Node groupid_use_node(YAML::NodeType::Sequence);

      for (const auto &proxy : x.Proxies) {
        // 如果不是以 [] 开头，则认为是正则表达式
        if (isProviderRegexRule(proxy)) {
          std::string groupid_target, groupid_filter;
          if (parseProviderGroupIdMatcher(proxy, groupid_target,
                                          groupid_filter)) {
            YAML::Node matched_providers =
                providersMatchingGroupId(groupid_target, ext.providers);
            if (matched_providers.size() > 0) {
              has_groupid_provider_match = true;
              groupid_use_node = matched_providers;
              regex_pattern = groupid_filter;
              has_regex = !regex_pattern.empty();
              break;
            }
          }

          has_regex = true;
          regex_pattern = proxy;
          break; // 找到第一个正则就够了
        }
      }

      if (has_groupid_provider_match) {
        singlegroup["use"] = groupid_use_node;
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
std::string generatePeer(Proxy &node, bool client_id_as_reserved = false) {
  std::string result;
  result += "public-key = " + node.PublicKey;
  result += ", endpoint = " + node.Hostname + ":" + std::to_string(node.Port);
  if (!node.AllowedIPs.empty())
    result += ", allowed-ips = \"" + node.AllowedIPs + "\"";
  if (!node.ClientId.empty()) {
    if (client_id_as_reserved)
      result += ", reserved = [" + node.ClientId + "]";
    else
      result += ", client-id = " + node.ClientId;
  }
  return result;
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
  TargetGenerationStats &generation_stats =
      surfboard ? ext.surfboard_generation_stats
                : ext.surge_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();

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
    case ProxyType::Snell:
      proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
      if (!obfs.empty()) {
        proxy += ", obfs=" + obfs;
        if (!host.empty())
          proxy += ", obfs-host=" + host;
      }
      if (x.SnellVersion != 0)
        proxy += ", version=" + std::to_string(x.SnellVersion);
      break;
    case ProxyType::Hysteria2:
      if (surge_ver < 4 || !surgeProxyScalarIsSafe(hostname) ||
          !surgeProxyScalarIsSafe(password) ||
          !surgeProxyScalarIsSafe(x.ServerName) ||
          !surgeProxyScalarIsSafe(x.Fingerprint) ||
          !surgeProxyScalarIsSafe(x.OBFSPassword) ||
          !surgeProxyScalarIsSafe(x.Alpn)) {
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
      section = randomStr(5);
      real_section = "WireGuard " + section;
      proxy = "wireguard, section-name=" + section;
      if (!x.TestUrl.empty())
        proxy += ", test-url=" + x.TestUrl;
      ini.set(real_section, "private-key", x.PrivateKey);
      ini.set(real_section, "self-ip", x.SelfIP);
      if (!x.SelfIPv6.empty())
        ini.set(real_section, "self-ip-v6", x.SelfIPv6);
      if (!x.PreSharedKey.empty())
        ini.set(real_section, "preshared-key", x.PreSharedKey);
      if (!x.DnsServers.empty())
        ini.set(real_section, "dns-server", join(x.DnsServers, ","));
      if (x.Mtu > 0)
        ini.set(real_section, "mtu", std::to_string(x.Mtu));
      if (x.KeepAlive > 0)
        ini.set(real_section, "keepalive", std::to_string(x.KeepAlive));
      ini.set(real_section, "peer", "(" + generatePeer(x) + ")");
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

std::string proxyToSingle(std::vector<Proxy> &nodes, SingleLinkTypes types,
                           extra_settings &ext) {
  std::string proxyStr, allLinks;
  const bool ss = (types & SingleLinkType::Shadowsocks) != 0;
  const bool ssr = (types & SingleLinkType::ShadowsocksR) != 0;
  const bool vmess = (types & SingleLinkType::VMess) != 0;
  const bool trojan = (types & SingleLinkType::Trojan) != 0;
  const bool hysteria2 = (types & SingleLinkType::Hysteria2) != 0;
  const bool vless = (types & SingleLinkType::VLESS) != 0;

  for (Proxy &x : nodes) {
    std::string remark = x.Remark;
    std::string &hostname = x.Hostname, &sni = x.ServerName,
                &password = x.Password, &method = x.EncryptMethod,
                &plugin = x.Plugin, &pluginopts = x.PluginOption,
                &protocol = x.Protocol, &protoparam = x.ProtocolParam,
                &flow = x.Flow, &pbk = x.PublicKey, &sid = x.ShortId,
                &fp = x.Fingerprint, &packet_encoding = x.PacketEncoding,
                &fake_type = x.FakeType, &mode = x.GRPCMode, &obfs = x.OBFS,
                &obfsparam = x.OBFSParam, &obfsPassword = x.OBFSPassword,
                &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &tls = x.TLSStr, &path = x.Path;
    std::vector<string> alpns = x.AlpnList;
    std::string port = std::to_string(x.Port);
    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (ss) {
        proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) +
                   "@" + hostname + ":" + port;
        if (!plugin.empty() && !pluginopts.empty()) {
          proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
        }
        proxyStr += "#" + urlEncode(remark);
      } else if (ssr) {
        if (std::find(ssr_ciphers.begin(), ssr_ciphers.end(), method) !=
                ssr_ciphers.end() &&
            plugin.empty())
          proxyStr =
              "ssr://" +
              urlSafeBase64Encode(hostname + ":" + port + ":origin:" + method +
                                  ":plain:" + urlSafeBase64Encode(password) +
                                  "/?group=" + urlSafeBase64Encode(x.Group) +
                                  "&remarks=" + urlSafeBase64Encode(remark));
      } else
        continue;
      break;
    case ProxyType::ShadowsocksR:
      if (ssr) {
        proxyStr = "ssr://" +
                   urlSafeBase64Encode(
                       hostname + ":" + port + ":" + protocol + ":" + method +
                       ":" + obfs + ":" + urlSafeBase64Encode(password) +
                       "/?group=" + urlSafeBase64Encode(x.Group) +
                       "&remarks=" + urlSafeBase64Encode(remark) +
                       "&obfsparam=" + urlSafeBase64Encode(obfsparam) +
                       "&protoparam=" + urlSafeBase64Encode(protoparam));
      } else if (ss) {
        if (std::find(ss_ciphers.begin(), ss_ciphers.end(), method) !=
                ss_ciphers.end() &&
            protocol == "origin" && obfs == "plain")
          proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) +
                     "@" + hostname + ":" + port + "#" + urlEncode(remark);
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
        const std::string port_spec = hysteria2PortSpec(x);
        proxyStr = "hysteria2://" +
                   (password.empty() ? std::string()
                                     : urlEncode(password) + "@") +
                   shareLinkHost(hostname) + ":" + port_spec + "/" +
                   joinShareQuery(query) + "#" + urlEncode(remark);
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
  }

  if (ext.nodelist)
    return allLinks;
  return base64Encode(allLinks);
}

std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes,
                         extra_settings &ext) {
  using namespace rapidjson_ext;
  rapidjson::Document base;

  auto &alloc = base.GetAllocator();

  base_conf = trimWhitespace(base_conf);
  if (base_conf.empty())
    base_conf = "{}";
  rapidjson::ParseResult result = base.Parse(base_conf.data());
  if (!result)
    writeLog(LOG_LEVEL_ERROR,
             std::string("SIP008 基础配置加载失败：") +
                 rapidjson::GetParseError_En(result.Code()) + " (" +
                 std::to_string(result.Offset()) + ")");

  rapidjson::Value proxies(rapidjson::kArrayType);
  for (Proxy &x : nodes) {
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
  }
  return proxies | SerializeObject();
}

std::string proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext) {
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
  std::string proxyStr;
  std::vector<Proxy> nodelist;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("SERVER");
  ini.erase_section();
  for (Proxy &x : nodes) {
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
        proxyStr = "ssr://" +
                   urlSafeBase64Encode(
                       hostname + ":" + port + ":" + protocol + ":" + method +
                       ":" + obfs + ":" + urlSafeBase64Encode(password) +
                       "/?group=" + urlSafeBase64Encode(x.Group) +
                       "&remarks=" + urlSafeBase64Encode(x.Remark) +
                       "&obfsparam=" + urlSafeBase64Encode(obfsparam) +
                       "&protoparam=" + urlSafeBase64Encode(protoparam));
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
        proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) +
                   "@" + hostname + ":" + port;
        if (!plugin.empty() && !pluginopts.empty()) {
          proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
        }
        proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" +
                    urlEncode(x.Remark);
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
  std::string proxyStr;
  tribool udp, tfo, scv, tls13;
  std::vector<Proxy> nodelist;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("server_local");
  ini.erase_section();
  for (Proxy &x : nodes) {
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, &method = x.EncryptMethod,
                &id = x.UserId, &transproto = x.TransferProtocol,
                &host = x.Host, &path = x.Path, &password = x.Password,
                &plugin = x.Plugin, &pluginopts = x.PluginOption,
                &protocol = x.Protocol, &protoparam = x.ProtocolParam,
                &obfs = x.OBFS, &obfsparam = x.OBFSParam,
                &username = x.Username;
    std::string port = std::to_string(x.Port);
    bool &tlssecure = x.TLSSecure;

    udp = ext.udp;
    tfo = ext.tfo;
    scv = ext.skip_cert_verify;
    tls13 = ext.tls13;
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);
    tls13.define(x.TLS13);

    switch (x.Type) {
    case ProxyType::VMess:
      if (method == "auto")
        method = "chacha20-ietf-poly1305";
      proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method +
                 ", password=" + id;
      if (x.AlterId != 0)
        proxyStr += ", aead=false";
      if (tlssecure && !tls13.is_undef())
        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
      if (transproto == "ws") {
        if (tlssecure)
          proxyStr += ", obfs=wss";
        else
          proxyStr += ", obfs=ws";
        proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
      } else if (tlssecure)
        proxyStr += ", obfs=over-tls, obfs-host=" + host;
      break;
    case ProxyType::VLESS:
      if (method == "auto")
        method = "none";
      else
        method = "none";
      proxyStr = "vless = " + hostname + ":" + port + ", method=" + method +
                 ", password=" + id;
      if (x.AlterId != 0)
        proxyStr += ", aead=false";
      if (tlssecure && !tls13.is_undef())
        proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
      if (transproto == "ws") {
        if (tlssecure)
          proxyStr += ", obfs=wss";
        else
          proxyStr += ", obfs=ws";
        proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
      } else if (tlssecure)
        proxyStr += ", obfs=over-tls, obfs-host=" + host;
      break;
    case ProxyType::Shadowsocks:
      proxyStr = "shadowsocks = " + hostname + ":" + port +
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
      proxyStr = "shadowsocks = " + hostname + ":" + port +
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
      proxyStr = "http = " + hostname + ":" + port +
                 ", username=" + (username.empty() ? "none" : username) +
                 ", password=" + (password.empty() ? "none" : password);
      if (tlssecure) {
        proxyStr += ", over-tls=true";
        if (!tls13.is_undef())
          proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
      } else {
        proxyStr += ", over-tls=false";
      }
      break;
    case ProxyType::Trojan:
      proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
      if (tlssecure) {
        proxyStr += ", over-tls=true, tls-host=" + host;
        if (!tls13.is_undef())
          proxyStr += ", tls13=" + std::string(tls13 ? "true" : "false");
      } else {
        proxyStr += ", over-tls=false";
      }
      break;
    case ProxyType::SOCKS5:
      proxyStr = "socks5 = " + hostname + ":" + port;
      if (!username.empty() && !password.empty()) {
        proxyStr += ", username=" + username + ", password=" + password;
        if (tlssecure) {
          proxyStr += ", over-tls=true, tls-host=" + host;
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
    if (!tfo.is_undef())
      proxyStr += ", fast-open=" + tfo.get_str();
    if (!udp.is_undef())
      proxyStr += ", udp-relay=" + udp.get_str();
    if (tlssecure && !scv.is_undef() &&
        (x.Type != ProxyType::Shadowsocks &&
         x.Type != ProxyType::ShadowsocksR && x.Type != ProxyType::VLESS))
      proxyStr += ", tls-verification=" + scv.reverse().get_str();
    proxyStr += ", tag=" + x.Remark;

    ini.set("{NONAME}", proxyStr);
    used_remarks.emplace(x.Remark);
    nodelist.emplace_back(x);
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
  std::string proxy;
  std::string username, password, method;
  std::string plugin, pluginopts;
  std::string id, aid, transproto, faketype, host, path, quicsecure, quicsecret,
      tlssecure;
  std::string url;
  tribool tfo, scv;
  std::vector<Proxy> nodelist;
  string_array vArray, remarks_list;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());

  ini.set_current_section("Endpoint");

  for (Proxy &x : nodes) {
    if (ext.append_proxy_type) {
      std::string type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }

    processRemark(x.Remark, used_remarks);

    std::string &hostname = x.Hostname, port = std::to_string(x.Port);

    tfo = ext.tfo;
    scv = ext.skip_cert_verify;
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);

    switch (x.Type) {
    case ProxyType::Shadowsocks:
      if (!x.Plugin.empty())
        continue;
      proxy = x.Remark + ", ss, ss://" +
              urlSafeBase64Encode(method + ":" + password) + "@" + hostname +
              ":" + port;
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
      proxy = x.Remark + ", builtin, socks, address=" + hostname +
              ", port=" + port + ", user=" + username + ", pass=" + password;
      break;
    case ProxyType::HTTP:
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
  TargetGenerationStats &generation_stats = ext.loon_generation_stats;
  generation_stats = TargetGenerationStats{};
  generation_stats.input_nodes = nodes.size();

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

    tribool scv = ext.skip_cert_verify;
    scv.define(x.AllowInsecure);
    tribool udp = x.UDP.is_undef() ? ext.udp.is_undef() ? false : ext.udp.get()
                                   : x.UDP.get();
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
      if (method == "auto")
        method = "chacha20-ietf-poly1305";

      proxy = "vmess," + hostname + "," + port + "," + method + ",\"" + id +
              "\",over-tls=" + (tlssecure ? "true" : "false");
      if (tlssecure)
        proxy += ",tls-name=" + host;
      switch (hash_(transproto)) {
      case "tcp"_hash:
        proxy += ",transport=tcp";
        break;
      case "ws"_hash:
        proxy += ",transport=ws,path=" + path + ",host=" + host;
        break;
      default:
        generation_stats.unsupported_by_type[x.Type]++;
        continue;
      }
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    case ProxyType::VLESS:
      if (flow != "xtls-rprx-vision") {
        if (transproto == "ws") {
          proxy = "VLESS," + hostname + "," + port + ",\"" + id + "\"" +
                  ",path=" + path + ",host=" + host +
                  ",transport=" + transproto +
                  ",udp=" + (udp.get() ? "true" : "false") +
                  ",over-tls=" + (tlssecure ? "true" : "false") + ",sni=" + sni;
        } else {
          generation_stats.unsupported_by_type[x.Type]++;
          continue;
        }
      } else {
        proxy = "VLESS," + hostname + "," + port + ",\"" + id +
                "\",flow=" + flow + ",public-key=\"" + pk +
                "\",short-id=" + shortId +
                ",udp=" + (udp.get() ? "true" : "false") +
                ",over-tls=" + (tlssecure ? "true" : "false") + ",sni=" + sni;
      }

      switch (hash_(transproto)) {
      case "tcp"_hash:
        proxy += ",transport=tcp";
        break;
      default:
        if (transproto != "ws") {
          generation_stats.unsupported_by_type[x.Type]++;
          continue;
        } else {
          break;
          ;
        }
      }
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
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
      proxy = "trojan," + hostname + "," + port + ",\"" + password + "\"";
      if (!host.empty())
        proxy += ",tls-name=" + host;
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
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
      proxy = "wireguard, interface-ip=" + x.SelfIP;
      if (!x.SelfIPv6.empty())
        proxy += ", interface-ipv6=" + x.SelfIPv6;
      proxy += ", private-key=" + x.PrivateKey;
      for (const auto &y : x.DnsServers) {
        if (isIPv4(y))
          proxy += ", dns=" + y;
        else if (isIPv6(y))
          proxy += ", dnsv6=" + y;
      }
      if (x.Mtu > 0)
        proxy += ", mtu=" + std::to_string(x.Mtu);
      if (x.KeepAlive > 0)
        proxy += ", keepalive=" + std::to_string(x.KeepAlive);
      proxy += ", peers=[{" + generatePeer(x, true) + "}]";
      break;
    case ProxyType::Hysteria2:
      proxy = "Hysteria2," + hostname + "," + port + ",\"" + password + "\"";
      if (!x.ServerName.empty()) {
        proxy += ",sni=" + x.ServerName;
      }
      if (!x.UpMbps.empty()) {
        std::string search = " Mbps";
        size_t pos = x.UpMbps.find(search);
        if (pos != std::string::npos) {
          x.UpMbps.replace(pos, search.length(), "");
        } else {
          search = "Mbps";
          pos = x.UpMbps.find(search);
          if (pos != std::string::npos) {
            x.UpMbps.replace(pos, search.length(), "");
          }
        }
        proxy += ",download-bandwidth=" + x.UpMbps;
      } else {
        proxy += ",download-bandwidth=100";
      }
      if (!scv.is_undef())
        proxy +=
            ",skip-cert-verify=" + std::string(scv.get() ? "true" : "false");
      break;
    default:
      generation_stats.unsupported_by_type[x.Type]++;
      continue;
    }

    if (ext.tfo) {
      proxy += ",fast-open=true";
    } else {
      if (x.Type == ProxyType::Hysteria2) {
        proxy += ",fast-open=false";
      }
    }
    if (ext.udp) {
      proxy += ",udp=true";
    } else {
      if (x.Type == ProxyType::Hysteria2) {
        proxy += ",udp=true";
      }
    }

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
      if (startsWith(toLower(rule), "http://") ||
          startsWith(toLower(rule), "https://"))
        continue;
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

void proxyToSingBox(std::vector<Proxy> &nodes, rapidjson::Document &json,
                    std::vector<RulesetContent> &ruleset_content_array,
                    const ProxyGroupConfigs &extra_proxy_group,
                    extra_settings &ext) {
  const bool add_clash_modes = effectiveSettings().singBoxAddClashModes;
  using namespace rapidjson_ext;
  rapidjson::Document::AllocatorType &allocator = json.GetAllocator();
  rapidjson::Value outbounds(rapidjson::kArrayType),
      route(rapidjson::kArrayType);
  std::vector<Proxy> nodelist;
  string_array remarks_list;
  RemarkSet used_remarks;
  used_remarks.reserve(nodes.size());
  std::string search = " Mbps";

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
      if (!singBoxTransportSupported(x))
        continue;
      addSingBoxCommonMembers(proxy, x, "vmess", allocator);
      proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()),
                      allocator);
      proxy.AddMember("alter_id", x.AlterId, allocator);
      proxy.AddMember("security", rapidjson::StringRef(x.EncryptMethod.c_str()),
                      allocator);

      auto transport = buildSingBoxTransport(x, allocator);
      if (!transport.ObjectEmpty())
        proxy.AddMember("transport", transport, allocator);
      break;
    }
    case ProxyType::VLESS: {
      if (!singBoxTransportSupported(x))
        continue;
      addSingBoxCommonMembers(proxy, x, "vless", allocator);
      proxy.AddMember("uuid", rapidjson::StringRef(x.UserId.c_str()),
                      allocator);
      if (xudp && udp)
        proxy.AddMember("packet_encoding", rapidjson::StringRef("xudp"),
                        allocator);
      if (!x.Flow.empty())
        proxy.AddMember("flow", rapidjson::StringRef(x.Flow.c_str()),
                        allocator);
      if (!x.PacketEncoding.empty()) {
        proxy.AddMember("packet_encoding",
                        rapidjson::StringRef(x.PacketEncoding.c_str()),
                        allocator);
      }
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
      proxy.AddMember("type", "wireguard", allocator);
      proxy.AddMember("tag", rapidjson::StringRef(x.Remark.c_str()), allocator);
      proxy.AddMember("inet4_bind_address",
                      rapidjson::StringRef(x.SelfIP.c_str()), allocator);
      rapidjson::Value addresses(rapidjson::kArrayType);
      std::string local_address = x.SelfIP + "/32";
      addresses.PushBack(rapidjson::Value(local_address.c_str(), allocator),
                         allocator);
      //                if (!x.SelfIPv6.empty())
      //                    addresses.PushBack(rapidjson::StringRef(x.SelfIPv6.c_str()),
      //                    allocator);
      proxy.AddMember("local_address", addresses, allocator);
      if (!x.SelfIPv6.empty())
        proxy.AddMember("inet6_bind_address",
                        rapidjson::StringRef(x.SelfIPv6.c_str()), allocator);
      proxy.AddMember("private_key", rapidjson::StringRef(x.PrivateKey.c_str()),
                      allocator);
      rapidjson::Value peer(rapidjson::kObjectType);
      peer.AddMember("server", rapidjson::StringRef(x.Hostname.c_str()),
                     allocator);
      peer.AddMember("server_port", x.Port, allocator);
      peer.AddMember("public_key", rapidjson::StringRef(x.PublicKey.c_str()),
                     allocator);
      if (!x.PreSharedKey.empty())
        peer.AddMember("pre_shared_key",
                       rapidjson::StringRef(x.PreSharedKey.c_str()), allocator);

      if (!x.AllowedIPs.empty()) {
        auto allowed_ips = stringArrayToJsonArray(x.AllowedIPs, ",", allocator);
        peer.AddMember("allowed_ips", allowed_ips, allocator);
      }

      if (!x.ClientId.empty()) {
        auto reserved = stringArrayToJsonArray(x.ClientId, ",", allocator);
        peer.AddMember("reserved", reserved, allocator);
      }
      if (!x.Password.empty()) {
        proxy.AddMember("pre_shared_key",
                        rapidjson::StringRef(x.Password.c_str()), allocator);
      }
      rapidjson::Value peers(rapidjson::kArrayType);
      peers.PushBack(peer, allocator);
      proxy.AddMember("peers", peers, allocator);
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
      addSingBoxCommonMembers(proxy, x, "hysteria", allocator);
      proxy.AddMember("auth_str", rapidjson::StringRef(x.Auth.c_str()),
                      allocator);
      if (isNumeric(x.UpMbps)) {
        proxy.AddMember("up_mbps", std::stoi(x.UpMbps), allocator);
      } else {
        size_t pos = x.UpMbps.find(search);
        if (pos != std::string::npos) {
          x.UpMbps.replace(pos, search.length(), "");
        }
        proxy.AddMember("up_mbps", std::stoi(x.UpMbps), allocator);
      }
      if (isNumeric(x.DownMbps)) {
        proxy.AddMember("down_mbps", std::stoi(x.DownMbps), allocator);
      } else {
        size_t pos = x.DownMbps.find(search);
        if (pos != std::string::npos) {
          x.DownMbps.replace(pos, search.length(), "");
        }
        proxy.AddMember("down_mbps", std::stoi(x.DownMbps), allocator);
      }
      if (!x.TLSSecure) {
        rapidjson::Value tls(rapidjson::kObjectType);
        tls.AddMember("enabled", true, allocator);
        if (!x.Alpn.empty()) {
          auto alpns = stringArrayToJsonArray(x.Alpn, ",", allocator);
          tls.AddMember("alpn", alpns, allocator);
        }
        if (!x.ServerName.empty()) {
          tls.AddMember("server_name",
                        rapidjson::StringRef(x.ServerName.c_str()), allocator);
        }
        tls.AddMember("insecure", buildBooleanValue(scv), allocator);
        proxy.AddMember("tls", tls, allocator);
      }
      if (!x.FakeType.empty() && x.FakeType != "none")
        proxy.AddMember("network", rapidjson::StringRef(x.FakeType.c_str()),
                        allocator);
      if (!x.OBFSParam.empty())
        proxy.AddMember("obfs", rapidjson::StringRef(x.OBFSParam.c_str()),
                        allocator);
      break;
    }
    case ProxyType::Hysteria2: {
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
    default:
      continue;
    }
    if (x.TLSSecure) {
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
    if (!udp.is_undef() && !udp && x.Type != ProxyType::AnyTLS) {
      proxy.AddMember("network", "tcp", allocator);
    }
    if (!tfo.is_undef() && x.Type != ProxyType::AnyTLS) {
      proxy.AddMember("tcp_fast_open", buildBooleanValue(tfo), allocator);
    }
    nodelist.push_back(x);
    remarks_list.emplace_back(x.Remark);
    used_remarks.emplace(x.Remark);
    outbounds.PushBack(proxy, allocator);
  }

  if (ext.nodelist) {
    json | AddMemberOrReplace("outbounds", outbounds, allocator);
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
}

std::string proxyToSingBox(std::vector<Proxy> &nodes,
                           const std::string &base_conf,
                           std::vector<RulesetContent> &ruleset_content_array,
                           const ProxyGroupConfigs &extra_proxy_group,
                           extra_settings &ext) {
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
