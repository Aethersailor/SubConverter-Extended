#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <exception>
#include <iostream>
#include <memory>
#include <map>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <unordered_set>

#include <inja.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <yaml-cpp/yaml.h>

#include "config/binding.h"
#include "generator/config/external_rules.h"
#include "generator/config/nodemanip.h"
#include "generator/config/ruleconvert.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "interfaces.h"
#include "multithread.h"
#include "ruleset_output.h"
#include "parser/mihomo_scheme_utils.h"
#include "parser/mihomo_bridge.h"
#include "script/cron.h"
#include "script/script_quickjs.h"
#include "server/webserver.h"
#include "settings.h"
#include "settings_view.h"
#include "statistics.h"
#include "sub_request_key.h"
#include "upload.h"
#include "webget.h"
#include "utils/time_compat.h"

static string_icase_map buildSubscriptionRequestHeaders() {
  string_icase_map headers;
  headers.emplace("User-Agent", "clash.meta");
  return headers;
}

#include "utils/base64/base64.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/system.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "webget.h"

extern WebServer webServer;

string_array gRegexBlacklist = {"(.*)*"};

static constexpr size_t kProviderUserAgentMaxLen = 512;

struct TargetDescriptor {
  const char *name;
  bool simple_subscription;
  SingleLinkTypes single_link_types;
};

static constexpr std::array<TargetDescriptor, 18> kTargetDescriptors = {{
    {"clash", false, 0},
    {"clashr", false, 0},
    {"surge", false, 0},
    {"quan", false, 0},
    {"quanx", false, 0},
    {"loon", false, 0},
    {"surfboard", false, 0},
    {"mellow", false, 0},
    {"singbox", false, 0},
    {"ss", true, SingleLinkType::Shadowsocks},
    {"ssd", true, 0},
    {"ssr", true, SingleLinkType::ShadowsocksR},
    {"sssub", true, 0},
    {"v2ray", true, SingleLinkType::VMess},
    {"trojan", true, SingleLinkType::Trojan},
    {"vless", true, SingleLinkType::VLESS},
    {"hysteria2", true, SingleLinkType::Hysteria2},
    {"mixed", true, SingleLinkType::Mixed},
}};

static const TargetDescriptor *findTargetDescriptor(const std::string &name) {
  const auto found =
      std::find_if(kTargetDescriptors.begin(), kTargetDescriptors.end(),
                   [&](const TargetDescriptor &target) {
                     return name == target.name;
                   });
  return found == kTargetDescriptors.end() ? nullptr : &*found;
}

static std::string supportedTargets(const std::string &separator) {
  std::string result;
  for (const TargetDescriptor &target : kTargetDescriptors) {
    if (!result.empty())
      result += separator;
    result += target.name;
  }
  return result;
}

static std::string trimProviderUserAgentCandidate(const std::string &ua) {
  size_t begin = ua.find_first_not_of(" \t");
  if (begin == std::string::npos)
    return "";
  size_t end = ua.find_last_not_of(" \t");
  return ua.substr(begin, end - begin + 1);
}

static bool hasInvalidProviderUserAgentChar(const std::string &ua) {
  for (unsigned char ch : ua) {
    if (ch < 0x20 || ch == 0x7f)
      return true;
  }
  return false;
}

static bool containsAnyUserAgentToken(const std::string &lower_ua,
                                      const string_array &tokens) {
  for (const std::string &token : tokens) {
    if (lower_ua.find(token) != std::string::npos)
      return true;
  }
  return false;
}

static bool isExcludedProviderUserAgent(const std::string &ua) {
  std::string lower = toLower(ua);
  static const string_array browser_tokens = {
      "mozilla/",        "applewebkit/",     "chrome/",
      "chromium/",       "crios/",           "safari/",
      "firefox/",        "fxios/",           "edg/",
      "edga/",           "edgios/",          "edge/",
      "opr/",            "opera/",           "brave/",
      "vivaldi/",        "yabrowser/",       "samsungbrowser/",
      "ucbrowser/",      "maxthon/",         "qqbrowser/",
      "mqqbrowser/",     "sogou/",           "360se",
      "360ee",           "whale/",           "micromessenger/",
      "msie ",           "trident/"};
  static const string_array inspection_tool_tokens = {
      "curl/",             "wget/",         "python-requests/",
      "python-urllib/",    "postmanruntime/", "insomnia/",
      "go-http-client/",   "java/",         "apache-httpclient/",
      "httpie/",           "powershell/",   "libwww-perl/",
      "axios/",            "node-fetch/",   "undici"};

  return containsAnyUserAgentToken(lower, browser_tokens) ||
         containsAnyUserAgentToken(lower, inspection_tool_tokens);
}

static std::string providerUserAgentFromRequest(const Request &request) {
  auto ua = request.headers.find("User-Agent");
  if (ua == request.headers.end())
    return "";

  std::string value = trimProviderUserAgentCandidate(ua->second);
  if (value.empty() || value.size() > kProviderUserAgentMaxLen ||
      hasInvalidProviderUserAgentChar(value) ||
      isExcludedProviderUserAgent(value))
    return "";

  return value;
}

static bool isValidProviderHeaderName(const std::string &name) {
  if (name.empty() || name.size() > 128)
    return false;
  static const std::string punctuation = "!#$%&'*+-.^_`|~";
  for (unsigned char ch : name) {
    if (!std::isalnum(ch) && punctuation.find(ch) == std::string::npos)
      return false;
  }
  return true;
}

static bool isReservedProviderHeader(const std::string &name) {
  std::string lower = toLower(name);
  static const std::unordered_set<std::string> reserved = {
      "host",              "connection",        "keep-alive",
      "proxy-authenticate", "proxy-authorization", "te",
      "trailer",           "transfer-encoding", "upgrade",
      "content-length",    "cookie",            "forwarded",
      "origin",            "referer",           "user-agent",
      "x-age-public-key",  "if-match",          "if-none-match",
      "if-modified-since", "if-unmodified-since", "if-range",
      "range"};
  if (reserved.find(lower) != reserved.end())
    return true;

  static const string_array reserved_prefixes = {
      "cf-",          "sec-",        "x-forwarded-", "x-real-ip",
      "x-client-ip",  "x-original-", "x-envoy-",     "true-client-ip",
      "fastly-",      "fly-"};
  for (const std::string &prefix : reserved_prefixes) {
    if (startsWith(lower, prefix))
      return true;
  }
  return false;
}

static bool hasInvalidProviderHeaderValue(const std::string &value) {
  if (value.empty() || value.size() > 8192)
    return true;
  for (unsigned char ch : value) {
    if (ch == '\r' || ch == '\n' || ch == 0 || ch == 0x7f)
      return true;
  }
  return false;
}

static bool providerHeadersFromRequest(
    const Request &request, const std::string &selected,
    std::map<std::string, std::string> &headers, std::string &error) {
  headers.clear();
  if (selected.empty())
    return true;
  if (selected.size() > 1024) {
    error = "provider_headers is too long";
    return false;
  }

  std::unordered_set<std::string> seen;
  string_array names = split(selected, ",");
  if (names.empty() || names.size() > 16) {
    error = "provider_headers must select between 1 and 16 headers";
    return false;
  }
  for (std::string name : names) {
    name = trim(name);
    std::string lower = toLower(name);
    if (!isValidProviderHeaderName(name)) {
      error = "provider_headers contains an invalid header name";
      return false;
    }
    if (isReservedProviderHeader(name)) {
      error = "provider_headers contains a reserved header name: " + name;
      return false;
    }
    if (!seen.insert(lower).second) {
      error = "provider_headers contains a duplicate header name: " + name;
      return false;
    }

    auto iter = request.headers.find(name);
    if (iter == request.headers.end()) {
      error = "provider_headers selected a header that is missing: " + name;
      return false;
    }
    if (hasInvalidProviderHeaderValue(iter->second)) {
      error = "provider_headers selected an invalid header value: " + name;
      return false;
    }
    headers.emplace(iter->first, iter->second);
  }
  return true;
}

static void appendVaryHeader(Response &response, const std::string &field) {
  auto iter = response.headers.find("Vary");
  if (iter == response.headers.end() || iter->second.empty()) {
    response.headers["Vary"] = field;
    return;
  }

  std::string lower_field = toLower(field);
  for (std::string token : split(iter->second, ",")) {
    token = trim(token);
    if (toLower(token) == lower_field)
      return;
  }
  iter->second += ", " + field;
}

static std::string buildProviderRemarkFilter(const string_array &rules) {
  string_array valid_rules;
  for (const std::string &rule : rules) {
    if (!rule.empty() && regValid(rule))
      valid_rules.emplace_back(rule);
  }

  if (valid_rules.empty())
    return "";
  if (valid_rules.size() == 1)
    return valid_rules.front();

  return "(" + join(valid_rules, ")|(") + ")";
}

extern string_array ClashRuleTypes, SurgeRuleTypes, QuanXRuleTypes;

struct UAProfile {
  std::string head;
  std::string version_match;
  std::string version_target;
  std::string target;
  tribool clash_new_name = tribool();
  int surge_ver = -1;
};

const std::vector<UAProfile> UAMatchList = {
    {"ClashForAndroid", "\\/([0-9.]+)", "2.0", "clash", true},
    {"ClashForAndroid", "\\/([0-9.]+)R", "", "clashr", false},
    {"ClashForAndroid", "", "", "clash", false},
    {"ClashforWindows", "\\/([0-9.]+)", "0.11", "clash", true},
    {"ClashforWindows", "", "", "clash", false},
    {"clash-verge", "", "", "clash", true},
    {"ClashX Pro", "", "", "clash", true},
    {"ClashX", "\\/([0-9.]+)", "0.13", "clash", true},
    {"Clash", "", "", "clash", true},
    {"Kitsunebi", "", "", "v2ray"},
    {"Loon", "", "", "loon"},
    {"Pharos", "", "", "mixed"},
    {"Potatso", "", "", "mixed"},
    {"Quantumult%20X", "", "", "quanx"},
    {"Quantumult", "", "", "quan"},
    {"Qv2ray", "", "", "v2ray"},
    {"Shadowrocket", "", "", "mixed"},
    {"Surfboard", "", "", "surfboard"},
    {"Surge", "\\/([0-9.]+).*x86", "906", "surge", false,
     4}, /// Surge for Mac (supports VMess)
    {"Surge", "\\/([0-9.]+).*x86", "368", "surge", false, 3},
    /// Surge for Mac (supports new rule types and Shadowsocks without plugin)
    {"Surge", "\\/([0-9.]+)", "1419", "surge", false,
     4}, /// Surge iOS 4 (first version)
    {"Surge", "\\/([0-9.]+)", "900", "surge", false,
     3},                                  /// Surge iOS 3 (approx)
    {"Surge", "", "", "surge", false, 2}, /// any version of Surge as fallback
    {"Trojan-Qt5", "", "", "trojan"},
    {"V2rayU", "", "", "v2ray"},
    {"V2RayX", "", "", "v2ray"}};

bool verGreaterEqual(const std::string &src_ver,
                     const std::string &target_ver) {
  std::istringstream src_stream(src_ver), target_stream(target_ver);
  int src_part, target_part;
  char dot;
  while (src_stream >> src_part) {
    if (target_stream >> target_part) {
      if (src_part < target_part) {
        return false;
      } else if (src_part > target_part) {
        return true;
      }
      // Skip the dot separator in both streams
      src_stream >> dot;
      target_stream >> dot;
    } else {
      // If we run out of target parts, the source version is greater only if it
      // has more parts
      return true;
    }
  }
  // If we get here, the common parts are equal, so check if target_ver has more
  // parts
  return !bool(target_stream >> target_part);
}

void matchUserAgent(const std::string &user_agent, std::string &target,
                    tribool &clash_new_name, int &surge_ver) {
  if (user_agent.empty())
    return;
  for (const UAProfile &x : UAMatchList) {
    if (startsWith(user_agent, x.head)) {
      if (!x.version_match.empty()) {
        std::string version;
        if (regGetMatch(user_agent, x.version_match, 2, 0, &version))
          continue;
        if (!x.version_target.empty() &&
            !verGreaterEqual(version, x.version_target))
          continue;
      }
      target = x.target;
      clash_new_name = x.clash_new_name;
      if (x.surge_ver != -1)
        surge_ver = x.surge_ver;
      return;
    }
  }
}

std::string getRuleset(RESPONSE_CALLBACK_ARGS) {
  SettingsSnapshot snapshot = captureEffectiveSettingsSnapshot();
  ScopedSettingsView settings_scope(std::move(snapshot));
  auto &argument = request.argument;
  int *status_code = &response.status_code;
  /// type: 1 for Surge, 2 for Quantumult X, 3 for Clash domain rule-provider, 4
  /// for Clash ipcidr rule-provider, 5 for Surge DOMAIN-SET, 6 for Clash
  /// classical ruleset
  std::string url = urlSafeBase64Decode(getUrlArg(argument, "url")),
              type = getUrlArg(argument, "type"),
              group = urlSafeBase64Decode(getUrlArg(argument, "group"));
  std::string output_content;
  int type_int = to_int(type, 0);

  if (url.empty() || type.empty() || (type_int == 2 && group.empty()) ||
      (type_int < 1 || type_int > 6)) {
    *status_code = 400;
    return "Invalid request: missing or invalid ruleset parameters.\n"
           "无效请求：规则集参数缺失或无效。\n"
           "Required: url and type=1..6; group is required when type=2.\n"
           "必须提供 url 和 type=1..6；当 type=2 时还必须提供 group。";
  }

  string_array vArray = split(url, "|");
  for (std::string &x : vArray)
    x.insert(0, "ruleset,");
  std::vector<RulesetContent> rca;
  RulesetConfigs confs = INIBinding::from<RulesetConfig>::from_ini(vArray);
  refreshRulesets(confs, rca, FetchContext::PublicRequest);
  for (RulesetContent &x : rca) {
    std::string content = x.rule_content.get();
    output_content += convertRuleset(content, x.rule_type);
  }

  if (output_content.empty()) {
    *status_code = 400;
    return "Invalid request: no valid rules were found in the supplied "
           "ruleset source.\n"
           "无效请求：提供的规则集来源中未找到有效规则。\n"
           "Please check whether the URL is reachable and the ruleset type "
           "matches the content.\n"
           "请检查链接是否可访问，以及规则集类型是否与内容匹配。";
  }

  return formatRulesetOutput(
      std::move(output_content), type_int, group,
      RulesetTypeCatalogs{ClashRuleTypes, SurgeRuleTypes, QuanXRuleTypes});
}

bool checkExternalBase(const std::string &path, std::string &dest,
                       FetchContext context) {
  if (path.empty())
    return false;
  if (isLink(path)) {
    if (!isFetchUrlAllowed(path, context))
      return false;
    dest = path;
    return true;
  }
  if (fileExist(path, true) && isTrustedLocalResourcePath(path)) {
    dest = path;
    return true;
  }
  return false;
}

static const std::string *selectedExternalBase(const ExternalConfig &extconf,
                                               const std::string &target,
                                               bool simple_subscription,
                                               bool nodelist) {
  if (nodelist)
    return nullptr;
  if (target == "sssub")
    return &extconf.sssub_rule_base;
  if (simple_subscription)
    return nullptr;
  if (target == "clash" || target == "clashr")
    return &extconf.clash_rule_base;
  if (target == "surge")
    return &extconf.surge_rule_base;
  if (target == "surfboard")
    return &extconf.surfboard_rule_base;
  if (target == "mellow")
    return &extconf.mellow_rule_base;
  if (target == "quan")
    return &extconf.quan_rule_base;
  if (target == "quanx")
    return &extconf.quanx_rule_base;
  if (target == "loon")
    return &extconf.loon_rule_base;
  if (target == "singbox")
    return &extconf.singbox_rule_base;
  return nullptr;
}

static bool validateSelectedExternalBase(const ExternalConfig &extconf,
                                         const std::string &target,
                                         bool simple_subscription,
                                         bool nodelist,
                                         FetchContext context) {
  const std::string *base = selectedExternalBase(
      extconf, target, simple_subscription, nodelist);
  if (!base || base->empty())
    return true;
  std::string validated;
  return checkExternalBase(*base, validated, context);
}

static bool hasEffectiveExternalConfig(const ExternalConfig &extconf,
                                       const template_args &tpl_args,
                                       const string_map &tpl_args_base) {
  if (tpl_args.local_vars != tpl_args_base)
    return true;

  if (!extconf.custom_proxy_group.empty() || !extconf.surge_ruleset.empty())
    return true;

  if (!extconf.rule_prepend_sources.empty() ||
      !extconf.rule_append_sources.empty())
    return true;

  if (!extconf.clash_rule_base.empty() || !extconf.surge_rule_base.empty() ||
      !extconf.surfboard_rule_base.empty() ||
      !extconf.mellow_rule_base.empty() || !extconf.quan_rule_base.empty() ||
      !extconf.quanx_rule_base.empty() || !extconf.loon_rule_base.empty() ||
      !extconf.sssub_rule_base.empty() ||
      !extconf.singbox_rule_base.empty())
    return true;

  if (!extconf.rename.empty() || !extconf.emoji.empty() ||
      !extconf.include.empty() || !extconf.exclude.empty())
    return true;

  if (!extconf.add_emoji.is_undef() || !extconf.remove_old_emoji.is_undef())
    return true;

  if (!extconf.enable_rule_generator || extconf.overwrite_original_rules)
    return true;

  return false;
}

static bool fetchExternalRuleSources(const string_array &sources,
                                     const std::string &field_name,
                                     FetchContext context,
                                     string_array &destination,
                                     std::string &error) {
  const Settings &settings = effectiveSettings();
  ProxyPolicy proxy = parseProxy(settings.proxyRuleset);
  string_icase_map request_headers = {
      {"Cache-Control", "no-cache, no-store, max-age=0"},
      {"Pragma", "no-cache"}};

  for (size_t i = 0; i < sources.size(); ++i) {
    const std::string source_identifier =
        field_name + " source #" + std::to_string(i + 1);
    const std::string lower_source = toLower(sources[i]);
    if (!startsWith(lower_source, "http://") &&
        !startsWith(lower_source, "https://")) {
      error =
          "Invalid external rule source " + source_identifier +
          ": only remote HTTP(S) URLs are supported; local paths and data "
          "URLs are not allowed.\n"
          "外部规则来源 " +
          source_identifier +
          " 无效：仅支持远程 HTTP(S) URL，不允许本地路径或 data URL。";
      return false;
    }

    int fetch_status = 0;
    std::string content;
    FetchArgument argument{HTTP_GET,
                           sources[i],
                           proxy,
                           nullptr,
                           &request_headers,
                           nullptr,
                           0,
                           false,
                           context};
    FetchResult result{&fetch_status, &content, nullptr, nullptr};
    webGet(argument, result);
    if (fetch_status < 200 || fetch_status >= 300 || content.empty()) {
      writeLog(0,
               "外部规则来源 " + source_identifier +
                   " 拉取失败、HTTP 状态异常或内容为空，已跳过。",
               LOG_LEVEL_WARNING);
      continue;
    }

    ExternalRuleParseResult parsed =
        parseExternalClashRules(content, source_identifier, ClashRuleTypes);
    if (!parsed.ok) {
      error = std::move(parsed.error);
      return false;
    }
    if (parsed.rules.empty()) {
      error =
          "Invalid external rule source " + source_identifier +
          ": no usable rules were found.\n"
          "外部规则来源 " +
          source_identifier + " 无效：未找到可用规则。";
      return false;
    }
    destination.insert(destination.end(),
                       std::make_move_iterator(parsed.rules.begin()),
                       std::make_move_iterator(parsed.rules.end()));
  }
  return true;
}

/**
 * 根据订阅链接生成唯一特征码（MD5 前 6 位，大写）
 * @param url 订阅链接（会自动解码后计算哈希）
 * @return 6 位大写 hex 特征码字符串
 */
inline std::string generateProviderHash(const std::string &url) {
  std::string decodedUrl = urlDecode(url);
  std::string fullHash = getMD5(decodedUrl);
  std::string shortHash = fullHash.substr(0, 6);
  // 转换为大写
  std::transform(shortHash.begin(), shortHash.end(), shortHash.begin(),
                 ::toupper);
  return shortHash;
}

inline std::string generateProviderHashFromDecodedUrl(
    const std::string &decoded_url) {
  std::string fullHash = getMD5(decoded_url);
  std::string shortHash = fullHash.substr(0, 6);
  std::transform(shortHash.begin(), shortHash.end(), shortHash.begin(),
                 ::toupper);
  return shortHash;
}

struct TaggedLink {
  enum class Error {
    None,
    InvalidInterval,
    DuplicateInterval,
    InvalidProxyDirect,
    DuplicateProxyDirect,
  };

  std::string tag;
  std::string provider;
  std::string link;
  int interval = 0;
  bool proxy_direct = kDefaultProxyProviderDirect;
  bool has_tag = false;
  bool has_provider = false;
  bool has_interval = false;
  bool has_proxy_direct = false;
  bool link_decoded = false;
  Error error = Error::None;
};

static bool extractLinkPrefix(const std::string &input,
                              const std::string &prefix,
                              std::string &value,
                              std::string &remainder,
                              bool &saw_bracketed) {
  std::string trimmed = trimWhitespace(input, true, true);
  size_t start = std::string::npos;
  bool bracketed = false;
  std::string bracket_prefix = "<" + prefix;
  if (startsWith(trimmed, bracket_prefix)) {
    start = bracket_prefix.size();
    bracketed = true;
  } else if (startsWith(trimmed, prefix)) {
    start = prefix.size();
  } else {
    return false;
  }

  size_t comma_pos = trimmed.find(',', start);
  if (comma_pos == std::string::npos)
    return false;

  value = trimmed.substr(start, comma_pos - start);
  size_t link_pos = comma_pos + 1;
  if (bracketed && link_pos < trimmed.size() && trimmed[link_pos] == '>')
    link_pos++;
  if (link_pos >= trimmed.size())
    return false;

  remainder = trimmed.substr(link_pos);
  if (bracketed)
    saw_bracketed = true;
  return true;
}

static bool parseLinkPrefixes(const std::string &input, TaggedLink &result) {
  std::string remainder = input;
  bool saw_bracketed = false;
  bool parsed = false;

  while (true) {
    std::string value;
    std::string next;
    if (extractLinkPrefix(remainder, "tag:", value, next, saw_bracketed)) {
      parsed = true;
      if (!value.empty() && !result.has_tag) {
        result.tag = value;
        result.has_tag = true;
      }
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "provider:", value, next, saw_bracketed)) {
      parsed = true;
      if (!value.empty() && !result.has_provider) {
        result.provider = value;
        result.has_provider = true;
      }
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "interval:", value, next,
                          saw_bracketed)) {
      parsed = true;
      if (result.has_interval) {
        result.error = TaggedLink::Error::DuplicateInterval;
        return true;
      }
      if (!parseProxyProviderInterval(value, result.interval)) {
        result.error = TaggedLink::Error::InvalidInterval;
        return true;
      }
      result.has_interval = true;
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "proxy_direct:", value, next,
                          saw_bracketed)) {
      parsed = true;
      if (result.has_proxy_direct) {
        result.error = TaggedLink::Error::DuplicateProxyDirect;
        return true;
      }
      if (!parseProxyProviderDirect(value, result.proxy_direct)) {
        result.error = TaggedLink::Error::InvalidProxyDirect;
        return true;
      }
      result.has_proxy_direct = true;
      remainder = next;
      continue;
    }
    break;
  }

  std::string lower_remainder =
      toLower(trimWhitespace(remainder, true, true));
  const bool starts_interval = startsWith(lower_remainder, "interval:") ||
                               startsWith(lower_remainder, "<interval:");
  const bool starts_proxy_direct =
      startsWith(lower_remainder, "proxy_direct:") ||
      startsWith(lower_remainder, "<proxy_direct:");
  if (starts_interval && lower_remainder.find("%2c") == std::string::npos) {
    result.error = TaggedLink::Error::InvalidInterval;
    return true;
  }
  if (starts_proxy_direct &&
      lower_remainder.find("%2c") == std::string::npos) {
    result.error = TaggedLink::Error::InvalidProxyDirect;
    return true;
  }

  if (!parsed)
    return false;

  remainder = trimWhitespace(remainder, true, true);
  if (saw_bracketed && !remainder.empty() && remainder.back() == '>')
    remainder.pop_back();
  result.link = remainder;
  return true;
}

static bool looksLikeEncodedLinkPrefix(const std::string &input) {
  std::string lower = toLower(input);
  return startsWith(lower, "tag%3a") || startsWith(lower, "provider%3a") ||
         startsWith(lower, "interval%3a") ||
         startsWith(lower, "proxy_direct%3a") ||
         startsWith(lower, "%3ctag%3a") ||
         startsWith(lower, "%3cprovider%3a") || startsWith(lower, "%3ctag:") ||
         startsWith(lower, "%3cinterval%3a") ||
         startsWith(lower, "%3cproxy_direct%3a") ||
         startsWith(lower, "%3cprovider:") ||
         startsWith(lower, "%3cinterval:") ||
         startsWith(lower, "%3cproxy_direct:") ||
         (startsWith(lower, "tag:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "provider:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "interval:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "proxy_direct:") &&
          lower.find("%2c") != std::string::npos);
}

static TaggedLink parseTaggedLink(const std::string &input) {
  TaggedLink result;
  std::string value = trimWhitespace(input, true, true);
  if (parseLinkPrefixes(value, result))
    return result;
  if (looksLikeEncodedLinkPrefix(value)) {
    TaggedLink decoded_result;
    std::string decoded = urlDecode(value);
    if (parseLinkPrefixes(decoded, decoded_result)) {
      decoded_result.link_decoded = true;
      return decoded_result;
    }
  }
  result.link = value;
  return result;
}

static std::string providerLinkPrefixError(
    size_t item_index, TaggedLink::Error error) {
  const std::string item = std::to_string(item_index + 1);
  if (error == TaggedLink::Error::DuplicateInterval) {
    return "Invalid request: interval: is repeated for URL item #" + item +
           ".\n"
           "无效请求：第 " + item +
           " 个 url 项重复设置了 interval: 前缀。";
  }
  if (error == TaggedLink::Error::InvalidInterval) {
    return "Invalid request: interval: for URL item #" + item +
           " must be a decimal integer from 0 to 2147483647.\n"
           "无效请求：第 " + item +
           " 个 url 项的 interval: 必须是 0 到 2147483647 之间的十进制整数。";
  }
  if (error == TaggedLink::Error::DuplicateProxyDirect) {
    return "Invalid request: proxy_direct: is repeated for URL item #" + item +
           ".\n"
           "无效请求：第 " + item +
           " 个 url 项重复设置了 proxy_direct: 前缀。";
  }
  return "Invalid request: proxy_direct: for URL item #" + item +
         " must be true, false, 1, or 0.\n"
         "无效请求：第 " + item +
         " 个 url 项的 proxy_direct: 必须是 true、false、1 或 0。";
}

static std::string providerIntervalScopeError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: interval: for URL item #" + item +
         " is only valid for subscription links that generate Clash/ClashR "
         "proxy-providers.\n"
         "无效请求：第 " + item +
         " 个 url 项的 interval: 仅适用于会生成 Clash/ClashR "
         "proxy-provider 的订阅链接。";
}

static std::string providerDirectScopeError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: proxy_direct: for URL item #" + item +
         " is only valid for subscription links that generate Clash/ClashR "
         "proxy-providers.\n"
         "无效请求：第 " + item +
         " 个 url 项的 proxy_direct: 仅适用于会生成 Clash/ClashR "
         "proxy-provider 的订阅链接。";
}

static constexpr size_t kProviderNameMaxLen = 64;

static bool isWindowsReservedName(const std::string &name) {
  if (name.empty())
    return false;
  std::string trimmed = trimWhitespace(name, true, true);
  trimmed = trimOf(trimmed, '.', true, true);
  if (trimmed.empty())
    return false;
  std::string upper = toUpper(trimmed);
  string_size dot_pos = upper.find('.');
  std::string base =
      dot_pos == std::string::npos ? upper : upper.substr(0, dot_pos);
  static const std::unordered_set<std::string> reserved = {
      "CON",  "PRN",  "AUX",  "NUL",  "COM1", "COM2", "COM3", "COM4",
      "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
      "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
  return reserved.find(base) != reserved.end();
}

static std::string clampProviderNameLength(const std::string &name,
                                           size_t max_len) {
  if (name.size() <= max_len)
    return name;
  std::string truncated = name.substr(0, max_len);
  while (!truncated.empty() && !isStrUTF8(truncated))
    truncated.pop_back();
  return truncated;
}

static std::string sanitizeProviderName(const std::string &input) {
  std::string name = trimWhitespace(input, true, true);
  if (name.empty())
    return "";

  std::string cleaned;
  cleaned.reserve(name.size());
  bool last_was_underscore = false;
  char last_out = '\0';

  for (unsigned char c : name) {
    bool invalid = false;
    if (c < 0x20 || c == 0x7F)
      invalid = true;
    if (!invalid) {
      switch (c) {
      case '<':
      case '>':
      case ':':
      case '"':
      case '/':
      case '\\':
      case '|':
      case '?':
      case '*':
        invalid = true;
        break;
      default:
        break;
      }
    }
    if (!invalid && c == '.' && last_out == '.')
      invalid = true;
    if (!invalid && c == '_')
      invalid = true;

    if (invalid) {
      if (!last_was_underscore) {
        cleaned.push_back('_');
        last_was_underscore = true;
        last_out = '_';
      }
      continue;
    }

    cleaned.push_back(static_cast<char>(c));
    last_was_underscore = false;
    last_out = static_cast<char>(c);
  }

  cleaned = trimWhitespace(cleaned, true, true);
  cleaned = trimOf(cleaned, '.', true, true);
  if (cleaned.empty() || isWindowsReservedName(cleaned))
    return "";

  cleaned = clampProviderNameLength(cleaned, kProviderNameMaxLen);
  cleaned = trimOf(cleaned, '.', true, true);
  if (cleaned.empty() || isWindowsReservedName(cleaned))
    return "";

  return cleaned;
}

static std::string subconverter_impl(Request &request, Response &response,
                                     const Settings &settings,
                                     RuleConversionStats *rule_stats = nullptr);

namespace {

struct CoalescedResponse {
  int status_code = 200;
  std::string content_type;
  string_icase_map headers;
  std::string body;
  uint64_t rule_conversions = 0;
};

using SharedCoalescedResponse = std::shared_ptr<const CoalescedResponse>;

struct InflightSubRequest {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  SharedCoalescedResponse result;
  std::exception_ptr exception;
};

struct CachedSubResponse {
  SharedCoalescedResponse result;
  std::chrono::steady_clock::time_point expires_at;
};

static std::mutex g_sub_inflight_mutex;
static std::map<std::string, std::shared_ptr<InflightSubRequest>>
    g_sub_inflight;
static std::mutex g_sub_response_cache_mutex;
static std::map<std::string, CachedSubResponse> g_sub_response_cache;

struct SubExplainProvider {
  std::string name;
  std::string tag;
  std::string source_hash;
  std::string path;
  std::string filter;
  std::string exclude_filter;
  int group_id = 0;
  uint32_t interval = 0;
  bool proxy_direct = kDefaultProxyProviderDirect;
};

struct SubExplainParameter {
  std::string name;
  std::string source;
  std::string status;
  std::string value_preview;
  std::string value_hash;
  std::string effective_value;
  std::string note;
  size_t raw_length = 0;
  size_t value_length = 0;
  bool present = false;
  bool sensitive = false;
};

struct SubExplainConfigSection {
  std::string name;
  std::string source;
  std::string status;
  std::string detail;
};

struct SubExplainReport {
  bool enabled = false;
  std::string requested_target;
  std::string target;
  bool simple_subscription = false;
  bool upload_requested = false;
  bool upload_suppressed = false;
  bool external_config_provided = false;
  bool external_config_loaded = false;
  bool fallback_config_used = false;
  bool rule_generator_enabled = false;
  bool expand_rulesets = false;
  bool proxy_provider_mode = false;
  bool nodelist = false;
  bool managed_config = false;
  std::string proxy_config;
  std::string proxy_ruleset;
  std::string proxy_subscription;
  std::string base_fetch_context = "trusted_config";
  std::string ruleset_fetch_context = "trusted_config";
  size_t raw_url_count = 0;
  size_t insert_url_count = 0;
  size_t subscription_url_count = 0;
  size_t node_link_count = 0;
  size_t unknown_node_link_count = 0;
  size_t provider_count = 0;
  size_t insert_node_count = 0;
  size_t direct_node_count = 0;
  size_t total_node_count = 0;
  size_t ruleset_count = 0;
  size_t custom_group_count = 0;
  size_t output_bytes = 0;
  std::vector<SubExplainProvider> providers;
  std::vector<SubExplainParameter> recognized_parameters;
  std::vector<SubExplainParameter> unrecognized_parameters;
  std::string effective_config_source = "none";
  std::vector<SubExplainConfigSection> effective_config_sections;
};

static std::string fetchContextName(FetchContext context) {
  switch (context) {
  case FetchContext::PublicRequest:
    return "public_request";
  case FetchContext::TrustedConfig:
  default:
    return "trusted_config";
  }
}

static std::string shortHash(const std::string &value) {
  if (value.empty())
    return "";
  return getMD5(value).substr(0, 10);
}

static std::string boolString(bool value) { return value ? "true" : "false"; }

static std::string previewExplainValue(const std::string &raw_value,
                                       bool sensitive) {
  std::string decoded = urlDecode(raw_value);
  if (decoded.empty())
    return "";
  if (sensitive)
    return "[redacted]";

  static constexpr size_t kMaxPreview = 180;
  if (decoded.size() <= kMaxPreview)
    return decoded;
  return decoded.substr(0, kMaxPreview) + "...";
}

static void writeJsonString(
    rapidjson::Writer<rapidjson::StringBuffer> &writer, const char *key,
    const std::string &value) {
  writer.Key(key);
  writer.String(value.c_str());
}

static void writeExplainParameter(
    rapidjson::Writer<rapidjson::StringBuffer> &writer,
    const SubExplainParameter &parameter) {
  writer.StartObject();
  writeJsonString(writer, "name", parameter.name);
  writer.Key("present");
  writer.Bool(parameter.present);
  writeJsonString(writer, "source", parameter.source);
  writeJsonString(writer, "status", parameter.status);
  writeJsonString(writer, "value_preview", parameter.value_preview);
  writeJsonString(writer, "value_hash", parameter.value_hash);
  writer.Key("raw_length");
  writer.Uint64(parameter.raw_length);
  writer.Key("value_length");
  writer.Uint64(parameter.value_length);
  writeJsonString(writer, "effective_value", parameter.effective_value);
  writeJsonString(writer, "note", parameter.note);
  writer.Key("sensitive");
  writer.Bool(parameter.sensitive);
  writer.EndObject();
}

static void writeExplainConfigSection(
    rapidjson::Writer<rapidjson::StringBuffer> &writer,
    const SubExplainConfigSection &section) {
  writer.StartObject();
  writeJsonString(writer, "name", section.name);
  writeJsonString(writer, "source", section.source);
  writeJsonString(writer, "status", section.status);
  writeJsonString(writer, "detail", section.detail);
  writer.EndObject();
}

static std::string serializeSubExplainReport(const SubExplainReport &report,
                                             const Response &response) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  writer.StartObject();
  writer.Key("ok");
  writer.Bool(response.status_code >= 200 && response.status_code < 300);
  writer.Key("status_code");
  writer.Int(response.status_code);
  writeJsonString(writer, "requested_target", report.requested_target);
  writeJsonString(writer, "target", report.target);

  writer.Key("mode");
  writer.StartObject();
  writer.Key("simple_subscription");
  writer.Bool(report.simple_subscription);
  writer.Key("proxy_provider");
  writer.Bool(report.proxy_provider_mode);
  writer.Key("nodelist");
  writer.Bool(report.nodelist);
  writer.Key("expand_rulesets");
  writer.Bool(report.expand_rulesets);
  writer.Key("rule_generator");
  writer.Bool(report.rule_generator_enabled);
  writer.Key("managed_config");
  writer.Bool(report.managed_config);
  writer.Key("upload_requested");
  writer.Bool(report.upload_requested);
  writer.Key("upload_suppressed");
  writer.Bool(report.upload_suppressed);
  writer.EndObject();

  writer.Key("inputs");
  writer.StartObject();
  writer.Key("raw_url_count");
  writer.Uint64(report.raw_url_count);
  writer.Key("insert_url_count");
  writer.Uint64(report.insert_url_count);
  writer.Key("subscription_url_count");
  writer.Uint64(report.subscription_url_count);
  writer.Key("node_link_count");
  writer.Uint64(report.node_link_count);
  writer.Key("unknown_node_link_count");
  writer.Uint64(report.unknown_node_link_count);
  writer.EndObject();

  writer.Key("external_config");
  writer.StartObject();
  writer.Key("provided");
  writer.Bool(report.external_config_provided);
  writer.Key("loaded");
  writer.Bool(report.external_config_loaded);
  writer.Key("fallback_used");
  writer.Bool(report.fallback_config_used);
  writer.EndObject();

  writer.Key("parameters");
  writer.StartObject();
  writer.Key("recognized");
  writer.StartArray();
  for (const SubExplainParameter &parameter : report.recognized_parameters)
    writeExplainParameter(writer, parameter);
  writer.EndArray();
  writer.Key("unrecognized");
  writer.StartArray();
  for (const SubExplainParameter &parameter : report.unrecognized_parameters)
    writeExplainParameter(writer, parameter);
  writer.EndArray();
  writer.EndObject();

  writer.Key("effective_config");
  writer.StartObject();
  writeJsonString(writer, "source", report.effective_config_source);
  writer.Key("sections");
  writer.StartArray();
  for (const SubExplainConfigSection &section :
       report.effective_config_sections)
    writeExplainConfigSection(writer, section);
  writer.EndArray();
  writer.EndObject();

  writer.Key("outbound_proxy");
  writer.StartObject();
  writeJsonString(writer, "config", report.proxy_config);
  writeJsonString(writer, "ruleset", report.proxy_ruleset);
  writeJsonString(writer, "subscription", report.proxy_subscription);
  writer.EndObject();

  writer.Key("resources");
  writer.StartObject();
  writeJsonString(writer, "base_fetch_context", report.base_fetch_context);
  writeJsonString(writer, "ruleset_fetch_context", report.ruleset_fetch_context);
  writer.Key("ruleset_count");
  writer.Uint64(report.ruleset_count);
  writer.Key("custom_group_count");
  writer.Uint64(report.custom_group_count);
  writer.EndObject();

  writer.Key("nodes");
  writer.StartObject();
  writer.Key("insert");
  writer.Uint64(report.insert_node_count);
  writer.Key("direct");
  writer.Uint64(report.direct_node_count);
  writer.Key("total");
  writer.Uint64(report.total_node_count);
  writer.EndObject();

  writer.Key("providers");
  writer.StartArray();
  for (const SubExplainProvider &provider : report.providers) {
    writer.StartObject();
    writeJsonString(writer, "name", provider.name);
    writeJsonString(writer, "tag", provider.tag);
    writeJsonString(writer, "source_hash", provider.source_hash);
    writeJsonString(writer, "path", provider.path);
    writeJsonString(writer, "filter", provider.filter);
    writeJsonString(writer, "exclude_filter", provider.exclude_filter);
    writer.Key("group_id");
    writer.Int(provider.group_id);
    writer.Key("interval");
    writer.Uint(provider.interval);
    writer.Key("proxy_direct");
    writer.Bool(provider.proxy_direct);
    writer.Key("proxy_field_emitted");
    writer.Bool(provider.proxy_direct);
    writer.EndObject();
  }
  writer.EndArray();

  writer.Key("output");
  writer.StartObject();
  writer.Key("bytes");
  writer.Uint64(report.output_bytes);
  writer.Key("provider_count");
  writer.Uint64(report.provider_count);
  writer.EndObject();

  writer.EndObject();
  return buffer.GetString();
}

static bool isTruthyRequestValue(const std::string &value) {
  std::string normalized = toLower(trimWhitespace(value, true, true));
  return normalized == "1" || normalized == "true" ||
         normalized == "yes" || normalized == "on";
}

struct AgeResponseContext {
  bool requested = false;
  bool valid = true;
  std::string recipient;
  std::string fingerprint;
};

static AgeResponseContext consumeAgeResponseContext(Request &request) {
  AgeResponseContext context;
  auto iter = request.headers.find("X-Age-Public-Key");
  if (iter == request.headers.end())
    return context;

  context.requested = true;
  std::string supplied_key = std::move(iter->second);
  request.headers.erase(iter);
  try {
    mihomo::AgeRecipient resolved = mihomo::resolveAgeRecipient(supplied_key);
    context.recipient = std::move(resolved.recipient);
    context.fingerprint = std::move(resolved.fingerprint);
  } catch (...) {
    context.valid = false;
  }
  std::fill(supplied_key.begin(), supplied_key.end(), '\0');
  supplied_key.clear();
  return context;
}

static std::string rejectAgeRequest(Response &response,
                                    const std::string &message) {
  response.status_code = 400;
  response.content_type = "text/plain; charset=utf-8";
  response.headers["Cache-Control"] = "private, no-store";
  response.headers["X-SCE-Age"] = "rejected";
  appendVaryHeader(response, "X-Age-Public-Key");
  return message;
}

static std::string finalizeSubResponse(const Request &request,
                                       Response &response, std::string body,
                                       const AgeResponseContext &age) {
  // Every /sub representation varies on this header, including the plaintext
  // variant, so shared caches cannot serve plaintext to an encrypted request.
  appendVaryHeader(response, "X-Age-Public-Key");
  if (!age.requested)
    return body;

  response.headers["Cache-Control"] = "private, no-store";
  response.headers["X-SCE-Age-Recipient"] = age.fingerprint;
  if (response.status_code < 200 || response.status_code >= 300) {
    response.headers["X-SCE-Age"] = "error-not-encrypted";
    return body;
  }
  if (request.method == "HEAD" ||
      isTruthyRequestValue(getUrlArg(request.argument, "explain"))) {
    response.headers["X-SCE-Age"] = "diagnostic-not-encrypted";
    return body;
  }

  try {
    body = mihomo::encryptAgeArmored(body, age.recipient);
    response.headers.erase("ETag");
    response.headers.erase("Content-MD5");
    response.headers.erase("Digest");
    response.headers["X-SCE-Age"] = "encrypted";
    return body;
  } catch (...) {
    response.status_code = 500;
    response.content_type = "text/plain; charset=utf-8";
    response.headers.erase("Subscription-UserInfo");
    response.headers.erase("Content-Disposition");
    response.headers["X-SCE-Age"] = "encryption-failed";
    return "Internal error: Age response encryption failed.\n"
           "内部错误：Age 响应加密失败。";
  }
}

static bool shouldCoalesceSubRequest(const Request &request,
                                     const Settings &settings) {
  if (!settings.enableRequestCoalescing)
    return false;
  if (request.method != "GET" || request.url != "/sub")
    return false;
  if (isTruthyRequestValue(getUrlArg(request.argument, "upload")))
    return false;
  return true;
}

static void copyCoalescedToResponse(const CoalescedResponse &result,
                                    Response &response) {
  response.status_code = result.status_code;
  response.content_type = result.content_type;
  response.headers = result.headers;
}

static SharedCoalescedResponse makeCoalescedResult(
    std::string &&body, Response &&response, uint64_t rule_conversions) {
  auto result = std::make_shared<CoalescedResponse>();
  result->status_code = response.status_code;
  result->content_type = std::move(response.content_type);
  result->headers = std::move(response.headers);
  result->body = std::move(body);
  result->rule_conversions = rule_conversions;
  return result;
}

static void pruneExpiredSubResponseCache(
    std::chrono::steady_clock::time_point now) {
  for (auto iter = g_sub_response_cache.begin();
       iter != g_sub_response_cache.end();) {
    if (iter->second.expires_at <= now)
      iter = g_sub_response_cache.erase(iter);
    else
      ++iter;
  }
}

static bool getCachedSubResponse(const std::string &key,
                                 SharedCoalescedResponse &result,
                                 const Settings &settings) {
  if (settings.responseCacheTtl <= 0)
    return false;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  auto iter = g_sub_response_cache.find(key);
  if (iter == g_sub_response_cache.end())
    return false;
  if (iter->second.expires_at <= now) {
    g_sub_response_cache.erase(iter);
    return false;
  }
  result = iter->second.result;
  return true;
}

static void storeCachedSubResponse(const std::string &key,
                                   const SharedCoalescedResponse &result,
                                   const Settings &settings) {
  if (settings.responseCacheTtl <= 0 || !result || result->status_code != 200)
    return;

  int ttl = std::min(settings.responseCacheTtl, 5);
  if (ttl <= 0)
    return;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  pruneExpiredSubResponseCache(now);
  if (g_sub_response_cache.size() > 2048) {
    writeLog(0,
             "响应微缓存条目数量过多，已清空以避免占用过多内存。",
             LOG_LEVEL_WARNING);
    g_sub_response_cache.clear();
  }
  g_sub_response_cache[key] = {
      result, now + std::chrono::seconds(ttl)};
}

static std::string runSubconverterImplWithRetry(const Request &original,
                                                Response &response,
                                                const Settings &settings,
                                                RuleConversionStats *stats) {
  Request first_request = original;
  Response first_response;
  RuleConversionStats first_stats;
  std::string body = subconverter_impl(first_request, first_response, settings,
                                       stats ? &first_stats : nullptr);
  if (first_response.status_code < 500 || !settings.coalesceRetryOn5xx) {
    if (stats)
      *stats = first_stats;
    response = first_response;
    return body;
  }

  writeLog(0,
           "/sub 请求首次转换返回 5xx，正在进行一次服务端内部重试。",
           LOG_LEVEL_WARNING);
  Request retry_request = original;
  Response retry_response;
  RuleConversionStats retry_stats;
  std::string retry_body = subconverter_impl(retry_request, retry_response,
                                             settings,
                                             stats ? &retry_stats : nullptr);
  if (retry_response.status_code < 500) {
    if (stats)
      *stats = retry_stats;
    response = retry_response;
    return retry_body;
  }

  if (stats)
    *stats = first_stats;
  response = first_response;
  return body;
}

static void recordTrackedSubRequest(bool track, const Request &request,
                                    const Response &response,
                                    uint64_t rule_conversions) {
  if (!track)
    return;
  if (response.status_code < 200 || response.status_code >= 300)
    return;
  statistics::recordSubscriptionConversion(request, rule_conversions);
}

static SettingsSnapshot captureSettingsForSubRequest(Request &request) {
  SettingsSnapshot current = captureSettingsSnapshot();
  if (!current->reloadConfOnRequest || !current->CFWChildProcess ||
      current->generatorMode)
    return current;

  std::string target = getUrlArg(request.argument, "target");
  if (target == "auto") {
    tribool clash_new_field;
    int surge_version =
        to_int(getUrlArg(request.argument, "ver"), 3);
    matchUserAgent(request.headers["User-Agent"], target, clash_new_field,
                   surge_version);
  }
  if (findTargetDescriptor(target)) {
    readConf();
    return captureSettingsSnapshot();
  }
  return current;
}

static std::string subconverterEntry(Request &request, Response &response,
                                     bool track) {
  AgeResponseContext age = consumeAgeResponseContext(request);
  if (age.requested && !age.valid) {
    return rejectAgeRequest(
        response,
        "Invalid X-Age-Public-Key: expected one Mihomo-supported Age public "
        "or secret key.\n"
        "X-Age-Public-Key 无效：应提供一个 Mihomo 支持的 Age 公钥或私钥。"
    );
  }
  if (age.requested && getUrlArg(request.argument, "target") != "clash") {
    return rejectAgeRequest(
        response,
        "Invalid request: Age response encryption is supported only for "
        "target=clash.\n"
        "无效请求：Age 响应加密仅支持 target=clash。"
    );
  }

  // CFW's compatibility reload remains after target validation, matching the
  // legacy control flow. The request view is captured only after that reload
  // transaction finishes (or restores the previous generation).
  SettingsSnapshot snapshot = captureSettingsForSubRequest(request);
  ScopedSettingsView settings_scope(snapshot);
  const Settings &settings = *snapshot;

  if (!shouldCoalesceSubRequest(request, settings)) {
    RuleConversionStats stats;
    std::string body = subconverter_impl(request, response, settings,
                                         track ? &stats : nullptr);
    body = finalizeSubResponse(request, response, std::move(body), age);
    recordTrackedSubRequest(track, request, response, stats.rules);
    return body;
  }

  std::string key =
      buildSubRequestKey(request, age.fingerprint, settings.configGeneration,
                         settings.managedConfigPrefix);
  if (key.empty()) {
    RuleConversionStats stats;
    std::string body = subconverter_impl(request, response, settings,
                                         track ? &stats : nullptr);
    body = finalizeSubResponse(request, response, std::move(body), age);
    recordTrackedSubRequest(track, request, response, stats.rules);
    return body;
  }

  SharedCoalescedResponse cached_result;
  if (getCachedSubResponse(key, cached_result, settings)) {
    writeLog(0, "/sub 响应微缓存命中。", LOG_LEVEL_DEBUG);
    copyCoalescedToResponse(*cached_result, response);
    recordTrackedSubRequest(track, request, response,
                            cached_result->rule_conversions);
    return cached_result->body;
  }

  std::shared_ptr<InflightSubRequest> call;
  bool owner = false;
  {
    std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
    auto iter = g_sub_inflight.find(key);
    if (iter == g_sub_inflight.end()) {
      call = std::make_shared<InflightSubRequest>();
      g_sub_inflight.emplace(key, call);
      owner = true;
    } else {
      call = iter->second;
    }
  }

  if (!owner) {
    writeLog(0, "/sub 请求已合并到正在执行的同 key 转换。",
             LOG_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(call->mutex);
    call->cv.wait(lock, [&call] { return call->done; });
    if (call->exception)
      std::rethrow_exception(call->exception);
    copyCoalescedToResponse(*call->result, response);
    recordTrackedSubRequest(track, request, response,
                            call->result->rule_conversions);
    return call->result->body;
  }

  try {
    writeLog(0, "/sub 请求成为同 key 转换 owner。", LOG_LEVEL_DEBUG);
    Response owner_response;
    RuleConversionStats stats;
    std::string body = runSubconverterImplWithRetry(
        request, owner_response, settings, track ? &stats : nullptr);
    body = finalizeSubResponse(request, owner_response, std::move(body), age);
    SharedCoalescedResponse result = makeCoalescedResult(
        std::move(body), std::move(owner_response), stats.rules);
    copyCoalescedToResponse(*result, response);
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->result = result;
      call->done = true;
    }
    {
      std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
      g_sub_inflight.erase(key);
    }
    if (!age.requested)
      storeCachedSubResponse(key, result, settings);
    call->cv.notify_all();
    recordTrackedSubRequest(track, request, response,
                            result->rule_conversions);
    return result->body;
  } catch (...) {
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->exception = std::current_exception();
      call->done = true;
    }
    {
      std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
      g_sub_inflight.erase(key);
    }
    call->cv.notify_all();
    throw;
  }
}

} // namespace

std::string subconverter(RESPONSE_CALLBACK_ARGS) {
  return subconverterEntry(request, response, false);
}

std::string subconverterTracked(RESPONSE_CALLBACK_ARGS) {
  return subconverterEntry(request, response, true);
}

namespace {

struct ParsedSubRequest {
  std::string target;
  std::string surge_version_text;
  bool explain_mode = false;
  SubExplainReport explain;
  tribool clash_new_field;
  int surge_version = 3;
  const TargetDescriptor *target_descriptor = nullptr;
  bool simple_subscription = false;

  std::string url;
  std::string group_name;
  std::string upload_path;
  std::string include_remark;
  std::string exclude_remark;
  std::string external_config;
  std::string device_id;
  std::string filename;
  std::string update_interval;
  std::string update_strict;
  std::string renames;
  std::string provider_headers;

  tribool upload;
  tribool emoji;
  tribool add_emoji;
  tribool remove_emoji;
  tribool append_type;
  tribool tfo;
  tribool udp;
  tribool generate_node_list;
  tribool sort;
  tribool use_sort_script;
  tribool generate_clash_script;
  tribool enable_insert;
  tribool skip_cert_verify;
  tribool filter_deprecated;
  tribool expand_rulesets;
  tribool append_userinfo;
  tribool prepend_insert;
  tribool generate_classical_rule_provider;
  tribool tls13;
  tribool provider_proxy_direct;
};

static std::string parseSubRequestArguments(Request &request,
                                            Response &response,
                                            const Settings &settings,
                                            ParsedSubRequest &parsed) {
  auto &argument = request.argument;
  parsed.target = getUrlArg(argument, "target");
  parsed.surge_version_text = getUrlArg(argument, "ver");
  parsed.explain_mode = isTruthyRequestValue(getUrlArg(argument, "explain"));
  parsed.explain.enabled = parsed.explain_mode;
  parsed.explain.proxy_config = parseProxy(settings.proxyConfig).describe();
  parsed.explain.proxy_ruleset = parseProxy(settings.proxyRuleset).describe();
  parsed.explain.proxy_subscription =
      parseProxy(settings.proxySubscription).describe();
  parsed.explain.requested_target = parsed.target;
  if (parsed.explain_mode) {
    std::string rawUrlForLog = getUrlArg(argument, "url");
    writeLog(0,
             "收到 /sub explain JSON 诊断请求：target=" +
                 (parsed.target.empty() ? std::string("<empty>")
                                        : parsed.target) +
                 ", 参数数量=" + std::to_string(argument.size()) +
                 ", url_hash=" +
                 (rawUrlForLog.empty()
                      ? std::string("-")
                      : shortHash(urlDecode(rawUrlForLog))) +
                 "。",
             LOG_LEVEL_INFO);
  }

  parsed.clash_new_field = getUrlArg(argument, "new_name");
  parsed.surge_version = !parsed.surge_version_text.empty()
                             ? to_int(parsed.surge_version_text, 3)
                             : 3;
  if (parsed.target == "auto")
    matchUserAgent(request.headers["User-Agent"], parsed.target,
                   parsed.clash_new_field, parsed.surge_version);
  parsed.explain.target = parsed.target;

  parsed.target_descriptor = findTargetDescriptor(parsed.target);
  if (!parsed.target_descriptor) {
    response.status_code = 400;
    return "Invalid request: unsupported target value.\n"
           "无效请求：不支持的 target 参数值。\n"
           "Supported targets: " +
           supportedTargets(", ") + ".\n" + "支持的 target：" +
           supportedTargets("、") + "。";
  }
  parsed.simple_subscription = parsed.target_descriptor->simple_subscription;

  parsed.url = getUrlArg(argument, "url");
  parsed.group_name = getUrlArg(argument, "group");
  parsed.upload_path = getUrlArg(argument, "upload_path");
  parsed.include_remark = getUrlArg(argument, "include");
  parsed.exclude_remark = getUrlArg(argument, "exclude");
  parsed.external_config = getUrlArg(argument, "config");
  parsed.device_id = getUrlArg(argument, "dev_id");
  parsed.filename = getUrlArg(argument, "filename");
  parsed.update_interval = getUrlArg(argument, "interval");
  parsed.update_strict = getUrlArg(argument, "strict");
  parsed.renames = getUrlArg(argument, "rename");
  parsed.provider_headers = getUrlArg(argument, "provider_headers");

  parsed.upload = getUrlArg(argument, "upload");
  parsed.emoji = getUrlArg(argument, "emoji");
  parsed.add_emoji = getUrlArg(argument, "add_emoji");
  parsed.remove_emoji = getUrlArg(argument, "remove_emoji");
  parsed.append_type = getUrlArg(argument, "append_type");
  parsed.tfo = getUrlArg(argument, "tfo");
  parsed.udp = getUrlArg(argument, "udp");
  parsed.generate_node_list = getUrlArg(argument, "list");
  parsed.sort = getUrlArg(argument, "sort");
  parsed.use_sort_script = getUrlArg(argument, "sort_script");
  parsed.generate_clash_script = getUrlArg(argument, "script");
  parsed.enable_insert = getUrlArg(argument, "insert");
  parsed.skip_cert_verify = getUrlArg(argument, "scv");
  parsed.filter_deprecated = getUrlArg(argument, "fdn");
  parsed.expand_rulesets = getUrlArg(argument, "expand");
  parsed.append_userinfo = getUrlArg(argument, "append_info");
  parsed.prepend_insert = getUrlArg(argument, "prepend");
  parsed.generate_classical_rule_provider = getUrlArg(argument, "classic");
  parsed.tls13 = getUrlArg(argument, "tls13");
  parsed.provider_proxy_direct =
      getUrlArg(argument, "provider_proxy_direct");
  parsed.explain.upload_requested = parsed.upload.get(false);
  if (parsed.explain_mode && parsed.upload) {
    parsed.upload = false;
    parsed.explain.upload_suppressed = true;
  }

  return "";
}

struct EffectiveSubPolicy {
  ProxyGroupConfigs custom_proxy_groups;
  RulesetConfigs custom_rulesets;
  string_array include_remarks;
  string_array exclude_remarks;
  extra_settings generator;
  int update_interval = 0;
  bool update_strict = false;

  std::string clash_base;
  std::string surge_base;
  std::string mellow_base;
  std::string surfboard_base;
  std::string quan_base;
  std::string quanx_base;
  std::string loon_base;
  std::string sssub_base;
  std::string singbox_base;

  std::map<std::string, std::string> provider_headers;
  template_args template_arguments;
  ProxyPolicy subscription_proxy;
};

static std::string buildEffectiveSubPolicy(Request &request,
                                           Response &response,
                                           const Settings &settings,
                                           RuleConversionStats *rule_stats,
                                           ParsedSubRequest &parsed,
                                           EffectiveSubPolicy &policy) {
  policy.custom_proxy_groups = settings.customProxyGroups;
  policy.custom_rulesets = settings.customRulesets;
  policy.include_remarks = settings.includeRemarks;
  policy.exclude_remarks = settings.excludeRemarks;
  policy.generator.rule_stats = rule_stats;
  policy.update_interval =
      !parsed.update_interval.empty()
          ? to_int(parsed.update_interval, settings.updateInterval)
          : settings.updateInterval;
  policy.update_strict = !parsed.update_strict.empty()
                             ? parsed.update_strict == "true"
                             : settings.updateStrict;
  parsed.explain.simple_subscription = parsed.simple_subscription;

  if (std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                parsed.include_remark) != gRegexBlacklist.cend() ||
      std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                parsed.exclude_remark) != gRegexBlacklist.cend()) {
    response.status_code = 400;
    return "Invalid request: include or exclude filter is not allowed.\n"
           "无效请求：include 或 exclude 过滤条件不被允许。\n"
           "Please remove blocked filter patterns and try again.\n"
           "请移除被拦截的过滤表达式后重试。";
  }

  policy.clash_base = settings.clashBase;
  policy.surge_base = settings.surgeBase;
  policy.mellow_base = settings.mellowBase;
  policy.surfboard_base = settings.surfboardBase;
  policy.quan_base = settings.quanBase;
  policy.quanx_base = settings.quanXBase;
  policy.loon_base = settings.loonBase;
  policy.sssub_base = settings.SSSubBase;
  policy.singbox_base = settings.singBoxBase;

  parsed.enable_insert.define(settings.enableInsert);
  if ((parsed.url.empty() &&
       !(!settings.insertUrls.empty() && parsed.enable_insert)) ||
      parsed.target.empty()) {
    response.status_code = 400;
    return "Invalid request: missing required target or url parameter.\n"
           "无效请求：缺少必需的 target 或 url 参数。\n"
           "Please provide target and url; url may be omitted only when "
           "configured insert nodes are enabled.\n"
           "请提供 target 和 url；只有启用已配置的插入节点时才能省略 url。";
  }

  std::string provider_headers_error;
  if (!parsed.provider_headers.empty() && parsed.target != "clash") {
    response.status_code = 400;
    return "Invalid request: provider_headers is supported only for target=clash.\n"
           "无效请求：provider_headers 仅支持 target=clash。";
  }
  if (!providerHeadersFromRequest(request, parsed.provider_headers,
                                  policy.provider_headers,
                                  provider_headers_error)) {
    response.status_code = 400;
    return "Invalid request: " + provider_headers_error + ".\n"
           "无效请求：proxy-provider 请求头选择失败。";
  }

  string_map req_arg_map;
  for (auto &argument : request.argument) {
    if (argument.first == "token")
      continue;
    req_arg_map[argument.first] = argument.second;
  }
  req_arg_map["target"] = parsed.target;
  req_arg_map["ver"] = std::to_string(parsed.surge_version);
  policy.template_arguments.global_vars = settings.templateVars;
  policy.template_arguments.request_params = std::move(req_arg_map);

  policy.subscription_proxy = parseProxy(settings.proxySubscription);
  policy.generator.append_proxy_type =
      parsed.append_type.get(settings.appendType);
  // 上游项目默认在 clash 目标下自动把 expand 设为 true
  // 本项目默认 expand=false（使用 rule-provider 模式不展开规则集）
  // 若用户主动传入 expand=true，则按照用户意愿内联展开规则集
  parsed.expand_rulesets.define(false);

  policy.generator.clash_proxies_style = settings.clashProxiesStyle;
  policy.generator.clash_proxy_groups_style = settings.clashProxyGroupsStyle;
  policy.generator.tfo.define(parsed.tfo).define(settings.TFOFlag);
  policy.generator.udp.define(parsed.udp).define(settings.UDPFlag);
  policy.generator.skip_cert_verify
      .define(parsed.skip_cert_verify)
      .define(settings.skipCertVerify);
  policy.generator.tls13.define(parsed.tls13).define(settings.TLS13Flag);

  policy.generator.sort_flag = parsed.sort.get(settings.enableSort);
  parsed.use_sort_script.define(!settings.sortScript.empty());
  if (policy.generator.sort_flag && parsed.use_sort_script)
    policy.generator.sort_script = settings.sortScript;
  policy.generator.filter_deprecated =
      parsed.filter_deprecated.get(settings.filterDeprecated);
  policy.generator.clash_new_field_name =
      parsed.clash_new_field.get(settings.clashUseNewField);
  policy.generator.clash_script = parsed.generate_clash_script.get();
  policy.generator.clash_classical_ruleset =
      parsed.generate_classical_rule_provider.get();
  policy.generator.provider_proxy_direct =
      parsed.provider_proxy_direct.get(settings.proxyProviderDirect);
  // 无论 expand 取何值，均强制使用 Mihomo 新字段名（proxy-groups / rules）
  // 避免因全局配置为旧字段名而导致 Mihomo 无法识别
  policy.generator.clash_new_field_name = true;
  if (parsed.expand_rulesets)
    policy.generator.clash_script = false;
  parsed.explain.expand_rulesets = parsed.expand_rulesets.get(false);

  // Clash defaults to proxy-provider mode, while an explicit list=true keeps
  // the traditional expanded-node behavior.
  policy.generator.nodelist = parsed.generate_node_list.get(false);
  parsed.explain.nodelist = policy.generator.nodelist;
  policy.generator.surge_ssr_path = settings.surgeSSRPath;
  policy.generator.quanx_dev_id = !parsed.device_id.empty()
                                        ? parsed.device_id
                                        : settings.quanXDevID;
  policy.generator.enable_rule_generator = settings.enableRuleGen;
  policy.generator.overwrite_original_rules = settings.overwriteOriginalRules;
  if (!parsed.expand_rulesets)
    policy.generator.managed_config_prefix = settings.managedConfigPrefix;
  parsed.explain.rule_generator_enabled =
      policy.generator.enable_rule_generator;
  parsed.explain.managed_config =
      !policy.generator.managed_config_prefix.empty();

  return "";
}

struct ExternalConfigFetchPlan {
  bool user_provided_external_config = false;
  bool config_load_success = false;
  FetchContext base_fetch_context = FetchContext::TrustedConfig;
  std::vector<RulesetContent> ruleset_content;
};

static std::string buildExternalConfigFetchPlan(
    Response &response, const Settings &settings, ParsedSubRequest &parsed,
    EffectiveSubPolicy &policy, ExternalConfigFetchPlan &plan) {
  plan.user_provided_external_config = !parsed.external_config.empty();
  FetchContext rulesetFetchContext = FetchContext::TrustedConfig;
  bool configLoadSuccess = false;
  string_array rulePrependSources, ruleAppendSources;
  FetchContext externalRuleFetchContext = FetchContext::TrustedConfig;
  string_map tpl_args_base = policy.template_arguments.local_vars;
  parsed.explain.external_config_provided =
      plan.user_provided_external_config;

  struct ExternalConfigCandidate {
    std::string path;
    FetchContext context;
    bool fallback = false;
  };
  std::vector<ExternalConfigCandidate> config_candidates;
  if (plan.user_provided_external_config) {
    config_candidates.push_back(
        {parsed.external_config, FetchContext::PublicRequest, false});
    if (settings.fallbackToDefaultExternalConfig &&
        !settings.defaultExtConfig.empty() &&
        settings.defaultExtConfig != parsed.external_config) {
      config_candidates.push_back(
          {settings.defaultExtConfig, FetchContext::TrustedConfig, true});
    }
  } else if (!settings.defaultExtConfig.empty()) {
    config_candidates.push_back(
        {settings.defaultExtConfig, FetchContext::TrustedConfig, false});
  }

  auto loadStatusName = [](ExternalConfigLoadStatus status) {
    switch (status) {
    case ExternalConfigLoadStatus::Success:
      return "success";
    case ExternalConfigLoadStatus::FetchFailed:
      return "fetch_failed";
    case ExternalConfigLoadStatus::RenderFailed:
      return "render_failed";
    case ExternalConfigLoadStatus::ParseFailed:
      return "parse_failed";
    case ExternalConfigLoadStatus::ImportFailed:
      return "import_failed";
    case ExternalConfigLoadStatus::ResourceLimitExceeded:
      return "resource_limit_exceeded";
    }
    return "unknown";
  };

  auto applyExternalConfig = [&](const ExternalConfig &extconf,
                                 FetchContext context) {
    rulePrependSources = extconf.rule_prepend_sources;
    ruleAppendSources = extconf.rule_append_sources;
    externalRuleFetchContext = extconf.rule_sources_context;
    if (!policy.generator.nodelist) {
      if (checkExternalBase(extconf.sssub_rule_base, policy.sssub_base,
                            context))
        plan.base_fetch_context = context;
      if (!parsed.simple_subscription) {
        if (checkExternalBase(extconf.clash_rule_base, policy.clash_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.surge_rule_base, policy.surge_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.surfboard_rule_base,
                              policy.surfboard_base, context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.mellow_rule_base, policy.mellow_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.quan_rule_base, policy.quan_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.quanx_rule_base, policy.quanx_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.loon_rule_base, policy.loon_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.singbox_rule_base, policy.singbox_base,
                              context))
          plan.base_fetch_context = context;

        if (!extconf.surge_ruleset.empty()) {
          policy.custom_rulesets = extconf.surge_ruleset;
          rulesetFetchContext = context;
        }
        if (!extconf.custom_proxy_group.empty())
          policy.custom_proxy_groups = extconf.custom_proxy_group;
        policy.generator.enable_rule_generator =
            extconf.enable_rule_generator;
        policy.generator.overwrite_original_rules =
            extconf.overwrite_original_rules;
      }
    }
    if (!extconf.rename.empty()) {
      policy.generator.rename_array = extconf.rename;
      policy.generator.rename_for_providers = true;
    }
    if (!extconf.emoji.empty())
      policy.generator.emoji_array = extconf.emoji;
    if (!extconf.include.empty())
      policy.include_remarks = extconf.include;
    if (!extconf.exclude.empty())
      policy.exclude_remarks = extconf.exclude;
    parsed.add_emoji.define(extconf.add_emoji);
    parsed.remove_emoji.define(extconf.remove_old_emoji);
  };

  for (const ExternalConfigCandidate &candidate : config_candidates) {
    policy.template_arguments.local_vars = tpl_args_base;
    writeLog(0, candidate.fallback
                    ? "用户外部配置失败，显式尝试默认外部配置：" +
                          summarizeUrlForLog(candidate.path)
                    : "正在加载外部配置：" +
                          summarizeUrlForLog(candidate.path),
             candidate.fallback ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO);

    ExternalConfig extconf;
    extconf.tpl_args = &policy.template_arguments;
    ExternalConfigLoadResult loaded =
        loadExternalConfig(candidate.path, extconf, candidate.context);
    bool effective =
        loaded.ok() && hasEffectiveExternalConfig(
                           extconf, policy.template_arguments, tpl_args_base);
    bool selected_base_valid =
        effective && validateSelectedExternalBase(
                         extconf, parsed.target, parsed.simple_subscription,
                         policy.generator.nodelist, candidate.context);
    if (loaded.ok() && effective && selected_base_valid) {
      applyExternalConfig(extconf, candidate.context);
      configLoadSuccess = true;
      plan.config_load_success = true;
      parsed.explain.external_config_loaded = true;
      parsed.explain.fallback_config_used = candidate.fallback;
      break;
    }

    policy.template_arguments.local_vars = tpl_args_base;
    std::string reason = !loaded.ok()
                             ? loadStatusName(loaded.status)
                             : (!effective ? "no_effective_settings"
                                           : "selected_base_invalid");
    writeLog(0, "外部配置不可用，原因：" + reason + "，来源：" +
                    summarizeUrlForLog(candidate.path),
             LOG_LEVEL_WARNING);
  }

  if (!configLoadSuccess) {
    policy.template_arguments.local_vars = tpl_args_base;
    response.status_code = plan.user_provided_external_config ? 400 : 500;
    response.content_type = "text/plain; charset=utf-8";
    response.headers["Cache-Control"] = "private, no-store";
    if (plan.user_provided_external_config)
      return "Invalid request: selected external configuration could not be "
             "loaded or applied.\n"
             "无效请求：无法加载或应用用户选择的外部配置。";
    return "Server configuration error: default external configuration could "
           "not be loaded or applied.\n"
           "服务器配置错误：无法加载或应用默认外部配置。";
  }

  const size_t externalRuleSourceCount =
      rulePrependSources.size() + ruleAppendSources.size();
  if (externalRuleSourceCount) {
    if (settings.maxAllowedRulesets &&
        externalRuleSourceCount > settings.maxAllowedRulesets) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend contain more "
             "sources than max_allowed_rulesets (" +
             std::to_string(settings.maxAllowedRulesets) +
             ").\n"
             "无效请求：ruleprepend 与 ruleappend 的来源总数超过 "
             "max_allowed_rulesets 限制（" +
             std::to_string(settings.maxAllowedRulesets) + "）。";
    }
    if (parsed.target != "clash") {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend are supported only "
             "for target=clash.\n"
             "无效请求：ruleprepend 与 ruleappend 第一版仅支持 "
             "target=clash。";
    }
    if (parsed.generate_node_list.get(false)) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend do not support "
             "list=true.\n"
             "无效请求：ruleprepend 与 ruleappend 不支持 list=true。";
    }
    if (parsed.generate_clash_script.get(false)) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend do not support "
             "script=true.\n"
             "无效请求：ruleprepend 与 ruleappend 不支持 script=true。";
    }

    std::string external_rule_error;
    if (!fetchExternalRuleSources(rulePrependSources, "ruleprepend",
                                  externalRuleFetchContext,
                                  policy.generator.rule_prepend,
                                  external_rule_error) ||
        !fetchExternalRuleSources(ruleAppendSources, "ruleappend",
                                  externalRuleFetchContext,
                                  policy.generator.rule_append,
                                  external_rule_error)) {
      response.status_code = 400;
      return external_rule_error;
    }
  }

  if (policy.generator.enable_rule_generator &&
      !policy.generator.nodelist && !parsed.simple_subscription) {
    if (policy.custom_rulesets != settings.customRulesets)
      refreshRulesets(policy.custom_rulesets, plan.ruleset_content,
                      rulesetFetchContext);
    else {
      if (settings.updateRulesetOnRequest)
        refreshRulesets(policy.custom_rulesets, plan.ruleset_content,
                        rulesetFetchContext);
      else
        plan.ruleset_content = settings.rulesetsContent;
    }
  }
  parsed.explain.rule_generator_enabled =
      policy.generator.enable_rule_generator;
  parsed.explain.base_fetch_context =
      fetchContextName(plan.base_fetch_context);
  parsed.explain.ruleset_fetch_context =
      fetchContextName(rulesetFetchContext);
  parsed.explain.ruleset_count = plan.ruleset_content.size();
  parsed.explain.custom_group_count = policy.custom_proxy_groups.size();

  if (!parsed.emoji.is_undef()) {
    parsed.add_emoji.set(parsed.emoji);
    parsed.remove_emoji.set(true);
  }
  policy.generator.add_emoji = parsed.add_emoji.get(settings.addEmoji);
  policy.generator.remove_emoji =
      parsed.remove_emoji.get(settings.removeEmoji);
  if (policy.generator.add_emoji && policy.generator.emoji_array.empty())
    policy.generator.emoji_array = settings.emojis;
  if (!parsed.renames.empty()) {
    policy.generator.rename_array =
        INIBinding::from<RegexMatchConfig>::from_ini(
            split(parsed.renames, "`"), "@");
    policy.generator.rename_for_providers = true;
  } else if (policy.generator.rename_array.empty())
    policy.generator.rename_array = settings.renames;

  if (!parsed.include_remark.empty() && regValid(parsed.include_remark))
    policy.include_remarks = string_array{parsed.include_remark};
  if (!parsed.exclude_remark.empty() && regValid(parsed.exclude_remark))
    policy.exclude_remarks = string_array{parsed.exclude_remark};

  return "";
}

struct SubscriptionNodeState {
  std::vector<Proxy> nodes;
  std::string subscription_info;
};

struct SubStageResponse {
  bool complete = false;
  std::string body;
};

static SubStageResponse processSubscriptionNodes(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    SubscriptionNodeState &state) {
  int *status_code = &response.status_code;
  std::string &argTarget = parsed.target;
  std::string &argUrl = parsed.url;
  std::string &argGroupName = parsed.group_name;
  std::string &argProviderHeaders = parsed.provider_headers;
  tribool &argUpload = parsed.upload;
  tribool &argEnableInsert = parsed.enable_insert;
  tribool &argAppendUserinfo = parsed.append_userinfo;
  tribool &argPrependInsert = parsed.prepend_insert;
  SubExplainReport &explain = parsed.explain;
  string_array &lIncludeRemarks = policy.include_remarks;
  string_array &lExcludeRemarks = policy.exclude_remarks;
  std::map<std::string, std::string> &provider_headers =
      policy.provider_headers;
  ProxyPolicy &proxy = policy.subscription_proxy;
  extra_settings &ext = policy.generator;

  RegexMatchConfigs stream_temp = settings.streamNodeRules,
                    time_temp = settings.timeNodeRules;
  string_array urls;
  std::vector<Proxy> &nodes = state.nodes;
  std::vector<Proxy> insert_nodes;
  std::string &subInfo = state.subscription_info;
  int groupID = 0;

  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = &lExcludeRemarks;
  parse_set.include_remarks = &lIncludeRemarks;
  parse_set.stream_rules = &stream_temp;
  parse_set.time_rules = &time_temp;
  parse_set.sub_info = &subInfo;
  parse_set.mihomo_only = argTarget == "clash" || argTarget == "clashr";
  string_icase_map subscription_headers = buildSubscriptionRequestHeaders();
  std::string selected_user_agent = providerUserAgentFromRequest(request);
  if (!selected_user_agent.empty())
    subscription_headers["User-Agent"] = selected_user_agent;
  for (const auto &[name, value] : provider_headers)
    subscription_headers[name] = value;
  parse_set.request_header = &subscription_headers;
  parse_set.fetch_context = FetchContext::TrustedConfig;
  parse_set.js_runtime = ext.js_runtime;
  parse_set.js_context = ext.js_context;

  if (!settings.insertUrls.empty() && argEnableInsert) {
    groupID = -1;
    urls = split(settings.insertUrls, "|");
    explain.insert_url_count = urls.size();
    importItems(urls, true);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(0, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。",
               LOG_LEVEL_INFO);
      if (addNodes(x, insert_nodes, groupID, parse_set) == -1) {
        if (settings.skipFailedLinks)
          writeLog(0, "以下链接不包含任何有效节点信息：" + x,
                   LOG_LEVEL_WARNING);
        else {
          *status_code = 400;
          return {true,
                  "Invalid request: this link does not contain any supported "
                  "proxy nodes.\n"
                  "无效请求：该链接不包含任何受支持的代理节点。\n"
                  "Please check whether the link is reachable and the node "
                  "URI format is supported.\n"
                  "请检查链接是否可访问，以及节点 URI 格式是否受支持。\n"
                  "Link / 链接: " +
                      x};
        }
      }
      groupID--;
    }
  }
  urls = split(argUrl, "|");
  explain.raw_url_count = urls.size();
  parse_set.fetch_context = FetchContext::PublicRequest;
  groupID = 0;

  const bool provider_mode_eligible =
      (argTarget == "clash" || argTarget == "clashr") && !ext.nodelist;
  if (!provider_mode_eligible) {
    for (size_t index = 0; index < urls.size(); ++index) {
      TaggedLink tagged = parseTaggedLink(regTrim(urls[index]));
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
    }
  }

  if (provider_mode_eligible) {
    struct SubscriptionLinkItem {
      std::string url;
      std::string tag;
      std::string provider;
      int interval = 0;
      bool proxy_direct = kDefaultProxyProviderDirect;
      bool has_interval = false;
      bool has_proxy_direct = false;
      bool url_decoded = false;
    };
    std::vector<SubscriptionLinkItem> subscription_urls;
    std::vector<std::string> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;
      bool isNodeLink = mihomo::isSupportedNonHttpSchemeLink(link);

      if (isNodeLink) {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        std::string node_link = link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "检测到节点链接：" + summarizeUrlForLog(link) +
                        "，将直接解析。",
                 LOG_LEVEL_INFO);
        node_urls.push_back(node_link);
        explain.node_link_count++;
      } else if (isLink(link) || mihomo::isHttpSchemeLink(link)) {
        writeLog(0, "检测到订阅链接：" + summarizeUrlForLog(link) +
                        "，将创建 provider。",
                 LOG_LEVEL_INFO);
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider, tagged.interval,
             tagged.proxy_direct, tagged.has_interval, tagged.has_proxy_direct,
             tagged.link_decoded});
        explain.subscription_url_count++;
      } else {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        std::string node_link = link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "未知 URL 类型：" + summarizeUrlForLog(link) +
                        "，按节点链接处理。",
                 LOG_LEVEL_WARNING);
        node_urls.push_back(node_link);
        explain.node_link_count++;
        explain.unknown_node_link_count++;
      }
    }

    if (!subscription_urls.empty()) {
      writeLog(0, "检测到订阅 URL，启用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = true;
      std::string provider_user_agent =
          argTarget == "clash" ? providerUserAgentFromRequest(request) : "";
      std::unordered_set<std::string> provider_names;
      auto reserve_provider_name = [&](const std::string &base) {
        std::string base_name =
            clampProviderNameLength(base, kProviderNameMaxLen);
        base_name = trimOf(base_name, '.', true, true);
        if (base_name.empty())
          base_name = "Provider";
        if (provider_names.insert(base_name).second)
          return base_name;
        int index = 1;
        while (true) {
          std::string suffix = "_" + std::to_string(index);
          size_t max_base = kProviderNameMaxLen > suffix.size()
                                ? kProviderNameMaxLen - suffix.size()
                                : 0;
          std::string prefix = clampProviderNameLength(base_name, max_base);
          prefix = trimOf(prefix, '.', true, true);
          if (prefix.empty())
            prefix = clampProviderNameLength("Provider", max_base);
          std::string candidate = prefix + suffix;
          if (provider_names.insert(candidate).second)
            return candidate;
          index++;
        }
      };

      for (const SubscriptionLinkItem &item : subscription_urls) {
        ProxyProvider provider;
        std::string urlHash =
            item.url_decoded ? generateProviderHashFromDecodedUrl(item.url)
                             : generateProviderHash(item.url);
        std::string default_name = "Provider_" + urlHash;
        std::string sanitized_provider = sanitizeProviderName(item.provider);
        std::string base_name =
            sanitized_provider.empty() ? default_name : sanitized_provider;
        base_name = sanitizeProviderName(base_name);
        if (base_name.empty())
          base_name = default_name;
        provider.name = reserve_provider_name(base_name);
        provider.tag = item.tag;
        writeLog(0,
                 "已生成 provider：" + provider.name + "，URL：" +
                     summarizeUrlForLog(item.url),
                 LOG_LEVEL_INFO);
        provider.url = item.url_decoded ? item.url : urlDecode(item.url);
        provider.interval = static_cast<uint32_t>(
            item.has_interval ? item.interval : settings.proxyProviderInterval);
        provider.proxy_direct =
            item.has_proxy_direct ? item.proxy_direct
                                  : ext.provider_proxy_direct;
        provider.groupId = groupID;
        provider.path = "./providers/" + provider.name + ".yaml";
        provider.user_agent = provider_user_agent;
        provider.headers = provider_headers;
        provider.filter = buildProviderRemarkFilter(lIncludeRemarks);
        provider.exclude_filter =
            buildProviderRemarkFilter(lExcludeRemarks);

        ext.providers.push_back(provider);
        SubExplainProvider explain_provider;
        explain_provider.name = provider.name;
        explain_provider.tag = provider.tag;
        explain_provider.source_hash = shortHash(provider.url);
        explain_provider.path = provider.path;
        explain_provider.filter = provider.filter;
        explain_provider.exclude_filter = provider.exclude_filter;
        explain_provider.group_id = provider.groupId;
        explain_provider.interval = provider.interval;
        explain_provider.proxy_direct = provider.proxy_direct;
        explain.providers.push_back(std::move(explain_provider));
        groupID++;
      }
    } else {
      writeLog(0, "未检测到订阅 URL，禁用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = false;
    }

    if (!node_urls.empty()) {
      writeLog(0,
               "正在直接解析 " + std::to_string(node_urls.size()) +
                   " 个节点链接。",
               LOG_LEVEL_INFO);
      importItems(node_urls, true, FetchContext::PublicRequest);
      for (std::string &x : node_urls) {
        writeLog(0, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) +
                        "。",
                 LOG_LEVEL_INFO);
        if (addNodes(x, nodes, groupID, parse_set) == -1) {
          writeLog(0,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。",
                   LOG_LEVEL_WARNING);
        }
        groupID++;
      }
    }
  } else {
    importItems(urls, true, FetchContext::PublicRequest);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(0, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。",
               LOG_LEVEL_INFO);
      if (addNodes(x, nodes, groupID, parse_set) == -1) {
        writeLog(0,
                 "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                     "，继续处理其他节点。",
                 LOG_LEVEL_WARNING);
      }
      groupID++;
    }
  }

  explain.provider_count = ext.providers.size();
  explain.proxy_provider_mode = ext.use_proxy_provider && !ext.providers.empty();
  explain.insert_node_count = insert_nodes.size();
  explain.direct_node_count = nodes.size();
  if (!argProviderHeaders.empty() && !ext.nodelist && ext.providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: provider_headers was selected, but no "
            "proxy-provider was generated.\n"
            "无效请求：已选择 provider_headers，但没有生成 proxy-provider。"};
  }
  if (nodes.empty() && insert_nodes.empty() && ext.providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: no valid proxy nodes or proxy providers were "
            "found.\n"
            "无效请求：未找到有效的代理节点或代理提供者。\n"
            "Please check whether the subscription URL or node URI format is "
            "supported, and whether filters excluded all nodes.\n"
            "请检查订阅链接或节点 URI 格式是否受支持，以及过滤规则是否排除了所有节点。"};
  }
  if (!subInfo.empty() && argAppendUserinfo.get(settings.appendUserinfo))
    response.headers.emplace("Subscription-UserInfo", subInfo);

  if (request.method == "HEAD")
    return {true, ""};

  if (argUpload && !isPublicUploadAllowed()) {
    *status_code = 403;
    return {true,
            "Upload is disabled for the current security profile.\n"
            "当前安全档位已禁用公开请求上传。\n"
            "Use security.profile=lan for private deployments, or explicitly "
            "enable security.allow_public_upload in public profile.\n"
            "内网私有部署请使用 security.profile=lan；公网档位如确需上传，"
            "请显式开启 security.allow_public_upload。"};
  }

  argPrependInsert.define(settings.prependInsert);
  if (argPrependInsert) {
    std::move(nodes.begin(), nodes.end(), std::back_inserter(insert_nodes));
    nodes.swap(insert_nodes);
  } else {
    std::move(insert_nodes.begin(), insert_nodes.end(),
              std::back_inserter(nodes));
  }

  std::string filterScript = settings.filterScript;
  if (!filterScript.empty()) {
    if (startsWith(filterScript, "path:"))
      filterScript = fileGet(filterScript.substr(5), false);
    script_safe_runner(
        ext.js_runtime, ext.js_context,
        [&](qjs::Context &ctx) {
          try {
            ctx.eval(filterScript);
            auto filter =
                (std::function<bool(const Proxy &)>)ctx.eval("filter");
            nodes.erase(std::remove_if(nodes.begin(), nodes.end(), filter),
                        nodes.end());
          } catch (qjs::exception) {
            script_print_stack(ctx);
          }
        },
        settings.scriptCleanContext);
  }

  if (!argGroupName.empty())
    for (Proxy &node : nodes)
      node.Group = argGroupName;

  preprocessNodes(nodes, ext);
  explain.total_node_count = nodes.size();
  return {};
}

struct TargetGenerationState {
  std::string output;
  std::string managed_url;
};

static SubStageResponse dispatchTargetGenerator(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    ExternalConfigFetchPlan &fetch_plan,
    SubscriptionNodeState &subscription, TargetGenerationState &generation) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;
  auto &target = parsed.target;
  auto &surge_version_text = parsed.surge_version_text;
  auto &group_name = parsed.group_name;
  auto &upload_path = parsed.upload_path;
  auto &upload = parsed.upload;
  auto &ext = policy.generator;
  auto &template_arguments = policy.template_arguments;
  auto &proxy = policy.subscription_proxy;
  auto &nodes = subscription.nodes;
  auto &subscription_info = subscription.subscription_info;
  auto &ruleset_content = fetch_plan.ruleset_content;
  const FetchContext base_context = fetch_plan.base_fetch_context;
  std::string base_content;
  std::string &output = generation.output;
  ProxyGroupConfigs dummy_group;
  std::vector<RulesetContent> dummy_ruleset;

  std::string &managed_url = generation.managed_url;
  managed_url = base64Decode(getUrlArg(argument, "profile_data"));
  if (managed_url.empty())
    managed_url =
        settings.managedConfigPrefix + "/sub?" + joinArguments(argument);

  bool upload_failed = false;
  auto recordUpload = [&](const std::string &name, const std::string &path,
                          const std::string &content, bool write_manage_url) {
    if (uploadGist(name, path, content, write_manage_url) != 0)
      upload_failed = true;
  };

  proxy = parseProxy(settings.proxyConfig);
  switch (hash_(target)) {
  case "clash"_hash:
  case "clashr"_hash:
    writeLog(0, target == "clashr" ? "生成目标：ClashR" : "生成目标：Clash",
             LOG_LEVEL_INFO);
    template_arguments.local_vars["clash.new_field_name"] =
        ext.clash_new_field_name ? "true" : "false";
    response.headers["profile-update-interval"] =
        std::to_string(policy.update_interval / 3600);
    if (ext.nodelist) {
      YAML::Node yamlnode;
      proxyToClash(nodes, yamlnode, dummy_group, target == "clashr", ext);
      output = YAML::Dump(yamlnode);
    } else {
      if (render_template(fetchFile(policy.clash_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
      output = proxyToClash(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, target == "clashr",
                            ext);
      if (!ext.external_rule_error.empty()) {
        *status_code = 400;
        return {true, ext.external_rule_error};
      }
    }
    if (upload)
      recordUpload(target, upload_path, output, false);
    break;

  case "surge"_hash:
    writeLog(0, "生成目标：Surge " + std::to_string(parsed.surge_version),
             LOG_LEVEL_INFO);
    if (ext.nodelist) {
      output = proxyToSurge(nodes, base_content, dummy_ruleset, dummy_group,
                            parsed.surge_version, ext);
      if (upload)
        recordUpload("surge" + surge_version_text + "list", upload_path,
                     output, true);
    } else {
      if (render_template(fetchFile(policy.surge_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
      output = proxyToSurge(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, parsed.surge_version,
                            ext);
      if (upload)
        recordUpload("surge" + surge_version_text, upload_path, output, true);
      if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
        output = "#!MANAGED-CONFIG " + managed_url +
                 (policy.update_interval
                      ? " interval=" +
                            std::to_string(policy.update_interval)
                      : "") +
                 " strict=" +
                 std::string(policy.update_strict ? "true" : "false") +
                 "\n\n" + output;
    }
    break;

  case "surfboard"_hash:
    writeLog(0, "生成目标：Surfboard", LOG_LEVEL_INFO);
    if (render_template(fetchFile(policy.surfboard_base, proxy,
                                  settings.cacheConfig, true, base_context),
                        template_arguments, base_content, settings.templatePath,
                        base_context) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToSurge(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, -3, ext);
    if (upload)
      recordUpload("surfboard", upload_path, output, true);
    if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
      output = "#!MANAGED-CONFIG " + managed_url +
               (policy.update_interval
                    ? " interval=" + std::to_string(policy.update_interval)
                    : "") +
               " strict=" +
               std::string(policy.update_strict ? "true" : "false") +
               "\n\n" + output;
    break;

  case "mellow"_hash:
    writeLog(0, "生成目标：Mellow", LOG_LEVEL_INFO);
    if (render_template(fetchFile(policy.mellow_base, proxy,
                                  settings.cacheConfig, true, base_context),
                        template_arguments, base_content, settings.templatePath,
                        base_context) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToMellow(nodes, base_content, ruleset_content,
                           policy.custom_proxy_groups, ext);
    if (upload)
      recordUpload("mellow", upload_path, output, true);
    break;

  case "sssub"_hash:
    writeLog(0, "生成目标：SS Subscription", LOG_LEVEL_INFO);
    if (render_template(fetchFile(policy.sssub_base, proxy,
                                  settings.cacheConfig, true, base_context),
                        template_arguments, base_content, settings.templatePath,
                        base_context) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToSSSub(base_content, nodes, ext);
    if (upload)
      recordUpload("sssub", upload_path, output, false);
    break;

  case "ss"_hash:
    writeLog(0, "生成目标：SS", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("ss", upload_path, output, false);
    break;
  case "ssr"_hash:
    writeLog(0, "生成目标：SSR", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("ssr", upload_path, output, false);
    break;
  case "v2ray"_hash:
    writeLog(0, "生成目标：v2rayN", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("v2ray", upload_path, output, false);
    break;
  case "trojan"_hash:
    writeLog(0, "生成目标：Trojan", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("trojan", upload_path, output, false);
    break;
  case "vless"_hash:
    writeLog(0, "生成目标：vless", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("vless", upload_path, output, false);
    break;
  case "hysteria2"_hash:
    writeLog(0, "生成目标：hysteria2", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("hysteria2", upload_path, output, false);
    break;
  case "mixed"_hash:
    writeLog(0, "生成目标：Standard Subscription", LOG_LEVEL_INFO);
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("sub", upload_path, output, false);
    break;

  case "quan"_hash:
    writeLog(0, "生成目标：Quantumult", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(policy.quan_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToQuan(nodes, base_content, ruleset_content,
                         policy.custom_proxy_groups, ext);
    if (upload)
      recordUpload("quan", upload_path, output, false);
    break;

  case "quanx"_hash:
    writeLog(0, "生成目标：Quantumult X", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(policy.quanx_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToQuanX(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, ext);
    if (upload)
      recordUpload("quanx", upload_path, output, false);
    break;

  case "loon"_hash:
    writeLog(0, "生成目标：Loon", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(policy.loon_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToLoon(nodes, base_content, ruleset_content,
                         policy.custom_proxy_groups, ext);
    if (upload)
      recordUpload("loon", upload_path, output, false);
    break;

  case "ssd"_hash:
    writeLog(0, "生成目标：SSD", LOG_LEVEL_INFO);
    output = proxyToSSD(nodes, group_name, subscription_info, ext);
    if (upload)
      recordUpload("ssd", upload_path, output, false);
    break;

  case "singbox"_hash:
    writeLog(0, "生成目标：sing-box", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(policy.singbox_base, proxy,
                                    settings.cacheConfig, true, base_context),
                          template_arguments, base_content,
                          settings.templatePath, base_context) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToSingBox(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, ext);
    if (upload)
      recordUpload("singbox", upload_path, output, false);
    break;

  default:
    writeLog(0, "生成目标：未指定", LOG_LEVEL_INFO);
    *status_code = 500;
    return {true,
            "Internal error: target passed validation but no generator handled "
            "it.\n"
            "内部错误：target 已通过校验，但没有对应的生成器处理它。\n"
            "Please report this request to the service maintainer.\n"
            "请将该请求反馈给服务维护者。"};
  }

  if (upload_failed)
    writeLog(0,
             "GIST_OPTIONAL_UPLOAD_FAILED action=return-conversion-result",
             LOG_LEVEL_WARNING);
  writeLog(0, "生成完成。", LOG_LEVEL_INFO);
  return {};
}

static std::string assembleSubResponse(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    ExternalConfigFetchPlan &fetch_plan, TargetGenerationState &generation) {
  auto &argument = request.argument;
  std::string &argTarget = parsed.target;
  bool explainMode = parsed.explain_mode;
  SubExplainReport &explain = parsed.explain;
  tribool &argClashNewField = parsed.clash_new_field;
  int intSurgeVer = parsed.surge_version;
  std::string &argGroupName = parsed.group_name;
  std::string &argUploadPath = parsed.upload_path;
  std::string &argIncludeRemark = parsed.include_remark;
  std::string &argExcludeRemark = parsed.exclude_remark;
  std::string &argFilename = parsed.filename;
  std::string &argRenames = parsed.renames;
  tribool &argUpload = parsed.upload;
  tribool &argAddEmoji = parsed.add_emoji;
  tribool &argRemoveEmoji = parsed.remove_emoji;
  tribool &argAppendType = parsed.append_type;
  tribool &argSort = parsed.sort;
  tribool &argUseSortScript = parsed.use_sort_script;
  tribool &argGenClashScript = parsed.generate_clash_script;
  tribool &argEnableInsert = parsed.enable_insert;
  tribool &argFilterDeprecated = parsed.filter_deprecated;
  tribool &argExpandRulesets = parsed.expand_rulesets;
  tribool &argAppendUserinfo = parsed.append_userinfo;
  tribool &argPrependInsert = parsed.prepend_insert;
  tribool &argGenClassicalRuleProvider =
      parsed.generate_classical_rule_provider;
  tribool &argProviderProxyDirect = parsed.provider_proxy_direct;
  ProxyGroupConfigs &lCustomProxyGroups = policy.custom_proxy_groups;
  string_array &lIncludeRemarks = policy.include_remarks;
  string_array &lExcludeRemarks = policy.exclude_remarks;
  extra_settings &ext = policy.generator;
  int interval = policy.update_interval;
  bool strict = policy.update_strict;
  std::map<std::string, std::string> &provider_headers =
      policy.provider_headers;
  bool userProvidedExternalConfig =
      fetch_plan.user_provided_external_config;
  bool configLoadSuccess = fetch_plan.config_load_success;
  std::vector<RulesetContent> &lRulesetContent =
      fetch_plan.ruleset_content;
  std::string &output_content = generation.output;
  std::string &managed_url = generation.managed_url;

  if (argTarget == "clash" && explain.proxy_provider_mode)
    appendVaryHeader(response, "User-Agent");
  for (const auto &[name, value] : provider_headers) {
    (void)value;
    appendVaryHeader(response, name);
  }

  if (explainMode) {
    auto hasArg = [&](const std::string &name) {
      return argument.find(name) != argument.end();
    };
    auto rawArg = [&](const std::string &name) {
      return getUrlArg(argument, name);
    };
    auto addParameter = [&](const std::string &name,
                            const std::string &effective_value,
                            const std::string &status,
                            const std::string &note,
                            bool sensitive = false,
                            const std::string &source = "request") {
      if (!hasArg(name))
        return;
      std::string raw_value = rawArg(name);
      std::string decoded_value = urlDecode(raw_value);
      SubExplainParameter parameter;
      parameter.name = name;
      parameter.present = true;
      parameter.source = source;
      parameter.status = status;
      parameter.value_preview = previewExplainValue(raw_value, sensitive);
      parameter.value_hash = shortHash(decoded_value);
      parameter.raw_length = raw_value.size();
      parameter.value_length = decoded_value.size();
      parameter.effective_value = effective_value;
      parameter.note = note;
      parameter.sensitive = sensitive;
      explain.recognized_parameters.push_back(std::move(parameter));
    };
    auto addSwitchParameter = [&](const std::string &name, bool effective_value,
                                  const tribool &arg_value,
                                  const std::string &note = "") {
      addParameter(name, boolString(effective_value),
                   arg_value.is_undef() ? "defaulted" : "applied", note);
    };
    auto addConfigSection = [&](const std::string &name,
                                const std::string &source,
                                const std::string &status,
                                const std::string &detail) {
      SubExplainConfigSection section;
      section.name = name;
      section.source = source;
      section.status = status;
      section.detail = detail;
      explain.effective_config_sections.push_back(std::move(section));
    };

    addParameter("target", argTarget,
                 explain.requested_target != argTarget ? "resolved" : "applied",
                 explain.requested_target != argTarget
                     ? "target=auto was resolved from the User-Agent"
                     : "");
    addParameter("url",
                 std::to_string(explain.raw_url_count) +
                     " source item(s), " +
                     std::to_string(explain.subscription_url_count) +
                     " subscription(s), " +
                     std::to_string(explain.node_link_count) + " node link(s)",
                 "applied",
                 "Sensitive values are redacted; use hash and length to "
                 "compare inputs.",
                 true);
    addParameter("explain", "true", "applied",
                 "The request returned a JSON diagnostic report.");
    addParameter("ver", std::to_string(intSurgeVer), "applied",
                 "Surge-compatible target version.");
    addParameter("new_name", boolString(ext.clash_new_field_name),
                 argClashNewField.is_undef() ||
                         argClashNewField.get(false) == ext.clash_new_field_name
                     ? "applied"
                     : "overridden",
                 "Mihomo-compatible field names are forced for Clash output.");
    addParameter("group", argGroupName,
                 argGroupName.empty() ? "ignored" : "applied",
                 "Overrides the group name on direct nodes.");
    addParameter("upload_path", argUploadPath,
                 argUpload ? "applied" : "ignored",
                 "Only used when upload is effective.", true);
    addParameter("include", argIncludeRemark,
                 !argIncludeRemark.empty() && regValid(argIncludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider include filter when valid.");
    addParameter("exclude", argExcludeRemark,
                 !argExcludeRemark.empty() && regValid(argExcludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider exclude filter when valid.");
    addParameter("groups", std::to_string(lCustomProxyGroups.size()) +
                              " custom group(s)",
                 configLoadSuccess ? "ignored" : "applied",
                 configLoadSuccess
                     ? "External config loaded; request groups were not used."
                     : "Decoded from URL-safe base64.");
    addParameter("ruleset", std::to_string(lRulesetContent.size()) +
                                " loaded ruleset(s)",
                 configLoadSuccess ? "ignored" : "applied",
                 configLoadSuccess
                     ? "External config loaded; request rulesets were not used."
                     : "Decoded from URL-safe base64.");
    std::string config_effective = explain.external_config_loaded
                                       ? "loaded"
                                       : "not loaded";
    if (explain.fallback_config_used)
      config_effective = "fallback loaded";
    addParameter("config", config_effective,
                 explain.external_config_loaded ? "applied" : "ignored",
                 explain.fallback_config_used
                     ? "User config failed and a fallback config was loaded."
                     : "External config URL or data source.",
                 true);
    addParameter("dev_id", ext.quanx_dev_id,
                 ext.quanx_dev_id.empty() ? "ignored" : "applied",
                 "Quantumult X device id.");
    addParameter("filename", argFilename, "ignored",
                 "Content-Disposition is not emitted for explain JSON.");
    addParameter("interval", std::to_string(interval), "applied",
                 "Effective update interval in seconds.");
    addParameter("strict", boolString(strict), "applied",
                 "Managed config strict flag.");
    addParameter("rename", std::to_string(ext.rename_array.size()) +
                               " rename rule(s)",
                 argRenames.empty() ? "ignored" : "applied",
                 "Request rename rules override configured rename rules.");
    addParameter("filter_script", "not used", "ignored",
                 "Public requests cannot provide executable filter scripts.",
                 true);
    addParameter("provider_headers",
                 std::to_string(provider_headers.size()) +
                     " explicitly selected header(s)",
                 provider_headers.empty() ? "ignored" : "applied",
                 "Only named, present, non-reserved request headers are "
                 "copied into generated proxy-providers.");
    addParameter("upload", boolString(argUpload), explain.upload_suppressed
                                                    ? "suppressed"
                                                    : "applied",
                 explain.upload_suppressed
                     ? "Uploads are disabled in explain mode."
                     : "");
    addParameter("emoji", boolString(ext.add_emoji), "applied",
                 "Sets add_emoji and remove_emoji together.");
    addSwitchParameter("add_emoji", ext.add_emoji, argAddEmoji);
    addSwitchParameter("remove_emoji", ext.remove_emoji, argRemoveEmoji);
    addSwitchParameter("append_type", ext.append_proxy_type, argAppendType);
    addSwitchParameter("tfo", ext.tfo.get(false), ext.tfo);
    addSwitchParameter("udp", ext.udp.get(false), ext.udp);
    addParameter("list", boolString(ext.nodelist), "applied",
                 ext.nodelist
                     ? "Explicit node-list mode expands subscription sources."
                     : "Clash-compatible output defaults to provider mode.");
    addSwitchParameter("sort", ext.sort_flag, argSort);
    addParameter("sort_script",
                 argUseSortScript ? "enabled" : "disabled",
                 argUseSortScript ? "applied" : "ignored",
                 "Uses configured sort script when sorting is enabled.");
    addSwitchParameter("script", ext.clash_script, argGenClashScript);
    addSwitchParameter("insert", argEnableInsert.get(settings.enableInsert),
                       argEnableInsert);
    addSwitchParameter("scv", ext.skip_cert_verify.get(false),
                       ext.skip_cert_verify);
    addSwitchParameter("fdn", ext.filter_deprecated, argFilterDeprecated);
    addSwitchParameter("expand", explain.expand_rulesets, argExpandRulesets);
    addSwitchParameter("append_info",
                       argAppendUserinfo.get(settings.appendUserinfo),
                       argAppendUserinfo);
    addSwitchParameter("prepend", argPrependInsert.get(settings.prependInsert),
                       argPrependInsert);
    addSwitchParameter("classic", ext.clash_classical_ruleset,
                       argGenClassicalRuleProvider);
    addSwitchParameter("tls13", ext.tls13.get(false), ext.tls13);
    addSwitchParameter("provider_proxy_direct", ext.provider_proxy_direct,
                       argProviderProxyDirect);
    addParameter("profile_data", managed_url.empty() ? "not used" : "provided",
                 managed_url.empty() ? "ignored" : "applied",
                 "Managed config URL override.", true);

    const std::unordered_set<std::string> known_parameters = {
        "target", "url", "ver", "new_name", "group", "upload_path",
        "include", "exclude", "groups", "ruleset", "config", "dev_id",
        "filename", "interval", "strict", "rename", "filter_script",
        "upload", "emoji", "add_emoji", "remove_emoji", "append_type",
        "tfo", "udp", "list", "sort", "sort_script", "script", "insert",
        "scv", "fdn", "expand", "append_info", "prepend", "classic",
        "tls13", "provider_proxy_direct", "provider_headers", "explain",
        "profile_data", "token"};
    for (const auto &arg : argument) {
      if (known_parameters.find(arg.first) != known_parameters.end())
        continue;
      std::string decoded_value = urlDecode(arg.second);
      SubExplainParameter parameter;
      parameter.name = arg.first;
      parameter.present = true;
      parameter.source = "request";
      parameter.status = "ignored";
      parameter.value_preview = previewExplainValue(arg.second, false);
      parameter.value_hash = shortHash(decoded_value);
      parameter.raw_length = arg.second.size();
      parameter.value_length = decoded_value.size();
      parameter.effective_value = "";
      parameter.note = "This parameter is not recognized by /sub.";
      parameter.sensitive = false;
      explain.unrecognized_parameters.push_back(std::move(parameter));
    }

    if (explain.fallback_config_used)
      explain.effective_config_source = "fallback";
    else if (explain.external_config_loaded && userProvidedExternalConfig)
      explain.effective_config_source = "request";
    else if (explain.external_config_loaded && !settings.defaultExtConfig.empty())
      explain.effective_config_source = "default";
    else if (userProvidedExternalConfig)
      explain.effective_config_source = "request_failed";
    else
      explain.effective_config_source = "none";

    if (explain.external_config_provided || explain.external_config_loaded) {
      addConfigSection("external_config", explain.effective_config_source,
                       explain.external_config_loaded ? "loaded" : "not_loaded",
                       explain.fallback_config_used
                           ? "Fallback config was used."
                           : (userProvidedExternalConfig
                                  ? "User-provided config was evaluated."
                                  : "Default external config was evaluated."));
    }
    addConfigSection("base_template", explain.base_fetch_context, "selected",
                     "Base template fetch context for target " + argTarget +
                         ".");
    if (explain.rule_generator_enabled)
      addConfigSection("rulesets", explain.ruleset_fetch_context, "loaded",
                       std::to_string(explain.ruleset_count) +
                           " ruleset(s).");
    if (explain.custom_group_count)
      addConfigSection("custom_groups", "effective", "loaded",
                       std::to_string(explain.custom_group_count) +
                           " custom group(s).");
    if (!ext.rename_array.empty())
      addConfigSection("rename", argRenames.empty() ? "configured" : "request",
                       "loaded",
                       std::to_string(ext.rename_array.size()) +
                           " rename rule(s).");
    if (!ext.emoji_array.empty())
      addConfigSection("emoji", "configured", "loaded",
                       std::to_string(ext.emoji_array.size()) +
                           " emoji rule(s).");
    if (!lIncludeRemarks.empty() || !lExcludeRemarks.empty())
      addConfigSection("filters", "effective", "loaded",
                       std::to_string(lIncludeRemarks.size()) +
                           " include filter(s), " +
                           std::to_string(lExcludeRemarks.size()) +
                           " exclude filter(s).");
    if (explain.provider_count)
      addConfigSection("proxy_providers", "request", "generated",
                       std::to_string(explain.provider_count) +
                           " provider(s).");
    if (explain.managed_config)
      addConfigSection("managed_config", "global", "enabled",
                       "Managed config prefix is available.");

    explain.output_bytes = output_content.size();
    writeLog(0,
             "已生成 /sub explain JSON 诊断结果：target=" + argTarget +
                 ", status=" + std::to_string(response.status_code) +
                 ", providers=" + std::to_string(explain.provider_count) +
                 ", nodes=" + std::to_string(explain.total_node_count) +
                 ", recognized_params=" +
                 std::to_string(explain.recognized_parameters.size()) +
                 ", unrecognized_params=" +
                 std::to_string(explain.unrecognized_parameters.size()) + "。",
             LOG_LEVEL_INFO);
    response.content_type = "application/json; charset=utf-8";
    return serializeSubExplainReport(explain, response);
  }
  if (!argFilename.empty())
    response.headers.emplace("Content-Disposition",
                             "attachment; filename=\"" + argFilename +
                                 "\"; filename*=utf-8''" +
                                 urlEncode(argFilename));
  return output_content;
}

} // namespace

static std::string subconverter_impl(Request &request, Response &response,
                                     const Settings &settings,
                                     RuleConversionStats *rule_stats) {
  ParsedSubRequest parsed_request;
  std::string parse_error =
      parseSubRequestArguments(request, response, settings, parsed_request);
  if (!parse_error.empty())
    return parse_error;

  EffectiveSubPolicy effective_policy;
  std::string policy_error = buildEffectiveSubPolicy(
      request, response, settings, rule_stats, parsed_request, effective_policy);
  if (!policy_error.empty())
    return policy_error;

  ExternalConfigFetchPlan fetch_plan;
  std::string fetch_plan_error = buildExternalConfigFetchPlan(
      response, settings, parsed_request, effective_policy, fetch_plan);
  if (!fetch_plan_error.empty())
    return fetch_plan_error;
  SubscriptionNodeState subscription_state;
  SubStageResponse subscription_response = processSubscriptionNodes(
      request, response, settings, parsed_request, effective_policy,
      subscription_state);
  if (subscription_response.complete)
    return subscription_response.body;
  TargetGenerationState generation_state;
  SubStageResponse generation_response = dispatchTargetGenerator(
      request, response, settings, parsed_request, effective_policy,
      fetch_plan, subscription_state, generation_state);
  if (generation_response.complete)
    return generation_response.body;
  return assembleSubResponse(request, response, settings, parsed_request,
                             effective_policy, fetch_plan, generation_state);
}

std::string simpleToClashR(RESPONSE_CALLBACK_ARGS) {
  auto argument = joinArguments(request.argument);
  int *status_code = &response.status_code;

  std::string url = argument.size() <= 8 ? "" : argument.substr(8);
  if (url.empty() || argument.substr(0, 8) != "sublink=") {
    *status_code = 400;
    return "Invalid request: missing sublink parameter.\n"
           "无效请求：缺少 sublink 参数。\n"
           "Please call this endpoint as /sub2clashr?sublink=<subscription-url>.\n"
           "请使用 /sub2clashr?sublink=<订阅链接> 调用该接口。";
  }
  if (url == "sublink") {
    *status_code = 400;
    return "Invalid request: the default placeholder was not replaced with a "
           "subscription link.\n"
           "无效请求：默认占位符没有被替换为订阅链接。\n"
           "Please provide a real subscription URL in the sublink parameter.\n"
           "请在 sublink 参数中提供真实订阅链接。";
  }
  request.argument.emplace("target", "clashr");
  request.argument.emplace("url", urlEncode(url));
  return subconverter(request, response);
}

std::string surgeConfToClash(RESPONSE_CALLBACK_ARGS) {
  auto argument = joinArguments(request.argument);
  int *status_code = &response.status_code;

  INIReader ini;
  string_array dummy_str_array;
  std::vector<Proxy> nodes;
  std::string base_content,
      url = argument.size() <= 5 ? "" : argument.substr(5);
  const std::string proxygroup_name = global.clashUseNewField ? "proxy-groups"
                                                              : "Proxy Group",
                    rule_name = global.clashUseNewField ? "rules" : "Rule";

  ini.store_any_line = true;

  if (url.empty())
    url = global.defaultUrls;
  if (url.empty() || argument.substr(0, 5) != "link=") {
    *status_code = 400;
    return "Invalid request: missing link parameter.\n"
           "无效请求：缺少 link 参数。\n"
           "Please call this endpoint as /surge2clash?link=<surge-config-url>.\n"
           "请使用 /surge2clash?link=<Surge配置链接> 调用该接口。";
  }
  if (url == "link") {
    *status_code = 400;
    return "Invalid request: the default placeholder was not replaced with a "
           "Surge configuration link.\n"
           "无效请求：默认占位符没有被替换为 Surge 配置链接。\n"
           "Please provide a real Surge configuration URL in the link "
           "parameter.\n"
           "请在 link 参数中提供真实 Surge 配置链接。";
  }
  writeLog(0, "SurgeConfToClash 调用，URL：" + summarizeUrlForLog(url) + "。",
           LOG_LEVEL_INFO);

  ProxyPolicy proxy = parseProxy(global.proxyConfig);
  YAML::Node clash;
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;
  tpl_args.local_vars["clash.new_field_name"] =
      global.clashUseNewField ? "true" : "false";
  tpl_args.request_params["target"] = "clash";
  tpl_args.request_params["url"] = url;

  if (render_template(fetchFile(global.clashBase, proxy, global.cacheConfig),
                      tpl_args, base_content, global.templatePath) != 0) {
    *status_code = 400;
    return base_content;
  }
  clash = YAML::Load(base_content);

  base_content = fetchFile(url, proxy, global.cacheConfig);

  if (ini.parse(base_content) != INIREADER_EXCEPTION_NONE) {
    const std::string parser_detail = ini.get_last_error();
    const std::string errmsg = "Invalid request: failed to parse Surge "
                               "configuration.\n"
                               "无效请求：Surge 配置解析失败。";
    // std::cerr<<errmsg<<"\n";
    writeLog(0, "SURGE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(parser_detail),
             LOG_LEVEL_ERROR);
    *status_code = 400;
    return errmsg;
  }
  if (!ini.section_exist("Proxy") || !ini.section_exist("Proxy Group") ||
      !ini.section_exist("Rule")) {
    std::string errmsg =
        "Invalid request: incomplete Surge configuration.\n"
        "无效请求：Surge 配置不完整。\n"
        "Required sections: [Proxy], [Proxy Group], and [Rule].\n"
        "必须包含以下配置段：[Proxy]、[Proxy Group] 和 [Rule]。";
    // std::cerr<<errmsg<<"\n";
    writeLog(0, "Surge 配置不完整，缺少必需配置段。",
             LOG_LEVEL_ERROR);
    *status_code = 400;
    return errmsg;
  }

  // scan groups first, get potential policy-path
  string_multimap section;
  ini.get_items("Proxy Group", section);
  std::string name, type, content;
  string_array links;
  links.emplace_back(url);
  YAML::Node singlegroup;
  for (auto &x : section) {
    singlegroup.reset();
    name = x.first;
    content = x.second;
    dummy_str_array = split(content, ",");
    if (dummy_str_array.empty())
      continue;
    type = dummy_str_array[0];
    if (!(type == "select" || type == "url-test" || type == "fallback" ||
          type == "load-balance"))
      // remove unsupported types
      continue;
    singlegroup["name"] = name;
    singlegroup["type"] = type;
    for (unsigned int i = 1; i < dummy_str_array.size(); i++) {
      if (startsWith(dummy_str_array[i], "url"))
        singlegroup["url"] =
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1));
      else if (startsWith(dummy_str_array[i], "interval"))
        singlegroup["interval"] =
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1));
      else if (startsWith(dummy_str_array[i], "policy-path"))
        links.emplace_back(
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1)));
      else
        singlegroup["proxies"].push_back(trim(dummy_str_array[i]));
    }
    clash[proxygroup_name].push_back(singlegroup);
  }

  proxy = parseProxy(global.proxySubscription);
  eraseElements(dummy_str_array);

  RegexMatchConfigs dummy_regex_array;
  std::string subInfo;
  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = parse_set.include_remarks = &dummy_str_array;
  parse_set.stream_rules = parse_set.time_rules = &dummy_regex_array;
  parse_set.request_header = &request.headers;
  parse_set.sub_info = &subInfo;
  for (std::string &x : links) {
    // std::cerr<<"Fetching node data from url '"<<x<<"'."<<std::endl;
    writeLog(0, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。",
             LOG_LEVEL_INFO);
    if (addNodes(x, nodes, 0, parse_set) == -1) {
      if (global.skipFailedLinks)
        writeLog(0,
                 "以下链接不包含任何有效节点信息：" + x,
                 LOG_LEVEL_WARNING);
      else {
        *status_code = 400;
        return "Invalid request: this link does not contain any supported "
               "proxy nodes.\n"
               "无效请求：该链接不包含任何受支持的代理节点。\n"
               "Please check whether the link is reachable and the node URI "
               "format is supported.\n"
               "请检查链接是否可访问，以及节点 URI 格式是否受支持。\n"
               "Link / 链接: " +
               x;
      }
    }
  }

  // exit if found nothing
  if (nodes.empty()) {
    *status_code = 400;
    return "Invalid request: no valid proxy nodes were found in the Surge "
           "configuration or its policy-path subscriptions.\n"
           "无效请求：Surge 配置或其 policy-path 订阅中未找到有效代理节点。\n"
           "Please check whether the source configuration contains supported "
           "proxy entries.\n"
           "请检查源配置中是否包含受支持的代理条目。";
  }

  extra_settings ext;
  ext.sort_flag = global.enableSort;
  ext.filter_deprecated = global.filterDeprecated;
  ext.clash_new_field_name = global.clashUseNewField;
  ext.udp = global.UDPFlag;
  ext.tfo = global.TFOFlag;
  ext.skip_cert_verify = global.skipCertVerify;
  ext.tls13 = global.TLS13Flag;
  ext.clash_proxies_style = global.clashProxiesStyle;

  ProxyGroupConfigs dummy_groups;
  proxyToClash(nodes, clash, dummy_groups, false, ext);

  section.clear();
  ini.get_items("Proxy", section);
  for (auto &x : section) {
    singlegroup.reset();
    name = x.first;
    content = x.second;
    dummy_str_array = split(content, ",");
    if (dummy_str_array.empty())
      continue;
    content = trim(dummy_str_array[0]);
    switch (hash_(content)) {
    case "direct"_hash:
      singlegroup["name"] = name;
      singlegroup["type"] = "select";
      singlegroup["proxies"].push_back("DIRECT");
      break;
    case "reject"_hash:
    case "reject-tinygif"_hash:
      singlegroup["name"] = name;
      singlegroup["type"] = "select";
      singlegroup["proxies"].push_back("REJECT");
      break;
    default:
      continue;
    }
    clash[proxygroup_name].push_back(singlegroup);
  }

  eraseElements(dummy_str_array);
  ini.get_all("Rule", "{NONAME}", dummy_str_array);
  YAML::Node rule;
  string_array strArray;
  std::string strLine;
  std::stringstream ss;
  std::string::size_type lineSize;
  for (std::string &x : dummy_str_array) {
    if (startsWith(x, "RULE-SET")) {
      strArray = split(x, ",");
      if (strArray.size() != 3)
        continue;
      content = webGet(strArray[1], proxy, global.cacheRuleset);
      if (content.empty())
        continue;

      ss << content;
      char delimiter = getLineBreak(content);

      while (getline(ss, strLine, delimiter)) {
        lineSize = strLine.size();
        if (lineSize && strLine[lineSize - 1] == '\r') // remove line break
          strLine.erase(--lineSize);
        if (!lineSize || strLine[0] == ';' || strLine[0] == '#' ||
            (lineSize >= 2 && strLine[0] == '/' &&
             strLine[1] == '/')) // empty lines and comments are ignored
          continue;
        else if (!std::any_of(ClashRuleTypes.begin(), ClashRuleTypes.end(),
                              [&strLine](const std::string &type) {
                                return startsWith(strLine, type);
                              })) // remove unsupported types
          continue;
        strLine = appendClashRuleTarget(strLine, trim(strArray[2]));
        rule.push_back(strLine);
      }
      ss.clear();
      continue;
    } else if (!std::any_of(ClashRuleTypes.begin(), ClashRuleTypes.end(),
                            [&strLine](const std::string &type) {
                              return startsWith(strLine, type);
                            }))
      continue;
    rule.push_back(x);
  }
  clash[rule_name] = rule;

  response.headers["profile-update-interval"] =
      std::to_string(global.updateInterval / 3600);
  writeLog(0, "转换完成。", LOG_LEVEL_INFO);
  return YAML::Dump(clash);
}

std::string getProfile(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string name = getUrlArg(argument, "name"),
              token = getUrlArg(argument, "token");
  string_array profiles = split(name, "|");
  if (token.empty() || profiles.empty()) {
    *status_code = 403;
    return "Forbidden: missing profile name or access token.\n"
           "禁止访问：缺少配置名称或访问令牌。";
  }
  std::string profile_content;
  name = profiles[0];
  /*if(vfs::vfs_exist(name))
  {
      profile_content = vfs::vfs_get(name);
  }
  else */
  if (fileExist(name)) {
    profile_content = fileGet(name, true);
  } else {
    *status_code = 404;
    return "Profile not found: the requested profile does not exist.\n"
           "未找到配置：请求的 profile 不存在。\n"
           "Profile / 配置: " +
           name;
  }
  // std::cerr<<"Trying to load profile '" + name + "'.\n";
  writeLog(0, "正在加载配置档：'" + name + "'。", LOG_LEVEL_INFO);
  INIReader ini;
  if (ini.parse(profile_content) != INIREADER_EXCEPTION_NONE &&
      !ini.section_exist("Profile")) {
    // std::cerr<<"Load profile failed! Reason: "<<ini.get_last_error()<<"\n";
    const std::string parser_detail = ini.get_last_error();
    writeLog(0, "PROFILE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(parser_detail),
             LOG_LEVEL_ERROR);
    *status_code = 500;
    return "Invalid profile: failed to parse profile content.\n"
           "无效配置：profile 内容解析失败。";
  }
  // std::cerr<<"Trying to parse profile '" + name + "'.\n";
  writeLog(0, "正在解析配置档：'" + name + "'。", LOG_LEVEL_INFO);
  string_multimap contents;
  ini.get_items("Profile", contents);
  if (contents.empty()) {
    // std::cerr<<"Load profile failed! Reason: Empty Profile section\n";
    writeLog(0, "加载配置档失败！原因：[Profile] 配置段为空。",
             LOG_LEVEL_ERROR);
    *status_code = 500;
    return "Invalid profile: [Profile] section is empty.\n"
           "无效配置：[Profile] 配置段为空。\n"
           "Please add at least one profile entry before requesting it.\n"
           "请至少添加一个 profile 条目后再请求。";
  }
  // Token authentication has been disabled - these checks are removed
  // All authentication logic is now bypassed
  // if (profiles.size() == 1 && profile_token != contents.end()) {
  //   authentication skipped
  // }
  /// check if more than one profile is provided
  if (profiles.size() > 1) {
    writeLog(0, "检测到多个配置档，正在合并...",
             LOG_TYPE_INFO);
    std::string all_urls, url;
    auto iter = contents.find("url");
    if (iter != contents.end())
      all_urls = iter->second;
    for (size_t i = 1; i < profiles.size(); i++) {
      name = profiles[i];
      if (!fileExist(name)) {
        writeLog(0, "忽略不存在的配置档：'" + name + "'。",
                 LOG_LEVEL_WARNING);
        continue;
      }
      if (ini.parse_file(name) != INIREADER_EXCEPTION_NONE &&
          !ini.section_exist("Profile")) {
        writeLog(0, "忽略损坏的配置档：'" + name + "'。",
                 LOG_LEVEL_WARNING);
        continue;
      }
      url = ini.get("Profile", "url");
      if (!url.empty()) {
        all_urls += "|" + url;
        writeLog(0, "已添加来自配置档 '" + name + "' 的 URL。", LOG_LEVEL_INFO);
      } else {
        writeLog(0, "配置档 '" + name + "' 没有 url 字段，跳过。",
                 LOG_LEVEL_INFO);
      }
    }
    iter->second = all_urls;
  }

  contents.emplace("token", token);
  contents.emplace("profile_data",
                   base64Encode(global.managedConfigPrefix + "/getprofile?" +
                                joinArguments(argument)));
  std::copy(argument.cbegin(), argument.cend(),
            std::inserter(contents, contents.end()));
  request.argument = contents;
  return subconverter(request, response);
}

/*
std::string jinja2_webGet(const std::string &url)
{
    ProxyPolicy proxy = parseProxy(global.proxyConfig);
    writeLog(0, "模板调用 fetch，URL：'" + url + "'。",
LOG_LEVEL_INFO); return webGet(url, proxy, global.cacheConfig);
}*/

inline std::string intToStream(unsigned long long stream) {
  char chrs[16] = {}, units[6] = {' ', 'K', 'M', 'G', 'T', 'P'};
  double streamval = stream;
  unsigned int level = 0;
  while (streamval > 1024.0) {
    if (level >= 5)
      break;
    level++;
    streamval /= 1024.0;
  }
  snprintf(chrs, 15, "%.2f %cB", streamval, units[level]);
  return {chrs};
}

std::string subInfoToMessage(std::string subinfo) {
  using ull = unsigned long long;
  subinfo = replaceAllDistinct(subinfo, "; ", "&");
  std::string retdata, useddata = "N/A", totaldata = "N/A", expirydata = "N/A";
  std::string upload = getUrlArg(subinfo, "upload"),
              download = getUrlArg(subinfo, "download"),
              total = getUrlArg(subinfo, "total"),
              expire = getUrlArg(subinfo, "expire");
  ull used = to_number<ull>(upload, 0) + to_number<ull>(download, 0),
      tot = to_number<ull>(total, 0);
  auto expiry = to_number<time_t>(expire, 0);
  if (used != 0)
    useddata = intToStream(used);
  if (tot != 0)
    totaldata = intToStream(tot);
  if (expiry != 0) {
    char buffer[30];
    struct tm dt;
    localtime_r(&expiry, &dt);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", &dt);
    expirydata.assign(buffer);
  }
  if (useddata == "N/A" && totaldata == "N/A" && expirydata == "N/A")
    retdata = "不可用";
  else
    retdata += "已用流量：" + useddata + " 总流量：" + totaldata +
               " 到期时间：" + expirydata;
  return retdata;
}

int simpleGenerator() {
  // std::cerr<<"\nReading generator configuration...\n";
  writeLog(0, "正在读取生成器配置...", LOG_LEVEL_INFO);
  std::string config = fileGet("generate.ini"), path, profile, content;
  if (config.empty()) {
    // std::cerr<<"Generator configuration not found or empty!\n";
    writeLog(0, "未找到生成器配置，或配置为空！", LOG_LEVEL_ERROR);
    return -1;
  }

  INIReader ini;
  if (ini.parse(config) != INIREADER_EXCEPTION_NONE) {
    // std::cerr<<"Generator configuration broken!
    // Reason:"<<ini.get_last_error()<<"\n";
    writeLog(0, "GENERATOR_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()),
             LOG_LEVEL_ERROR);
    return -2;
  }
  // std::cerr<<"Read generator configuration completed.\n\n";
  writeLog(0, "生成器配置读取完成。\n", LOG_LEVEL_INFO);

  string_array sections = ini.get_section_names();
  if (!global.generateProfiles.empty()) {
    // std::cerr<<"Generating with specific artifacts:
    // \""<<gen_profile<<"\"...\n";
    writeLog(0,
             "正在按指定生成项生成：\"" + global.generateProfiles + "\"...",
             LOG_LEVEL_INFO);
    string_array targets = split(global.generateProfiles, ","), new_targets;
    for (std::string &x : targets) {
      x = trim(x);
      if (std::find(sections.cbegin(), sections.cend(), x) != sections.cend())
        new_targets.emplace_back(std::move(x));
      else {
        // std::cerr<<"Artifact \""<<x<<"\" not found in generator settings!\n";
        writeLog(0, "生成器设置中未找到生成项：\"" + x + "\"！",
                 LOG_LEVEL_ERROR);
        return -3;
      }
    }
    sections = new_targets;
    sections.shrink_to_fit();
  } else
    // std::cerr<<"Generating all artifacts...\n";
    writeLog(0, "正在生成所有生成项...", LOG_LEVEL_INFO);

  string_multimap allItems;
  ProxyPolicy proxy = parseProxy(global.proxySubscription);
  Request request;
  Response response;
  bool write_failed = false;
  for (std::string &x : sections) {
    response.status_code = 200;
    // std::cerr<<"Generating artifact '"<<x<<"'...\n";
    writeLog(0, "正在生成生成项：'" + x + "'。", LOG_LEVEL_INFO);
    ini.enter_section(x);
    if (ini.item_exist("path"))
      path = ini.get("path");
    else {
      // std::cerr<<"Artifact '"<<x<<"' output path missing! Skipping...\n\n";
      writeLog(0, "生成项 '" + x + "' 缺少输出路径，跳过。\n",
               LOG_LEVEL_ERROR);
      continue;
    }
    if (ini.item_exist("profile")) {
      profile = ini.get("profile");
      request.argument.emplace("name", urlEncode(profile));
      // Token no longer needed as authentication is disabled
      request.argument.emplace("expand", "true");
      content = getProfile(request, response);
    } else {
      if (ini.get_bool("direct")) {
        std::string url = ini.get("url");
        content = fetchFile(url, proxy, global.cacheSubscription);
        if (content.empty()) {
          // std::cerr<<"Artifact '"<<x<<"' generate ERROR! Please check your
          // link.\n\n";
          writeLog(0,
                   "生成项 '" + x + "' 生成失败！请检查链接。\n",
                   LOG_LEVEL_ERROR);
          if (sections.size() == 1)
            return -1;
        }
        // add UTF-8 BOM
        const int write_result =
            fileWrite(path, "\xEF\xBB\xBF" + content, true);
        if (fileCommitFailed(write_result)) {
          writeLog(0,
                   "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                       (fileCommitTemporaryRemaining(write_result)
                            ? " temporary_file_remaining=true"
                            : " temporary_file_remaining=false"),
                   LOG_LEVEL_ERROR);
          write_failed = true;
          if (sections.size() == 1)
            return -1;
        } else if (fileCommitDurabilityUnconfirmed(write_result)) {
          writeLog(0,
                   "ARTIFACT_WRITE_VISIBLE target=" + x +
                       " new_file_visible=true durability=unconfirmed "
                       "action=continue",
                   LOG_LEVEL_WARNING);
        }
        continue;
      }
      ini.get_items(allItems);
      allItems.emplace("expand", "true");
      for (auto &y : allItems) {
        if (y.first == "path")
          continue;
        request.argument.emplace(y.first, y.second);
      }
      content = subconverter(request, response);
    }
    if (response.status_code != 200) {
      // std::cerr<<"Artifact '"<<x<<"' generate ERROR! Reason:
      // "<<content<<"\n\n";
      writeLog(0,
               "生成项 '" + x + "' 生成失败！原因：" + content + "\n",
               LOG_LEVEL_ERROR);
      if (sections.size() == 1)
        return -1;
      continue;
    }
    const int write_result = fileWrite(path, content, true);
    if (fileCommitFailed(write_result)) {
      writeLog(0,
               "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                   (fileCommitTemporaryRemaining(write_result)
                        ? " temporary_file_remaining=true"
                        : " temporary_file_remaining=false"),
               LOG_LEVEL_ERROR);
      write_failed = true;
      if (sections.size() == 1)
        return -1;
      continue;
    }
    if (fileCommitDurabilityUnconfirmed(write_result)) {
      writeLog(0,
               "ARTIFACT_WRITE_VISIBLE target=" + x +
                   " new_file_visible=true durability=unconfirmed "
                   "action=continue",
               LOG_LEVEL_WARNING);
    }
    auto iter =
        std::find_if(response.headers.begin(), response.headers.end(),
                     [](auto y) { return y.first == "Subscription-UserInfo"; });
    if (iter != response.headers.end())
      writeLog(0,
               "生成项 '" + x + "' 的用户信息：" + subInfoToMessage(iter->second),
               LOG_LEVEL_INFO);
    // std::cerr<<"Artifact '"<<x<<"' generate SUCCESS!\n\n";
    writeLog(0, "生成项 '" + x + "' 生成成功！\n", LOG_LEVEL_INFO);
    eraseElements(response.headers);
  }
  // std::cerr<<"All artifact generated. Exiting...\n";
  if (write_failed) {
    writeLog(0, "部分生成项写入失败，正在以失败状态退出...",
             LOG_LEVEL_ERROR);
    return -1;
  }
  writeLog(0, "所有生成项已生成，正在退出...", LOG_LEVEL_INFO);
  return 0;
}

std::string renderTemplate(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string path = getUrlArg(argument, "path");
  writeLog(0, "正在渲染模板：'" + path + "'。", LOG_LEVEL_INFO);

  if (!startsWith(path, global.templatePath) || !fileExist(path)) {
    *status_code = 404;
    return "Template not found or outside the allowed template directory.\n"
           "未找到模板，或模板路径超出允许的模板目录。\n"
           "Please provide a path under the configured template directory.\n"
           "请提供位于已配置模板目录下的路径。";
  }
  std::string template_content =
      fetchFile(path, parseProxy(global.proxyConfig), global.cacheConfig);
  if (template_content.empty()) {
    *status_code = 400;
    return "Invalid template: file is empty or cannot be read within the "
           "allowed scope.\n"
           "无效模板：文件为空，或无法在允许范围内读取。\n"
           "Please check the template content and configured template path.\n"
           "请检查模板内容和已配置的模板路径。";
  }
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;

  // load request arguments as template variables
  string_map req_arg_map;
  for (auto &x : argument) {
    req_arg_map[x.first] = x.second;
  }
  tpl_args.request_params = req_arg_map;

  std::string output_content;
  if (render_template(template_content, tpl_args, output_content,
                      global.templatePath) != 0) {
    *status_code = 400;
    writeLog(0, "渲染失败。", LOG_LEVEL_WARNING);
  } else
    writeLog(0, "渲染完成。", LOG_LEVEL_INFO);

  return output_content;
}
