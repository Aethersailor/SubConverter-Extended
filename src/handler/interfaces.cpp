#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <inja.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <yaml-cpp/yaml.h>

#include "config/binding.h"
#include "generator/config/clash_proxy.h"
#include "generator/config/external_rules.h"
#include "generator/config/nodemanip.h"
#include "generator/config/ruleconvert.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "conversion_service.h"
#include "interfaces.h"
#include "multithread.h"
#include "ruleset_output.h"
#include "parser/mihomo_scheme_utils.h"
#include "parser/mihomo_bridge.h"
#include "parser/subparser.h"
#include "script/cron.h"
#include "script/script_quickjs.h"
#include "server/request_context.h"
#include "server/webserver.h"
#include "settings.h"
#include "settings_view.h"
#include "statistics.h"
#include "sub_request_key.h"
#include "upload.h"
#include "user_agent.h"
#include "webget.h"
#include "utils/time_compat.h"

static string_icase_map buildSubscriptionRequestHeaders() {
  string_icase_map headers;
  headers.emplace("User-Agent", "clash.meta");
  return headers;
}

#include "utils/base64/base64.h"
#include "utils/bounded_executor.h"
#include "utils/cooperative_cpu.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/resource_control.h"
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

enum class RemoteSubscriptionMode {
  ServerSideParse,
  ClashProxyProvider,
  QuanXServerRemote,
  SurgePolicyPath,
  SurfboardPolicyPath,
  LoonRemoteProxy,
  StashProxyProvider,
};

struct TargetDescriptor {
  const char *name;
  NodeParserMode parser_mode;
  RemoteSubscriptionMode remote_subscription_mode;
  bool simple_subscription;
  SingleLinkTypes single_link_types;
};

static constexpr std::array<TargetDescriptor, 22> kTargetDescriptors = {{
    {"clash", NodeParserMode::MihomoOnly,
     RemoteSubscriptionMode::ClashProxyProvider, false, 0},
    {"clashr", NodeParserMode::MihomoOnly,
     RemoteSubscriptionMode::ClashProxyProvider, false, 0},
    {"surge", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::SurgePolicyPath, false, 0},
    {"quan", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, false, 0},
    {"quanx", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::QuanXServerRemote, false, 0},
    {"loon", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::LoonRemoteProxy, false, 0},
    {"surfboard", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::SurfboardPolicyPath, false, 0},
    {"stash", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::StashProxyProvider, false, 0},
    {"mellow", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, false, 0},
    {"singbox", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, false, 0},
    {"ss", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true,
     SingleLinkType::Shadowsocks},
    {"ssd", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, 0},
    {"ssr", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true,
     SingleLinkType::ShadowsocksR},
    {"sssub", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, 0},
    {"v2ray", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, SingleLinkType::VMess},
    {"v2rayn", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, 0},
    {"v2rayng", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, 0},
    {"shadowrocket", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, 0},
    {"trojan", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, SingleLinkType::Trojan},
    {"vless", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, SingleLinkType::VLESS},
    {"hysteria2", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true,
     SingleLinkType::Hysteria2},
    {"mixed", NodeParserMode::LegacyOnly,
     RemoteSubscriptionMode::ServerSideParse, true, SingleLinkType::Mixed},
}};

static const TargetDescriptor *findTargetDescriptor(const std::string &name) {
  const auto found =
      std::find_if(kTargetDescriptors.begin(), kTargetDescriptors.end(),
                   [&](const TargetDescriptor &target) {
                     return name == target.name;
                   });
  return found == kTargetDescriptors.end() ? nullptr : &*found;
}

static const char *nodeParserModeName(NodeParserMode mode) {
  return mode == NodeParserMode::MihomoOnly ? "mihomo" : "legacy";
}

static const char *remoteSubscriptionModeName(RemoteSubscriptionMode mode) {
  switch (mode) {
  case RemoteSubscriptionMode::ClashProxyProvider:
    return "clash-proxy-provider";
  case RemoteSubscriptionMode::QuanXServerRemote:
    return "quanx-server-remote";
  case RemoteSubscriptionMode::SurgePolicyPath:
    return "surge-policy-path";
  case RemoteSubscriptionMode::SurfboardPolicyPath:
    return "surfboard-policy-path";
  case RemoteSubscriptionMode::LoonRemoteProxy:
    return "loon-remote-proxy";
  case RemoteSubscriptionMode::StashProxyProvider:
    return "stash-proxy-provider";
  case RemoteSubscriptionMode::ServerSideParse:
  default:
    return "server-side-parse";
  }
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
    std::string content;
    try {
      content = waitWithoutCpuPermit([&] { return x.rule_content.get(); });
    } catch (const ExecutorSubmitError &error) {
      response.content_type = "text/plain; charset=utf-8";
      response.headers["Cache-Control"] = "private, no-store";
      switch (error.status()) {
      case ExecutorSubmitStatus::Deadline:
        *status_code = 504;
        if (request.context) {
          request.context->requestCancellation(
              RequestCancellationReason::Deadline);
          request.context->suggestFailure(RequestFailureAttribution::Client);
        }
        return "Gateway timeout: ruleset processing exceeded the request "
               "deadline.\n网关超时：规则集处理已超过请求截止时间。\n";
      case ExecutorSubmitStatus::Cancelled:
        if (request.context &&
            request.context->cancellationToken().reason() ==
                RequestCancellationReason::Shutdown) {
          *status_code = 503;
          request.context->suggestFailure(RequestFailureAttribution::Server);
          return "Service is shutting down.\n服务正在关闭。\n";
        }
        *status_code = 499;
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Client);
        return "Client closed request during ruleset processing.\n"
               "客户端在规则集处理期间关闭了请求。\n";
      case ExecutorSubmitStatus::QueueFull:
      case ExecutorSubmitStatus::Recursive:
        response.headers["Retry-After"] = "1";
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Capacity);
        *status_code = 503;
        return "Service temporarily unavailable: ruleset capacity is full.\n"
               "服务暂时不可用：规则集处理容量已满。\n";
      case ExecutorSubmitStatus::Stopping:
        *status_code = 503;
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Server);
        return "Service is shutting down.\n服务正在关闭。\n";
      case ExecutorSubmitStatus::Accepted:
        throw;
      }
    } catch (const std::future_error &) {
      *status_code = 503;
      response.content_type = "text/plain; charset=utf-8";
      response.headers["Cache-Control"] = "private, no-store";
      if (request.context)
        request.context->suggestFailure(RequestFailureAttribution::Server);
      return "Service is shutting down.\n服务正在关闭。\n";
    }
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
  if (target == "stash")
    return &extconf.stash_rule_base;
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
                                       const string_map &tpl_args_base,
                                       const std::string &target) {
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
      (target == "stash" && !extconf.stash_rule_base.empty()) ||
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
  ProxyPolicy proxy = parseProxy(settings.proxyRuleset, settings.proxyBypass);
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
      writeLog(LOG_LEVEL_WARNING,
               "外部规则来源 " + source_identifier +
                   " 拉取失败、HTTP 状态异常或内容为空，已跳过。");
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
         "proxy-providers, Quantumult X server_remote resources, Surge "
         "policy-path resources, or Stash proxy-providers.\n"
         "无效请求：第 " + item +
         " 个 url 项的 interval: 仅适用于会生成 Clash/ClashR "
         "proxy-provider、Quantumult X server_remote、Surge policy-path "
         "或 Stash proxy-provider 资源的订阅链接。";
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

static std::string quanxRemoteSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Quantumult X remote subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Quantumult X 远程订阅项包含未转义空格或控制字符。";
}

static std::string surgePolicyPathSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Surge policy-path subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Surge policy-path 订阅项包含未转义空格或控制字符。";
}

static std::string surfboardPolicyPathSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Surfboard policy-path subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Surfboard policy-path 订阅项包含未转义空格或控制字符。";
}

static std::string loonRemoteProxySourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Loon Remote Proxy subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Loon Remote Proxy 订阅项包含未转义空格或控制字符。";
}

static std::string stashProxyProviderSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Stash proxy-provider subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Stash proxy-provider 订阅项包含未转义空格或控制字符。";
}

static std::string surgePolicyPathIntervalError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: interval: for Surge policy-path item #" + item +
         " must be greater than zero. Omit it to use the client default.\n"
         "无效请求：第 " + item +
         " 个 Surge policy-path 项的 interval: 必须大于 0；省略该前缀可使用客户端默认值。";
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

static std::string sanitizeRemoteResourceName(const std::string &input) {
  std::string tag = sanitizeProviderName(input);
  std::replace(tag.begin(), tag.end(), ',', '_');
  std::replace(tag.begin(), tag.end(), '=', '_');
  tag = trimWhitespace(tag, true, true);
  return tag;
}

static std::string reserveStashProviderName(
    const std::string &base, std::unordered_set<std::string> &reserved_keys) {
  std::string base_name = clampProviderNameLength(base, 64);
  if (base_name.empty())
    base_name = "SubConverter_Provider";
  if (reserved_keys.insert(toLower(base_name)).second)
    return base_name;
  int suffix_index = 1;
  while (true) {
    const std::string suffix = "_" + std::to_string(suffix_index++);
    const size_t max_base = 64 > suffix.size() ? 64 - suffix.size() : 0;
    const std::string candidate =
        clampProviderNameLength(base_name, max_base) + suffix;
    if (reserved_keys.insert(toLower(candidate)).second)
      return candidate;
  }
}

static bool hasUnsafeQuanXRemoteUrlChar(const std::string &url) {
  return std::any_of(url.begin(), url.end(), [](unsigned char ch) {
    return ch <= 0x20 || ch == 0x7f;
  });
}

static bool isHttpSubscriptionLink(const std::string &link,
                                   bool explicitly_remote) {
  if (!mihomo::isHttpSchemeLink(link))
    return false;
  const std::string lower_link = toLower(link);
  if (startsWith(lower_link, "https://t.me/socks") ||
      startsWith(lower_link, "https://t.me/http"))
    return false;
  if (isLegacyHttpProxyUri(link))
    return false;
  if (explicitly_remote)
    return true;
  const size_t protocol_end = link.find("://") + 3;
  const size_t query_start = link.find('?', protocol_end);
  if (query_start != std::string::npos)
    return true;
  const size_t path_start = link.find('/', protocol_end);
  return path_start != std::string::npos &&
         link.size() - path_start > 1;
}

static std::string subconverter_impl(Request &request, Response &response,
                                     const Settings &settings,
                                     RuleConversionStats *rule_stats = nullptr);

namespace {

struct CoalescedResponse {
  int status_code = 200;
  std::string content_type;
  string_icase_map headers;
  shared_response_body body;
  std::string fallback_body;
  bool capacity_rejected = false;
  uint64_t rule_conversions = 0;
};

using SharedCoalescedResponse = std::shared_ptr<const CoalescedResponse>;

struct InflightSubRequest {
  std::mutex mutex;
  std::condition_variable cv;
  std::string owner_request_id;
  std::shared_ptr<RequestContext> work_context;
  std::atomic<uint32_t> consumers{1};
  bool done = false;
  SharedCoalescedResponse result;
  std::exception_ptr exception;

  uint32_t tryAddConsumer() noexcept {
    uint32_t current = consumers.load(std::memory_order_acquire);
    while (current != 0 && current != UINT32_MAX) {
      if (consumers.compare_exchange_weak(current, current + 1,
                                          std::memory_order_acq_rel,
                                          std::memory_order_acquire))
        return current + 1;
    }
    return 0;
  }

  uint32_t releaseConsumer() noexcept {
    uint32_t current = consumers.load(std::memory_order_acquire);
    while (current != 0) {
      if (consumers.compare_exchange_weak(current, current - 1,
                                          std::memory_order_acq_rel,
                                          std::memory_order_acquire))
        return current - 1;
    }
    return 0;
  }
};

struct InflightConsumerState {
  explicit InflightConsumerState(std::shared_ptr<InflightSubRequest> call)
      : call(std::move(call)) {}

  void release() noexcept {
    bool expected = false;
    if (!released.compare_exchange_strong(expected, true,
                                          std::memory_order_acq_rel,
                                          std::memory_order_acquire))
      return;
    if (!call)
      return;
    const uint32_t remaining = call->releaseConsumer();
    if (call->work_context)
      call->work_context->setConsumerCount(remaining);
    bool done = false;
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      done = call->done;
    }
    if (remaining == 0 && !done && call->work_context)
      call->work_context->requestCancellation(
          RequestCancellationReason::NoConsumers);
  }

  std::shared_ptr<InflightSubRequest> call;
  std::atomic<bool> released{false};
};

struct InflightConsumerGuard {
  InflightConsumerGuard(std::shared_ptr<InflightSubRequest> call,
                        const std::shared_ptr<RequestContext> &client_context)
      : state(std::make_shared<InflightConsumerState>(std::move(call))) {
    if (client_context) {
      const std::weak_ptr<InflightConsumerState> weak_state = state;
      cancellation_registration = client_context->registerCancellationCallback(
          [weak_state] {
            if (auto current = weak_state.lock())
              current->release();
          });
    }
  }
  ~InflightConsumerGuard() {
    cancellation_registration.reset();
    release();
  }

  void release() noexcept {
    if (state)
      state->release();
  }

  InflightConsumerGuard(const InflightConsumerGuard &) = delete;
  InflightConsumerGuard &operator=(const InflightConsumerGuard &) = delete;

  std::shared_ptr<InflightConsumerState> state;
  RequestCancellationRegistration cancellation_registration;
};

struct CachedSubResponse {
  SharedCoalescedResponse result;
  std::chrono::steady_clock::time_point expires_at;
  uint64_t bytes = 0;
  uint64_t sequence = 0;
};

static std::mutex g_sub_inflight_mutex;
static std::map<std::string, std::shared_ptr<InflightSubRequest>>
    g_sub_inflight;
static std::mutex g_sub_response_cache_mutex;
static std::map<std::string, CachedSubResponse> g_sub_response_cache;
static uint64_t g_sub_response_cache_bytes = 0;
static uint64_t g_sub_response_cache_sequence = 0;

static void eraseInflightSubRequest(
    const std::string &key,
    const std::shared_ptr<InflightSubRequest> &expected_call) {
  std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
  auto iter = g_sub_inflight.find(key);
  if (iter != g_sub_inflight.end() && iter->second == expected_call)
    g_sub_inflight.erase(iter);
}

static std::map<std::string, CachedSubResponse>::iterator
eraseSubResponseCacheEntry(
    std::map<std::string, CachedSubResponse>::iterator iter) {
  const uint64_t bytes = iter->second.bytes;
  g_sub_response_cache_bytes =
      bytes <= g_sub_response_cache_bytes
          ? g_sub_response_cache_bytes - bytes
          : 0;
  return g_sub_response_cache.erase(iter);
}

static uint64_t subResponseCacheMaxBytes() {
  static const uint64_t limit = [] {
    const std::string configured =
        getEnv("SUBCONVERTER_RESPONSE_CACHE_MAX_BYTES");
    if (configured.empty())
      return UINT64_C(8) * 1024 * 1024;
    try {
      return static_cast<uint64_t>(std::clamp<unsigned long long>(
          std::stoull(configured), 1024, UINT64_C(64) * 1024 * 1024));
    } catch (...) {
      return UINT64_C(8) * 1024 * 1024;
    }
  }();
  return limit;
}

struct SubExplainProvider {
  std::string backend = "mihomo";
  std::string name;
  std::string tag;
  std::string source_hash;
  std::string source_summary;
  std::string path;
  std::string filter;
  std::string exclude_filter;
  bool filter_present = false;
  bool exclude_filter_present = false;
  bool name_generated = false;
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
  std::string remote_subscription_backend = "server-side-parse";
  std::string remote_subscription_reason = "target-default";
  bool nodelist = false;
  bool managed_config = false;
  std::string proxy_config;
  std::string proxy_ruleset;
  std::string proxy_subscription;
  std::string proxy_bypass;
  std::string base_fetch_context = "trusted_config";
  std::string ruleset_fetch_context = "trusted_config";
  size_t raw_url_count = 0;
  size_t insert_url_count = 0;
  size_t subscription_url_count = 0;
  size_t node_link_count = 0;
  size_t unknown_node_link_count = 0;
  size_t provider_count = 0;
  size_t remote_subscription_count = 0;
  size_t insert_node_count = 0;
  size_t direct_node_count = 0;
  size_t total_node_count = 0;
  size_t generated_node_count = 0;
  size_t unsupported_node_count = 0;
  string_array unsupported_protocols;
  size_t ruleset_count = 0;
  size_t rule_provider_count = 0;
  size_t inline_rule_source_count = 0;
  size_t expanded_rule_source_count = 0;
  size_t unsupported_ruleset_count = 0;
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

static std::string boolString(bool value) { return value ? "true" : "false"; }

static std::string previewExplainValue(const std::string &value,
                                       bool sensitive) {
  if (value.empty())
    return "";
  if (sensitive)
    return "[redacted]";

  static constexpr size_t kMaxPreview = 180;
  std::string safe = sanitizeLogLine(value);
  if (safe.size() <= kMaxPreview)
    return safe;
  return safe.substr(0, kMaxPreview) + "...";
}

static std::string summarizeExplainSourceList(const std::string &value) {
  if (value.empty())
    return "not provided";

  static constexpr size_t kMaxSummarizedSources = 8;
  const string_array sources = split(value, "|");
  string_array summaries;
  summaries.reserve(std::min(sources.size(), kMaxSummarizedSources) + 1);
  for (size_t index = 0;
       index < sources.size() && index < kMaxSummarizedSources; ++index) {
    const TaggedLink tagged = parseTaggedLink(sources[index]);
    summaries.emplace_back(summarizeUrlForLog(tagged.link));
  }
  if (sources.size() > kMaxSummarizedSources) {
    summaries.emplace_back("... " +
                           std::to_string(sources.size() -
                                          kMaxSummarizedSources) +
                           " more source(s)");
  }
  return join(summaries, "; ");
}

static std::string explainParameterName(const std::string &name) {
  static constexpr size_t kMaxParameterName = 64;
  if (!name.empty() && name.size() <= kMaxParameterName &&
      std::all_of(name.begin(), name.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.';
      }))
    return name;
  return "[redacted-name]";
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
  writeJsonString(writer, "remote_subscription_backend",
                  report.remote_subscription_backend);
  writeJsonString(writer, "remote_subscription_reason",
                  report.remote_subscription_reason);
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
  writeJsonString(writer, "bypass", report.proxy_bypass);
  writer.EndObject();

  writer.Key("resources");
  writer.StartObject();
  writeJsonString(writer, "base_fetch_context", report.base_fetch_context);
  writeJsonString(writer, "ruleset_fetch_context", report.ruleset_fetch_context);
  writer.Key("ruleset_count");
  writer.Uint64(report.ruleset_count);
  writer.Key("rule_provider_count");
  writer.Uint64(report.rule_provider_count);
  writer.Key("inline_rule_source_count");
  writer.Uint64(report.inline_rule_source_count);
  writer.Key("expanded_rule_source_count");
  writer.Uint64(report.expanded_rule_source_count);
  writer.Key("unsupported_ruleset_count");
  writer.Uint64(report.unsupported_ruleset_count);
  writer.Key("custom_group_count");
  writer.Uint64(report.custom_group_count);
  writer.Key("remote_subscription_count");
  writer.Uint64(report.remote_subscription_count);
  writer.EndObject();

  writer.Key("nodes");
  writer.StartObject();
  writer.Key("insert");
  writer.Uint64(report.insert_node_count);
  writer.Key("direct");
  writer.Uint64(report.direct_node_count);
  writer.Key("total");
  writer.Uint64(report.total_node_count);
  writer.Key("generated");
  writer.Uint64(report.generated_node_count);
  writer.Key("unsupported");
  writer.Uint64(report.unsupported_node_count);
  writer.Key("unsupported_protocols");
  writer.StartArray();
  for (const std::string &protocol : report.unsupported_protocols)
    writer.String(protocol.c_str());
  writer.EndArray();
  writer.EndObject();

  writer.Key("providers");
  writer.StartArray();
  for (const SubExplainProvider &provider : report.providers) {
    writer.StartObject();
    writeJsonString(writer, "backend", provider.backend);
    writeJsonString(writer, "name", provider.name);
    writeJsonString(writer, "tag", provider.tag);
    writeJsonString(writer, "source_hash", provider.source_hash);
    writeJsonString(writer, "source_summary", provider.source_summary);
    writeJsonString(writer, "path", provider.path);
    writeJsonString(writer, "filter", provider.filter);
    writeJsonString(writer, "exclude_filter", provider.exclude_filter);
    writer.Key("filter_present");
    writer.Bool(provider.filter_present);
    writer.Key("exclude_filter_present");
    writer.Bool(provider.exclude_filter_present);
    writer.Key("name_generated");
    writer.Bool(provider.name_generated);
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
  writer.Key("remote_subscription_count");
  writer.Uint64(report.remote_subscription_count);
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

static void applyExplainPrivacyHeaders(Response &response) {
  response.headers["Cache-Control"] = "private, no-store, max-age=0";
  response.headers["Pragma"] = "no-cache";
}

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
  RequestStageTimer serialize_timer(request.context, RequestStage::Serialize);
  if (isTruthyRequestValue(getUrlArg(request.argument, "explain")))
    applyExplainPrivacyHeaders(response);
  // User-Agent can select target=auto and affects subscription/provider
  // request headers. Separate every /sub representation in shared caches.
  appendVaryHeader(response, "User-Agent");
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

static std::string applyCoalescedToResponse(
    const CoalescedResponse &result,
    const std::shared_ptr<RequestContext> &client_context,
    Response &response) {
  response.status_code = result.status_code;
  response.content_type = result.content_type;
  response.headers = result.headers;
  response.shared_body = result.body;
  if (result.capacity_rejected && client_context)
    client_context->suggestFailure(RequestFailureAttribution::Capacity);
  return result.body ? std::string() : result.fallback_body;
}

static shared_response_body tryMakeRetainedResponseBody(
    std::string body) noexcept {
  const uint64_t content_bytes = static_cast<uint64_t>(body.size());
  RetainedResponseByteLease lease;
  if (!lease.acquire(content_bytes))
    return {};
  try {
    auto result = std::make_shared<ImmutableResponseBody>();
    result->content = std::move(body);
    result->retained_bytes = std::move(lease);
    return result;
  } catch (...) {
    return {};
  }
}

static SharedCoalescedResponse makeCoalescedResult(
    std::string &&body, Response &&response, uint64_t rule_conversions) {
  auto result = std::make_shared<CoalescedResponse>();
  result->body = tryMakeRetainedResponseBody(std::move(body));
  if (!result->body) {
    if (const std::shared_ptr<RequestContext> context =
            captureCurrentRequestContext())
      context->suggestFailure(RequestFailureAttribution::Capacity);
    response.status_code = 503;
    response.content_type = "text/plain; charset=utf-8";
    response.headers = {{"Cache-Control", "private, no-store"},
                        {"Retry-After", "1"}};
    result->fallback_body =
        "Service temporarily unavailable: retained response byte capacity "
        "is full.\n服务暂时不可用：响应字节容量已满。\n";
    result->capacity_rejected = true;
  }
  result->status_code = response.status_code;
  result->content_type = std::move(response.content_type);
  result->headers = std::move(response.headers);
  result->rule_conversions = result->body ? rule_conversions : 0;
  return result;
}

static void pruneExpiredSubResponseCache(
    std::chrono::steady_clock::time_point now) {
  for (auto iter = g_sub_response_cache.begin();
       iter != g_sub_response_cache.end();) {
    if (iter->second.expires_at <= now) {
      iter = eraseSubResponseCacheEntry(iter);
    } else
      ++iter;
  }
}

static uint64_t coalescedResponseBytes(const CoalescedResponse &result) {
  uint64_t bytes = (result.body ? result.body->content.size()
                                : result.fallback_body.size()) +
                   result.content_type.size();
  for (const auto &[name, value] : result.headers)
    bytes += name.size() + value.size();
  return bytes;
}

static void evictOldestSubResponseCacheEntry() {
  if (g_sub_response_cache.empty())
    return;
  auto oldest = std::min_element(
      g_sub_response_cache.begin(), g_sub_response_cache.end(),
      [](const auto &left, const auto &right) {
        return left.second.sequence < right.second.sequence;
      });
  eraseSubResponseCacheEntry(oldest);
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
    eraseSubResponseCacheEntry(iter);
    return false;
  }
  result = iter->second.result;
  iter->second.sequence = ++g_sub_response_cache_sequence;
  return true;
}

static void storeCachedSubResponse(const std::string &key,
                                   const SharedCoalescedResponse &result,
                                   const Settings &settings) {
  if (settings.responseCacheTtl <= 0 || !result || result->status_code != 200)
    return;
  const auto cache_control = result->headers.find("Cache-Control");
  if (cache_control != result->headers.end() &&
      toLower(cache_control->second).find("no-store") != std::string::npos)
    return;

  int ttl = std::min(settings.responseCacheTtl, 5);
  if (ttl <= 0)
    return;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  pruneExpiredSubResponseCache(now);
  const uint64_t bytes = coalescedResponseBytes(*result);
  const uint64_t max_bytes = subResponseCacheMaxBytes();
  if (bytes > max_bytes)
    return;
  auto existing = g_sub_response_cache.find(key);
  if (existing != g_sub_response_cache.end())
    eraseSubResponseCacheEntry(existing);
  while (!g_sub_response_cache.empty() &&
         (g_sub_response_cache.size() >= 2048 ||
          g_sub_response_cache_bytes > max_bytes - bytes))
    evictOldestSubResponseCacheEntry();
  CachedSubResponse cached;
  cached.result = result;
  cached.expires_at = now + std::chrono::seconds(ttl);
  cached.bytes = bytes;
  cached.sequence = ++g_sub_response_cache_sequence;
  g_sub_response_cache_bytes += bytes;
  g_sub_response_cache.emplace(key, std::move(cached));
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
  if (original.context &&
      (original.context->cancellationToken().isCancellationRequested() ||
       original.context->deadlineExceeded())) {
    if (stats)
      *stats = first_stats;
    response = first_response;
    return body;
  }

  writeLog(LOG_LEVEL_WARNING,
           "/sub 请求首次转换返回 5xx，正在进行一次服务端内部重试。");
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
  SettingsSnapshot current = captureEffectiveSettingsSnapshot();
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

static std::string runScheduledConversion(
    Request &request, Response &response, const SettingsSnapshot &snapshot,
    RuleConversionStats *stats, bool with_retry,
    std::shared_ptr<RequestContext> admission_context = {});

struct PreparedSubRequest {
  SettingsSnapshot settings;
  AgeResponseContext age;
  std::string key;
  bool explain_request = false;
  bool coalesce = false;
  bool early_complete = false;
};

enum class AsyncInflightPhase {
  Accepting,
  Publishing,
  Done,
  Abandoned,
};

struct AsyncInflightSubRequest;

struct AsyncSubRequestConsumer {
  uint64_t id = 0;
  bool follower = false;
  std::atomic<bool> waiting_counted{false};
  std::shared_ptr<RequestContext> context;
  statistics::SubscriptionConversionMetadata statistics_metadata;
  ConversionService::Completion completion;
  std::weak_ptr<AsyncInflightSubRequest> call;
  RequestCancellationRegistration cancellation_registration;
  std::atomic<bool> completion_claimed{false};
  std::atomic<bool> detached{false};
};

struct AsyncInflightSubRequest {
  std::mutex mutex;
  AsyncInflightPhase phase = AsyncInflightPhase::Accepting;
  std::string key;
  std::string owner_request_id;
  std::shared_ptr<RequestContext> work_context;
  std::unordered_map<uint64_t, std::shared_ptr<AsyncSubRequestConsumer>>
      consumers;
  uint64_t next_consumer_id = 1;
  SharedCoalescedResponse result;
  std::atomic<bool> active_released{false};
};

std::mutex g_async_sub_inflight_mutex;
std::map<std::string, std::shared_ptr<AsyncInflightSubRequest>>
    g_async_sub_inflight;
std::atomic<uint64_t> g_async_singleflight_active_owners{0};
std::atomic<uint64_t> g_async_singleflight_waiting_followers{0};
std::atomic<uint64_t> g_async_singleflight_owners_created{0};
std::atomic<uint64_t> g_async_singleflight_followers_attached{0};
std::atomic<uint64_t> g_async_singleflight_followers_cancelled{0};
std::atomic<uint64_t> g_async_singleflight_no_consumer_cancellations{0};
std::atomic<uint64_t> g_async_singleflight_owner_flow_rejections{0};

static PreparedSubRequest prepareSubRequest(Request &request,
                                            Response &response,
                                            std::string &early_body) {
  PreparedSubRequest prepared;
  // Early validation failures do not pass through finalizeSubResponse.
  appendVaryHeader(response, "User-Agent");
  prepared.explain_request =
      isTruthyRequestValue(getUrlArg(request.argument, "explain"));
  if (prepared.explain_request)
    applyExplainPrivacyHeaders(response);
  prepared.age = consumeAgeResponseContext(request);
  if (prepared.age.requested && !prepared.age.valid) {
    early_body = rejectAgeRequest(
        response,
        "Invalid X-Age-Public-Key: expected one Mihomo-supported Age public "
        "or secret key.\n"
        "X-Age-Public-Key 无效：应提供一个 Mihomo 支持的 Age 公钥或私钥。");
    prepared.early_complete = true;
    return prepared;
  }
  if (prepared.age.requested &&
      getUrlArg(request.argument, "target") != "clash") {
    early_body = rejectAgeRequest(
        response,
        "Invalid request: Age response encryption is supported only for "
        "target=clash.\n"
        "无效请求：Age 响应加密仅支持 target=clash。");
    prepared.early_complete = true;
    return prepared;
  }

  // CFW's compatibility reload remains after target validation, matching the
  // legacy control flow. Capture the view only after that transaction ends.
  prepared.settings = captureSettingsForSubRequest(request);
  ScopedSettingsView settings_scope(prepared.settings);
  const Settings &settings = *prepared.settings;
  prepared.coalesce = shouldCoalesceSubRequest(request, settings);
  if (prepared.coalesce) {
    prepared.key = buildSubRequestKey(
        request, prepared.age.fingerprint, settings.configGeneration,
        settings.managedConfigPrefix);
    prepared.coalesce = !prepared.key.empty();
  }
  return prepared;
}

static SharedCoalescedResponse executePreparedSubRequestOwner(
    Request &request, const PreparedSubRequest &prepared,
    RuleConversionStats *stats,
    std::shared_ptr<RequestContext> admission_context = {}) {
  ScopedSettingsView settings_scope(prepared.settings);
  Response owner_response;
  std::string body = runScheduledConversion(
      request, owner_response, prepared.settings, stats, true,
      std::move(admission_context));
  body = finalizeSubResponse(request, owner_response, std::move(body),
                             prepared.age);
  return makeCoalescedResult(std::move(body), std::move(owner_response),
                             stats ? stats->rules : 0);
}

static std::string subconverterEntry(Request &request, Response &response,
                                     bool track) {
  std::string early_body;
  PreparedSubRequest prepared =
      prepareSubRequest(request, response, early_body);
  if (prepared.early_complete)
    return early_body;

  ScopedSettingsView settings_scope(prepared.settings);
  const Settings &settings = *prepared.settings;
  if (!prepared.coalesce) {
    RuleConversionStats stats;
    std::string body = runScheduledConversion(
        request, response, prepared.settings, track ? &stats : nullptr, false);
    body = finalizeSubResponse(request, response, std::move(body), prepared.age);
    recordTrackedSubRequest(track, request, response, stats.rules);
    return body;
  }

  SharedCoalescedResponse cached_result;
  if (!prepared.explain_request &&
      getCachedSubResponse(prepared.key, cached_result, settings)) {
    writeLog(LOG_LEVEL_DEBUG, "/sub 响应微缓存命中。");
    if (request.context)
      request.context->setCostClass(RequestCostClass::Low);
    if (request.context)
      request.context->markWorkAdmitted();
    std::string body = applyCoalescedToResponse(
        *cached_result, request.context, response);
    recordTrackedSubRequest(track, request, response,
                            cached_result->rule_conversions);
    return body;
  }

  std::shared_ptr<InflightSubRequest> call;
  bool owner = false;
  uint32_t follower_consumers = 0;
  {
    std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
    auto iter = g_sub_inflight.find(prepared.key);
    if (iter != g_sub_inflight.end()) {
      follower_consumers = iter->second->tryAddConsumer();
      if (follower_consumers != 0) {
        call = iter->second;
      } else {
        g_sub_inflight.erase(iter);
      }
    }
    if (!call) {
      call = std::make_shared<InflightSubRequest>();
      call->owner_request_id = currentLogRequestId();
      const auto work_started = RequestContext::Clock::now();
      call->work_context = std::make_shared<RequestContext>(
          call->owner_request_id, work_started,
          work_started +
              std::chrono::milliseconds(
                  std::max(1, settings.requestDeadlineMs)),
          RequestContextKind::InternalWork);
      call->work_context->setConsumerCount(1);
      if (request.context) {
        request.context->setSingleflightRole(RequestSingleflightRole::Owner);
        request.context->setConsumerCount(1);
      }
      g_sub_inflight.emplace(prepared.key, call);
      owner = true;
    }
  }

  if (!owner) {
    if (request.context)
      request.context->markWorkAdmitted();
    if (request.context)
      request.context->setSingleflightRole(RequestSingleflightRole::Follower);
    if (call->work_context)
      call->work_context->setConsumerCount(follower_consumers);
    InflightConsumerGuard consumer_guard(call, request.context);
    writeLog(LOG_LEVEL_INFO,
             "SUB_REQUEST_COALESCED owner_request_id=" +
                 (call->owner_request_id.empty() ? "unavailable"
                                                 : call->owner_request_id));
    std::optional<RequestCancellationResponse> follower_cancellation =
        waitWithoutCpuPermit([&]()
                                 -> std::optional<
                                     RequestCancellationResponse> {
          std::unique_lock<std::mutex> lock(call->mutex);
          while (!call->done) {
            RequestCancellationResponse cancellation_response;
            if (requestCancellationResponse(request.context,
                                            cancellation_response))
              return cancellation_response;
            auto wake = RequestContext::Clock::now() +
                        std::chrono::milliseconds(10);
            if (request.context &&
                request.context->deadline() !=
                    RequestContext::Clock::time_point::max())
              wake = std::min(wake, request.context->deadline());
            call->cv.wait_until(lock, wake);
          }
          return std::nullopt;
        });
    if (follower_cancellation) {
      response.status_code = follower_cancellation->status_code;
      response.content_type = "text/plain; charset=utf-8";
      response.headers = std::move(follower_cancellation->headers);
      return std::move(follower_cancellation->body);
    }
    if (call->exception)
      std::rethrow_exception(call->exception);
    if (request.context) {
      if (call->work_context)
        request.context->setCostClass(call->work_context->costClass());
    }
    std::string body = applyCoalescedToResponse(
        *call->result, request.context, response);
    recordTrackedSubRequest(track, request, response,
                            call->result->rule_conversions);
    return body;
  }

  InflightConsumerGuard consumer_guard(call, request.context);
  try {
    writeLog(LOG_LEVEL_DEBUG, "/sub 请求成为同 key 转换 owner。");
    Request work_request = request;
    work_request.context = call->work_context;
    ScopedRequestContext work_scope(call->work_context);
    RuleConversionStats stats;
    SharedCoalescedResponse result = executePreparedSubRequestOwner(
        work_request, prepared, track ? &stats : nullptr, request.context);
    if (request.context && call->work_context)
      request.context->setCostClass(call->work_context->costClass());
    std::string response_body = applyCoalescedToResponse(
        *result, request.context, response);
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->result = result;
      call->done = true;
    }
    if (!prepared.age.requested && !prepared.explain_request)
      storeCachedSubResponse(prepared.key, result, settings);
    eraseInflightSubRequest(prepared.key, call);
    call->cv.notify_all();
    recordTrackedSubRequest(track, request, response,
                            result->rule_conversions);
    return response_body;
  } catch (...) {
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->exception = std::current_exception();
      call->done = true;
    }
    eraseInflightSubRequest(prepared.key, call);
    call->cv.notify_all();
    throw;
  }
}

} // namespace

namespace {

std::atomic<WorkloadScheduler *> conversion_scheduler_instance{nullptr};
std::atomic<WorkloadScheduler *> legacy_request_flow_instance{nullptr};
std::atomic<CpuPermitGate *> conversion_cpu_gate_instance{nullptr};
std::atomic<bool> conversion_shutdown_requested{false};
std::atomic<uint64_t> desired_cpu_permits{0};

CpuPermitGate &conversionCpuGate() {
  const uint64_t desired = desired_cpu_permits.load(std::memory_order_acquire);
  static CpuPermitGate gate(static_cast<std::size_t>(
      std::max<uint64_t>(1, desired != 0
                                ? desired
                                : static_cast<uint64_t>(std::max(
                                      1, effectiveSettings().maxConcurThreads)))));
  conversion_cpu_gate_instance.store(&gate, std::memory_order_release);
  uint64_t published_desired = 0;
  do {
    published_desired =
        desired_cpu_permits.load(std::memory_order_acquire);
    if (published_desired != 0)
      gate.setLimit(static_cast<std::size_t>(std::min<uint64_t>(
          published_desired, std::numeric_limits<std::size_t>::max())));
  } while (desired_cpu_permits.load(std::memory_order_acquire) !=
           published_desired);
  if (conversion_shutdown_requested.load(std::memory_order_acquire))
    gate.requestShutdown();
  return gate;
}

std::size_t legacyRequestFlowWorkerCount(const Settings &settings) {
  const unsigned int hardware_threads =
      std::max(1U, std::thread::hardware_concurrency());
  const std::size_t cpu_workers = static_cast<std::size_t>(
      std::clamp(std::min(settings.maxConcurThreads,
                          static_cast<int>(hardware_threads)),
                 1, INT_MAX));
  const ResourceControlSnapshot resources = resourceControlSnapshot();
  if (resources.effective_mode != "force_max" ||
      !resources.startup_budget_applied)
    return cpu_workers;

  uint64_t flow_workers = std::max<uint64_t>(
      cpu_workers, resources.suggested_active_flows);
  const uint64_t cooperative_thread_cap =
      cooperativeFlowWorkerCap(cpu_workers);
  flow_workers = std::min(flow_workers, cooperative_thread_cap);
  flow_workers = std::min<uint64_t>(
      flow_workers, static_cast<uint64_t>(std::max(1, settings.maxPendingConns)));
  uint64_t memory_boundary = 0;
  const auto include_memory_boundary = [&memory_boundary](uint64_t value) {
    if (value != 0)
      memory_boundary = memory_boundary == 0
                            ? value
                            : std::min(memory_boundary, value);
  };
  include_memory_boundary(resources.memory_high_bytes);
  include_memory_boundary(resources.memory_max_bytes);
  include_memory_boundary(resources.host_total_memory_bytes);
  if (memory_boundary != 0)
    flow_workers = std::min<uint64_t>(
        flow_workers,
        std::max<uint64_t>(1, memory_boundary / (UINT64_C(4) * 1024 * 1024)));
  if (resources.pids_max != 0) {
    const uint64_t remaining = resources.pids_max > resources.pids_current
                                   ? resources.pids_max - resources.pids_current
                                   : 0;
    const uint64_t pids_headroom = remaining > 16 ? remaining - 16 : 1;
    flow_workers = std::min<uint64_t>(flow_workers, pids_headroom);
  }
  return static_cast<std::size_t>(std::max<uint64_t>(1, flow_workers));
}

WorkloadScheduler &legacyRequestFlowScheduler() {
  const Settings &settings = effectiveSettings();
  const std::size_t entries = static_cast<std::size_t>(
      std::max(settings.maxPendingConns, 1));
  static WorkloadScheduler scheduler(legacyRequestFlowWorkerCount(settings),
                                     entries,
                                     requestAdmissionSnapshot().max_bytes);
  legacy_request_flow_instance.store(&scheduler, std::memory_order_release);
  if (conversion_shutdown_requested.load(std::memory_order_acquire))
    scheduler.requestShutdown(true);
  return scheduler;
}

WorkloadScheduler &conversionScheduler() {
  const Settings &settings = effectiveSettings();
  const unsigned int hardware_threads =
      std::max(1U, std::thread::hardware_concurrency());
  const std::size_t workers = static_cast<std::size_t>(
      std::clamp(std::min(settings.maxConcurThreads,
                          static_cast<int>(hardware_threads)),
                 1, INT_MAX));
  const std::size_t entries = static_cast<std::size_t>(
      std::max(settings.maxPendingConns, 1));
  static WorkloadScheduler scheduler(workers, entries,
                                     requestAdmissionSnapshot().max_bytes);
  conversion_scheduler_instance.store(&scheduler, std::memory_order_release);
  if (conversion_shutdown_requested.load(std::memory_order_acquire))
    scheduler.requestShutdown(true);
  return scheduler;
}

RequestCostClass estimateConversionCost(const Request &request) {
  const std::string target = getUrlArg(request.argument, "target");
  const std::string url = getUrlArg(request.argument, "url");
  const bool list = isTruthyRequestValue(getUrlArg(request.argument, "list"));
  const bool script =
      isTruthyRequestValue(getUrlArg(request.argument, "script"));
  const bool expand =
      isTruthyRequestValue(getUrlArg(request.argument, "expand"));
  const bool multiple = url.find('|') != std::string::npos;
  const bool external_config =
      !getUrlArg(request.argument, "config").empty();
  static constexpr const char *transform_parameters[] = {
      "include", "exclude", "rename", "emoji", "add_emoji",
      "remove_emoji", "append_type", "sort", "filter_deprecated",
      "udp", "tfo", "scv", "tls13", "group", "ruleprepend",
      "ruleappend", "ruleset", "provider_headers"};
  bool transformation = false;
  for (const char *name : transform_parameters) {
    if (!getUrlArg(request.argument, name).empty()) {
      transformation = true;
      break;
    }
  }
  if (script || expand || multiple || external_config || transformation)
    return RequestCostClass::High;
  (void)target;
  (void)list;
  return RequestCostClass::Medium;
}

ConversionResult schedulerFailureResult(Request &request,
                                        SchedulerSubmitStatus status) {
  int http_status = 503;
  std::string body =
      "Service temporarily unavailable: conversion capacity is full.\n"
      "服务暂时不可用：转换容量已满。\n";
  string_icase_map headers{{"Cache-Control", "private, no-store"}};
  switch (status) {
  case SchedulerSubmitStatus::Deadline:
    http_status = 504;
    body = "Gateway timeout: request deadline exceeded before conversion.\n"
           "网关超时：请求在转换开始前已超过截止时间。\n";
    if (request.context) {
      request.context->requestCancellation(RequestCancellationReason::Deadline);
      request.context->suggestFailure(RequestFailureAttribution::Client);
    }
    break;
  case SchedulerSubmitStatus::Cancelled:
    http_status = 499;
    body = "Client closed request before conversion started.\n"
           "客户端在转换开始前关闭了请求。\n";
    if (request.context) {
      request.context->requestCancellation(
          RequestCancellationReason::ClientDisconnected);
      request.context->suggestFailure(RequestFailureAttribution::Client);
    }
    break;
  case SchedulerSubmitStatus::EntryLimit:
  case SchedulerSubmitStatus::ByteLimit:
    headers.emplace("Retry-After", "1");
    if (request.context)
      request.context->suggestFailure(RequestFailureAttribution::Capacity);
    break;
  case SchedulerSubmitStatus::Stopping:
    body = "Service is shutting down.\n服务正在关闭。\n";
    if (request.context)
      request.context->suggestFailure(RequestFailureAttribution::Server);
    break;
  case SchedulerSubmitStatus::Accepted:
    break;
  }
  return ConversionResult(http_status, "text/plain; charset=utf-8",
                          std::move(headers), std::move(body));
}

ConversionResult executorFailureResult(Request &request,
                                       ExecutorSubmitStatus status) {
  int http_status = 503;
  std::string body =
      "Service temporarily unavailable: ruleset capacity is full.\n"
      "服务暂时不可用：规则集处理容量已满。\n";
  string_icase_map headers{{"Cache-Control", "private, no-store"}};
  switch (status) {
  case ExecutorSubmitStatus::Deadline:
    http_status = 504;
    body = "Gateway timeout: ruleset processing exceeded the request "
           "deadline.\n网关超时：规则集处理已超过请求截止时间。\n";
    if (request.context) {
      request.context->requestCancellation(RequestCancellationReason::Deadline);
      request.context->suggestFailure(RequestFailureAttribution::Client);
    }
    break;
  case ExecutorSubmitStatus::Cancelled:
    if (request.context &&
        request.context->cancellationToken().reason() ==
            RequestCancellationReason::Shutdown) {
      body = "Service is shutting down.\n服务正在关闭。\n";
      request.context->suggestFailure(RequestFailureAttribution::Server);
    } else {
      http_status = 499;
      body = "Client closed request during ruleset processing.\n"
             "客户端在规则集处理期间关闭了请求。\n";
      if (request.context)
        request.context->suggestFailure(RequestFailureAttribution::Client);
    }
    break;
  case ExecutorSubmitStatus::QueueFull:
  case ExecutorSubmitStatus::Recursive:
    headers.emplace("Retry-After", "1");
    if (request.context)
      request.context->suggestFailure(RequestFailureAttribution::Capacity);
    break;
  case ExecutorSubmitStatus::Stopping:
    body = "Service is shutting down.\n服务正在关闭。\n";
    if (request.context)
      request.context->suggestFailure(RequestFailureAttribution::Server);
    break;
  case ExecutorSubmitStatus::Accepted:
    break;
  }
  return ConversionResult(http_status, "text/plain; charset=utf-8",
                          std::move(headers), std::move(body));
}

std::string runScheduledConversion(
    Request &request, Response &response, const SettingsSnapshot &snapshot,
    RuleConversionStats *stats, bool with_retry,
    std::shared_ptr<RequestContext> admission_context) {
  const std::shared_ptr<RequestContext> admitted_context =
      admission_context ? std::move(admission_context) : request.context;
  if (cooperativeCpuPermitActive()) {
    if (admitted_context)
      admitted_context->markWorkAdmitted();
    ScopedSettingsView settings_scope(snapshot);
    if (with_retry)
      return runSubconverterImplWithRetry(request, response, *snapshot, stats);
    return subconverter_impl(request, response, *snapshot, stats);
  }
  const std::string scheduler_mode =
      toLower(getEnv("SUBCONVERTER_CONVERSION_SCHEDULER"));
  if (scheduler_mode == "direct") {
    if (admitted_context)
      admitted_context->markWorkAdmitted();
    if (with_retry)
      return runSubconverterImplWithRetry(request, response, *snapshot, stats);
    return subconverter_impl(request, response, *snapshot, stats);
  }
  if (!scheduler_mode.empty() && scheduler_mode != "bounded") {
    static std::atomic<bool> invalid_mode_logged{false};
    bool expected = false;
    if (invalid_mode_logged.compare_exchange_strong(expected, true))
      writeLog(LOG_LEVEL_ERROR,
               "CONVERSION_SCHEDULER_INVALID value_length=" +
                   std::to_string(scheduler_mode.size()) +
                   " fallback=direct");
    if (admitted_context)
      admitted_context->markWorkAdmitted();
    if (with_retry)
      return runSubconverterImplWithRetry(request, response, *snapshot, stats);
    return subconverter_impl(request, response, *snapshot, stats);
  }
  const RequestCostClass cost = estimateConversionCost(request);
  if (request.context)
    request.context->setCostClass(cost);
  writeLog(LOG_LEVEL_DEBUG,
           "CONVERSION_ADMISSION cost=" +
               std::string(requestCostClassName(cost)));
  const uint64_t bytes = request.context
                             ? request.context->estimatedBytes()
                             : static_cast<uint64_t>(request.postdata.size());
  const auto deadline = request.context
                            ? request.context->deadline()
                            : RequestContext::Clock::time_point::max();
  const RequestCancellationToken cancellation =
      request.context ? request.context->cancellationToken()
                      : RequestCancellationToken();
  const std::shared_ptr<RequestContext> context = request.context;
  const auto queued_at = RequestContext::Clock::now();
  auto submission = conversionScheduler().submit(
      cost, bytes, deadline, cancellation,
      [&request, &response, snapshot, stats, with_retry, context,
       queued_at]() -> std::string {
        ScopedSettingsView settings_scope(snapshot);
        ScopedRequestContext request_scope(context);
        ScopedLogRequestContext log_scope(context ? context->requestId()
                                                   : std::string());
        if (context) {
          context->addStageDuration(RequestStage::Queue,
                                    RequestContext::Clock::now() - queued_at);
          context->setCurrentStage(RequestStage::Parse);
        }
        if (with_retry)
          return runSubconverterImplWithRetry(request, response, *snapshot,
                                              stats);
        return subconverter_impl(request, response, *snapshot, stats);
      });
  if (submission.status == SchedulerSubmitStatus::Accepted) {
    if (admitted_context)
      admitted_context->markWorkAdmitted();
    try {
      return submission.future.get();
    } catch (const SchedulerSubmitError &error) {
      ConversionResult failure =
          schedulerFailureResult(request, error.status());
      response.status_code = failure.statusCode();
      response.content_type = std::move(failure).releaseContentType();
      response.headers = std::move(failure).releaseHeaders();
      return std::move(failure).releaseBody();
    } catch (const ExecutorSubmitError &error) {
      ConversionResult failure =
          executorFailureResult(request, error.status());
      response.status_code = failure.statusCode();
      response.content_type = std::move(failure).releaseContentType();
      response.headers = std::move(failure).releaseHeaders();
      return std::move(failure).releaseBody();
    } catch (const std::future_error &) {
      ConversionResult failure = executorFailureResult(
          request, ExecutorSubmitStatus::Stopping);
      response.status_code = failure.statusCode();
      response.content_type = std::move(failure).releaseContentType();
      response.headers = std::move(failure).releaseHeaders();
      return std::move(failure).releaseBody();
    }
  }
  ConversionResult failure =
      schedulerFailureResult(request, submission.status);
  response.status_code = failure.statusCode();
  response.content_type = std::move(failure).releaseContentType();
  response.headers = std::move(failure).releaseHeaders();
  return std::move(failure).releaseBody();
}

} // namespace

static ConversionResult makeConversionResult(Response response,
                                             std::string body) {
  if (response.shared_body)
    return ConversionResult(response.status_code,
                            std::move(response.content_type),
                            std::move(response.headers),
                            std::move(response.shared_body));
  return ConversionResult(response.status_code,
                          std::move(response.content_type),
                          std::move(response.headers), std::move(body));
}

ConversionResult ConversionService::convertSubscription(
    Request &request, bool track_statistics) const {
  if (conversion_shutdown_requested.load(std::memory_order_acquire))
    return schedulerFailureResult(request, SchedulerSubmitStatus::Stopping);
  Response response;
  std::string body =
      subconverterEntry(request, response, track_statistics);
  return makeConversionResult(std::move(response), std::move(body));
}

const ConversionService &defaultConversionService() {
  static const ConversionService service;
  return service;
}

namespace {

void eraseAsyncInflightSubRequest(
    const std::shared_ptr<AsyncInflightSubRequest> &call) noexcept {
  if (!call)
    return;
  std::lock_guard<std::mutex> lock(g_async_sub_inflight_mutex);
  auto iter = g_async_sub_inflight.find(call->key);
  if (iter != g_async_sub_inflight.end() && iter->second == call)
    g_async_sub_inflight.erase(iter);
}

void releaseAsyncInflightOwner(
    const std::shared_ptr<AsyncInflightSubRequest> &call) noexcept {
  if (call &&
      !call->active_released.exchange(true, std::memory_order_acq_rel))
    g_async_singleflight_active_owners.fetch_sub(1,
                                                  std::memory_order_relaxed);
}

void detachAsyncSubRequestConsumer(
    const std::shared_ptr<AsyncSubRequestConsumer> &consumer,
    bool cancelled) noexcept {
  if (!consumer || consumer->detached.exchange(true, std::memory_order_acq_rel))
    return;
  const std::shared_ptr<AsyncInflightSubRequest> call = consumer->call.lock();
  if (!call) {
    if (consumer->waiting_counted.exchange(false,
                                            std::memory_order_acq_rel)) {
      g_async_singleflight_waiting_followers.fetch_sub(
          1, std::memory_order_relaxed);
    }
    if (consumer->follower && cancelled)
      g_async_singleflight_followers_cancelled.fetch_add(
          1, std::memory_order_relaxed);
    return;
  }
  bool cancel_owner = false;
  bool counted_waiting = false;
  uint32_t remaining = 0;
  {
    std::lock_guard<std::mutex> lock(call->mutex);
    call->consumers.erase(consumer->id);
    counted_waiting = consumer->waiting_counted.exchange(
        false, std::memory_order_acq_rel);
    remaining = static_cast<uint32_t>(std::min<std::size_t>(
        call->consumers.size(), std::numeric_limits<uint32_t>::max()));
    if (call->work_context)
      call->work_context->setConsumerCount(remaining);
    if (remaining == 0 && call->phase == AsyncInflightPhase::Accepting) {
      call->phase = AsyncInflightPhase::Abandoned;
      cancel_owner = true;
    }
  }
  if (counted_waiting) {
    g_async_singleflight_waiting_followers.fetch_sub(
        1, std::memory_order_relaxed);
  }
  if (consumer->follower && cancelled)
    g_async_singleflight_followers_cancelled.fetch_add(
        1, std::memory_order_relaxed);
  if (cancel_owner) {
    g_async_singleflight_no_consumer_cancellations.fetch_add(
        1, std::memory_order_relaxed);
    if (call->work_context)
      call->work_context->requestCancellation(
          RequestCancellationReason::NoConsumers);
    eraseAsyncInflightSubRequest(call);
    releaseAsyncInflightOwner(call);
  }
}

ConversionResult asyncConsumerCancellationResult(
    const std::shared_ptr<RequestContext> &context) {
  RequestCancellationResponse cancellation;
  if (requestCancellationResponse(context, cancellation))
    return ConversionResult(cancellation.status_code,
                            "text/plain; charset=utf-8",
                            std::move(cancellation.headers),
                            std::move(cancellation.body));
  Request failure_request;
  failure_request.context = context;
  return schedulerFailureResult(failure_request,
                                SchedulerSubmitStatus::Cancelled);
}

ConversionResult asyncInternalServerErrorResult(
    const std::shared_ptr<RequestContext> &context) {
  if (context)
    context->suggestFailure(RequestFailureAttribution::Server);
  return ConversionResult(
      500, "text/plain; charset=utf-8",
      {{"Cache-Control", "private, no-store"}},
      "Internal server error while processing request.\n"
      "处理请求时发生内部服务器错误。\n");
}

template <class Factory>
void invokeAsyncSubRequestCompletion(
    ConversionService::Completion completion,
    const std::shared_ptr<RequestContext> &context,
    Factory &&factory) noexcept {
  if (!completion)
    return;
  bool invoked = false;
  try {
    ConversionResult result = std::invoke(std::forward<Factory>(factory));
    invoked = true;
    completion(std::move(result));
  } catch (...) {
    if (invoked)
      return;
    try {
      invoked = true;
      completion(asyncInternalServerErrorResult(context));
    } catch (...) {
    }
  }
}

void completeAsyncSubRequestCancellation(
    const std::shared_ptr<AsyncSubRequestConsumer> &consumer) noexcept {
  if (!consumer ||
      consumer->completion_claimed.exchange(true, std::memory_order_acq_rel))
    return;
  detachAsyncSubRequestConsumer(consumer, true);
  ConversionService::Completion completion = std::move(consumer->completion);
  const std::shared_ptr<RequestContext> context =
      std::exchange(consumer->context, {});
  invokeAsyncSubRequestCompletion(
      std::move(completion), context,
      [&] { return asyncConsumerCancellationResult(context); });
}

void registerAsyncSubRequestCancellation(
    const std::shared_ptr<AsyncSubRequestConsumer> &consumer) {
  if (!consumer || !consumer->context)
    return;
  const std::weak_ptr<AsyncSubRequestConsumer> weak_consumer = consumer;
  consumer->cancellation_registration =
      consumer->context->registerCancellationCallback([weak_consumer] {
        if (auto current = weak_consumer.lock())
          completeAsyncSubRequestCancellation(current);
      });
}

void completeAsyncSubRequestSuccess(
    const std::shared_ptr<AsyncSubRequestConsumer> &consumer,
    const SharedCoalescedResponse &result) noexcept {
  if (!consumer || !result ||
      consumer->completion_claimed.exchange(true, std::memory_order_acq_rel))
    return;
  const std::shared_ptr<AsyncInflightSubRequest> call = consumer->call.lock();
  const std::shared_ptr<RequestContext> context =
      std::exchange(consumer->context, {});
  RequestCancellationResponse cancellation;
  const bool cancelled = requestCancellationResponse(context, cancellation);
  detachAsyncSubRequestConsumer(consumer, cancelled);
  ConversionService::Completion completion = std::move(consumer->completion);
  invokeAsyncSubRequestCompletion(
      std::move(completion), context, [&]() -> ConversionResult {
        if (cancelled)
          return ConversionResult(cancellation.status_code,
                                  "text/plain; charset=utf-8",
                                  std::move(cancellation.headers),
                                  std::move(cancellation.body));
        if (context && call && call->work_context)
          context->setCostClass(call->work_context->costClass());
        Response response;
        std::string body =
            applyCoalescedToResponse(*result, context, response);
        if (response.status_code >= 200 && response.status_code < 300)
          statistics::recordSubscriptionConversion(
              consumer->statistics_metadata, result->rule_conversions);
        return makeConversionResult(std::move(response), std::move(body));
      });
}

void completeAsyncSubRequestFailure(
    const std::shared_ptr<AsyncSubRequestConsumer> &consumer,
    SchedulerSubmitStatus status, const std::exception_ptr &error) noexcept {
  if (!consumer ||
      consumer->completion_claimed.exchange(true, std::memory_order_acq_rel))
    return;
  const std::shared_ptr<RequestContext> context =
      std::exchange(consumer->context, {});
  RequestCancellationResponse cancellation;
  const bool cancelled = requestCancellationResponse(context, cancellation);
  detachAsyncSubRequestConsumer(consumer, cancelled);
  ConversionService::Completion completion = std::move(consumer->completion);
  invokeAsyncSubRequestCompletion(
      std::move(completion), context, [&]() -> ConversionResult {
        if (cancelled)
          return ConversionResult(cancellation.status_code,
                                  "text/plain; charset=utf-8",
                                  std::move(cancellation.headers),
                                  std::move(cancellation.body));
        Request failure_request;
        failure_request.context = context;
        if (status != SchedulerSubmitStatus::Accepted)
          return schedulerFailureResult(failure_request, status);
        if (error) {
          try {
            std::rethrow_exception(error);
          } catch (const SchedulerSubmitError &submit_error) {
            return schedulerFailureResult(failure_request,
                                          submit_error.status());
          } catch (...) {
          }
        }
        return asyncInternalServerErrorResult(context);
      });
}

std::shared_ptr<AsyncSubRequestConsumer> makeAsyncSubRequestConsumer(
    const std::shared_ptr<RequestContext> &context, bool follower,
    statistics::SubscriptionConversionMetadata statistics_metadata,
    ConversionService::Completion completion) {
  auto consumer = std::make_shared<AsyncSubRequestConsumer>();
  consumer->follower = follower;
  consumer->context = context;
  consumer->statistics_metadata = statistics_metadata;
  consumer->completion = std::move(completion);
  return consumer;
}

void publishAsyncSubRequestSuccess(
    const std::shared_ptr<AsyncInflightSubRequest> &call,
    const std::shared_ptr<const PreparedSubRequest> &prepared,
    SharedCoalescedResponse result) noexcept {
  if (!call || !prepared || !result)
    return;
  bool publish_cache = false;
  {
    std::lock_guard<std::mutex> lock(call->mutex);
    if (call->phase == AsyncInflightPhase::Abandoned ||
        call->consumers.empty()) {
      call->phase = AsyncInflightPhase::Abandoned;
    } else {
      call->phase = AsyncInflightPhase::Publishing;
      call->result = result;
      publish_cache = !prepared->age.requested &&
                      !prepared->explain_request;
    }
  }
  if (publish_cache) {
    try {
      storeCachedSubResponse(call->key, result, *prepared->settings);
    } catch (...) {
    }
  }

  std::unordered_map<uint64_t, std::shared_ptr<AsyncSubRequestConsumer>>
      consumers;
  {
    std::lock_guard<std::mutex> lock(call->mutex);
    if (call->phase != AsyncInflightPhase::Abandoned)
      call->phase = AsyncInflightPhase::Done;
    consumers.swap(call->consumers);
  }
  if (call->work_context)
    call->work_context->setConsumerCount(0);
  eraseAsyncInflightSubRequest(call);
  releaseAsyncInflightOwner(call);
  for (auto &[_, consumer] : consumers)
    completeAsyncSubRequestSuccess(consumer, result);
}

void publishAsyncSubRequestFailure(
    const std::shared_ptr<AsyncInflightSubRequest> &call,
    SchedulerSubmitStatus status, std::exception_ptr error) noexcept {
  if (!call)
    return;
  if (status != SchedulerSubmitStatus::Accepted &&
      status != SchedulerSubmitStatus::Cancelled)
    g_async_singleflight_owner_flow_rejections.fetch_add(
        1, std::memory_order_relaxed);
  std::unordered_map<uint64_t, std::shared_ptr<AsyncSubRequestConsumer>>
      consumers;
  {
    std::lock_guard<std::mutex> lock(call->mutex);
    if (call->phase != AsyncInflightPhase::Abandoned)
      call->phase = AsyncInflightPhase::Done;
    consumers.swap(call->consumers);
  }
  if (call->work_context)
    call->work_context->setConsumerCount(0);
  eraseAsyncInflightSubRequest(call);
  releaseAsyncInflightOwner(call);
  for (auto &[_, consumer] : consumers)
    completeAsyncSubRequestFailure(consumer, status, error);
}

ConversionResult executePreparedStandalone(Request &request,
                                           const PreparedSubRequest &prepared,
                                           bool track_statistics) {
  ScopedSettingsView settings_scope(prepared.settings);
  Response response;
  RuleConversionStats stats;
  std::string body = runScheduledConversion(
      request, response, prepared.settings,
      track_statistics ? &stats : nullptr, false);
  body = finalizeSubResponse(request, response, std::move(body), prepared.age);
  recordTrackedSubRequest(track_statistics, request, response, stats.rules);
  return makeConversionResult(std::move(response), std::move(body));
}

} // namespace

void ConversionService::convertSubscriptionAsync(Request request,
                                                  bool track_statistics,
                                                  Completion completion) const {
  if (!completion)
    return;
  if (conversion_shutdown_requested.load(std::memory_order_acquire)) {
    Request failure_request;
    failure_request.context = request.context;
    completion(schedulerFailureResult(failure_request,
                                      SchedulerSubmitStatus::Stopping));
    return;
  }
  RequestCancellationResponse cancellation_response;
  if (requestCancellationResponse(request.context, cancellation_response)) {
    completion(ConversionResult(cancellation_response.status_code,
                                "text/plain; charset=utf-8",
                                std::move(cancellation_response.headers),
                                std::move(cancellation_response.body)));
    return;
  }
  const RequestCostClass cost = estimateConversionCost(request);
  if (request.context)
    request.context->setCostClass(cost);
  writeLog(LOG_LEVEL_DEBUG,
           "CONVERSION_ADMISSION cost=" +
               std::string(requestCostClassName(cost)));
  const uint64_t bytes = request.context
                             ? request.context->estimatedBytes()
                             : static_cast<uint64_t>(request.postdata.size());
  const std::shared_ptr<RequestContext> context = request.context;
  Response prepared_response;
  std::string early_body;
  PreparedSubRequest prepared =
      prepareSubRequest(request, prepared_response, early_body);
  if (prepared.early_complete) {
    completion(makeConversionResult(std::move(prepared_response),
                                    std::move(early_body)));
    return;
  }
  statistics::SubscriptionConversionMetadata statistics_metadata;
  if (track_statistics) {
    ScopedSettingsView settings_scope(prepared.settings);
    statistics_metadata =
        statistics::prepareSubscriptionConversionMetadata(request);
  }
  if (prepared.coalesce) {
    SharedCoalescedResponse cached_result;
    if (!prepared.explain_request &&
        getCachedSubResponse(prepared.key, cached_result,
                             *prepared.settings)) {
      writeLog(LOG_LEVEL_DEBUG, "/sub 响应微缓存命中。");
      if (context)
        context->setCostClass(RequestCostClass::Low);
      if (context)
        context->markWorkAdmitted();
      Response response;
      std::string body =
          applyCoalescedToResponse(*cached_result, context, response);
      if (response.status_code >= 200 && response.status_code < 300)
        statistics::recordSubscriptionConversion(
            statistics_metadata, cached_result->rule_conversions);
      completion(makeConversionResult(std::move(response), std::move(body)));
      return;
    }

    for (;;) {
      std::shared_ptr<AsyncInflightSubRequest> call;
      std::shared_ptr<AsyncSubRequestConsumer> owner_consumer;
      bool owner = false;
      {
        std::lock_guard<std::mutex> lock(g_async_sub_inflight_mutex);
        auto iter = g_async_sub_inflight.find(prepared.key);
        if (iter != g_async_sub_inflight.end()) {
          call = iter->second;
        } else {
          call = std::make_shared<AsyncInflightSubRequest>();
          call->key = prepared.key;
          call->owner_request_id = currentLogRequestId();
          const auto work_started = RequestContext::Clock::now();
          call->work_context = std::make_shared<RequestContext>(
              call->owner_request_id, work_started,
              work_started + std::chrono::milliseconds(std::max(
                                 1, prepared.settings->requestDeadlineMs)),
              RequestContextKind::InternalWork);
          call->work_context->setCostClass(cost);
          call->work_context->setEstimatedBytes(bytes);
          owner_consumer = makeAsyncSubRequestConsumer(
              context, false, statistics_metadata, std::move(completion));
          owner_consumer->id = call->next_consumer_id++;
          owner_consumer->call = call;
          call->consumers.emplace(owner_consumer->id, owner_consumer);
          call->work_context->setConsumerCount(1);
          g_async_sub_inflight.emplace(call->key, call);
          g_async_singleflight_active_owners.fetch_add(
              1, std::memory_order_relaxed);
          g_async_singleflight_owners_created.fetch_add(
              1, std::memory_order_relaxed);
          owner = true;
        }
      }

      if (!owner) {
        SharedCoalescedResponse ready_result;
        auto consumer = makeAsyncSubRequestConsumer(
            context, true, statistics_metadata, std::move(completion));
        bool prepare_attach = false;
        bool attached = false;
        bool cancelled_before_attach = false;
        bool retry = false;
        {
          std::lock_guard<std::mutex> lock(call->mutex);
          if (call->phase == AsyncInflightPhase::Accepting) {
            consumer->id = call->next_consumer_id++;
            consumer->call = call;
            prepare_attach = true;
          } else if ((call->phase == AsyncInflightPhase::Publishing ||
                      call->phase == AsyncInflightPhase::Done) &&
                     call->result) {
            consumer->call = call;
            ready_result = call->result;
          } else {
            retry = true;
          }
        }
        if (prepare_attach) {
          registerAsyncSubRequestCancellation(consumer);
          if (consumer->completion_claimed.load(std::memory_order_acquire))
            return;
          {
            std::lock_guard<std::mutex> lock(call->mutex);
            if (call->phase == AsyncInflightPhase::Accepting &&
                !consumer->completion_claimed.load(
                    std::memory_order_acquire)) {
              call->consumers.emplace(consumer->id, consumer);
              consumer->waiting_counted.store(true,
                                               std::memory_order_release);
              g_async_singleflight_waiting_followers.fetch_add(
                  1, std::memory_order_relaxed);
              if (call->work_context)
                call->work_context->setConsumerCount(
                    static_cast<uint32_t>(std::min<std::size_t>(
                        call->consumers.size(),
                        std::numeric_limits<uint32_t>::max())));
              attached = true;
            } else if (call->phase == AsyncInflightPhase::Accepting &&
                       consumer->completion_claimed.load(
                           std::memory_order_acquire)) {
              cancelled_before_attach = true;
            } else if ((call->phase == AsyncInflightPhase::Publishing ||
                        call->phase == AsyncInflightPhase::Done) &&
                       call->result) {
              ready_result = call->result;
            } else {
              retry = true;
            }
          }
        }
        if (cancelled_before_attach)
          return;
        if (retry) {
          eraseAsyncInflightSubRequest(call);
          if (consumer->completion_claimed.exchange(
                  true, std::memory_order_acq_rel))
            return;
          completion = std::move(consumer->completion);
          continue;
        }
        if (context)
          context->markWorkAdmitted();
        if (context)
          context->setSingleflightRole(RequestSingleflightRole::Follower);
        g_async_singleflight_followers_attached.fetch_add(
            1, std::memory_order_relaxed);
        if (attached) {
          writeLog(LOG_LEVEL_INFO,
                   "SUB_REQUEST_COALESCED owner_request_id=" +
                       (call->owner_request_id.empty()
                            ? "unavailable"
                            : call->owner_request_id));
        } else {
          completeAsyncSubRequestSuccess(consumer, ready_result);
        }
        return;
      }

      if (context) {
        context->setSingleflightRole(RequestSingleflightRole::Owner);
        context->setConsumerCount(1);
      }
      try {
        registerAsyncSubRequestCancellation(owner_consumer);
        auto prepared_owner =
            std::make_shared<const PreparedSubRequest>(std::move(prepared));
        Request work_request = std::move(request);
        work_request.context = call->work_context;
        const auto work_deadline = call->work_context->deadline();
        const RequestCancellationToken work_cancellation =
            call->work_context->cancellationToken();
        const auto queued_at = RequestContext::Clock::now();
        const SchedulerSubmitStatus owner_submit_status =
            legacyRequestFlowScheduler().submitAsync(
            cost, bytes, work_deadline, work_cancellation,
            [work_request = std::move(work_request), prepared_owner, call,
             track_statistics, work_deadline, work_cancellation,
             queued_at]() mutable {
              ScopedRequestContext request_scope(call->work_context);
              ScopedLogRequestContext log_scope(call->owner_request_id);
              if (call->work_context) {
                call->work_context->addStageDuration(
                    RequestStage::Queue,
                    RequestContext::Clock::now() - queued_at);
                call->work_context->setCurrentStage(RequestStage::Parse);
              }
              CpuPermitLease permit(conversionCpuGate(), work_deadline,
                                    work_cancellation);
              const SchedulerSubmitStatus permit_status = permit.acquire();
              if (permit_status != SchedulerSubmitStatus::Accepted)
                throw SchedulerSubmitError(permit_status);
              ScopedCpuPermit permit_scope(permit);
              RuleConversionStats stats;
              return executePreparedSubRequestOwner(
                  work_request, *prepared_owner,
                  track_statistics ? &stats : nullptr);
            },
            [call, prepared_owner](
                SchedulerAsyncResult<SharedCoalescedResponse> result) mutable {
              if (result.status == SchedulerSubmitStatus::Accepted &&
                  !result.error && result.value && *result.value) {
                publishAsyncSubRequestSuccess(
                    call, prepared_owner, std::move(*result.value));
                return;
              }
              publishAsyncSubRequestFailure(call, result.status,
                                            std::move(result.error));
            });
        if (owner_submit_status == SchedulerSubmitStatus::Accepted && context)
          context->markWorkAdmitted();
      } catch (...) {
        g_async_singleflight_owner_flow_rejections.fetch_add(
            1, std::memory_order_relaxed);
        publishAsyncSubRequestFailure(
            call, SchedulerSubmitStatus::Accepted,
            std::current_exception());
      }
      return;
    }
  }

  const auto deadline = context ? context->deadline()
                                : RequestContext::Clock::time_point::max();
  const RequestCancellationToken cancellation =
      context ? context->cancellationToken() : RequestCancellationToken();
  auto prepared_standalone =
      std::make_shared<const PreparedSubRequest>(std::move(prepared));
  const auto queued_at = RequestContext::Clock::now();
  const SchedulerSubmitStatus standalone_submit_status =
      legacyRequestFlowScheduler().submitAsync(
      cost, bytes, deadline, cancellation,
      [request = std::move(request), prepared_standalone, track_statistics,
       deadline, cancellation, queued_at]() mutable {
        ScopedRequestContext request_scope(request.context);
        ScopedLogRequestContext log_scope(
            request.context ? request.context->requestId() : std::string());
        if (request.context) {
          request.context->addStageDuration(
              RequestStage::Queue, RequestContext::Clock::now() - queued_at);
          request.context->setCurrentStage(RequestStage::Parse);
        }
        CpuPermitLease permit(conversionCpuGate(), deadline, cancellation);
        const SchedulerSubmitStatus permit_status = permit.acquire();
        if (permit_status != SchedulerSubmitStatus::Accepted)
          throw SchedulerSubmitError(permit_status);
        ScopedCpuPermit permit_scope(permit);
        return executePreparedStandalone(
            request, *prepared_standalone, track_statistics);
      },
      [context, completion = std::move(completion)](
          SchedulerAsyncResult<ConversionResult> result) mutable {
        if (result.status == SchedulerSubmitStatus::Accepted &&
            !result.error && result.value) {
          completion(std::move(*result.value));
          return;
        }
        Request failure_request;
        failure_request.context = context;
        if (result.status != SchedulerSubmitStatus::Accepted) {
          completion(schedulerFailureResult(failure_request, result.status));
          return;
        }
        if (result.error) {
          try {
            std::rethrow_exception(result.error);
          } catch (const SchedulerSubmitError &error) {
            completion(schedulerFailureResult(failure_request,
                                              error.status()));
            return;
          } catch (...) {
          }
        }
        if (context)
          context->suggestFailure(RequestFailureAttribution::Server);
        writeLog(LOG_LEVEL_ERROR,
                 "ASYNC_REQUEST_FLOW_FAILED reason=unexpected_exception");
        completion(ConversionResult(
            500, "text/plain; charset=utf-8",
            {{"Cache-Control", "private, no-store"}},
            "Internal server error while processing request.\n"
            "处理请求时发生内部服务器错误。\n"));
      });
  if (standalone_submit_status == SchedulerSubmitStatus::Accepted && context)
    context->markWorkAdmitted();
}

WorkloadSchedulerSnapshot conversionSchedulerSnapshot() {
  if (WorkloadScheduler *scheduler =
          conversion_scheduler_instance.load(std::memory_order_acquire))
    return scheduler->snapshot();
  return {};
}

WorkloadSchedulerSnapshot legacyRequestFlowSnapshot() {
  if (WorkloadScheduler *scheduler =
          legacy_request_flow_instance.load(std::memory_order_acquire))
    return scheduler->snapshot();
  return {};
}

SubscriptionOwnerAdmissionSnapshot subscriptionOwnerAdmissionSnapshot() {
  auto make_snapshot = [](const char *source, WorkloadScheduler *scheduler) {
    SubscriptionOwnerAdmissionSnapshot result;
    result.source = source;
    const WorkloadSchedulerSnapshot snapshot = scheduler->snapshot();
    result.waiting_entries = snapshot.queued_entries;
    result.waiting_bytes = snapshot.queued_bytes;
    result.active = snapshot.active;
    result.accepted_total = snapshot.accepted;
    result.rejected_total = snapshot.rejected;
    result.cancelled_total = snapshot.cancelled;
    result.max_wait_entries = scheduler->maxEntries();
    result.max_wait_bytes = scheduler->maxBytes();
    result.oldest_wait_ms = snapshot.oldest_queued_age_ms;
    return result;
  };
  if (WorkloadScheduler *scheduler =
          legacy_request_flow_instance.load(std::memory_order_acquire))
    return make_snapshot("legacy_request_flow", scheduler);
  if (WorkloadScheduler *scheduler =
          conversion_scheduler_instance.load(std::memory_order_acquire))
    return make_snapshot("conversion_scheduler", scheduler);
  return {};
}

CpuPermitSnapshot conversionCpuPermitSnapshot() {
  if (CpuPermitGate *gate =
          conversion_cpu_gate_instance.load(std::memory_order_acquire))
    return gate->snapshot();
  return {std::max<uint64_t>(
              1, desired_cpu_permits.load(std::memory_order_acquire)),
          0, 0};
}

void setConversionCpuPermitLimit(uint64_t limit) noexcept {
  const uint64_t normalized = std::max<uint64_t>(1, limit);
  desired_cpu_permits.store(normalized, std::memory_order_release);
  if (CpuPermitGate *gate =
          conversion_cpu_gate_instance.load(std::memory_order_acquire))
    gate->setLimit(static_cast<std::size_t>(std::min<uint64_t>(
        normalized, std::numeric_limits<std::size_t>::max())));
}

ResponseMicroCacheSnapshot responseMicroCacheSnapshot() {
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  pruneExpiredSubResponseCache(std::chrono::steady_clock::now());
  return {static_cast<uint64_t>(g_sub_response_cache.size()),
          g_sub_response_cache_bytes, subResponseCacheMaxBytes()};
}

void shutdownConversionScheduler() noexcept {
  requestConversionSchedulerShutdown();
  if (WorkloadScheduler *scheduler =
          conversion_scheduler_instance.load(std::memory_order_acquire))
    scheduler->shutdown(true);
  if (WorkloadScheduler *scheduler =
          legacy_request_flow_instance.load(std::memory_order_acquire))
    scheduler->shutdown(true);
}

void requestConversionSchedulerShutdown() noexcept {
  conversion_shutdown_requested.store(true, std::memory_order_release);
  if (WorkloadScheduler *scheduler =
          legacy_request_flow_instance.load(std::memory_order_acquire))
    scheduler->requestShutdown(true);
  if (WorkloadScheduler *scheduler =
          conversion_scheduler_instance.load(std::memory_order_acquire))
    scheduler->requestShutdown(true);
  if (CpuPermitGate *gate =
          conversion_cpu_gate_instance.load(std::memory_order_acquire))
    gate->requestShutdown();
}

static std::string applyConversionResult(ConversionResult result,
                                         Response &response) {
  response.status_code = result.statusCode();
  response.content_type = std::move(result).releaseContentType();
  response.headers = std::move(result).releaseHeaders();
  response.shared_body = std::move(result).releaseSharedBody();
  return std::move(result).releaseBody();
}

std::string subconverter(RESPONSE_CALLBACK_ARGS) {
  return applyConversionResult(
      defaultConversionService().convertSubscription(request, false), response);
}

std::string subconverterTracked(RESPONSE_CALLBACK_ARGS) {
  return applyConversionResult(
      defaultConversionService().convertSubscription(request, true), response);
}

SubscriptionSingleflightSnapshot subscriptionSingleflightSnapshot() noexcept {
  return {
      g_async_singleflight_active_owners.load(std::memory_order_relaxed),
      g_async_singleflight_waiting_followers.load(std::memory_order_relaxed),
      g_async_singleflight_owners_created.load(std::memory_order_relaxed),
      g_async_singleflight_followers_attached.load(std::memory_order_relaxed),
      g_async_singleflight_followers_cancelled.load(std::memory_order_relaxed),
      g_async_singleflight_no_consumer_cancellations.load(
          std::memory_order_relaxed),
      g_async_singleflight_owner_flow_rejections.load(
          std::memory_order_relaxed),
  };
}

static void applyAsyncConversionResult(
    ConversionResult result, async_response_completion completion) {
  Response response;
  response.status_code = result.statusCode();
  response.content_type = std::move(result).releaseContentType();
  response.headers = std::move(result).releaseHeaders();
  response.shared_body = std::move(result).releaseSharedBody();
  std::string body = std::move(result).releaseBody();
  completion(std::move(response), std::move(body));
}

void subconverterAsync(Request request, async_response_completion completion) {
  defaultConversionService().convertSubscriptionAsync(
      std::move(request), false,
      [completion = std::move(completion)](ConversionResult result) mutable {
        applyAsyncConversionResult(std::move(result), std::move(completion));
      });
}

void subconverterTrackedAsync(Request request,
                              async_response_completion completion) {
  defaultConversionService().convertSubscriptionAsync(
      std::move(request), true,
      [completion = std::move(completion)](ConversionResult result) mutable {
        applyAsyncConversionResult(std::move(result), std::move(completion));
      });
}

namespace {

struct ParsedSubRequest {
  std::string target;
  std::string surge_version_text;
  bool target_was_auto = false;
  UserAgentMatch user_agent_match;
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
  parsed.explain.proxy_config =
      parseProxy(settings.proxyConfig, settings.proxyBypass).describe();
  parsed.explain.proxy_ruleset =
      parseProxy(settings.proxyRuleset, settings.proxyBypass).describe();
  parsed.explain.proxy_subscription =
      parseProxy(settings.proxySubscription, settings.proxyBypass).describe();
  parsed.explain.proxy_bypass =
      ProxyBypassPolicy::parse(settings.proxyBypass).describe();
  parsed.explain.requested_target = parsed.target;
  if (parsed.explain_mode) {
    std::string rawUrlForLog = getUrlArg(argument, "url");
    const bool target_is_known = parsed.target == "auto" ||
                                 findTargetDescriptor(parsed.target) != nullptr;
    writeLog(LOG_LEVEL_INFO,
             "EXPLAIN_REQUEST_RECEIVED requested_target=" +
                  (parsed.target.empty() ? std::string("<empty>")
                   : (target_is_known ? parsed.target
                                      : std::string("<unsupported>"))) +
                  " parameter_count=" + std::to_string(argument.size()) +
                  " url_length=" + std::to_string(rawUrlForLog.size()));
  }

  parsed.clash_new_field = getUrlArg(argument, "new_name");
  parsed.surge_version = !parsed.surge_version_text.empty()
                             ? to_int(parsed.surge_version_text, 3)
                             : 3;
  parsed.target_was_auto = parsed.target == "auto";
  if (parsed.target_was_auto)
    parsed.user_agent_match =
        matchUserAgent(request.headers["User-Agent"], parsed.target,
                       parsed.clash_new_field, parsed.surge_version);
  parsed.explain.target = parsed.target;

  parsed.target_descriptor = findTargetDescriptor(parsed.target);
  if (!parsed.target_descriptor) {
    if (parsed.target_was_auto)
      writeLog(LOG_LEVEL_WARNING,
               "AUTO_TARGET_UNRESOLVED ua_family=unknown");
    response.status_code = 400;
    return "Invalid request: unsupported target value.\n"
           "无效请求：不支持的 target 参数值。\n"
           "Supported targets: " +
           supportedTargets(", ") + ".\n" + "支持的 target：" +
           supportedTargets("、") + "。";
  }
  parsed.simple_subscription = parsed.target_descriptor->simple_subscription;
  parsed.explain.remote_subscription_backend = remoteSubscriptionModeName(
      parsed.target_descriptor->remote_subscription_mode);
  if (parsed.target_was_auto) {
    writeLog(LOG_LEVEL_INFO,
             "AUTO_TARGET_RESOLVED target=" + parsed.target +
                 " parser=" +
                 nodeParserModeName(parsed.target_descriptor->parser_mode) +
                 " ua_family=" + parsed.user_agent_match.family);
  }

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
  std::string stash_base;
  std::string quan_base;
  std::string quanx_base;
  std::string loon_base;
  std::string sssub_base;
  std::string singbox_base;

  std::map<std::string, std::string> provider_headers;
  template_args template_arguments;
  ProxyPolicy subscription_proxy;

  // Client-managed remote resources cannot consume server-side node
  // transformations. Preserve explicit request semantics by selecting the
  // Legacy route, while configured defaults remain applicable to direct
  // nodes without disabling native remote subscriptions for existing
  // deployments.
  bool requested_remote_node_filter = false;
  bool requested_remote_node_rename = false;
  bool requested_remote_node_transform = false;
  bool requested_remote_node_option_override = false;
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
  policy.stash_base = settings.stashBase;
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
  if (!parsed.provider_headers.empty() && parsed.target != "clash" &&
      parsed.target != "stash") {
    response.status_code = 400;
    return "Invalid request: provider_headers is supported only for "
           "target=clash or target=stash.\n"
           "无效请求：provider_headers 仅支持 target=clash 或 "
           "target=stash。";
  }
  if (parsed.target == "stash" && !parsed.provider_proxy_direct.is_undef()) {
    response.status_code = 400;
    return "Invalid request: provider_proxy_direct is a Mihomo-only option "
           "and cannot be applied to Stash proxy-providers.\n"
           "无效请求：provider_proxy_direct 是 Mihomo 专用选项，不能应用于 "
           "Stash proxy-provider。";
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

  policy.subscription_proxy =
      parseProxy(settings.proxySubscription, settings.proxyBypass);
  policy.requested_remote_node_filter =
      !parsed.include_remark.empty() || !parsed.exclude_remark.empty();
  policy.requested_remote_node_rename = !parsed.renames.empty();
  policy.requested_remote_node_transform =
      !parsed.emoji.is_undef() || parsed.add_emoji.get(false) ||
      parsed.remove_emoji.get(false) || parsed.append_type.get(false) ||
      parsed.sort.get(false) || parsed.filter_deprecated.get(false);
  policy.requested_remote_node_option_override =
      !parsed.tfo.is_undef() || !parsed.udp.is_undef() ||
      !parsed.skip_cert_verify.is_undef() || !parsed.tls13.is_undef();
  policy.generator.append_proxy_type =
      parsed.append_type.get(settings.appendType);
  // 上游项目默认在 clash 目标下自动把 expand 设为 true
  // 本项目默认 expand=false（使用 rule-provider 模式不展开规则集）
  // 若用户主动传入 expand=true，则按照用户意愿内联展开规则集
  parsed.expand_rulesets.define(false);

  policy.generator.clash_proxies_style = settings.clashProxiesStyle;
  policy.generator.clash_proxy_groups_style = settings.clashProxyGroupsStyle;
  policy.generator.stash_request_tfo = parsed.tfo;
  policy.generator.stash_request_udp = parsed.udp;
  policy.generator.stash_request_tls13 = parsed.tls13;
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
    const bool requested_config = context == FetchContext::PublicRequest;
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
        if (parsed.target == "stash" &&
            checkExternalBase(extconf.stash_rule_base, policy.stash_base,
                              context))
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
      if (requested_config)
        policy.requested_remote_node_rename = true;
    }
    if (!extconf.emoji.empty())
      policy.generator.emoji_array = extconf.emoji;
    if (!extconf.include.empty()) {
      policy.include_remarks = extconf.include;
      if (requested_config)
        policy.requested_remote_node_filter = true;
    }
    if (!extconf.exclude.empty()) {
      policy.exclude_remarks = extconf.exclude;
      if (requested_config)
        policy.requested_remote_node_filter = true;
    }
    if (requested_config &&
        (extconf.add_emoji.get(false) ||
         extconf.remove_old_emoji.get(false)))
      policy.requested_remote_node_transform = true;
    parsed.add_emoji.define(extconf.add_emoji);
    parsed.remove_emoji.define(extconf.remove_old_emoji);
  };

  for (const ExternalConfigCandidate &candidate : config_candidates) {
    policy.template_arguments.local_vars = tpl_args_base;
    writeLog((candidate.fallback ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO),
             candidate.fallback
                 ? "用户外部配置失败，显式尝试默认外部配置：" +
                       summarizeUrlForLog(candidate.path)
                 : "正在加载外部配置：" +
                       summarizeUrlForLog(candidate.path));

    ExternalConfig extconf;
    extconf.tpl_args = &policy.template_arguments;
    ExternalConfigLoadResult loaded =
        loadExternalConfig(candidate.path, extconf, candidate.context);
    bool effective =
        loaded.ok() && hasEffectiveExternalConfig(
                           extconf, policy.template_arguments, tpl_args_base,
                           parsed.target);
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
    writeLog(LOG_LEVEL_WARNING, "外部配置不可用，原因：" + reason + "，来源：" +
                    summarizeUrlForLog(candidate.path));
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
    const bool stash_native_rulesets = parsed.target == "stash";
    if (stash_native_rulesets) {
      const bool reuse_cached_rulesets =
          policy.custom_rulesets == settings.customRulesets &&
          !settings.updateRulesetOnRequest &&
          settings.rulesetsContent.size() == policy.custom_rulesets.size();
      refreshRulesets(policy.custom_rulesets, plan.ruleset_content,
                      rulesetFetchContext,
                      RulesetRefreshMode::PreferNativeStashProviders,
                      reuse_cached_rulesets ? &settings.rulesetsContent
                                            : nullptr);
    } else if (policy.custom_rulesets != settings.customRulesets)
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

static bool parseSourceGroupRule(const std::string &rule,
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

static bool parseGroupIdRule(const std::string &rule,
                             std::string &group_id_pattern,
                             std::string &server_pattern) {
  static const std::string group_id_regex =
      R"(^!!GROUPID=([\d\-+!,]+)(?:!!(.*))?$)";
  if (!startsWith(rule, "!!GROUPID="))
    return false;
  group_id_pattern.clear();
  server_pattern.clear();
  return regGetMatch(rule, group_id_regex, 3,
                     static_cast<std::string *>(nullptr), &group_id_pattern,
                     &server_pattern) == 0 &&
         !group_id_pattern.empty();
}

static bool remotePolicyRegexIsSafe(const std::string &pattern) {
  return pattern.find(',') == std::string::npos &&
         std::none_of(pattern.begin(), pattern.end(), [](unsigned char ch) {
           return ch < 0x20 || ch == 0x7f;
         });
}

static bool policyPathRegexIsSafe(const std::string &pattern) {
  return pattern.find('"') == std::string::npos &&
         std::none_of(pattern.begin(), pattern.end(), [](unsigned char ch) {
           return ch < 0x20 || ch == 0x7f;
         });
}

static std::string quanxRemoteCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings) {
  const extra_settings &ext = policy.generator;
  if (ext.nodelist)
    return "list-mode";
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
  }
  if (!policy.include_remarks.empty() || !policy.exclude_remarks.empty())
    return "node-filters";
  if (!ext.rename_array.empty())
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (ext.add_emoji || ext.remove_emoji || ext.append_proxy_type ||
      ext.sort_flag || ext.filter_deprecated || !settings.filterScript.empty())
    return "node-transform";
  if (!ext.udp.is_undef() || !ext.tfo.is_undef() ||
      !ext.skip_cert_verify.is_undef() || !ext.tls13.is_undef())
    return "node-option-override";

  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    if (group.Type == ProxyGroupType::SSID ||
        group.Type == ProxyGroupType::Relay ||
        group.Type == ProxyGroupType::Smart)
      continue;

    size_t dynamic_rule_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!remotePolicyRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!remotePolicyRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }

      if (++dynamic_rule_count > 1)
        return "multiple-group-selectors";
    }
    if (!group.UsingProvider.empty() && dynamic_rule_count)
      return "provider-and-rule-selectors";
  }
  return "native-capable";
}

static std::string policyPathCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings, RemoteSubscriptionMode mode) {
  const extra_settings &ext = policy.generator;
  const bool surfboard = mode == RemoteSubscriptionMode::SurfboardPolicyPath;
  if ((surfboard && !settings.surfboardPolicyPath) ||
      (!surfboard && !settings.surgePolicyPath))
    return "disabled-by-config";
  if (ext.nodelist)
    return "list-mode";
  if (!surfboard && parsed.surge_version < 3)
    return "unsupported-target-version";

  size_t remote_subscription_count = 0;
  int remote_group_id = -1;
  std::string remote_source_tag;
  std::string remote_requested_name;
  int item_group_id = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (surfboard && tagged.has_interval)
      return "unsupported-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(
            link, tagged.has_provider || (!surfboard && tagged.has_interval))) {
      remote_subscription_count++;
      remote_group_id = item_group_id;
      remote_source_tag = tagged.tag;
      remote_requested_name = tagged.provider;
    }
    item_group_id++;
  }
  if (remote_subscription_count == 0)
    return "no-remote-subscription";
  if (remote_subscription_count > 1)
    return "multiple-remote-subscriptions";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  bool selects_remote_subscription = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    size_t dynamic_rule_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      const bool group_id_selector =
          parseGroupIdRule(rule, selector, server_pattern);
      const bool source_selector =
          !group_id_selector &&
          parseSourceGroupRule(rule, selector, server_pattern);
      if (group_id_selector || source_selector) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!policyPathRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!policyPathRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }

      if (group_id_selector && matchRange(selector, remote_group_id))
        selects_remote_subscription = true;
      else if (source_selector && !remote_source_tag.empty() &&
               regFind(remote_source_tag, selector))
        selects_remote_subscription = true;
      else if (!group_id_selector && !source_selector)
        selects_remote_subscription = true;
      if (++dynamic_rule_count > 1)
        return "multiple-group-selectors";
    }

    if (!group.UsingProvider.empty()) {
      if (dynamic_rule_count)
        return "provider-and-rule-selectors";
      if (!remote_requested_name.empty() &&
          std::find(group.UsingProvider.begin(), group.UsingProvider.end(),
                    remote_requested_name) != group.UsingProvider.end())
        selects_remote_subscription = true;
    }
    if ((group.Type == ProxyGroupType::SSID ||
         group.Type == ProxyGroupType::Relay ||
         group.Type == ProxyGroupType::Smart) &&
        (dynamic_rule_count || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_subscription ? "native-capable"
                                     : "no-remote-policy-group";
}

struct LoonProspectiveRemote {
  int group_id = 0;
  std::string source_tag;
  std::string requested_name;
  std::string selection_name;
};

static bool loonGroupRuleSelectsRemote(
    const std::string &rule,
    const std::vector<LoonProspectiveRemote> &remotes) {
  std::string selector, server_pattern;
  if (parseGroupIdRule(rule, selector, server_pattern)) {
    return std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
      return matchRange(selector, remote.group_id);
    });
  }
  if (parseSourceGroupRule(rule, selector, server_pattern)) {
    return std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
      return !remote.source_tag.empty() && regFind(remote.source_tag, selector);
    });
  }
  return !startsWith(rule, "!!") && !startsWith(rule, "script:");
}

static std::string loonRemoteCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings) {
  if (!settings.loonRemoteProxy)
    return "disabled-by-config";
  if (policy.generator.nodelist)
    return "list-mode";
  std::vector<LoonProspectiveRemote> remotes;
  int item_group_id = 0;
  size_t generated_index = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (tagged.has_interval)
      return "unsupported-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(link, tagged.has_provider)) {
      std::string selection_name = sanitizeRemoteResourceName(tagged.provider);
      if (selection_name.empty())
        selection_name =
            "SubConverter_Remote_" + std::to_string(++generated_index);
      remotes.push_back({item_group_id, tagged.tag, tagged.provider,
                         std::move(selection_name)});
    }
    item_group_id++;
  }
  if (remotes.empty())
    return "no-remote-subscription";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  bool selects_remote_subscription = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    bool group_has_dynamic_selector = false;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      {
        const std::string normalized_rule = toLower(rule);
        if (startsWith(normalized_rule, "http://") ||
            startsWith(normalized_rule, "https://"))
          continue;
      }
      group_has_dynamic_selector = true;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!policyPathRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!policyPathRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }
      if (loonGroupRuleSelectsRemote(rule, remotes))
        selects_remote_subscription = true;
    }

    for (const std::string &provider : group.UsingProvider) {
      const std::string sanitized = sanitizeRemoteResourceName(provider);
      if (std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
            return provider == remote.requested_name ||
                   provider == remote.selection_name ||
                   sanitized == remote.selection_name;
          }))
        selects_remote_subscription = true;
    }

    if ((group.Type == ProxyGroupType::SSID ||
         group.Type == ProxyGroupType::Relay ||
         group.Type == ProxyGroupType::Smart) &&
        (group_has_dynamic_selector || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_subscription ? "native-capable"
                                     : "no-remote-policy-group";
}

struct StashProspectiveProvider {
  int group_id = 0;
  std::string source_tag;
  std::string requested_name;
  std::string selection_name;
};

static bool stashGroupRuleSelectsProvider(
    const std::string &rule,
    const std::vector<StashProspectiveProvider> &providers) {
  std::string selector, server_pattern;
  if (parseGroupIdRule(rule, selector, server_pattern)) {
    return std::any_of(providers.begin(), providers.end(),
                       [&](const auto &provider) {
                         return matchRange(selector, provider.group_id);
                       });
  }
  if (parseSourceGroupRule(rule, selector, server_pattern)) {
    return std::any_of(providers.begin(), providers.end(),
                       [&](const auto &provider) {
                         return !provider.source_tag.empty() &&
                                regFind(provider.source_tag, selector);
                       });
  }
  return !startsWith(rule, "!!") && !startsWith(rule, "script:");
}

static std::string stashProxyProviderCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy) {
  if (policy.generator.nodelist)
    return "list-mode";
  if (parsed.provider_proxy_direct.get(false))
    return "unsupported-provider-proxy";

  std::vector<StashProspectiveProvider> providers;
  std::unordered_set<std::string> reserved_provider_keys;
  int item_group_id = 0;
  size_t generated_index = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (tagged.has_proxy_direct)
      return "unsupported-provider-proxy";
    if (tagged.has_interval && tagged.interval <= 0)
      return "invalid-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(
            link, tagged.has_provider || tagged.has_interval)) {
      std::string selection_name = sanitizeRemoteResourceName(tagged.provider);
      if (selection_name.empty())
        selection_name =
            "SubConverter_Provider_" + std::to_string(++generated_index);
      selection_name = reserveStashProviderName(selection_name,
                                                reserved_provider_keys);
      providers.push_back({item_group_id, tagged.tag, tagged.provider,
                           std::move(selection_name)});
    }
    item_group_id++;
  }
  if (providers.empty())
    return "no-remote-subscription";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  // The built-in Stash base contains a safe `Proxy` selector. When no custom
  // groups are configured, the generator attaches every provider to that
  // selector so legacy preference files need no migration.
  if (policy.custom_proxy_groups.empty())
    return "native-capable";

  bool selects_remote_provider = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    if (group.Type == ProxyGroupType::Smart ||
        group.Type == ProxyGroupType::SSID)
      return "unsupported-group-type";
    size_t dynamic_selector_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      {
        const std::string normalized_rule = toLower(rule);
        if (startsWith(normalized_rule, "http://") ||
            startsWith(normalized_rule, "https://"))
          continue;
      }
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!remotePolicyRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!remotePolicyRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }
      if (++dynamic_selector_count > 1)
        return "multiple-group-selectors";
      if (stashGroupRuleSelectsProvider(rule, providers))
        selects_remote_provider = true;
    }

    if (!group.UsingProvider.empty() && dynamic_selector_count)
      return "provider-and-rule-selectors";
    for (const std::string &requested : group.UsingProvider) {
      const std::string sanitized = sanitizeRemoteResourceName(requested);
      if (std::any_of(providers.begin(), providers.end(),
                      [&](const auto &provider) {
                        return requested == provider.requested_name ||
                               requested == provider.selection_name ||
                               sanitized == provider.selection_name;
                      }))
        selects_remote_provider = true;
    }
    if (group.Type == ProxyGroupType::Relay &&
        (dynamic_selector_count || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_provider ? "native-capable"
                                 : "no-remote-policy-group";
}

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
  size_t source_calls = 0;
  size_t source_failures = 0;
  NodeParserStats parser_stats;

  RemoteSubscriptionMode remote_mode =
      parsed.target_descriptor->remote_subscription_mode;
  std::string remote_reason = "target-default";
  if (ext.nodelist) {
    remote_mode = RemoteSubscriptionMode::ServerSideParse;
    remote_reason = "list-mode";
  } else if (remote_mode == RemoteSubscriptionMode::QuanXServerRemote) {
    remote_reason = quanxRemoteCapabilityReason(parsed, policy, settings);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::SurgePolicyPath) {
    remote_reason =
        policyPathCapabilityReason(parsed, policy, settings, remote_mode);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath) {
    remote_reason =
        policyPathCapabilityReason(parsed, policy, settings, remote_mode);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::LoonRemoteProxy) {
    remote_reason = loonRemoteCapabilityReason(parsed, policy, settings);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::StashProxyProvider) {
    remote_reason = stashProxyProviderCapabilityReason(parsed, policy);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  }
  explain.remote_subscription_backend = remoteSubscriptionModeName(remote_mode);
  explain.remote_subscription_reason = remote_reason;

  if (remote_mode == RemoteSubscriptionMode::SurgePolicyPath ||
      remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath ||
      remote_mode == RemoteSubscriptionMode::LoonRemoteProxy ||
      remote_mode == RemoteSubscriptionMode::StashProxyProvider) {
    const size_t configured_filter_count =
        policy.include_remarks.size() + policy.exclude_remarks.size();
    const size_t configured_node_transform_count =
        static_cast<size_t>(policy.generator.add_emoji) +
        static_cast<size_t>(policy.generator.remove_emoji) +
        static_cast<size_t>(policy.generator.append_proxy_type) +
        static_cast<size_t>(policy.generator.sort_flag) +
        static_cast<size_t>(policy.generator.filter_deprecated) +
        static_cast<size_t>(!settings.filterScript.empty());
    const size_t configured_node_option_count =
        static_cast<size_t>(!policy.generator.udp.is_undef()) +
        static_cast<size_t>(!policy.generator.tfo.is_undef()) +
        static_cast<size_t>(
            !policy.generator.skip_cert_verify.is_undef()) +
        static_cast<size_t>(!policy.generator.tls13.is_undef());
    if (configured_filter_count || !policy.generator.rename_array.empty() ||
        configured_node_transform_count || configured_node_option_count) {
      writeLog(
          LOG_LEVEL_INFO,
          std::string(remote_mode == RemoteSubscriptionMode::SurgePolicyPath
                          ? "SURGE_POLICY_PATH"
                          : remote_mode ==
                                    RemoteSubscriptionMode::SurfboardPolicyPath
                                ? "SURFBOARD_POLICY_PATH"
                                : remote_mode ==
                                          RemoteSubscriptionMode::LoonRemoteProxy
                                      ? "LOON_REMOTE"
                                      : "STASH_PROXY_PROVIDER") +
              "_TRANSFORM_SCOPE remote_nodes=client "
          "direct_nodes=server configured_filters=" +
              std::to_string(configured_filter_count) +
              " configured_rename_rules=" +
              std::to_string(policy.generator.rename_array.size()) +
              " configured_node_transforms=" +
              std::to_string(configured_node_transform_count) +
              " configured_node_option_overrides=" +
              std::to_string(configured_node_option_count));
    }
  }

  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = &lExcludeRemarks;
  parse_set.include_remarks = &lIncludeRemarks;
  parse_set.stream_rules = &stream_temp;
  parse_set.time_rules = &time_temp;
  parse_set.sub_info = &subInfo;
  parse_set.parser_mode = parsed.target_descriptor->parser_mode;
  parse_set.parser_stats = &parser_stats;
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

  auto logRouteSelection = [&]() {
    const size_t provider_count = ext.providers.size();
    const size_t remote_count = ext.quanx_server_remotes.size() +
                                ext.surge_policy_paths.size() +
                                ext.surfboard_policy_paths.size() +
                                ext.loon_remote_proxies.size() +
                                ext.stash_proxy_providers.size();
    std::string route = "none";
    if ((provider_count || remote_count) && source_calls)
      route = "hybrid";
    else if (provider_count)
      route = "proxy-provider";
    else if (remote_count)
      route = remoteSubscriptionModeName(remote_mode);
    else if (parser_stats.invocations)
      route = "node-parser";
    else if (source_calls)
      route = "node-source";
    std::string event =
        "SUB_ROUTE_RESULT target=" + parsed.target +
        " source=" +
        std::string(parsed.target_was_auto ? "auto" : "explicit") +
        " route=" + route + " parser_policy=" +
        nodeParserModeName(parse_set.parser_mode) + " parser=" +
        (parser_stats.invocations
             ? std::string(nodeParserModeName(parse_set.parser_mode))
             : std::string("none")) +
        " provider_count=" + std::to_string(provider_count) +
        " source_calls=" + std::to_string(source_calls) +
        " source_failures=" + std::to_string(source_failures) +
        " parser_calls=" + std::to_string(parser_stats.invocations) +
        " parser_failures=" + std::to_string(parser_stats.failures);
    if (parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::QuanXServerRemote ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::SurgePolicyPath ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::SurfboardPolicyPath ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::LoonRemoteProxy ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::StashProxyProvider) {
      event += " remote_backend=" +
               std::string(remoteSubscriptionModeName(remote_mode)) +
               " remote_reason=" + remote_reason +
               " remote_count=" + std::to_string(remote_count);
    }
    writeLog(LOG_LEVEL_INFO, event);
  };

  if (!settings.insertUrls.empty() && argEnableInsert) {
    groupID = -1;
    urls = split(settings.insertUrls, "|");
    explain.insert_url_count = urls.size();
    importItems(urls, true);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(LOG_LEVEL_INFO, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。");
      source_calls++;
      if (addNodes(x, insert_nodes, groupID, parse_set) == -1) {
        source_failures++;
        if (settings.skipFailedLinks)
          writeLog(LOG_LEVEL_WARNING,
                   "以下链接不包含任何有效节点信息：" +
                       summarizeUrlForLog(x));
        else {
          logRouteSelection();
          *status_code = 400;
          return {true,
                  "Invalid request: this link does not contain any supported "
                  "proxy nodes.\n"
                  "无效请求：该链接不包含任何受支持的代理节点。\n"
                  "Please check whether the link is reachable and the node "
                  "URI format is supported.\n"
                  "请检查链接是否可访问，以及节点 URI 格式是否受支持。"};
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
      remote_mode == RemoteSubscriptionMode::ClashProxyProvider;
  const bool quanx_remote_eligible =
      remote_mode == RemoteSubscriptionMode::QuanXServerRemote;
  const bool surge_remote_eligible =
      remote_mode == RemoteSubscriptionMode::SurgePolicyPath;
  const bool surfboard_remote_eligible =
      remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath;
  const bool loon_remote_eligible =
      remote_mode == RemoteSubscriptionMode::LoonRemoteProxy;
  const bool stash_remote_eligible =
      remote_mode == RemoteSubscriptionMode::StashProxyProvider;
  const bool native_remote_target =
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::QuanXServerRemote ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::SurgePolicyPath ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::SurfboardPolicyPath ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::LoonRemoteProxy ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::StashProxyProvider;
  if (!provider_mode_eligible && !quanx_remote_eligible &&
      !surge_remote_eligible && !surfboard_remote_eligible &&
      !loon_remote_eligible && !stash_remote_eligible) {
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
      if (native_remote_target && tagged.has_provider) {
        std::string normalized = tagged.link;
        if (tagged.has_tag)
          normalized = "tag:" + tagged.tag + "," + normalized;
        urls[index] = std::move(normalized);
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
        writeLog(LOG_LEVEL_INFO, "检测到节点链接：" + summarizeUrlForLog(link) +
                        "，将直接解析。");
        node_urls.push_back(node_link);
        explain.node_link_count++;
      } else if (isLink(link) || mihomo::isHttpSchemeLink(link)) {
        writeLog(LOG_LEVEL_INFO, "检测到订阅链接：" + summarizeUrlForLog(link) +
                        "，将创建 provider。");
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
        writeLog(LOG_LEVEL_WARNING, "未知 URL 类型：" + summarizeUrlForLog(link) +
                        "，按节点链接处理。");
        node_urls.push_back(node_link);
        explain.node_link_count++;
        explain.unknown_node_link_count++;
      }
    }

    if (!subscription_urls.empty()) {
      writeLog(LOG_LEVEL_INFO, "检测到订阅 URL，启用 proxy-provider 模式。");
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

      size_t generated_explain_provider_index = 0;

      for (const SubscriptionLinkItem &item : subscription_urls) {
        ProxyProvider provider;
        std::string urlHash =
            item.url_decoded ? generateProviderHashFromDecodedUrl(item.url)
                             : generateProviderHash(item.url);
        std::string default_name = "Provider_" + urlHash;
        std::string sanitized_provider = sanitizeProviderName(item.provider);
        const bool generated_provider_name = sanitized_provider.empty();
        std::string base_name =
            sanitized_provider.empty() ? default_name : sanitized_provider;
        base_name = sanitizeProviderName(base_name);
        if (base_name.empty())
          base_name = default_name;
        provider.name = reserve_provider_name(base_name);
        provider.tag = item.tag;
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
        writeLog(LOG_LEVEL_INFO,
                 "PROXY_PROVIDER_CREATED group_id=" +
                     std::to_string(provider.groupId) + " interval=" +
                     std::to_string(provider.interval) + " proxy_direct=" +
                     boolString(provider.proxy_direct) + " source=" +
                     summarizeUrlForLog(provider.url));

        ext.providers.push_back(provider);
        SubExplainProvider explain_provider;
        explain_provider.name_generated = generated_provider_name;
        if (generated_provider_name) {
          const std::string safe_name =
              "Provider_Auto_" +
              std::to_string(++generated_explain_provider_index);
          explain_provider.name = safe_name;
          explain_provider.path = "./providers/" + safe_name + ".yaml";
        } else {
          explain_provider.name = provider.name;
          explain_provider.path = provider.path;
        }
        explain_provider.tag = provider.tag;
        explain_provider.source_summary = summarizeUrlForLog(provider.url);
        explain_provider.filter_present = !provider.filter.empty();
        explain_provider.exclude_filter_present =
            !provider.exclude_filter.empty();
        explain_provider.group_id = provider.groupId;
        explain_provider.interval = provider.interval;
        explain_provider.proxy_direct = provider.proxy_direct;
        explain.providers.push_back(std::move(explain_provider));
        groupID++;
      }
    } else {
      writeLog(LOG_LEVEL_INFO, "未检测到订阅 URL，禁用 proxy-provider 模式。");
      ext.use_proxy_provider = false;
    }

    if (!node_urls.empty()) {
      writeLog(LOG_LEVEL_INFO,
               "正在直接解析 " + std::to_string(node_urls.size()) +
                   " 个节点链接。");
      importItems(node_urls, true, FetchContext::PublicRequest);
      for (std::string &x : node_urls) {
        writeLog(LOG_LEVEL_INFO, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) +
                        "。");
        source_calls++;
        if (addNodes(x, nodes, groupID, parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
        groupID++;
      }
    }
  } else if (quanx_remote_eligible) {
    struct QuanXRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string resource_tag;
      int interval = 0;
      bool has_interval = false;
      int group_id = 0;
    };
    struct QuanXNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<QuanXRemoteLinkItem> subscription_urls;
    std::vector<QuanXNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider || tagged.has_interval);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        const std::string decoded_link = link;
        if (hasUnsafeQuanXRemoteUrlChar(decoded_link)) {
          *status_code = 400;
          return {true, quanxRemoteSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Quantumult X 远程订阅：" +
                     summarizeUrlForLog(decoded_link) +
                     "，将由客户端更新。");
        subscription_urls.push_back(
            {decoded_link, tagged.tag, tagged.provider, tagged.interval,
             tagged.has_interval, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

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
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> resource_tags;
    auto reserve_resource_tag = [&](const std::string &base) {
      std::string base_tag =
          clampProviderNameLength(base, kProviderNameMaxLen);
      if (base_tag.empty())
        base_tag = "Provider";
      if (resource_tags.insert(base_tag).second)
        return base_tag;
      int suffix_index = 1;
      while (true) {
        const std::string suffix = "_" + std::to_string(suffix_index++);
        const size_t max_base = kProviderNameMaxLen > suffix.size()
                                    ? kProviderNameMaxLen - suffix.size()
                                    : 0;
        std::string candidate =
            clampProviderNameLength(base_tag, max_base) + suffix;
        if (resource_tags.insert(candidate).second)
          return candidate;
      }
    };

    for (const QuanXRemoteLinkItem &item : subscription_urls) {
      const std::string default_tag =
          "Provider_" + generateProviderHashFromDecodedUrl(item.url);
      std::string requested_tag = sanitizeRemoteResourceName(item.resource_tag);
      if (requested_tag.empty())
        requested_tag = default_tag;

      QuanXServerRemote remote;
      remote.resource_tag = reserve_resource_tag(requested_tag);
      remote.requested_resource_tag = item.resource_tag;
      remote.selection_resource_tag = remote.resource_tag;
      remote.source_tag = item.source_tag;
      remote.url = item.url;
      remote.update_interval = item.interval;
      remote.has_update_interval = item.has_interval;
      remote.group_id = item.group_id;
      writeLog(LOG_LEVEL_INFO,
               "QUANX_REMOTE_RESOURCE_CREATED group_id=" +
                   std::to_string(remote.group_id) + " interval=" +
                   (remote.has_update_interval
                        ? std::to_string(remote.update_interval)
                        : std::string("client-default")) +
                   " source=" + summarizeUrlForLog(remote.url));
      ext.quanx_server_remotes.push_back(std::move(remote));
    }

    if (!node_urls.empty()) {
      for (const QuanXNodeLinkItem &item : node_urls) {
        string_array import_urls{item.url};
        if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
          source_calls++;
          source_failures++;
          continue;
        }
        for (std::string &x : import_urls) {
          source_calls++;
          parse_settings item_parse_set = parse_set;
          item_parse_set.force_direct_link = item.force_direct_link;
          if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
            source_failures++;
            writeLog(LOG_LEVEL_WARNING,
                     "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                         "，继续处理其他节点。");
          }
        }
      }
    }
    if (subscription_urls.empty()) {
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
      remote_reason = "no-remote-subscription";
      explain.remote_subscription_backend =
          remoteSubscriptionModeName(remote_mode);
      explain.remote_subscription_reason = remote_reason;
    }
  } else if (stash_remote_eligible) {
    struct StashRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int interval = 3600;
      int group_id = 0;
    };
    struct StashNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<StashRemoteLinkItem> subscription_urls;
    std::vector<StashNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      const std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider || tagged.has_interval);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (tagged.has_interval && tagged.interval <= 0) {
          *status_code = 400;
          return {true, surgePolicyPathIntervalError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, stashProxyProviderSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Stash proxy-provider 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider,
             tagged.has_interval ? tagged.interval : 3600, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

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
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> provider_names;

    size_t generated_index = 0;
    for (const StashRemoteLinkItem &item : subscription_urls) {
      std::string requested = sanitizeRemoteResourceName(item.requested_name);
      if (requested.empty())
        requested =
            "SubConverter_Provider_" + std::to_string(++generated_index);

      StashProxyProvider provider;
      provider.name = reserveStashProviderName(requested, provider_names);
      provider.requested_name = item.requested_name;
      provider.selection_name = provider.name;
      provider.source_tag = item.source_tag;
      provider.url = item.url;
      provider.path = "./providers/" + provider.name + ".yaml";
      provider.interval = item.interval;
      provider.group_id = item.group_id;
      provider.headers = provider_headers;
      writeLog(LOG_LEVEL_INFO,
               "STASH_PROXY_PROVIDER_CREATED group_id=" +
                   std::to_string(provider.group_id) + " interval=" +
                   std::to_string(provider.interval) + " source=" +
                   summarizeUrlForLog(provider.url));
      SubExplainProvider explain_provider;
      explain_provider.backend = "stash-client";
      explain_provider.name = provider.name;
      explain_provider.tag = provider.source_tag;
      explain_provider.source_summary = summarizeUrlForLog(provider.url);
      explain_provider.path = provider.path;
      explain_provider.name_generated = item.requested_name.empty();
      explain_provider.group_id = provider.group_id;
      explain_provider.interval = provider.interval;
      explain_provider.proxy_direct = false;
      explain.providers.push_back(std::move(explain_provider));
      ext.stash_proxy_providers.push_back(std::move(provider));
    }

    for (const StashNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else if (loon_remote_eligible) {
    struct LoonRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int group_id = 0;
    };
    struct LoonNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<LoonRemoteLinkItem> subscription_urls;
    std::vector<LoonNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription =
          isHttpSubscriptionLink(link, tagged.has_provider);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, loonRemoteProxySourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Loon Remote Proxy 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

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
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> resource_names;
    auto reserve_resource_name = [&](const std::string &base) {
      std::string base_name = clampProviderNameLength(base, 64);
      if (base_name.empty())
        base_name = "SubConverter_Remote";
      if (resource_names.insert(base_name).second)
        return base_name;
      int suffix_index = 1;
      while (true) {
        const std::string suffix = "_" + std::to_string(suffix_index++);
        const size_t max_base = 64 > suffix.size() ? 64 - suffix.size() : 0;
        const std::string candidate =
            clampProviderNameLength(base_name, max_base) + suffix;
        if (resource_names.insert(candidate).second)
          return candidate;
      }
    };

    size_t generated_index = 0;
    for (const LoonRemoteLinkItem &item : subscription_urls) {
      std::string requested = sanitizeRemoteResourceName(item.requested_name);
      if (requested.empty())
        requested =
            "SubConverter_Remote_" + std::to_string(++generated_index);

      LoonRemoteProxyResource remote;
      remote.resource_name = reserve_resource_name(requested);
      remote.requested_name = item.requested_name;
      remote.selection_name = remote.resource_name;
      remote.source_tag = item.source_tag;
      remote.url = item.url;
      remote.group_id = item.group_id;
      writeLog(LOG_LEVEL_INFO,
               "LOON_REMOTE_PROXY_CREATED group_id=" +
                   std::to_string(remote.group_id) + " source=" +
                   summarizeUrlForLog(remote.url));
      ext.loon_remote_proxies.push_back(std::move(remote));
    }

    for (const LoonNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else if (surge_remote_eligible || surfboard_remote_eligible) {
    struct PolicyPathRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int interval = 0;
      bool has_interval = false;
      int group_id = 0;
    };
    struct PolicyPathNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<PolicyPathRemoteLinkItem> subscription_urls;
    std::vector<PolicyPathNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }

      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider ||
                    (surge_remote_eligible && tagged.has_interval));
      const int item_group_id = groupID++;
      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (surfboard_remote_eligible && tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (surge_remote_eligible && tagged.has_interval &&
            tagged.interval <= 0) {
          *status_code = 400;
          return {true, surgePolicyPathIntervalError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, surge_remote_eligible
                            ? surgePolicyPathSourceError(index)
                            : surfboardPolicyPathSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 std::string("检测到 ") +
                     (surge_remote_eligible ? "Surge" : "Surfboard") +
                     " policy-path 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back({link, tagged.tag, tagged.provider,
                                     tagged.interval, tagged.has_interval,
                                     item_group_id});
        explain.subscription_url_count++;
        continue;
      }

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
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    for (const PolicyPathRemoteLinkItem &item : subscription_urls) {
      if (surge_remote_eligible) {
        SurgePolicyPathResource resource;
        resource.url = item.url;
        resource.source_tag = item.source_tag;
        resource.requested_name = item.requested_name;
        resource.update_interval = item.interval;
        resource.has_update_interval = item.has_interval;
        resource.group_id = item.group_id;
        writeLog(LOG_LEVEL_INFO,
                 "SURGE_POLICY_PATH_CREATED group_id=" +
                     std::to_string(resource.group_id) + " interval=" +
                     (resource.has_update_interval
                          ? std::to_string(resource.update_interval)
                          : std::string("client-default")) +
                     " source=" + summarizeUrlForLog(resource.url));
        ext.surge_policy_paths.push_back(std::move(resource));
      } else {
        SurfboardPolicyPathResource resource;
        resource.url = item.url;
        resource.source_tag = item.source_tag;
        resource.requested_name = item.requested_name;
        resource.group_id = item.group_id;
        writeLog(LOG_LEVEL_INFO,
                 "SURFBOARD_POLICY_PATH_CREATED group_id=" +
                     std::to_string(resource.group_id) +
                     " interval=client-default source=" +
                     summarizeUrlForLog(resource.url));
        ext.surfboard_policy_paths.push_back(std::move(resource));
      }
    }

    for (const PolicyPathNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else {
    importItems(urls, true, FetchContext::PublicRequest);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(LOG_LEVEL_INFO, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。");
      source_calls++;
      parse_settings item_parse_set = parse_set;
      if (native_remote_target) {
        const TaggedLink tagged = parseTaggedLink(x);
        item_parse_set.force_direct_link =
            isLegacyHttpProxyUri(tagged.link.empty() ? x : tagged.link);
      }
      if (addNodes(x, nodes, groupID, item_parse_set) == -1) {
        source_failures++;
        writeLog(LOG_LEVEL_WARNING,
                 "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                     "，继续处理其他节点。");
      }
      groupID++;
    }
  }

  explain.provider_count =
      ext.providers.size() + ext.stash_proxy_providers.size();
  explain.remote_subscription_count = ext.quanx_server_remotes.size() +
                                      ext.surge_policy_paths.size() +
                                      ext.surfboard_policy_paths.size() +
                                      ext.loon_remote_proxies.size() +
                                      ext.stash_proxy_providers.size();
  explain.proxy_provider_mode =
      (ext.use_proxy_provider && !ext.providers.empty()) ||
      !ext.stash_proxy_providers.empty();
  explain.insert_node_count = insert_nodes.size();
  explain.direct_node_count = nodes.size();
  logRouteSelection();
  if (!argProviderHeaders.empty() && !ext.nodelist && ext.providers.empty() &&
      ext.stash_proxy_providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: provider_headers was selected, but no "
            "proxy-provider was generated.\n"
            "无效请求：已选择 provider_headers，但没有生成 proxy-provider。"};
  }
  if (nodes.empty() && insert_nodes.empty() && ext.providers.empty() &&
      ext.quanx_server_remotes.empty() && ext.surge_policy_paths.empty() &&
      ext.surfboard_policy_paths.empty() && ext.loon_remote_proxies.empty() &&
      ext.stash_proxy_providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: no valid proxy nodes or remote resources were "
            "found.\n"
            "无效请求：未找到有效的代理节点或远程资源。\n"
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
  bool managed_url_from_profile_data = false;
  bool managed_url_used = false;
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
  generation.managed_url_from_profile_data = !managed_url.empty();
  if (managed_url.empty())
    managed_url =
        settings.managedConfigPrefix + "/sub?" + joinArguments(argument);

  struct PendingUpload {
    std::string name;
    std::string path;
    std::string content;
    bool write_manage_url = false;
  };
  std::vector<PendingUpload> pending_uploads;
  bool upload_failed = false;
  auto recordUpload = [&](const std::string &name, const std::string &path,
                          const std::string &content, bool write_manage_url) {
    pending_uploads.push_back({name, path, content, write_manage_url});
  };

  proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
  switch (hash_(target)) {
  case "clash"_hash:
  case "clashr"_hash:
    writeLog(LOG_LEVEL_INFO, target == "clashr" ? "生成目标：ClashR" : "生成目标：Clash");
    template_arguments.local_vars["clash.new_field_name"] =
        ext.clash_new_field_name ? "true" : "false";
    response.headers["profile-update-interval"] =
        std::to_string(policy.update_interval / 3600);
    if (ext.nodelist) {
      YAML::Node yamlnode;
      proxyToClash(nodes, yamlnode, dummy_group, target == "clashr", ext);
      output = dumpCanonicalClashYaml(yamlnode);
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
    writeLog(LOG_LEVEL_INFO, "生成目标：Surge " + std::to_string(parsed.surge_version));
    if (ext.nodelist) {
      output = proxyToSurge(nodes, base_content, dummy_ruleset, dummy_group,
                            parsed.surge_version, ext);
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
    }

    {
      const TargetGenerationStats &stats = ext.surge_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "SURGE_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.surge_policy_paths.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: the Surge policy-path subscription was not "
                "selected by any compatible proxy group.\n"
                "无效请求：没有兼容的策略组选择该 Surge policy-path 订阅。"};
      }
    }

    if (upload)
      recordUpload(ext.nodelist ? "surge" + surge_version_text + "list"
                                : "surge" + surge_version_text,
                   upload_path, output, true);
    if (!ext.nodelist) {
      if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
        generation.managed_url_used = true;
      if (generation.managed_url_used)
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
    writeLog(LOG_LEVEL_INFO, "生成目标：Surfboard");
    if (render_template(fetchFile(policy.surfboard_base, proxy,
                                  settings.cacheConfig, true, base_context),
                        template_arguments, base_content, settings.templatePath,
                        base_context) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToSurge(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, -3, ext);
    {
      const TargetGenerationStats &stats = ext.surfboard_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "SURFBOARD_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.surfboard_policy_paths.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: the Surfboard policy-path subscription was "
                "not selected by any compatible proxy group.\n"
                "无效请求：没有兼容的策略组选择该 Surfboard policy-path "
                "订阅。"};
      }
    }
    if (upload)
      recordUpload("surfboard", upload_path, output, true);
    if (!ext.nodelist) {
      if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
        generation.managed_url_used = true;
      if (generation.managed_url_used)
        output = "#!MANAGED-CONFIG " + managed_url +
                 (policy.update_interval > 0
                      ? " interval=" + std::to_string(policy.update_interval)
                      : "") +
                 " strict=" +
                 std::string(policy.update_strict ? "true" : "false") +
                 "\n\n" + output;
    }
    break;

  case "stash"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Stash");
    if (render_template(fetchFile(policy.stash_base, proxy,
                                  settings.cacheConfig, true, base_context),
                        template_arguments, base_content,
                        settings.templatePath, base_context) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToStash(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, ext);
    parsed.explain.rule_provider_count =
        ext.stash_rule_stats.final_provider_count;
    parsed.explain.inline_rule_source_count =
        ext.stash_rule_stats.inline_sources;
    parsed.explain.expanded_rule_source_count =
        ext.stash_rule_stats.expanded_sources;
    parsed.explain.unsupported_ruleset_count =
        ext.stash_rule_stats.unsupported_sources;
    if (!ext.external_rule_error.empty()) {
      *status_code = 400;
      return {true, ext.external_rule_error};
    }
    if (ext.stash_proxy_providers.size() !=
        ext.target_generation_stats.remote_references_emitted) {
      *status_code = 400;
      return {true,
              "Invalid request: every Stash proxy-provider must be selected "
              "by a compatible proxy group.\n"
              "无效请求：每个 Stash proxy-provider 都必须被兼容的策略组"
              "选中。"};
    }
    if (upload)
      recordUpload("stash", upload_path, output, false);
    break;

  case "mellow"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Mellow");
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
    writeLog(LOG_LEVEL_INFO, "生成目标：SS Subscription");
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
    writeLog(LOG_LEVEL_INFO, "生成目标：SS");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("ss", upload_path, output, false);
    break;
  case "ssr"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：SSR");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("ssr", upload_path, output, false);
    break;
  case "v2ray"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Legacy VMess Subscription");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("v2ray", upload_path, output, false);
    break;
  case "v2rayn"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：v2rayN");
    output = proxyToV2RayClient(nodes, V2RayClientTarget::V2RayN, ext);
    if (upload)
      recordUpload("v2rayn", upload_path, output, false);
    break;
  case "v2rayng"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：v2rayNG");
    output = proxyToV2RayClient(nodes, V2RayClientTarget::V2RayNG, ext);
    if (upload)
      recordUpload("v2rayng", upload_path, output, false);
    break;
  case "shadowrocket"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Shadowrocket");
    output = proxyToShadowrocket(nodes, ext);
    if (upload)
      // Shadowrocket UA requests historically resolved to mixed and updated
      // the default Gist path "sub". Preserve that path for smooth upgrades.
      recordUpload(parsed.target_was_auto ? "sub" : "shadowrocket", upload_path,
                   output, false);
    break;
  case "trojan"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Trojan");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("trojan", upload_path, output, false);
    break;
  case "vless"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：vless");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("vless", upload_path, output, false);
    break;
  case "hysteria2"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：hysteria2");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("hysteria2", upload_path, output, false);
    break;
  case "mixed"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Standard Subscription");
    output = proxyToSingle(nodes, parsed.target_descriptor->single_link_types,
                           ext);
    if (upload)
      recordUpload("sub", upload_path, output, false);
    break;

  case "quan"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Quantumult");
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
    writeLog(LOG_LEVEL_INFO, "生成目标：Quantumult X");
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
    writeLog(LOG_LEVEL_INFO, "生成目标：Loon");
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
    {
      const TargetGenerationStats &stats = ext.loon_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "LOON_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.loon_remote_proxies.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: no compatible Loon proxy group selected "
                "the Remote Proxy subscription.\n"
                "无效请求：没有兼容的 Loon 策略组选择 Remote Proxy 订阅。"};
      }
    }
    if (upload)
      recordUpload("loon", upload_path, output, false);
    break;

  case "ssd"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：SSD");
    output = proxyToSSD(nodes, group_name, subscription_info, ext);
    if (upload)
      recordUpload("ssd", upload_path, output, false);
    break;

  case "singbox"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：sing-box");
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
    writeLog(LOG_LEVEL_INFO, "生成目标：未指定");
    *status_code = 500;
    return {true,
            "Internal error: target passed validation but no generator handled "
            "it.\n"
            "内部错误：target 已通过校验，但没有对应的生成器处理它。\n"
            "Please report this request to the service maintainer.\n"
            "请将该请求反馈给服务维护者。"};
  }

  if (parsed.target_descriptor->parser_mode == NodeParserMode::LegacyOnly) {
    const TargetGenerationStats &stats = ext.target_generation_stats;
    string_array unsupported_protocols;
    unsupported_protocols.reserve(stats.unsupported_by_type.size());
    for (const auto &[type, count] : stats.unsupported_by_type) {
      unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                         ":" + std::to_string(count));
    }
    const size_t unsupported_count = stats.unsupported_nodes();
    writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
             "TARGET_NODE_GENERATION target=" + target + " input=" +
                 std::to_string(stats.input_nodes) + " emitted=" +
                 std::to_string(stats.emitted_nodes) + " unsupported=" +
                 std::to_string(unsupported_count) + " protocols=" +
                 (unsupported_protocols.empty()
                      ? std::string("none")
                      : join(unsupported_protocols, ";")) +
                 " remote_references=" +
                 std::to_string(stats.remote_references_emitted));
    parsed.explain.generated_node_count = stats.emitted_nodes;
    parsed.explain.unsupported_node_count = unsupported_count;
    parsed.explain.unsupported_protocols = unsupported_protocols;

    if (stats.input_nodes > 0 && stats.emitted_nodes == 0 &&
        stats.remote_references_emitted == 0) {
      *status_code = 400;
      return {true,
              "Invalid request: none of the parsed proxy nodes can be "
              "represented by the selected output target.\n"
              "无效请求：解析到的代理节点均无法由所选输出目标表示。"};
    }
  }

  for (const PendingUpload &pending : pending_uploads) {
    if (uploadGist(pending.name, pending.path, pending.content,
                   pending.write_manage_url) != 0)
      upload_failed = true;
  }

  if (upload_failed)
    writeLog(LOG_LEVEL_WARNING,
             "GIST_OPTIONAL_UPLOAD_FAILED action=return-conversion-result");
  writeLog(LOG_LEVEL_INFO, "生成完成。");
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
  string_array &lIncludeRemarks = policy.include_remarks;
  string_array &lExcludeRemarks = policy.exclude_remarks;
  extra_settings &ext = policy.generator;
  int interval = policy.update_interval;
  bool strict = policy.update_strict;
  std::map<std::string, std::string> &provider_headers =
      policy.provider_headers;
  bool userProvidedExternalConfig =
      fetch_plan.user_provided_external_config;
  std::string &output_content = generation.output;
  std::string &managed_url = generation.managed_url;

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
      SubExplainParameter parameter;
      parameter.name = name;
      parameter.present = true;
      parameter.source = source;
      parameter.status = status;
      parameter.value_preview = previewExplainValue(raw_value, sensitive);
      parameter.value_hash.clear();
      parameter.raw_length = raw_value.size();
      parameter.value_length = raw_value.size();
      parameter.effective_value = previewExplainValue(effective_value, false);
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
                     std::to_string(explain.node_link_count) +
                     " node link(s); sources: " +
                     summarizeExplainSourceList(rawArg("url")),
                 "applied",
                 "Sensitive values are redacted; use lengths and structural "
                 "summaries to compare inputs.",
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
    addParameter("upload_path",
                 argUploadPath.empty() ? "not provided" : "provided",
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
    addParameter("groups", "not consumed", "ignored",
                 "This compatibility parameter is not consumed by /sub.",
                 true);
    addParameter("ruleset", "not consumed", "ignored",
                 "This compatibility parameter is not consumed by /sub.",
                 true);
    const bool request_config_provided = !parsed.external_config.empty();
    std::string config_effective = explain.external_config_loaded
                                       ? "loaded"
                                       : "not loaded";
    if (explain.fallback_config_used)
      config_effective = "fallback loaded";
    if (!rawArg("config").empty())
      config_effective +=
          "; requested source: " + summarizeUrlForLog(rawArg("config"));
    const std::string config_status =
        explain.fallback_config_used
            ? "overridden"
            : (request_config_provided
                   ? (explain.external_config_loaded ? "applied" : "ignored")
                   : (explain.external_config_loaded ? "defaulted"
                                                     : "ignored"));
    const std::string config_source =
        explain.fallback_config_used
            ? "fallback"
            : (request_config_provided
                   ? "request"
                   : (explain.external_config_loaded ? "default" : "request"));
    addParameter("config", config_effective, config_status,
                 explain.fallback_config_used
                     ? "User config failed and a fallback config was loaded."
                     : "External config URL or data source.",
                 true, config_source);
    const bool request_device_id_applied = !parsed.device_id.empty();
    const bool effective_device_id_configured = !ext.quanx_dev_id.empty();
    addParameter(
        "dev_id",
        effective_device_id_configured ? "configured" : "not configured",
        request_device_id_applied
            ? "applied"
            : (effective_device_id_configured ? "defaulted" : "ignored"),
        request_device_id_applied
            ? "Quantumult X device ID."
            : (effective_device_id_configured
                   ? "Empty request value; the configured device ID remained "
                     "effective."
                   : "No effective Quantumult X device ID is configured."),
        true, request_device_id_applied
                  ? "request"
                  : (effective_device_id_configured ? "default" : "request"));
    addParameter("filename", argFilename, "ignored",
                 "Content-Disposition is not emitted for explain JSON.");
    addParameter("interval", std::to_string(interval), "applied",
                 "Effective update interval in seconds.");
    addParameter("strict", boolString(strict), "applied",
                 "Managed config strict flag.");
    addParameter("rename", std::to_string(ext.rename_array.size()) +
                               " rename rule(s)",
                  argRenames.empty() ? "ignored" : "applied",
                  "Request rename rules override configured rename rules.",
                  true);
    addParameter("filter_script", "not used", "ignored",
                 "Public requests cannot provide executable filter scripts.",
                 true);
    addParameter("provider_headers",
                 std::to_string(provider_headers.size()) +
                     " explicitly selected header(s)",
                 provider_headers.empty() ? "ignored" : "applied",
                 "Only named, present, non-reserved request headers are "
                 "copied into generated Clash or Stash proxy-providers.");
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
                      : (argTarget == "quanx"
                             ? "Quantumult X full-config output uses client-managed "
                               "server_remote resources when the request can be "
                               "represented without losing advanced semantics."
                             : (argTarget == "stash"
                                    ? "Stash full-config output uses named client-managed "
                                      "proxy-providers when the request can be represented "
                                      "without losing advanced semantics."
                                    : "Clash-compatible output defaults to provider mode.")));
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
    std::string profile_effective = "not used";
    std::string profile_status = "ignored";
    std::string profile_source = "request";
    std::string profile_note =
        "This target did not emit a managed configuration URL.";
    if (generation.managed_url_used) {
      profile_effective = generation.managed_url_from_profile_data
                              ? "provided"
                              : "generated";
      profile_effective += "; source: " + summarizeUrlForLog(managed_url);
      profile_status = generation.managed_url_from_profile_data
                           ? "applied"
                           : "defaulted";
      profile_source = generation.managed_url_from_profile_data ? "request"
                                                                 : "global";
      profile_note = generation.managed_url_from_profile_data
                         ? "Managed configuration URL override."
                         : "A managed configuration URL was generated.";
    }
    addParameter("profile_data", profile_effective, profile_status,
                 profile_note, true, profile_source);
    addParameter("token", "not used", "ignored",
                 "Token authentication is disabled.", true);

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
      SubExplainParameter parameter;
      parameter.name = explainParameterName(arg.first);
      parameter.present = true;
      parameter.source = "request";
      parameter.status = "ignored";
      parameter.value_preview = previewExplainValue(arg.second, true);
      parameter.value_hash.clear();
      parameter.raw_length = arg.second.size();
      parameter.value_length = arg.second.size();
      parameter.effective_value = "";
      parameter.note = parameter.name == "[redacted-name]"
                           ? "The parameter name and value were redacted."
                           : "This parameter is not recognized by /sub; its "
                             "value was redacted.";
      parameter.sensitive = true;
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
    if (explain.remote_subscription_count) {
      std::string remote_section = "quanx_server_remote";
      if (explain.remote_subscription_backend == "surge-policy-path")
        remote_section = "surge_policy_path";
      else if (explain.remote_subscription_backend ==
               "surfboard-policy-path")
        remote_section = "surfboard_policy_path";
      else if (explain.remote_subscription_backend == "loon-remote-proxy")
        remote_section = "loon_remote_proxy";
      else if (explain.remote_subscription_backend ==
               "stash-proxy-provider")
        remote_section = "stash_proxy_provider";
      addConfigSection(remote_section, "request", "generated",
                       std::to_string(explain.remote_subscription_count) +
                           " remote resource(s); node-name transformations run "
                           "only in the client or its configured resource parser.");
    }
    if (explain.managed_config)
      addConfigSection("managed_config", "global", "enabled",
                       "Managed config prefix is available.");

    explain.output_bytes = output_content.size();
    writeLog(LOG_LEVEL_INFO,
             "已生成 /sub explain JSON 诊断结果：target=" + argTarget +
                 ", status=" + std::to_string(response.status_code) +
                 ", providers=" + std::to_string(explain.provider_count) +
                 ", remote_resources=" +
                 std::to_string(explain.remote_subscription_count) +
                 ", nodes=" + std::to_string(explain.total_node_count) +
                 ", recognized_params=" +
                 std::to_string(explain.recognized_parameters.size()) +
                 ", unrecognized_params=" +
                 std::to_string(explain.unrecognized_parameters.size()) + "。");
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
  auto cancelled = [&]() -> std::optional<std::string> {
    RequestCancellationResponse cancellation_response;
    if (!requestCancellationResponse(request.context,
                                     cancellation_response))
      return std::nullopt;
    response.status_code = cancellation_response.status_code;
    response.content_type = "text/plain; charset=utf-8";
    response.headers = std::move(cancellation_response.headers);
    return std::move(cancellation_response.body);
  };
  if (auto body = cancelled())
    return std::move(*body);
  ParsedSubRequest parsed_request;
  EffectiveSubPolicy effective_policy;
  {
    RequestStageTimer parse_timer(request.context, RequestStage::Parse);
    std::string parse_error =
        parseSubRequestArguments(request, response, settings, parsed_request);
    if (!parse_error.empty())
      return parse_error;

    std::string policy_error = buildEffectiveSubPolicy(
        request, response, settings, rule_stats, parsed_request,
        effective_policy);
    if (!policy_error.empty())
      return policy_error;
  }
  if (auto body = cancelled())
    return std::move(*body);

  ExternalConfigFetchPlan fetch_plan;
  {
    RequestStageTimer rules_timer(request.context, RequestStage::Rules);
    std::string fetch_plan_error = buildExternalConfigFetchPlan(
        response, settings, parsed_request, effective_policy, fetch_plan);
    if (!fetch_plan_error.empty())
      return fetch_plan_error;
  }
  if (auto body = cancelled())
    return std::move(*body);

  SubscriptionNodeState subscription_state;
  {
    RequestStageTimer parse_timer(request.context, RequestStage::Parse);
    SubStageResponse subscription_response = processSubscriptionNodes(
        request, response, settings, parsed_request, effective_policy,
        subscription_state);
    if (request.context) {
      const bool high_cost =
          parsed_request.explain.subscription_url_count > 1 ||
          effective_policy.custom_rulesets.size() > 1 ||
          parsed_request.generate_clash_script.get(false) ||
          !parsed_request.external_config.empty();
      request.context->setCostClass(
          parsed_request.explain.proxy_provider_mode
              ? RequestCostClass::Low
              : (high_cost ? RequestCostClass::High
                           : RequestCostClass::Medium));
    }
    if (subscription_response.complete)
      return subscription_response.body;
  }
  if (auto body = cancelled())
    return std::move(*body);

  RequestStageTimer serialize_timer(request.context, RequestStage::Serialize);
  TargetGenerationState generation_state;
  SubStageResponse generation_response = dispatchTargetGenerator(
      request, response, settings, parsed_request, effective_policy,
      fetch_plan, subscription_state, generation_state);
  if (generation_response.complete)
    return generation_response.body;
  if (auto body = cancelled())
    return std::move(*body);
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
  writeLog(LOG_LEVEL_INFO, "SurgeConfToClash 调用，URL：" + summarizeUrlForLog(url) + "。");

  ProxyPolicy proxy = parseProxy(global.proxyConfig, global.proxyBypass);
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
    writeLog(LOG_LEVEL_ERROR, "SURGE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(parser_detail));
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
    writeLog(LOG_LEVEL_ERROR, "Surge 配置不完整，缺少必需配置段。");
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

  proxy = parseProxy(global.proxySubscription, global.proxyBypass);
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
    writeLog(LOG_LEVEL_INFO, "正在从 URL 获取节点数据：" + summarizeUrlForLog(x) + "。");
    if (addNodes(x, nodes, 0, parse_set) == -1) {
      if (global.skipFailedLinks)
        writeLog(LOG_LEVEL_WARNING,
                 "以下链接不包含任何有效节点信息：" + x);
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
  writeLog(LOG_LEVEL_INFO, "转换完成。");
  return dumpCanonicalClashYaml(clash);
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
  writeLog(LOG_LEVEL_INFO, "正在加载配置档：'" + name + "'。");
  INIReader ini;
  if (ini.parse(profile_content) != INIREADER_EXCEPTION_NONE &&
      !ini.section_exist("Profile")) {
    // std::cerr<<"Load profile failed! Reason: "<<ini.get_last_error()<<"\n";
    const std::string parser_detail = ini.get_last_error();
    writeLog(LOG_LEVEL_ERROR, "PROFILE_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(parser_detail));
    *status_code = 500;
    return "Invalid profile: failed to parse profile content.\n"
           "无效配置：profile 内容解析失败。";
  }
  // std::cerr<<"Trying to parse profile '" + name + "'.\n";
  writeLog(LOG_LEVEL_INFO, "正在解析配置档：'" + name + "'。");
  string_multimap contents;
  ini.get_items("Profile", contents);
  if (contents.empty()) {
    // std::cerr<<"Load profile failed! Reason: Empty Profile section\n";
    writeLog(LOG_LEVEL_ERROR, "加载配置档失败！原因：[Profile] 配置段为空。");
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
    writeLog(LOG_LEVEL_INFO, "检测到多个配置档，正在合并...");
    std::string all_urls, url;
    auto iter = contents.find("url");
    if (iter != contents.end())
      all_urls = iter->second;
    for (size_t i = 1; i < profiles.size(); i++) {
      name = profiles[i];
      if (!fileExist(name)) {
        writeLog(LOG_LEVEL_WARNING, "忽略不存在的配置档：'" + name + "'。");
        continue;
      }
      if (ini.parse_file(name) != INIREADER_EXCEPTION_NONE &&
          !ini.section_exist("Profile")) {
        writeLog(LOG_LEVEL_WARNING, "忽略损坏的配置档：'" + name + "'。");
        continue;
      }
      url = ini.get("Profile", "url");
      if (!url.empty()) {
        all_urls += "|" + url;
        writeLog(LOG_LEVEL_INFO, "已添加来自配置档 '" + name + "' 的 URL。");
      } else {
        writeLog(LOG_LEVEL_INFO, "配置档 '" + name + "' 没有 url 字段，跳过。");
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
    ProxyPolicy proxy = parseProxy(global.proxyConfig, global.proxyBypass);
    writeLog(LOG_LEVEL_INFO, "模板调用 fetch，URL：'" + url + "'。");
    return webGet(url, proxy, global.cacheConfig);
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
  writeLog(LOG_LEVEL_INFO, "正在读取生成器配置...");
  std::string config = fileGet("generate.ini"), path, profile, content;
  if (config.empty()) {
    // std::cerr<<"Generator configuration not found or empty!\n";
    writeLog(LOG_LEVEL_ERROR, "未找到生成器配置，或配置为空！");
    return -1;
  }

  INIReader ini;
  if (ini.parse(config) != INIREADER_EXCEPTION_NONE) {
    // std::cerr<<"Generator configuration broken!
    // Reason:"<<ini.get_last_error()<<"\n";
    writeLog(LOG_LEVEL_ERROR, "GENERATOR_CONFIG_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return -2;
  }
  // std::cerr<<"Read generator configuration completed.\n\n";
  writeLog(LOG_LEVEL_INFO, "生成器配置读取完成。\n");

  string_array sections = ini.get_section_names();
  if (!global.generateProfiles.empty()) {
    // std::cerr<<"Generating with specific artifacts:
    // \""<<gen_profile<<"\"...\n";
    writeLog(LOG_LEVEL_INFO,
             "正在按指定生成项生成：\"" + global.generateProfiles + "\"...");
    string_array targets = split(global.generateProfiles, ","), new_targets;
    for (std::string &x : targets) {
      x = trim(x);
      if (std::find(sections.cbegin(), sections.cend(), x) != sections.cend())
        new_targets.emplace_back(std::move(x));
      else {
        // std::cerr<<"Artifact \""<<x<<"\" not found in generator settings!\n";
        writeLog(LOG_LEVEL_ERROR, "生成器设置中未找到生成项：\"" + x + "\"！");
        return -3;
      }
    }
    sections = new_targets;
    sections.shrink_to_fit();
  } else
    // std::cerr<<"Generating all artifacts...\n";
    writeLog(LOG_LEVEL_INFO, "正在生成所有生成项...");

  string_multimap allItems;
  ProxyPolicy proxy = parseProxy(global.proxySubscription, global.proxyBypass);
  Request request;
  Response response;
  bool write_failed = false;
  for (std::string &x : sections) {
    response.status_code = 200;
    // std::cerr<<"Generating artifact '"<<x<<"'...\n";
    writeLog(LOG_LEVEL_INFO, "正在生成生成项：'" + x + "'。");
    ini.enter_section(x);
    if (ini.item_exist("path"))
      path = ini.get("path");
    else {
      // std::cerr<<"Artifact '"<<x<<"' output path missing! Skipping...\n\n";
      writeLog(LOG_LEVEL_ERROR, "生成项 '" + x + "' 缺少输出路径，跳过。\n");
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
          writeLog(LOG_LEVEL_ERROR,
                   "生成项 '" + x + "' 生成失败！请检查链接。\n");
          if (sections.size() == 1)
            return -1;
        }
        // add UTF-8 BOM
        const int write_result =
            fileWrite(path, "\xEF\xBB\xBF" + content, true);
        if (fileCommitFailed(write_result)) {
          writeLog(LOG_LEVEL_ERROR,
                   "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                       (fileCommitTemporaryRemaining(write_result)
                            ? " temporary_file_remaining=true"
                            : " temporary_file_remaining=false"));
          write_failed = true;
          if (sections.size() == 1)
            return -1;
        } else if (fileCommitDurabilityUnconfirmed(write_result)) {
          writeLog(LOG_LEVEL_WARNING,
                   "ARTIFACT_WRITE_VISIBLE target=" + x +
                       " new_file_visible=true durability=unconfirmed "
                       "action=continue");
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
      writeLog(LOG_LEVEL_ERROR,
               "生成项 '" + x + "' 生成失败！原因：" + content + "\n");
      if (sections.size() == 1)
        return -1;
      continue;
    }
    const int write_result = fileWrite(path, content, true);
    if (fileCommitFailed(write_result)) {
      writeLog(LOG_LEVEL_ERROR,
               "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                   (fileCommitTemporaryRemaining(write_result)
                        ? " temporary_file_remaining=true"
                        : " temporary_file_remaining=false"));
      write_failed = true;
      if (sections.size() == 1)
        return -1;
      continue;
    }
    if (fileCommitDurabilityUnconfirmed(write_result)) {
      writeLog(LOG_LEVEL_WARNING,
               "ARTIFACT_WRITE_VISIBLE target=" + x +
                   " new_file_visible=true durability=unconfirmed "
                   "action=continue");
    }
    auto iter =
        std::find_if(response.headers.begin(), response.headers.end(),
                     [](auto y) { return y.first == "Subscription-UserInfo"; });
    if (iter != response.headers.end())
      writeLog(LOG_LEVEL_INFO,
               "生成项 '" + x + "' 的用户信息：" + subInfoToMessage(iter->second));
    // std::cerr<<"Artifact '"<<x<<"' generate SUCCESS!\n\n";
    writeLog(LOG_LEVEL_INFO, "生成项 '" + x + "' 生成成功！\n");
    eraseElements(response.headers);
  }
  // std::cerr<<"All artifact generated. Exiting...\n";
  if (write_failed) {
    writeLog(LOG_LEVEL_ERROR, "部分生成项写入失败，正在以失败状态退出...");
    return -1;
  }
  writeLog(LOG_LEVEL_INFO, "所有生成项已生成，正在退出...");
  return 0;
}

std::string renderTemplate(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string path = getUrlArg(argument, "path");
  writeLog(LOG_LEVEL_INFO, "正在渲染模板：'" + path + "'。");

  if (!startsWith(path, global.templatePath) || !fileExist(path)) {
    *status_code = 404;
    return "Template not found or outside the allowed template directory.\n"
           "未找到模板，或模板路径超出允许的模板目录。\n"
           "Please provide a path under the configured template directory.\n"
           "请提供位于已配置模板目录下的路径。";
  }
  std::string template_content =
      fetchFile(path, parseProxy(global.proxyConfig, global.proxyBypass),
                global.cacheConfig);
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
    writeLog(LOG_LEVEL_WARNING, "渲染失败。");
  } else
    writeLog(LOG_LEVEL_INFO, "渲染完成。");

  return output_content;
}
