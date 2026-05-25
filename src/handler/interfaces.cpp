#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <exception>
#include <iostream>
#include <memory>
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
#include "generator/config/nodemanip.h"
#include "generator/config/ruleconvert.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "interfaces.h"
#include "multithread.h"
#include "parser/mihomo_scheme_utils.h"
#include "script/cron.h"
#include "script/script_quickjs.h"
#include "server/webserver.h"
#include "settings.h"
#include "upload.h"
#include "utils/time_compat.h"

// Multiple CDN fallback URLs for default external config
// Will be tried in order if user-provided config fails to load
const std::vector<std::string> FALLBACK_CONFIG_URLS = {
    "https://gcore.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@refs/"
    "heads/main/cfg/Custom_Clash.ini",
    "https://testingcf.jsdelivr.net/gh/Aethersailor/"
    "Custom_OpenClash_Rules@refs/heads/main/cfg/Custom_Clash.ini",
    "https://cdn.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@refs/"
    "heads/main/cfg/Custom_Clash.ini",
    "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/"
    "main/cfg/Custom_Clash.ini"};

#include "utils/base64/base64.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
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

std::string parseProxy(const std::string &source) {
  std::string proxy = source;
  if (source == "SYSTEM")
    proxy = getSystemProxy();
  else if (source == "NONE")
    proxy = "";
  return proxy;
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
  auto &argument = request.argument;
  int *status_code = &response.status_code;
  /// type: 1 for Surge, 2 for Quantumult X, 3 for Clash domain rule-provider, 4
  /// for Clash ipcidr rule-provider, 5 for Surge DOMAIN-SET, 6 for Clash
  /// classical ruleset
  std::string url = urlSafeBase64Decode(getUrlArg(argument, "url")),
              type = getUrlArg(argument, "type"),
              group = urlSafeBase64Decode(getUrlArg(argument, "group"));
  std::string output_content, dummy;
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

  std::string strLine;
  std::stringstream ss;
  const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

  ss << output_content;
  char delimiter = getLineBreak(output_content);
  std::string::size_type lineSize, posb, pose;
  auto filterLine = [&]() {
    posb = 0;
    pose = strLine.find(',');
    if (pose == std::string::npos)
      return 1;
    posb = pose + 1;
    pose = strLine.find(',', posb);
    if (pose == std::string::npos) {
      pose = strLine.size();
      if (strLine[pose - 1] == '\r')
        pose--;
    }
    pose -= posb;
    return 0;
  };

  lineSize = output_content.size();
  output_content.clear();
  output_content.reserve(lineSize);

  if (type_int == 3 || type_int == 4 || type_int == 6)
    output_content = "payload:\n";

  while (getline(ss, strLine, delimiter)) {
    if (strFind(strLine, "//")) {
      strLine.erase(strLine.find("//"));
      strLine = trimWhitespace(strLine);
    }
    switch (type_int) {
    case 2:
      if (!std::any_of(QuanXRuleTypes.begin(), QuanXRuleTypes.end(),
                       [&strLine](const std::string &type) {
                         return startsWith(strLine, type);
                       }))
        continue;
      break;
    case 1:
      if (!std::any_of(SurgeRuleTypes.begin(), SurgeRuleTypes.end(),
                       [&strLine](const std::string &type) {
                         return startsWith(strLine, type);
                       }))
        continue;
      break;
    case 3:
      if (!startsWith(strLine, "DOMAIN-SUFFIX,") &&
          !startsWith(strLine, "DOMAIN,"))
        continue;
      if (filterLine())
        continue;
      output_content += "  - '";
      if (strLine[posb - 2] == 'X')
        output_content += "+.";
      output_content += strLine.substr(posb, pose);
      output_content += "'\n";
      continue;
    case 4:
      if (!startsWith(strLine, "IP-CIDR,") && !startsWith(strLine, "IP-CIDR6,"))
        continue;
      if (filterLine())
        continue;
      output_content += "  - '";
      output_content += strLine.substr(posb, pose);
      output_content += "'\n";
      continue;
    case 5:
      if (!startsWith(strLine, "DOMAIN-SUFFIX,") &&
          !startsWith(strLine, "DOMAIN,"))
        continue;
      if (filterLine())
        continue;
      if (strLine[posb - 2] == 'X')
        output_content += '.';
      output_content += strLine.substr(posb, pose);
      output_content += '\n';
      continue;
    case 6:
      if (!std::any_of(ClashRuleTypes.begin(), ClashRuleTypes.end(),
                       [&strLine](const std::string &type) {
                         return startsWith(strLine, type);
                       }))
        continue;
      output_content += "  - ";
    default:
      break;
    }

    lineSize = strLine.size();
    if (lineSize && strLine[lineSize - 1] == '\r') // remove line break
      strLine.erase(--lineSize);

    if (!strLine.empty() &&
        (strLine[0] != ';' && strLine[0] != '#' &&
         !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/'))) {
      if (type_int == 2) {
        if (startsWith(strLine, "IP-CIDR6"))
          strLine.replace(0, 8, "IP6-CIDR");
        strLine += "," + group;
        if (count_least(strLine, ',', 3) &&
            regReplace(strLine, rule_match_regex, "$2") == ",no-resolve")
          strLine = regReplace(strLine, rule_match_regex, "$1$3$2");
        else
          strLine = regReplace(strLine, rule_match_regex, "$1$3");
      }
    }
    output_content += strLine;
    output_content += '\n';
  }

  if (output_content == "payload:\n") {
    switch (type_int) {
    case 3:
      output_content += "  - '--placeholder--'";
      break;
    case 4:
      output_content += "  - '0.0.0.0/32'";
      break;
    case 6:
      output_content += "  - 'DOMAIN,--placeholder--'";
      break;
    }
  }
  return output_content;
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

static bool hasEffectiveExternalConfig(const ExternalConfig &extconf,
                                       const template_args &tpl_args,
                                       const string_map &tpl_args_base) {
  if (tpl_args.local_vars != tpl_args_base)
    return true;

  if (!extconf.custom_proxy_group.empty() || !extconf.surge_ruleset.empty())
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
  std::string tag;
  std::string provider;
  std::string link;
  bool has_tag = false;
  bool has_provider = false;
  bool link_decoded = false;
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
    break;
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
         startsWith(lower, "%3ctag%3a") ||
         startsWith(lower, "%3cprovider%3a") || startsWith(lower, "%3ctag:") ||
         startsWith(lower, "%3cprovider:") ||
         (startsWith(lower, "tag:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "provider:") &&
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

static std::string subconverter_impl(RESPONSE_CALLBACK_ARGS);

namespace {

struct CoalescedResponse {
  int status_code = 200;
  std::string content_type;
  string_icase_map headers;
  std::string body;
};

struct InflightSubRequest {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  CoalescedResponse result;
  std::exception_ptr exception;
};

struct CachedSubResponse {
  CoalescedResponse result;
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

static bool appendKeyPart(std::string &identity, const std::string &name,
                          const std::string &value) {
  static constexpr size_t kMaxIdentitySize = 2 * 1024 * 1024;
  size_t extra_size = name.size() + value.size() + 32;
  if (identity.size() + extra_size > kMaxIdentitySize)
    return false;
  identity += name;
  identity += ':';
  identity += std::to_string(value.size());
  identity += ':';
  identity += value;
  identity += '\n';
  return true;
}

static bool shouldCoalesceSubRequest(const Request &request) {
  if (!global.enableRequestCoalescing)
    return false;
  if (request.method != "GET" || request.url != "/sub")
    return false;
  if (isTruthyRequestValue(getUrlArg(request.argument, "upload")))
    return false;
  return true;
}

static std::string buildSubRequestKey(const Request &request) {
  std::string identity;
  if (!appendKeyPart(identity, "version", VERSION) ||
      !appendKeyPart(identity, "config_generation",
                     std::to_string(global.configGeneration)) ||
      !appendKeyPart(identity, "managed_config_prefix",
                     global.managedConfigPrefix) ||
      !appendKeyPart(identity, "method", request.method) ||
      !appendKeyPart(identity, "path", request.url))
    return "";

  for (const auto &arg : request.argument) {
    if (!appendKeyPart(identity, "arg_name", arg.first) ||
        !appendKeyPart(identity, "arg_value", arg.second))
      return "";
  }

  for (const auto &header : request.headers) {
    if (!appendKeyPart(identity, "header_name", toLower(header.first)) ||
        !appendKeyPart(identity, "header_value", header.second))
      return "";
  }

  return getMD5(identity);
}

static void copyCoalescedToResponse(const CoalescedResponse &result,
                                    Response &response) {
  response.status_code = result.status_code;
  response.content_type = result.content_type;
  response.headers = result.headers;
}

static CoalescedResponse makeCoalescedResult(const std::string &body,
                                             const Response &response) {
  CoalescedResponse result;
  result.status_code = response.status_code;
  result.content_type = response.content_type;
  result.headers = response.headers;
  result.body = body;
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
                                 CoalescedResponse &result) {
  if (global.responseCacheTtl <= 0)
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
                                   const CoalescedResponse &result) {
  if (global.responseCacheTtl <= 0 || result.status_code != 200)
    return;

  int ttl = std::min(global.responseCacheTtl, 5);
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
                                                Response &response) {
  Request first_request = original;
  Response first_response;
  std::string body = subconverter_impl(first_request, first_response);
  if (first_response.status_code < 500 || !global.coalesceRetryOn5xx) {
    response = first_response;
    return body;
  }

  writeLog(0,
           "/sub 请求首次转换返回 5xx，正在进行一次服务端内部重试。",
           LOG_LEVEL_WARNING);
  Request retry_request = original;
  Response retry_response;
  std::string retry_body = subconverter_impl(retry_request, retry_response);
  if (retry_response.status_code < 500) {
    response = retry_response;
    return retry_body;
  }

  response = first_response;
  return body;
}

} // namespace

std::string subconverter(RESPONSE_CALLBACK_ARGS) {
  if (!shouldCoalesceSubRequest(request))
    return subconverter_impl(request, response);

  std::string key = buildSubRequestKey(request);
  if (key.empty())
    return subconverter_impl(request, response);

  CoalescedResponse cached_result;
  if (getCachedSubResponse(key, cached_result)) {
    writeLog(0, "/sub 响应微缓存命中。", LOG_LEVEL_DEBUG);
    copyCoalescedToResponse(cached_result, response);
    return cached_result.body;
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
    copyCoalescedToResponse(call->result, response);
    return call->result.body;
  }

  try {
    writeLog(0, "/sub 请求成为同 key 转换 owner。", LOG_LEVEL_DEBUG);
    Request original_request = request;
    Response owner_response;
    std::string body =
        runSubconverterImplWithRetry(original_request, owner_response);
    CoalescedResponse result = makeCoalescedResult(body, owner_response);
    response = owner_response;
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->result = result;
      call->done = true;
    }
    {
      std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
      g_sub_inflight.erase(key);
    }
    storeCachedSubResponse(key, result);
    call->cv.notify_all();
    return body;
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

static std::string subconverter_impl(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string argTarget = getUrlArg(argument, "target"),
              argSurgeVer = getUrlArg(argument, "ver");
  bool explainMode = isTruthyRequestValue(getUrlArg(argument, "explain"));
  SubExplainReport explain;
  explain.enabled = explainMode;
  explain.requested_target = argTarget;
  tribool argClashNewField = getUrlArg(argument, "new_name");
  int intSurgeVer = !argSurgeVer.empty() ? to_int(argSurgeVer, 3) : 3;
  if (argTarget == "auto")
    matchUserAgent(request.headers["User-Agent"], argTarget, argClashNewField,
                   intSurgeVer);
  explain.target = argTarget;

  /// don't try to load groups or rulesets when generating simple subscriptions
  bool lSimpleSubscription = false;
  switch (hash_(argTarget)) {
  case "ss"_hash:
  case "ssd"_hash:
  case "ssr"_hash:
  case "sssub"_hash:
  case "v2ray"_hash:
  case "trojan"_hash:
  case "mixed"_hash:
    lSimpleSubscription = true;
    break;
  case "clash"_hash:
  case "clashr"_hash:
  case "surge"_hash:
  case "quan"_hash:
  case "quanx"_hash:
  case "loon"_hash:
  case "surfboard"_hash:
  case "mellow"_hash:
  case "singbox"_hash:
    break;
  default:
    *status_code = 400;
    return "Invalid request: unsupported target value.\n"
           "无效请求：不支持的 target 参数值。\n"
           "Supported targets: clash, clashr, surge, quan, quanx, loon, "
           "surfboard, mellow, singbox, ss, ssd, ssr, sssub, v2ray, trojan, "
           "mixed.\n"
           "支持的 target：clash、clashr、surge、quan、quanx、loon、"
           "surfboard、mellow、singbox、ss、ssd、ssr、sssub、v2ray、trojan、"
           "mixed。";
  }
  // check if we need to read configuration
  if (global.reloadConfOnRequest &&
      (!global.APIMode || global.CFWChildProcess) && !global.generatorMode)
    readConf();

  /// string values
  std::string argUrl = getUrlArg(argument, "url");
  std::string argGroupName = getUrlArg(argument, "group"),
              argUploadPath = getUrlArg(argument, "upload_path");
  std::string argIncludeRemark = getUrlArg(argument, "include"),
              argExcludeRemark = getUrlArg(argument, "exclude");
  std::string argCustomGroups =
                  urlSafeBase64Decode(getUrlArg(argument, "groups")),
              argCustomRulesets =
                  urlSafeBase64Decode(getUrlArg(argument, "ruleset")),
              argExternalConfig = getUrlArg(argument, "config");
  std::string argDeviceID = getUrlArg(argument, "dev_id"),
              argFilename = getUrlArg(argument, "filename"),
              argUpdateInterval = getUrlArg(argument, "interval"),
              argUpdateStrict = getUrlArg(argument, "strict");
  std::string argRenames = getUrlArg(argument, "rename"),
              argFilterScript = getUrlArg(argument, "filter_script");

  /// switches with default value
  tribool argUpload = getUrlArg(argument, "upload"),
          argEmoji = getUrlArg(argument, "emoji"),
          argAddEmoji = getUrlArg(argument, "add_emoji"),
          argRemoveEmoji = getUrlArg(argument, "remove_emoji");
  tribool argAppendType = getUrlArg(argument, "append_type"),
          argTFO = getUrlArg(argument, "tfo"),
          argUDP = getUrlArg(argument, "udp"),
          argGenNodeList = getUrlArg(argument, "list");
  tribool argSort = getUrlArg(argument, "sort"),
          argUseSortScript = getUrlArg(argument, "sort_script");
  tribool argGenClashScript = getUrlArg(argument, "script"),
          argEnableInsert = getUrlArg(argument, "insert");
  tribool argSkipCertVerify = getUrlArg(argument, "scv"),
          argFilterDeprecated = getUrlArg(argument, "fdn"),
          argExpandRulesets = getUrlArg(argument, "expand"),
          argAppendUserinfo = getUrlArg(argument, "append_info");
  tribool argPrependInsert = getUrlArg(argument, "prepend"),
          argGenClassicalRuleProvider = getUrlArg(argument, "classic"),
          argTLS13 = getUrlArg(argument, "tls13"),
          argProviderProxyDirect = getUrlArg(argument, "provider_proxy_direct");
  explain.upload_requested = argUpload.get(false);
  if (explainMode && argUpload) {
    argUpload = false;
    explain.upload_suppressed = true;
  }

  std::string base_content, output_content;
  ProxyGroupConfigs lCustomProxyGroups = global.customProxyGroups;
  RulesetConfigs lCustomRulesets = global.customRulesets;
  string_array lIncludeRemarks = global.includeRemarks,
               lExcludeRemarks = global.excludeRemarks;
  std::vector<RulesetContent> lRulesetContent;
  extra_settings ext;
  std::string subInfo, dummy;
  int interval = !argUpdateInterval.empty()
                     ? to_int(argUpdateInterval, global.updateInterval)
                     : global.updateInterval;
  // Token authentication is permanently disabled for security
  bool authorized = false, strict = !argUpdateStrict.empty()
                                        ? argUpdateStrict == "true"
                                        : global.updateStrict;
  explain.simple_subscription = lSimpleSubscription;

  if (std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                argIncludeRemark) != gRegexBlacklist.cend() ||
      std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                argExcludeRemark) != gRegexBlacklist.cend()) {
    *status_code = 400;
    return "Invalid request: include or exclude filter is not allowed.\n"
           "无效请求：include 或 exclude 过滤条件不被允许。\n"
           "Please remove blocked filter patterns and try again.\n"
           "请移除被拦截的过滤表达式后重试。";
  }

  /// for external configuration
  std::string lClashBase = global.clashBase, lSurgeBase = global.surgeBase,
              lMellowBase = global.mellowBase,
              lSurfboardBase = global.surfboardBase;
  std::string lQuanBase = global.quanBase, lQuanXBase = global.quanXBase,
              lLoonBase = global.loonBase, lSSSubBase = global.SSSubBase;
  std::string lSingBoxBase = global.singBoxBase;

  /// validate urls
  argEnableInsert.define(global.enableInsert);
  // default_url is permanently disabled - users must provide url parameter
  // if (argUrl.empty() && (!global.APIMode || authorized))
  //     argUrl = global.defaultUrls;
  if ((argUrl.empty() && !(!global.insertUrls.empty() && argEnableInsert)) ||
      argTarget.empty()) {
    *status_code = 400;
    return "Invalid request: missing required target or url parameter.\n"
           "无效请求：缺少必需的 target 或 url 参数。\n"
           "Please provide target and url; url may be omitted only when "
           "configured insert nodes are enabled.\n"
           "请提供 target 和 url；只有启用已配置的插入节点时才能省略 url。";
  }

  /// load request arguments as template variables
  //    string_array req_args = split(argument, "&");
  //    string_map req_arg_map;
  //    for(std::string &x : req_args)
  //    {
  //        string_size pos = x.find("=");
  //        if(pos == x.npos)
  //        {
  //            req_arg_map[x] = "";
  //            continue;
  //        }
  //        if(x.substr(0, pos) == "token")
  //            continue;
  //        req_arg_map[x.substr(0, pos)] = x.substr(pos + 1);
  //    }
  string_map req_arg_map;
  for (auto &x : argument) {
    if (x.first == "token")
      continue;
    req_arg_map[x.first] = x.second;
  }
  req_arg_map["target"] = argTarget;
  req_arg_map["ver"] = std::to_string(intSurgeVer);

  /// save template variables
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;
  tpl_args.request_params = req_arg_map;

  /// check for proxy settings
  std::string proxy = parseProxy(global.proxySubscription);

  /// check other flags
  ext.authorized = authorized;
  ext.append_proxy_type = argAppendType.get(global.appendType);
  // 上游项目默认在 clash 目标下自动把 expand 设为 true
  // 本项目默认 expand=false（使用 rule-provider 模式不展开规则集）
  // 若用户主动传入 expand=true，则按照用户意愿内联展开规则集
  argExpandRulesets.define(false);

  ext.clash_proxies_style = global.clashProxiesStyle;
  ext.clash_proxy_groups_style = global.clashProxyGroupsStyle;

  /// read preference from argument, assign global var if not in argument
  ext.tfo.define(argTFO).define(global.TFOFlag);
  ext.udp.define(argUDP).define(global.UDPFlag);
  ext.skip_cert_verify.define(argSkipCertVerify).define(global.skipCertVerify);
  ext.tls13.define(argTLS13).define(global.TLS13Flag);

  ext.sort_flag = argSort.get(global.enableSort);
  argUseSortScript.define(!global.sortScript.empty());
  if (ext.sort_flag && argUseSortScript)
    ext.sort_script = global.sortScript;
  ext.filter_deprecated = argFilterDeprecated.get(global.filterDeprecated);
  ext.clash_new_field_name = argClashNewField.get(global.clashUseNewField);
  ext.clash_script = argGenClashScript.get();
  ext.clash_classical_ruleset = argGenClassicalRuleProvider.get();
  ext.provider_proxy_direct = argProviderProxyDirect.get(true);
  // 无论 expand 取何值，均强制使用 Mihomo 新字段名（proxy-groups / rules）
  // 避免因全局配置为旧字段名而导致 Mihomo 无法识别
  ext.clash_new_field_name = true;
  if (argExpandRulesets)
    ext.clash_script = false;
  explain.expand_rulesets = argExpandRulesets.get(false);

  ext.nodelist = argGenNodeList;
  // 强制 list=false，直接覆盖用户提供的任何值
  // 确保始终使用 proxy-provider 模式，而不是读取订阅并形成节点列表
  ext.nodelist = false;
  explain.nodelist = ext.nodelist;
  ext.surge_ssr_path = global.surgeSSRPath;
  ext.quanx_dev_id = !argDeviceID.empty() ? argDeviceID : global.quanXDevID;
  ext.enable_rule_generator = global.enableRuleGen;
  ext.overwrite_original_rules = global.overwriteOriginalRules;
  if (!argExpandRulesets)
    ext.managed_config_prefix = global.managedConfigPrefix;
  explain.rule_generator_enabled = ext.enable_rule_generator;
  explain.managed_config = !ext.managed_config_prefix.empty();

  /// load external configuration
  std::string userProvidedConfig = getUrlArg(argument, "config");
  bool userProvidedExternalConfig = !argExternalConfig.empty();
  FetchContext externalConfigContext =
      userProvidedExternalConfig ? FetchContext::PublicRequest
                                 : FetchContext::TrustedConfig;
  FetchContext rulesetFetchContext = FetchContext::TrustedConfig;
  FetchContext baseFetchContext = FetchContext::TrustedConfig;
  bool configLoadSuccess = false;
  string_map tpl_args_base = tpl_args.local_vars;
  explain.external_config_provided = userProvidedExternalConfig;

  if (argExternalConfig.empty())
    argExternalConfig = global.defaultExtConfig;

  if (!argExternalConfig.empty()) {
    // std::cerr<<"External configuration file provided. Loading...\n";
    writeLog(0, "已提供外部配置文件，正在加载...",
             LOG_LEVEL_INFO);
    ExternalConfig extconf;
    extconf.tpl_args = &tpl_args;
    int load_result =
        loadExternalConfig(argExternalConfig, extconf, externalConfigContext);
    if (load_result == 0 &&
        hasEffectiveExternalConfig(extconf, tpl_args, tpl_args_base)) {
      configLoadSuccess = true;
      explain.external_config_loaded = true;
      if (!ext.nodelist) {
        if (checkExternalBase(extconf.sssub_rule_base, lSSSubBase,
                              externalConfigContext))
          baseFetchContext = externalConfigContext;
        if (!lSimpleSubscription) {
          if (checkExternalBase(extconf.clash_rule_base, lClashBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.surge_rule_base, lSurgeBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.surfboard_rule_base, lSurfboardBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.mellow_rule_base, lMellowBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.quan_rule_base, lQuanBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.quanx_rule_base, lQuanXBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.loon_rule_base, lLoonBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.singbox_rule_base, lSingBoxBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;

          if (!extconf.surge_ruleset.empty()) {
            lCustomRulesets = extconf.surge_ruleset;
            rulesetFetchContext = externalConfigContext;
          }
          if (!extconf.custom_proxy_group.empty())
            lCustomProxyGroups = extconf.custom_proxy_group;
          ext.enable_rule_generator = extconf.enable_rule_generator;
          ext.overwrite_original_rules = extconf.overwrite_original_rules;
        }
      }
      if (!extconf.rename.empty()) {
        ext.rename_array = extconf.rename;
        ext.rename_for_providers = true;
      }
      if (!extconf.emoji.empty())
        ext.emoji_array = extconf.emoji;
      if (!extconf.include.empty())
        lIncludeRemarks = extconf.include;
      if (!extconf.exclude.empty())
        lExcludeRemarks = extconf.exclude;
      argAddEmoji.define(extconf.add_emoji);
      argRemoveEmoji.define(extconf.remove_old_emoji);
    } else {
      tpl_args.local_vars = tpl_args_base;
      if (load_result == 0) {
        writeLog(
            0,
            "外部配置已加载，但未包含有效设置，按加载失败处理。",
            LOG_LEVEL_WARNING);
      }
    }

    if (!configLoadSuccess && !userProvidedConfig.empty() &&
        !global.defaultExtConfig.empty() &&
        argExternalConfig != global.defaultExtConfig) {
      // User provided config failed, try multiple fallback CDN URLs
      writeLog(
          0, "加载用户提供的配置失败，正在尝试回退配置...",
          LOG_LEVEL_WARNING);

      for (std::string fallbackUrl : FALLBACK_CONFIG_URLS) {
        writeLog(0, "正在尝试加载配置：" + fallbackUrl,
                 LOG_LEVEL_INFO);

        tpl_args.local_vars = tpl_args_base;
        ExternalConfig extconf;
        extconf.tpl_args = &tpl_args;
        int fallback_result =
            loadExternalConfig(fallbackUrl, extconf, FetchContext::TrustedConfig);
        if (fallback_result == 0 &&
            hasEffectiveExternalConfig(extconf, tpl_args, tpl_args_base)) {
          writeLog(0, "已成功加载配置：" + fallbackUrl,
                   LOG_LEVEL_INFO);
          configLoadSuccess = true;
          explain.external_config_loaded = true;
          explain.fallback_config_used = true;
          if (!ext.nodelist) {
            checkExternalBase(extconf.sssub_rule_base, lSSSubBase,
                              FetchContext::TrustedConfig);
            if (!lSimpleSubscription) {
              checkExternalBase(extconf.clash_rule_base, lClashBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.surge_rule_base, lSurgeBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.surfboard_rule_base, lSurfboardBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.mellow_rule_base, lMellowBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.quan_rule_base, lQuanBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.quanx_rule_base, lQuanXBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.loon_rule_base, lLoonBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.singbox_rule_base, lSingBoxBase,
                                FetchContext::TrustedConfig);

              if (!extconf.surge_ruleset.empty())
                lCustomRulesets = extconf.surge_ruleset;
              if (!extconf.custom_proxy_group.empty())
                lCustomProxyGroups = extconf.custom_proxy_group;
              ext.enable_rule_generator = extconf.enable_rule_generator;
              ext.overwrite_original_rules = extconf.overwrite_original_rules;
            }
          }
          if (!extconf.rename.empty()) {
            ext.rename_array = extconf.rename;
            ext.rename_for_providers = true;
          }
          if (!extconf.emoji.empty())
            ext.emoji_array = extconf.emoji;
          if (!extconf.include.empty())
            lIncludeRemarks = extconf.include;
          if (!extconf.exclude.empty())
            lExcludeRemarks = extconf.exclude;
          argAddEmoji.define(extconf.add_emoji);
          argRemoveEmoji.define(extconf.remove_old_emoji);
          break; // Success, stop trying other URLs
        } else {
          tpl_args.local_vars = tpl_args_base;
          if (fallback_result == 0) {
            writeLog(
                0,
                "已从 " + fallbackUrl + " 加载配置，但未发现有效设置，跳过。",
                LOG_LEVEL_WARNING);
          } else {
            writeLog(0, "加载配置失败：" + fallbackUrl,
                     LOG_LEVEL_WARNING);
          }
        }
      }

      if (!configLoadSuccess) {
        writeLog(0, "所有回退配置 URL 均加载失败。", LOG_LEVEL_ERROR);
      }
    }
  }

  if (!configLoadSuccess) {
    if (!lSimpleSubscription) {
      /// loading custom groups
      if (!argCustomGroups.empty() && !ext.nodelist) {
        string_array vArray = split(argCustomGroups, "@");
        lCustomProxyGroups =
            INIBinding::from<ProxyGroupConfig>::from_ini(vArray);
      }

      /// loading custom rulesets
      if (!argCustomRulesets.empty() && !ext.nodelist) {
        string_array vArray = split(argCustomRulesets, "@");
        lCustomRulesets = INIBinding::from<RulesetConfig>::from_ini(vArray);
        rulesetFetchContext = FetchContext::PublicRequest;
      }
    }
  }
  if (ext.enable_rule_generator && !ext.nodelist && !lSimpleSubscription) {
    if (lCustomRulesets != global.customRulesets)
      refreshRulesets(lCustomRulesets, lRulesetContent, rulesetFetchContext);
    else {
      if (global.updateRulesetOnRequest)
        refreshRulesets(global.customRulesets, global.rulesetsContent);
      lRulesetContent = global.rulesetsContent;
    }
  }
  explain.rule_generator_enabled = ext.enable_rule_generator;
  explain.base_fetch_context = fetchContextName(baseFetchContext);
  explain.ruleset_fetch_context = fetchContextName(rulesetFetchContext);
  explain.ruleset_count = lRulesetContent.size();
  explain.custom_group_count = lCustomProxyGroups.size();

  if (!argEmoji.is_undef()) {
    argAddEmoji.set(argEmoji);
    argRemoveEmoji.set(true);
  }
  ext.add_emoji = argAddEmoji.get(global.addEmoji);
  ext.remove_emoji = argRemoveEmoji.get(global.removeEmoji);
  if (ext.add_emoji && ext.emoji_array.empty())
    ext.emoji_array = safe_get_emojis();
  if (!argRenames.empty()) {
    ext.rename_array = INIBinding::from<RegexMatchConfig>::from_ini(
        split(argRenames, "`"), "@");
    ext.rename_for_providers = true;
  } else if (ext.rename_array.empty())
    ext.rename_array = safe_get_renames();

  /// check custom include/exclude settings
  if (!argIncludeRemark.empty() && regValid(argIncludeRemark))
    lIncludeRemarks = string_array{argIncludeRemark};
  if (!argExcludeRemark.empty() && regValid(argExcludeRemark))
    lExcludeRemarks = string_array{argExcludeRemark};

  /// initialize script runtime
  if (authorized && !global.scriptCleanContext) {
    ext.js_runtime = new qjs::Runtime();
    script_runtime_init(*ext.js_runtime);
    ext.js_context = new qjs::Context(*ext.js_runtime);
    script_context_init(*ext.js_context);
  }

  // start parsing urls
  RegexMatchConfigs stream_temp = safe_get_streams(),
                    time_temp = safe_get_times();

  // loading urls
  string_array urls;
  std::vector<Proxy> nodes, insert_nodes;
  int groupID = 0;

  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = &lExcludeRemarks;
  parse_set.include_remarks = &lIncludeRemarks;
  parse_set.stream_rules = &stream_temp;
  parse_set.time_rules = &time_temp;
  parse_set.sub_info = &subInfo;
  parse_set.authorized = authorized;
  parse_set.request_header = &request.headers;
  parse_set.fetch_context = FetchContext::TrustedConfig;
  parse_set.js_runtime = ext.js_runtime;
  parse_set.js_context = ext.js_context;

  if (!global.insertUrls.empty() && argEnableInsert) {
    groupID = -1;
    urls = split(global.insertUrls, "|");
    explain.insert_url_count = urls.size();
    importItems(urls, true);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
      if (addNodes(x, insert_nodes, groupID, parse_set) == -1) {
        if (global.skipFailedLinks)
          writeLog(
              0, "以下链接不包含任何有效节点信息：" + x,
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
      groupID--;
    }
  }
  urls = split(argUrl, "|");
  explain.raw_url_count = urls.size();
  parse_set.fetch_context = FetchContext::PublicRequest;
  groupID = 0;

  //  对于 Clash，区分节点链接和订阅链接
  if ((argTarget == "clash" || argTarget == "clashr") && !ext.nodelist) {
    // 先区分节点链接和订阅链接
    struct SubscriptionLinkItem {
      std::string url;
      std::string tag;
      std::string provider;
      bool url_decoded = false;
    };
    std::vector<SubscriptionLinkItem> subscription_urls; // HTTP/HTTPS 订阅链接
    std::vector<std::string> node_urls; // 节点链接（vless://, vmess:// 等）

    for (std::string &x : urls) {
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      std::string link = tagged.link.empty() ? x : tagged.link;

      // Keep HTTP(S)/data links available for proxy-provider mode. Other
      // Mihomo-supported schemes are direct node links.
      bool isNodeLink = mihomo::isSupportedNonHttpSchemeLink(link);

      if (isNodeLink) {
        std::string node_link = link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "检测到节点链接：'" + link + "'，将直接解析。",
                 LOG_LEVEL_INFO);
        node_urls.push_back(node_link);
        explain.node_link_count++;
      } else if (isLink(link) || mihomo::isHttpSchemeLink(link)) {
        // HTTP/HTTPS 订阅链接
        writeLog(
            0, "检测到订阅链接：'" + link + "'，将创建 provider。",
            LOG_LEVEL_INFO);
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider, tagged.link_decoded});
        explain.subscription_url_count++;
      } else {
        std::string node_link = link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "未知 URL 类型：'" + link + "'，按节点链接处理。",
                 LOG_LEVEL_WARNING);
        node_urls.push_back(node_link);
        explain.node_link_count++;
        explain.unknown_node_link_count++;
      }
    }

    // 只有当有订阅链接时才启用 proxy-provider 模式
    if (!subscription_urls.empty()) {
      writeLog(0, "检测到订阅 URL，启用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = true;
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

      // 为订阅链接创建 proxy-provider
      for (const SubscriptionLinkItem &item : subscription_urls) {
        ProxyProvider provider;
        // 使用 URL 的 MD5 哈希前 10 位作为唯一特征码
        // 这样相同的订阅链接会生成相同的 provider 名称
        // 不同的订阅链接会生成不同的名称，触发客户端自动更新
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
                     item.url,
                 LOG_LEVEL_INFO);
        provider.url = item.url_decoded ? item.url
                                        : urlDecode(item.url); // 解码 URL
        provider.interval = 3600;    // 固定使用 3600 秒（1小时）
        provider.groupId = groupID;
        provider.path = "./providers/" + provider.name + ".yaml";

        // 将 include/exclude 参数转换为 filter
        if (!argIncludeRemark.empty() && regValid(argIncludeRemark)) {
          provider.filter = argIncludeRemark;
        }
        if (!argExcludeRemark.empty() && regValid(argExcludeRemark)) {
          provider.exclude_filter = argExcludeRemark;
        }

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
        explain.providers.push_back(std::move(explain_provider));
        groupID++;
      }
    } else {
      // 没有订阅链接，禁用 proxy-provider 模式
      writeLog(0, "未检测到订阅 URL，禁用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = false;
    }

    // 节点链接使用原有逻辑直接解析
    if (!node_urls.empty()) {
      writeLog(0,
               "正在直接解析 " + std::to_string(node_urls.size()) +
                   " 个节点链接。",
               LOG_LEVEL_INFO);
      importItems(node_urls, true, FetchContext::PublicRequest);
      // 关键：实际添加节点到 nodes 列表
      for (std::string &x : node_urls) {
        writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
        if (addNodes(x, nodes, groupID, parse_set) == -1) {
          // 跳过无法解析的节点链接，记录警告后继续处理其他节点
          writeLog(0,
                   "已跳过无效节点链接：'" + x + "'，继续处理其他节点。",
                   LOG_LEVEL_WARNING);
        }
        groupID++;
      }
    }
  } else {
    // 其他格式保持原有逻辑，完全展开节点
    importItems(urls, true,
                FetchContext::PublicRequest); // 只为非 proxy-provider 模式处理 import 语法
    for (std::string &x : urls) {
      x = regTrim(x);
      // std::cerr<<"Fetching node data from url '"<<x<<"'."<<std::endl;
      writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
      if (addNodes(x, nodes, groupID, parse_set) == -1) {
        // 跳过无法解析的节点链接，记录警告后继续处理其他节点
        writeLog(0,
                 "已跳过无效节点链接：'" + x + "'，继续处理其他节点。",
                 LOG_LEVEL_WARNING);
      }
      groupID++;
    }
  }
  // exit if found nothing
  // 对于 proxy-provider 模式，允许 nodes 为空（节点从 provider 获取）
  explain.provider_count = ext.providers.size();
  explain.proxy_provider_mode = ext.use_proxy_provider && !ext.providers.empty();
  explain.insert_node_count = insert_nodes.size();
  explain.direct_node_count = nodes.size();
  if (nodes.empty() && insert_nodes.empty() && ext.providers.empty()) {
    *status_code = 400;
    return "Invalid request: no valid proxy nodes or proxy providers were "
           "found.\n"
           "无效请求：未找到有效的代理节点或代理提供者。\n"
           "Please check whether the subscription URL or node URI format is "
           "supported, and whether filters excluded all nodes.\n"
           "请检查订阅链接或节点 URI 格式是否受支持，以及过滤规则是否排除了所有节点。";
  }
  if (!subInfo.empty() && argAppendUserinfo.get(global.appendUserinfo))
    response.headers.emplace("Subscription-UserInfo", subInfo);

  if (request.method == "HEAD")
    return "";

  if (argUpload && !isPublicUploadAllowed()) {
    *status_code = 403;
    return "Upload is disabled for the current security profile.\n"
           "当前安全档位已禁用公开请求上传。\n"
           "Use security.profile=lan for private deployments, or explicitly "
           "enable security.allow_public_upload in public profile.\n"
           "内网私有部署请使用 security.profile=lan；公网档位如确需上传，"
           "请显式开启 security.allow_public_upload。";
  }

  argPrependInsert.define(global.prependInsert);
  if (argPrependInsert) {
    std::move(nodes.begin(), nodes.end(), std::back_inserter(insert_nodes));
    nodes.swap(insert_nodes);
  } else {
    std::move(insert_nodes.begin(), insert_nodes.end(),
              std::back_inserter(nodes));
  }
  // run filter script
  std::string filterScript = global.filterScript;
  if (authorized && !argFilterScript.empty())
    filterScript = argFilterScript;
  if (!filterScript.empty()) {
    if (startsWith(filterScript, "path:"))
      filterScript = fileGet(filterScript.substr(5), false);
    /*
    duk_context *ctx = duktape_init();
    if(ctx)
    {
        defer(duk_destroy_heap(ctx);)
        if(duktape_peval(ctx, filterScript) == 0)
        {
            auto filter = [&](const Proxy &x)
            {
                duk_get_global_string(ctx, "filter");
                duktape_push_Proxy(ctx, x);
                duk_pcall(ctx, 1);
                return !duktape_get_res_bool(ctx);
            };
            nodes.erase(std::remove_if(nodes.begin(), nodes.end(), filter),
    nodes.end());
        }
        else
        {
            writeLog(0, "解析脚本时发生错误：\n" +
    duktape_get_err_stack(ctx), LOG_LEVEL_ERROR); duk_pop(ctx); /// pop err
        }
    }
    */
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
        global.scriptCleanContext);
  }

  // check custom group name
  if (!argGroupName.empty())
    for (Proxy &x : nodes)
      x.Group = argGroupName;

  // do pre-process now
  preprocessNodes(nodes, ext);
  explain.total_node_count = nodes.size();

  /*
  //insert node info to template
  int index = 0;
  std::string template_node_prefix;
  for(Proxy &x : nodes)
  {
      template_node_prefix = std::to_string(index) + ".";
      tpl_args.node_list[template_node_prefix + "remarks"] = x.remarks;
      tpl_args.node_list[template_node_prefix + "group"] = x.Group;
      tpl_args.node_list[template_node_prefix + "groupid"] =
  std::to_string(x.GroupId); index++;
  }
  */

  ProxyGroupConfigs dummy_group;
  std::vector<RulesetContent> dummy_ruleset;
  std::string managed_url = base64Decode(getUrlArg(argument, "profile_data"));
  if (managed_url.empty())
    managed_url =
        global.managedConfigPrefix + "/sub?" + joinArguments(argument);

  // std::cerr<<"Generate target: ";
  proxy = parseProxy(global.proxyConfig);
  switch (hash_(argTarget)) {
  case "clash"_hash:
  case "clashr"_hash:
    writeLog(0,
             argTarget == "clashr" ? "生成目标：ClashR" : "生成目标：Clash",
             LOG_LEVEL_INFO);
    tpl_args.local_vars["clash.new_field_name"] =
        ext.clash_new_field_name ? "true" : "false";
    response.headers["profile-update-interval"] =
        std::to_string(interval / 3600);
    if (ext.nodelist) {
      YAML::Node yamlnode;
      proxyToClash(nodes, yamlnode, dummy_group, argTarget == "clashr", ext);
      output_content = YAML::Dump(yamlnode);
    } else {
      if (render_template(fetchFile(lClashBase, proxy, global.cacheConfig,
                                    true, baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
      output_content =
          proxyToClash(nodes, base_content, lRulesetContent, lCustomProxyGroups,
                       argTarget == "clashr", ext);
    }

    if (argUpload)
      uploadGist(argTarget, argUploadPath, output_content, false);
    break;
  case "surge"_hash:

    writeLog(0, "生成目标：Surge " + std::to_string(intSurgeVer),
             LOG_LEVEL_INFO);

    if (ext.nodelist) {
      output_content = proxyToSurge(nodes, base_content, dummy_ruleset,
                                    dummy_group, intSurgeVer, ext);

      if (argUpload)
        uploadGist("surge" + argSurgeVer + "list", argUploadPath,
                   output_content, true);
    } else {
      if (render_template(fetchFile(lSurgeBase, proxy, global.cacheConfig,
                                    true, baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
      output_content = proxyToSurge(nodes, base_content, lRulesetContent,
                                    lCustomProxyGroups, intSurgeVer, ext);

      if (argUpload)
        uploadGist("surge" + argSurgeVer, argUploadPath, output_content, true);

      if (global.writeManagedConfig && !global.managedConfigPrefix.empty())
        output_content =
            "#!MANAGED-CONFIG " + managed_url +
            (interval ? " interval=" + std::to_string(interval) : "") +
            " strict=" + std::string(strict ? "true" : "false") + "\n\n" +
            output_content;
    }
    break;
  case "surfboard"_hash:
    writeLog(0, "生成目标：Surfboard", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lSurfboardBase, proxy, global.cacheConfig,
                                  true, baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return base_content;
    }
    output_content = proxyToSurge(nodes, base_content, lRulesetContent,
                                  lCustomProxyGroups, -3, ext);
    if (argUpload)
      uploadGist("surfboard", argUploadPath, output_content, true);

    if (global.writeManagedConfig && !global.managedConfigPrefix.empty())
      output_content =
          "#!MANAGED-CONFIG " + managed_url +
          (interval ? " interval=" + std::to_string(interval) : "") +
          " strict=" + std::string(strict ? "true" : "false") + "\n\n" +
          output_content;
    break;
  case "mellow"_hash:
    writeLog(0, "生成目标：Mellow", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lMellowBase, proxy, global.cacheConfig, true,
                                  baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return base_content;
    }
    output_content = proxyToMellow(nodes, base_content, lRulesetContent,
                                   lCustomProxyGroups, ext);

    if (argUpload)
      uploadGist("mellow", argUploadPath, output_content, true);
    break;
  case "sssub"_hash:
    writeLog(0, "生成目标：SS Subscription", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lSSSubBase, proxy, global.cacheConfig, true,
                                  baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return base_content;
    }
    output_content = proxyToSSSub(base_content, nodes, ext);
    if (argUpload)
      uploadGist("sssub", argUploadPath, output_content, false);
    break;
  case "ss"_hash:
    writeLog(0, "生成目标：SS", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 1, ext);
    if (argUpload)
      uploadGist("ss", argUploadPath, output_content, false);
    break;
  case "ssr"_hash:
    writeLog(0, "生成目标：SSR", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 2, ext);
    if (argUpload)
      uploadGist("ssr", argUploadPath, output_content, false);
    break;
  case "v2ray"_hash:
    writeLog(0, "生成目标：v2rayN", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 4, ext);
    if (argUpload)
      uploadGist("v2ray", argUploadPath, output_content, false);
    break;
  case "trojan"_hash:
    writeLog(0, "生成目标：Trojan", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 8, ext);
    if (argUpload)
      uploadGist("trojan", argUploadPath, output_content, false);
    break;
  case "vless"_hash:
    writeLog(0, "生成目标：vless", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 16, ext);
    if (argUpload)
      uploadGist("vless", argUploadPath, output_content, false);
    break;
  case "hysteria2"_hash:
    writeLog(0, "生成目标：hysteria2", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 32, ext);
    if (argUpload)
      uploadGist("hysteria2", argUploadPath, output_content, false);
    break;
  case "mixed"_hash:
    writeLog(0, "生成目标：Standard Subscription", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 63, ext);
    if (argUpload)
      uploadGist("sub", argUploadPath, output_content, false);
    break;
  case "quan"_hash:
    writeLog(0, "生成目标：Quantumult", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(lQuanBase, proxy, global.cacheConfig, true,
                                    baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
    }

    output_content = proxyToQuan(nodes, base_content, lRulesetContent,
                                 lCustomProxyGroups, ext);

    if (argUpload)
      uploadGist("quan", argUploadPath, output_content, false);
    break;
  case "quanx"_hash:
    writeLog(0, "生成目标：Quantumult X", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(lQuanXBase, proxy, global.cacheConfig,
                                    true, baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
    }

    output_content = proxyToQuanX(nodes, base_content, lRulesetContent,
                                  lCustomProxyGroups, ext);

    if (argUpload)
      uploadGist("quanx", argUploadPath, output_content, false);
    break;
  case "loon"_hash:
    writeLog(0, "生成目标：Loon", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(lLoonBase, proxy, global.cacheConfig, true,
                                    baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
    }

    output_content = proxyToLoon(nodes, base_content, lRulesetContent,
                                 lCustomProxyGroups, ext);

    if (argUpload)
      uploadGist("loon", argUploadPath, output_content, false);
    break;
  case "ssd"_hash:
    writeLog(0, "生成目标：SSD", LOG_LEVEL_INFO);
    output_content = proxyToSSD(nodes, argGroupName, subInfo, ext);
    if (argUpload)
      uploadGist("ssd", argUploadPath, output_content, false);
    break;
  case "singbox"_hash:
    writeLog(0, "生成目标：sing-box", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (render_template(fetchFile(lSingBoxBase, proxy, global.cacheConfig,
                                    true, baseFetchContext),
                          tpl_args, base_content, global.templatePath,
                          baseFetchContext) != 0) {
        *status_code = 400;
        return base_content;
      }
    }

    output_content = proxyToSingBox(nodes, base_content, lRulesetContent,
                                    lCustomProxyGroups, ext);

    if (argUpload)
      uploadGist("singbox", argUploadPath, output_content, false);
    break;
  default:
    writeLog(0, "生成目标：未指定", LOG_LEVEL_INFO);
    *status_code = 500;
    return "Internal error: target passed validation but no generator handled "
           "it.\n"
           "内部错误：target 已通过校验，但没有对应的生成器处理它。\n"
           "Please report this request to the service maintainer.\n"
           "请将该请求反馈给服务维护者。";
  }
  writeLog(0, "生成完成。", LOG_LEVEL_INFO);
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
    addParameter("filter_script",
                 authorized && !argFilterScript.empty() ? "script accepted"
                                                        : "not used",
                 authorized ? "applied" : "ignored",
                 "Public requests cannot provide executable filter scripts.",
                 true);
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
    addParameter("list", boolString(ext.nodelist),
                 isTruthyRequestValue(rawArg("list")) && !ext.nodelist
                     ? "overridden"
                     : "applied",
                 "This project forces provider mode for Clash-compatible "
                 "output.");
    addSwitchParameter("sort", ext.sort_flag, argSort);
    addParameter("sort_script",
                 argUseSortScript ? "enabled" : "disabled",
                 argUseSortScript ? "applied" : "ignored",
                 "Uses configured sort script when sorting is enabled.");
    addSwitchParameter("script", ext.clash_script, argGenClashScript);
    addSwitchParameter("insert", argEnableInsert.get(global.enableInsert),
                       argEnableInsert);
    addSwitchParameter("scv", ext.skip_cert_verify.get(false),
                       ext.skip_cert_verify);
    addSwitchParameter("fdn", ext.filter_deprecated, argFilterDeprecated);
    addSwitchParameter("expand", explain.expand_rulesets, argExpandRulesets);
    addSwitchParameter("append_info",
                       argAppendUserinfo.get(global.appendUserinfo),
                       argAppendUserinfo);
    addSwitchParameter("prepend", argPrependInsert.get(global.prependInsert),
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
        "tls13", "provider_proxy_direct", "explain", "profile_data",
        "token"};
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
    else if (explain.external_config_loaded && !global.defaultExtConfig.empty())
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
  writeLog(0, "SurgeConfToClash 调用，URL：'" + url + "'。",
           LOG_LEVEL_INFO);

  std::string proxy = parseProxy(global.proxyConfig);
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
    std::string errmsg = "Invalid request: failed to parse Surge "
                         "configuration.\n"
                         "无效请求：Surge 配置解析失败。\n"
                         "Reason / 原因: " +
                         ini.get_last_error();
    // std::cerr<<errmsg<<"\n";
    writeLog(0, "Surge 配置解析失败。原因：" + ini.get_last_error(),
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
  parse_set.authorized = !global.APIMode;
  for (std::string &x : links) {
    // std::cerr<<"Fetching node data from url '"<<x<<"'."<<std::endl;
    writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
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
    writeLog(0, "加载配置档失败！原因：" + ini.get_last_error(),
             LOG_LEVEL_ERROR);
    *status_code = 500;
    return "Invalid profile: failed to parse profile content.\n"
           "无效配置：profile 内容解析失败。\n"
           "Reason / 原因: " +
           ini.get_last_error();
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
    std::string proxy = parseProxy(global.proxyConfig);
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
    writeLog(0,
             "生成器配置损坏！原因：" + ini.get_last_error(),
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
  std::string proxy = parseProxy(global.proxySubscription);
  Request request;
  Response response;
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
        fileWrite(path, "\xEF\xBB\xBF" + content, true);
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
    fileWrite(path, content, true);
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
