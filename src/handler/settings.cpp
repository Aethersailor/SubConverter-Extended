#include <algorithm>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <filesystem>

#include "config/binding.h"
#include "handler/webget.h"
#include "interfaces.h"
#include "multithread.h"
#include "script/cron.h"
#include "server/request_context.h"
#include "server/webserver.h"
#include "settings.h"
#include "settings_view.h"
#include "utils/logger.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/resource_control.h"
#include "utils/system.h"

// multi-thread lock
std::mutex gMutexConfigure;

Settings global;

extern WebServer webServer;

namespace {

constexpr const char *kDefaultExternalConfig =
    "https://gcore.jsdelivr.net/gh/Aethersailor/"
    "Custom_OpenClash_Rules@refs/heads/main/cfg/Custom_Clash.ini";

struct CommonScalarSettings {
  bool prependInsert;
  std::string basePath;
  std::string clashBase;
  std::string surgeBase;
  std::string surfboardBase;
  std::string mellowBase;
  std::string quanBase;
  std::string quanXBase;
  std::string loonBase;
  std::string SSSubBase;
  std::string singBoxBase;
  std::string stashBase;
  std::string defaultExtConfig;
  bool fallbackToDefaultExternalConfig;
  bool appendType;
  std::string proxyConfig;
  std::string proxyRuleset;
  std::string proxySubscription;
  std::string proxyBypass;
  bool reloadConfOnRequest;
};

CommonScalarSettings captureCommonScalarSettings() {
  return {global.prependInsert,
          global.basePath,
          global.clashBase,
          global.surgeBase,
          global.surfboardBase,
          global.mellowBase,
          global.quanBase,
          global.quanXBase,
          global.loonBase,
          global.SSSubBase,
          global.singBoxBase,
          global.stashBase,
          global.defaultExtConfig,
          global.fallbackToDefaultExternalConfig,
          global.appendType,
          global.proxyConfig,
          global.proxyRuleset,
          global.proxySubscription,
          global.proxyBypass,
          global.reloadConfOnRequest};
}

void applyCommonScalarSettings(CommonScalarSettings settings) {
  const ProxyBypassPolicy bypass =
      ProxyBypassPolicy::parse(settings.proxyBypass);
  if (!bypass.valid)
    throw std::invalid_argument("proxy_bypass 配置无效：" + bypass.error + "。");
  if (settings.defaultExtConfig.empty())
    settings.defaultExtConfig = kDefaultExternalConfig;

  global.prependInsert = settings.prependInsert;
  global.basePath = std::move(settings.basePath);
  global.clashBase = std::move(settings.clashBase);
  global.surgeBase = std::move(settings.surgeBase);
  global.surfboardBase = std::move(settings.surfboardBase);
  global.mellowBase = std::move(settings.mellowBase);
  global.quanBase = std::move(settings.quanBase);
  global.quanXBase = std::move(settings.quanXBase);
  global.loonBase = std::move(settings.loonBase);
  global.SSSubBase = std::move(settings.SSSubBase);
  global.singBoxBase = std::move(settings.singBoxBase);
  global.stashBase = std::move(settings.stashBase);
  global.defaultExtConfig = std::move(settings.defaultExtConfig);
  global.fallbackToDefaultExternalConfig =
      settings.fallbackToDefaultExternalConfig;
  global.appendType = settings.appendType;
  global.proxyConfig = std::move(settings.proxyConfig);
  global.proxyRuleset = std::move(settings.proxyRuleset);
  global.proxySubscription = std::move(settings.proxySubscription);
  global.proxyBypass = std::move(settings.proxyBypass);
  global.reloadConfOnRequest = settings.reloadConfOnRequest;
}

LogLevel configuredLogLevel(const std::string &value,
                            bool print_debug_info) {
  if (print_debug_info)
    return LOG_LEVEL_VERBOSE;
  const std::string normalized =
      toLower(trimWhitespace(value, true, true));
  switch (hash_(normalized)) {
  case "warn"_hash:
    return LOG_LEVEL_WARNING;
  case "error"_hash:
    return LOG_LEVEL_ERROR;
  case "fatal"_hash:
    return LOG_LEVEL_FATAL;
  case "verbose"_hash:
    return LOG_LEVEL_VERBOSE;
  case "debug"_hash:
    return LOG_LEVEL_DEBUG;
  default:
    return LOG_LEVEL_INFO;
  }
}

const char *configuredLogLevelName(LogLevel level) {
  switch (level) {
  case LogLevel::Fatal:
    return "fatal";
  case LogLevel::Error:
    return "error";
  case LogLevel::Warning:
    return "warn";
  case LogLevel::Info:
    return "info";
  case LogLevel::Debug:
    return "debug";
  case LogLevel::Verbose:
    return "verbose";
  }
  return "info";
}

void applyConfiguredLogLevel(const std::string &value,
                             bool print_debug_info,
                             ScopedLogLevelOverride &log_level_scope) {
  global.printDbgInfo = print_debug_info;
  global.logLevel = configuredLogLevel(value, print_debug_info);
  log_level_scope.set(global.logLevel);
  writeLog(LOG_LEVEL_DEBUG,
           "LOG_LEVEL_CONFIGURED level=" +
               std::string(configuredLogLevelName(global.logLevel)) +
               " print_debug_info=" +
               std::string(print_debug_info ? "true" : "false") +
               " phase=pre-import");
}

} // namespace

const std::map<std::string, ruleset_type> RulesetTypes = {
    {"clash-domain:", RULESET_CLASH_DOMAIN},
    {"clash-ipcidr:", RULESET_CLASH_IPCIDR},
    {"clash-classic:", RULESET_CLASH_CLASSICAL},
    {"quanx:", RULESET_QUANX},
    {"surge:", RULESET_SURGE}};

static bool parseBoolSetting(const std::string &value) {
  std::string normalized = toLower(trimWhitespace(value, true, true));
  return normalized == "1" || normalized == "true" || normalized == "yes" ||
         normalized == "on";
}

static bool isRecognizedBoolSetting(const std::string &value) {
  std::string normalized = toLower(trimWhitespace(value, true, true));
  return normalized == "1" || normalized == "true" || normalized == "yes" ||
         normalized == "on" || normalized == "0" || normalized == "false" ||
         normalized == "no" || normalized == "off";
}

static int requireEnvironmentPort(const char *name, const std::string &value) {
  const std::string normalized = trimWhitespace(value, true, true);
  std::size_t consumed = 0;
  long long parsed = 0;
  try {
    parsed = std::stoll(normalized, &consumed, 10);
  } catch (const std::exception &) {
    throw std::invalid_argument(std::string(name) +
                                " must be an integer from 1 to 65535");
  }
  if (consumed != normalized.size() || parsed < 1 || parsed > 65535) {
    throw std::invalid_argument(std::string(name) +
                                " must be an integer from 1 to 65535");
  }
  return static_cast<int>(parsed);
}

static void finalizeBasicEnvironmentSettings() {
  std::string listen_address = getEnv("SUBCONVERTER_LISTEN_ADDRESS");
  if (!listen_address.empty()) {
    listen_address = trimWhitespace(listen_address, true, true);
    if (listen_address.empty())
      throw std::invalid_argument(
          "SUBCONVERTER_LISTEN_ADDRESS must not be blank");
    global.listenAddress = listen_address;
  }

  const std::string listen_port = getEnv("SUBCONVERTER_LISTEN_PORT");
  if (!listen_port.empty())
    global.listenPort =
        requireEnvironmentPort("SUBCONVERTER_LISTEN_PORT", listen_port);

  const std::string log_level = getEnv("SUBCONVERTER_LOG_LEVEL");
  if (!log_level.empty()) {
    const std::string normalized =
        toLower(trimWhitespace(log_level, true, true));
    if (normalized != "fatal" && normalized != "error" &&
        normalized != "warn" && normalized != "info" &&
        normalized != "debug" && normalized != "verbose") {
      throw std::invalid_argument(
          "SUBCONVERTER_LOG_LEVEL must be fatal, error, warn, info, debug, "
          "or verbose");
    }
    global.printDbgInfo = false;
    global.logLevel = configuredLogLevel(normalized, false);
  }

  const std::string statistics_enabled =
      getEnv("SUBCONVERTER_STATISTICS_ENABLED");
  if (!statistics_enabled.empty()) {
    if (!isRecognizedBoolSetting(statistics_enabled)) {
      throw std::invalid_argument(
          "SUBCONVERTER_STATISTICS_ENABLED must be a boolean value");
    }
    global.statisticsEnabled = parseBoolSetting(statistics_enabled);
  }
}

static std::string securityLogValue(const std::string &value) {
  static const char hex[] = "0123456789ABCDEF";
  std::string escaped;
  const size_t limit = std::min<size_t>(value.size(), 80);
  escaped.reserve(limit);
  for (size_t index = 0; index < limit; ++index) {
    const unsigned char ch = static_cast<unsigned char>(value[index]);
    if (ch < 0x20 || ch == 0x7f || ch == '\'' || ch == '\\') {
      escaped += "\\x";
      escaped += hex[ch >> 4];
      escaped += hex[ch & 0x0f];
    } else {
      escaped.push_back(static_cast<char>(ch));
    }
  }
  if (value.size() > limit)
    escaped += "...";
  return escaped;
}

static void beginSecuritySettingsLoad() {
  auto &diagnostics = global.securityDiagnostics;
  const bool first_load = global.configGeneration == 0;
  diagnostics.profileSource =
      first_load ? "builtin-default" : "reload-retained";
  diagnostics.profileFileSource.clear();
  diagnostics.profileInputValid = true;
  diagnostics.profileUsedCompatibilityFallback = false;
  diagnostics.uploadSource =
      first_load ? "builtin-default" : "reload-retained";
  diagnostics.uploadFileSource.clear();
  diagnostics.uploadInput.clear();
  diagnostics.uploadInputValid = true;
}

static int requireProxyProviderInterval(const std::string &value) {
  int interval = 0;
  if (!parseProxyProviderInterval(value, interval)) {
    throw std::invalid_argument(
        "proxy_provider.interval 必须是 0 到 2147483647 之间的十进制整数。");
  }
  return interval;
}

static int requireProxyProviderInterval(std::int64_t value) {
  return requireProxyProviderInterval(std::to_string(value));
}

static bool requireProxyProviderDirect(const std::string &value) {
  bool proxy_direct = false;
  if (!parseProxyProviderDirect(value, proxy_direct)) {
    throw std::invalid_argument(
        "proxy_provider.proxy_direct 必须是 true、false、1 或 0。");
  }
  return proxy_direct;
}

static bool pathInsideRoot(const std::string &path, const std::string &root) {
  return isPathInScope(path, root);
}

static void finalizeSecuritySettings() {
  std::string profile_override = getEnv("SUBCONVERTER_SECURITY_PROFILE");
  if (!profile_override.empty()) {
    global.securityProfile = profile_override;
    global.securityDiagnostics.profileSource = "environment";
  }

  std::string upload_override = getEnv("SUBCONVERTER_ALLOW_PUBLIC_UPLOAD");
  if (!upload_override.empty()) {
    global.allowPublicUpload = parseBoolSetting(upload_override);
    global.securityDiagnostics.uploadSource = "environment";
    global.securityDiagnostics.uploadInput = upload_override;
    global.securityDiagnostics.uploadInputValid =
        isRecognizedBoolSetting(upload_override);
  }

  global.securityProfile =
      toLower(trimWhitespace(global.securityProfile, true, true));
  if (global.securityProfile != "lan" && global.securityProfile != "public" &&
      global.securityProfile != "strict") {
    writeLog(LOG_LEVEL_WARNING,
             "security.profile 的值无效：'" + global.securityProfile +
                 "'，已回退为 lan。");
    global.securityDiagnostics.profileInputValid = false;
    global.securityDiagnostics.profileUsedCompatibilityFallback = true;
    writeLog(LOG_LEVEL_WARNING,
             "SECURITY_PROFILE_INVALID_FALLBACK source=" +
                 global.securityDiagnostics.profileSource + " input='" +
                 securityLogValue(global.securityProfile) +
                 "' effective=lan compatibility_fallback=true；该回退仅用于"
                 "兼容，不代表实例适合公网暴露。");
    global.securityProfile = "lan";
  }

  if (!global.securityDiagnostics.uploadInputValid) {
    writeLog(LOG_LEVEL_WARNING,
             "SECURITY_UPLOAD_VALUE_INVALID source=" +
                 global.securityDiagnostics.uploadSource + " input='" +
                 securityLogValue(global.securityDiagnostics.uploadInput) +
                 "' effective=" +
                 (global.allowPublicUpload ? "true" : "false") +
                 " compatibility_behavior=preserved。");
  }

  writeLog(LOG_LEVEL_INFO, "当前安全档位：" + global.securityProfile);
  writeLog(LOG_LEVEL_INFO,
           "SECURITY_PROFILE_EFFECTIVE profile=" + global.securityProfile +
               " source=" + global.securityDiagnostics.profileSource +
               (global.securityDiagnostics.profileSource != "environment" ||
                        global.securityDiagnostics.profileFileSource.empty()
                    ? ""
                    : " file_candidate=" +
                          global.securityDiagnostics.profileFileSource) +
               " input_valid=" +
               (global.securityDiagnostics.profileInputValid ? "true"
                                                               : "false") +
               " compatibility_fallback=" +
               (global.securityDiagnostics.profileUsedCompatibilityFallback
                    ? "true"
                    : "false"));
}

static void finalizePerformanceSettings() {
  std::string disable_coalescing = getEnv("SUBCONVERTER_DISABLE_COALESCING");
  if (!disable_coalescing.empty() && parseBoolSetting(disable_coalescing))
    global.enableRequestCoalescing = false;

  std::string retry_on_5xx = getEnv("SUBCONVERTER_COALESCE_RETRY_ON_5XX");
  if (!retry_on_5xx.empty())
    global.coalesceRetryOn5xx = parseBoolSetting(retry_on_5xx);

  std::string max_concurrent_threads =
      getEnv("SUBCONVERTER_MAX_CONCURRENT_THREADS");
  if (!max_concurrent_threads.empty())
    global.maxConcurThreads =
        to_int(max_concurrent_threads, global.maxConcurThreads);

  std::string max_server_threads =
      getEnv("SUBCONVERTER_MAX_SERVER_THREADS");
  if (!max_server_threads.empty())
    global.maxServerThreads =
        to_int(max_server_threads, global.maxServerThreads);

  std::string request_deadline_ms =
      getEnv("SUBCONVERTER_REQUEST_DEADLINE_MS");
  if (!request_deadline_ms.empty())
    global.requestDeadlineMs =
        to_int(request_deadline_ms, global.requestDeadlineMs);

  std::string resource_control =
      getEnv("SUBCONVERTER_RESOURCE_CONTROL");
  if (!resource_control.empty()) {
    global.resourceControl = resource_control;
    global.resourceControlSource = "environment";
  }

  std::string force_max_curve_fingerprint =
      getEnv("SUBCONVERTER_FORCE_MAX_CURVE_FINGERPRINT");
  if (!force_max_curve_fingerprint.empty())
    global.forceMaxCurveFingerprint =
        trimWhitespace(force_max_curve_fingerprint, true, true);

  std::string response_cache_ttl = getEnv("SUBCONVERTER_RESPONSE_CACHE_TTL");
  if (!response_cache_ttl.empty())
    global.responseCacheTtl = to_int(response_cache_ttl, global.responseCacheTtl);

  if (global.responseCacheTtl < 0)
    global.responseCacheTtl = 0;
  if (global.maxConcurThreads < 1)
    global.maxConcurThreads = 1;
  if (global.maxServerThreads < global.maxConcurThreads)
    global.maxServerThreads = global.maxConcurThreads;
  global.requestDeadlineMs =
      std::clamp(global.requestDeadlineMs, 100, 300000);
  configureResourceControl(global);
  if (global.responseCacheTtl > 5) {
    writeLog(LOG_LEVEL_WARNING,
             "response_cache_ttl 最大允许 5 秒，已自动收敛到 5。");
    global.responseCacheTtl = 5;
  }
}

static void finalizeDashboardAuthSettings() {
  std::string client_ip_header =
      getEnv("SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER");
  if (!client_ip_header.empty())
    global.dashboardAuthClientIpHeader = client_ip_header;
  std::string trusted_proxy_cidrs =
      getEnv("SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS");
  if (!trusted_proxy_cidrs.empty())
    global.dashboardAuthTrustedProxyCidrs = split(trusted_proxy_cidrs, ",");

  global.dashboardAuthClientIpHeader = client_ip::headerSettingName(
      client_ip::parseHeader(global.dashboardAuthClientIpHeader));
  for (std::string &cidr : global.dashboardAuthTrustedProxyCidrs)
    cidr = trimWhitespace(cidr, true, true);
  global.dashboardAuthTrustedProxyCidrs.erase(
      std::remove_if(global.dashboardAuthTrustedProxyCidrs.begin(),
                     global.dashboardAuthTrustedProxyCidrs.end(),
                     [](const std::string &value) { return value.empty(); }),
      global.dashboardAuthTrustedProxyCidrs.end());
  (void)client_ip::makePolicy(global.dashboardAuthClientIpHeader,
                              global.dashboardAuthTrustedProxyCidrs);
  const bool header_configured =
      client_ip::parseHeader(global.dashboardAuthClientIpHeader) !=
      client_ip::Header::None;
  if (header_configured != !global.dashboardAuthTrustedProxyCidrs.empty()) {
    writeLog(LOG_LEVEL_WARNING,
             "Dashboard 客户端 IP 头与 trusted proxy CIDR 必须同时配置；"
             "当前已安全降级为仅使用 socket peer。");
  }
  if (global.dashboardAuthMaxFailures < 1)
    global.dashboardAuthMaxFailures = 1;
  if (global.dashboardAuthWindowSeconds < 1)
    global.dashboardAuthWindowSeconds = 1;
  if (global.dashboardAuthLockSeconds < 1)
    global.dashboardAuthLockSeconds = 1;
}

static void finalizeRuntimeSettings() {
  if (global.proxyProviderInterval < 0) {
    throw std::invalid_argument(
        "proxy_provider.interval 必须是非负整数。");
  }
  finalizeBasicEnvironmentSettings();
  finalizeSecuritySettings();
  finalizePerformanceSettings();
  finalizeDashboardAuthSettings();
  global.configGeneration++;
}

bool isPublicFetchRestricted(FetchContext context) {
  const Settings &settings = effectiveSettings();
  return context == FetchContext::PublicRequest &&
         (settings.securityProfile == "public" ||
          settings.securityProfile == "strict");
}

bool isTrustedLocalResourcePath(const std::string &path) {
  const Settings &settings = effectiveSettings();
  return pathInsideRoot(path, settings.basePath) ||
         pathInsideRoot(path, settings.templatePath) ||
         pathInsideRoot(path, "Custom_OpenClash_Rules") ||
         pathInsideRoot(path, "base/Custom_OpenClash_Rules");
}

bool isPublicUploadAllowed() {
  const Settings &settings = effectiveSettings();
  if (settings.securityProfile == "lan")
    return true;
  if (settings.securityProfile == "strict")
    return false;
  return settings.allowPublicUpload;
}

void logSecurityPosture() {
  const bool upload_allowed = isPublicUploadAllowed();
  writeLog(LOG_LEVEL_INFO,
           "SECURITY_UPLOAD_EFFECTIVE profile=" + global.securityProfile +
               " configured_allow_public_upload=" +
               (global.allowPublicUpload ? "true" : "false") + " source=" +
               global.securityDiagnostics.uploadSource +
               (global.securityDiagnostics.uploadSource != "environment" ||
                        global.securityDiagnostics.uploadFileSource.empty()
                    ? ""
                    : " file_candidate=" +
                          global.securityDiagnostics.uploadFileSource) +
               " effective=" +
               (upload_allowed ? "allowed" : "blocked") +
               (global.securityProfile == "lan"
                    ? " reason=lan-compatibility"
                    : global.securityProfile == "strict"
                          ? " reason=strict-policy"
                          : " reason=public-upload-setting"));

  const bool wildcard_bind = global.listenAddress == "0.0.0.0" ||
                             global.listenAddress == "::" ||
                             global.listenAddress == "[::]";
  if (global.securityProfile == "lan" && wildcard_bind) {
    std::string bind_endpoint = global.listenAddress;
    if (bind_endpoint.find(':') != std::string::npos &&
        !startsWith(bind_endpoint, "[")) {
      bind_endpoint = "[" + bind_endpoint + "]";
    }
    writeLog(LOG_LEVEL_WARNING,
             "SECURITY_EXPOSURE_POSSIBLE profile=lan bind=" +
                 bind_endpoint + ":" +
                 std::to_string(global.listenPort) +
                 " public_reachability=unknown；监听所有本地接口不等于已暴露"
                 "公网，请同时检查端口发布、宿主防火墙、云安全组、NAT 和"
                 "反向代理。公网部署请显式使用 public 或 strict。");
  }
}

static bool canImportLocalPath(const std::string &path, FetchContext context) {
  if (!isPublicFetchRestricted(context) || isTrustedLocalResourcePath(path))
    return true;
  writeLog(LOG_LEVEL_WARNING, "已阻止公开请求导入本地文件：" + path);
  return false;
}

static bool readImportLocalPath(const std::string &path, bool scope_limit,
                                FetchContext context, std::string &content) {
  const bool trusted = isTrustedLocalResourcePath(path);
  const bool effective_scope_limit = scope_limit && !trusted;
  if (!fileExist(path, effective_scope_limit) ||
      !canImportLocalPath(path, context))
    return false;
  content = fileGet(path, effective_scope_limit);
  return true;
}

int importItems(string_array &target, bool scope_limit, FetchContext context) {
  string_array result;
  std::stringstream ss;
  std::string path, content, strLine;
  unsigned int itemCount = 0;
  for (std::string &x : target) {
    if (x.find("!!import:") == std::string::npos) {
      result.emplace_back(x);
      continue;
    }
    path = x.substr(x.find(":") + 1);
    writeLog(LOG_LEVEL_VERBOSE, "正在导入项目：" + path);
    content.clear();

    const Settings &settings = effectiveSettings();
    ProxyPolicy proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);

    if (readImportLocalPath(path, scope_limit, context, content)) {
      // Local content was loaded through the effective scoped/trusted policy.
    } else if (isLink(path))
      content = webGet(path, proxy, settings.cacheConfig, nullptr, nullptr,
                       context);
    else
      writeLog(LOG_LEVEL_ERROR, "文件不存在或不是有效 URL：" + path);
    if (content.empty())
      return -1;

    ss << content;
    char delimiter = getLineBreak(content);
    std::string::size_type lineSize;
    while (getline(ss, strLine, delimiter)) {
      lineSize = strLine.size();
      if (lineSize && strLine[lineSize - 1] == '\r') // remove line break
        strLine.erase(--lineSize);
      if (!lineSize || strLine[0] == ';' || strLine[0] == '#' ||
          (lineSize >= 2 && strLine[0] == '/' &&
           strLine[1] == '/')) // empty lines and comments are ignored
        continue;
      result.emplace_back(std::move(strLine));
      itemCount++;
    }
    ss.clear();
  }
  target.swap(result);
  writeLog(LOG_LEVEL_VERBOSE,
           "已导入 " + std::to_string(itemCount) + " 个项目。");
  return 0;
}

toml::value parseToml(const std::string &content, const std::string &fname) {
  std::istringstream is(content);
  return toml::parse(is, fname);
}

int importItems(std::vector<toml::value> &root, const std::string &import_key,
                bool scope_limit = true,
                FetchContext context = FetchContext::TrustedConfig) {
  std::string content;
  std::vector<toml::value> newRoot;
  auto iter = root.begin();
  size_t count = 0;
  bool failed = false;

  const Settings &settings = effectiveSettings();
  ProxyPolicy proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
  while (iter != root.end()) {
    auto &table = iter->as_table();
    if (table.find("import") == table.end())
      newRoot.emplace_back(std::move(*iter));
    else {
      const std::string &path = toml::get<std::string>(table.at("import"));
      writeLog(LOG_LEVEL_VERBOSE, "正在导入项目：" + path);
      content.clear();
      if (readImportLocalPath(path, scope_limit, context, content)) {
        // Local content was loaded through the effective scoped/trusted policy.
      } else if (isLink(path))
        content = webGet(path, proxy, settings.cacheConfig, nullptr, nullptr,
                         context);
      else
        writeLog(LOG_LEVEL_ERROR, "文件不存在或不是有效 URL：" + path);
      if (content.empty()) {
        failed = true;
      } else {
        try {
          auto items = parseToml(content, path);
          auto list = toml::find<std::vector<toml::value>>(items, import_key);
          count += list.size();
          std::move(list.begin(), list.end(), std::back_inserter(newRoot));
        } catch (const std::exception &e) {
          writeLog(LOG_LEVEL_ERROR, "导入项目失败：" + summarizeUrlForLog(path) +
                          "，detail=" + summarizeSensitiveTextForLog(e.what()));
          failed = true;
        }
      }
    }
    iter++;
  }
  root.swap(newRoot);
  writeLog(LOG_LEVEL_VERBOSE,
           "已导入 " + std::to_string(count) + " 个项目。");
  return failed ? -1 : 0;
}

int readRegexMatch(YAML::Node node, const std::string &delimiter,
                   string_array &dest, bool scope_limit = true,
                   FetchContext context = FetchContext::TrustedConfig) {
  for (auto &&object : node) {
    std::string script, url, match, rep, strLine;
    object["script"] >>= script;
    if (!script.empty()) {
      dest.emplace_back("!!script:" + script);
      continue;
    }
    object["import"] >>= url;
    if (!url.empty()) {
      dest.emplace_back("!!import:" + url);
      continue;
    }
    object["match"] >>= match;
    object["replace"] >>= rep;
    if (!match.empty() && !rep.empty())
      strLine = match + delimiter + rep;
    else
      continue;
    dest.emplace_back(std::move(strLine));
  }
  return importItems(dest, scope_limit, context);
}

int readEmoji(YAML::Node node, string_array &dest, bool scope_limit = true,
              FetchContext context = FetchContext::TrustedConfig) {
  for (auto &&object : node) {
    std::string script, url, match, rep, strLine;
    object["script"] >>= script;
    if (!script.empty()) {
      dest.emplace_back("!!script:" + script);
      continue;
    }
    object["import"] >>= url;
    if (!url.empty()) {
      url = "!!import:" + url;
      dest.emplace_back(url);
      continue;
    }
    object["match"] >>= match;
    object["emoji"] >>= rep;
    if (!match.empty() && !rep.empty())
      strLine = match + "," + rep;
    else
      continue;
    dest.emplace_back(std::move(strLine));
  }
  return importItems(dest, scope_limit, context);
}

int readGroup(YAML::Node node, string_array &dest, bool scope_limit = true,
              FetchContext context = FetchContext::TrustedConfig) {
  for (YAML::Node &&object : node) {
    string_array tempArray;
    std::string name, type;
    object["import"] >>= name;
    if (!name.empty()) {
      dest.emplace_back("!!import:" + name);
      continue;
    }
    std::string url = "http://www.gstatic.com/generate_204", interval = "300",
                tolerance, timeout;
    object["name"] >>= name;
    object["type"] >>= type;
    tempArray.emplace_back(name);
    tempArray.emplace_back(type);
    object["url"] >>= url;
    object["interval"] >>= interval;
    object["tolerance"] >>= tolerance;
    object["timeout"] >>= timeout;
    for (std::size_t j = 0; j < object["rule"].size(); j++)
      tempArray.emplace_back(safe_as<std::string>(object["rule"][j]));
    switch (hash_(type)) {
    case "select"_hash:
      if (tempArray.size() < 3)
        continue;
      break;
    case "ssid"_hash:
      if (tempArray.size() < 4)
        continue;
      break;
    default:
      if (tempArray.size() < 3)
        continue;
      tempArray.emplace_back(url);
      tempArray.emplace_back(interval + "," + timeout + "," + tolerance);
    }

    std::string strLine = join(tempArray, "`");
    dest.emplace_back(std::move(strLine));
  }
  return importItems(dest, scope_limit, context);
}

int readRuleset(YAML::Node node, string_array &dest, bool scope_limit = true,
                FetchContext context = FetchContext::TrustedConfig) {
  for (auto &&object : node) {
    std::string strLine, name, url, group, interval;
    string_array options;
    object["import"] >>= name;
    if (!name.empty()) {
      dest.emplace_back("!!import:" + name);
      continue;
    }
    object["ruleset"] >>= url;
    object["group"] >>= group;
    object["rule"] >>= name;
    object["interval"] >>= interval;
    if (object["options"].IsSequence())
      object["options"] >> options;
    if (!url.empty()) {
      strLine = group + "," + url;
      if (!options.empty() && interval.empty())
        interval = "86400";
      if (!interval.empty())
        strLine += "," + interval;
      if (!options.empty())
        strLine += "|" + join(options, "|");
    } else if (!name.empty())
      strLine = group + ",[]" + name;
    else
      continue;
    dest.emplace_back(std::move(strLine));
  }
  return importItems(dest, scope_limit, context);
}

void refreshRulesets(RulesetConfigs &ruleset_list,
                     std::vector<RulesetContent> &ruleset_content_array,
                     FetchContext context, RulesetRefreshMode mode,
                     const std::vector<RulesetContent> *reusable_content) {
  RequestStageTimer rules_timer(RequestStage::Rules);
  ruleset_content_array.clear();
  ruleset_content_array.reserve(ruleset_list.size());
  std::string rule_group, rule_url, rule_url_typed, interval;
  RulesetContent rc;

  const Settings &settings = effectiveSettings();
  ProxyPolicy proxy = parseProxy(settings.proxyRuleset, settings.proxyBypass);

  size_t source_index = 0;
  for (RulesetConfig &x : ruleset_list) {
    rule_group = x.Group;
    rule_url = x.Url;
    std::string::size_type pos = x.Url.find("[]");
    if (pos != std::string::npos) {
      writeLog(LOG_LEVEL_INFO,
               "正在添加规则：'" + rule_url.substr(pos + 2) + "," +
                   rule_group + "'。");
      if (reusable_content &&
          reusable_content->size() == ruleset_list.size())
        rc = (*reusable_content)[source_index];
      else
        rc = {rule_group,
              "",
              "",
              RULESET_SURGE,
              makeReadyStringFuture(rule_url.substr(pos)),
              0,
              x.Options};
    } else {
      ruleset_type type = RULESET_SURGE;
      rule_url_typed = rule_url;
      auto iter = std::find_if(
          RulesetTypes.begin(), RulesetTypes.end(),
          [rule_url](auto y) { return startsWith(rule_url, y.first); });
      if (iter != RulesetTypes.end()) {
        rule_url.erase(0, iter->first.size());
        type = iter->second;
      }
      if (x.Options.no_resolve && type != RULESET_CLASH_IPCIDR)
        writeLog(LOG_LEVEL_WARNING,
                 "规则集选项 no-resolve 仅适用于 clash-ipcidr，已对策略组 '" +
                     rule_group + "' 安全忽略。");

      writeLog(LOG_LEVEL_INFO,
               "正在更新规则集 URL：'" + summarizeUrlForLog(rule_url) +
                   "'，策略组：'" +
                   rule_group + "'。");
      std::string native_rule_path = toLower(rule_url);
      const size_t native_rule_query = native_rule_path.find_first_of("?#");
      if (native_rule_query != std::string::npos)
        native_rule_path.erase(native_rule_query);
      const bool native_stash_provider =
          mode == RulesetRefreshMode::PreferNativeStashProviders &&
          (startsWith(rule_url, "https://") || startsWith(rule_url, "http://")) &&
          (type == RULESET_CLASH_DOMAIN || type == RULESET_CLASH_IPCIDR ||
           type == RULESET_CLASH_CLASSICAL) &&
          (!x.Options.stash_format.empty() ||
           endsWith(native_rule_path, ".mrs") ||
           endsWith(native_rule_path, ".yaml") ||
           endsWith(native_rule_path, ".yml"));
      if (!native_stash_provider && reusable_content &&
          reusable_content->size() == ruleset_list.size())
        rc = (*reusable_content)[source_index];
      else
        rc = {rule_group,
              rule_url,
              rule_url_typed,
              type,
              native_stash_provider
                  ? makeReadyStringFuture("")
                  : fetchFileAsync(rule_url, proxy, settings.cacheRuleset, true,
                                   settings.asyncFetchRuleset, context),
              x.Interval,
              x.Options,
              native_stash_provider ? RulesetDelivery::NativeStashProvider
                                    : RulesetDelivery::ServerFetched};
    }
    ruleset_content_array.emplace_back(std::move(rc));
    ++source_index;
  }
}

void readYAMLConf(YAML::Node &node,
                  ScopedLogLevelOverride &log_level_scope) {
  std::string early_log_level;
  bool early_print_debug_info = false;
  if (node["advanced"].IsDefined()) {
    node["advanced"]["log_level"] >> early_log_level;
    node["advanced"]["print_debug_info"] >> early_print_debug_info;
  }
  applyConfiguredLogLevel(early_log_level, early_print_debug_info,
                          log_level_scope);

  YAML::Node section = node["common"];
  std::string strLine;
  string_array tempArray;
  CommonScalarSettings common = captureCommonScalarSettings();

  // api_mode and api_access_token removed - hardcoded in settings.h
  if (section["default_url"].IsSequence()) {
    section["default_url"] >> tempArray;
    if (tempArray.size()) {
      strLine = std::accumulate(std::next(tempArray.begin()), tempArray.end(),
                                tempArray[0], [](std::string a, std::string b) {
                                  return std::move(a) + "|" + std::move(b);
                                });
      global.defaultUrls = strLine;
      eraseElements(tempArray);
    }
  }
  global.enableInsert = safe_as<std::string>(section["enable_insert"]);
  if (section["insert_url"].IsSequence()) {
    section["insert_url"] >> tempArray;
    if (tempArray.size()) {
      strLine = std::accumulate(std::next(tempArray.begin()), tempArray.end(),
                                tempArray[0], [](std::string a, std::string b) {
                                  return std::move(a) + "|" + std::move(b);
                                });
      global.insertUrls = strLine;
      eraseElements(tempArray);
    }
  }
  section["prepend_insert_url"] >> common.prependInsert;
  if (section["exclude_remarks"].IsSequence())
    section["exclude_remarks"] >> global.excludeRemarks;
  if (section["include_remarks"].IsSequence())
    section["include_remarks"] >> global.includeRemarks;
  global.filterScript = safe_as<bool>(section["enable_filter"])
                            ? safe_as<std::string>(section["filter_script"])
                            : "";
  section["base_path"] >> common.basePath;
  section["clash_rule_base"] >> common.clashBase;
  section["surge_rule_base"] >> common.surgeBase;
  section["surfboard_rule_base"] >> common.surfboardBase;
  section["mellow_rule_base"] >> common.mellowBase;
  section["quan_rule_base"] >> common.quanBase;
  section["quanx_rule_base"] >> common.quanXBase;
  section["loon_rule_base"] >> common.loonBase;
  section["sssub_rule_base"] >> common.SSSubBase;
  section["singbox_rule_base"] >> common.singBoxBase;
  section["stash_rule_base"] >> common.stashBase;

  section["default_external_config"] >> common.defaultExtConfig;
  section["fallback_to_default_external_config"] >>
      common.fallbackToDefaultExternalConfig;
  section["append_proxy_type"] >> common.appendType;
  section["proxy_config"] >> common.proxyConfig;
  section["proxy_ruleset"] >> common.proxyRuleset;
  section["proxy_subscription"] >> common.proxySubscription;
  section["proxy_bypass"] >> common.proxyBypass;
  section["reload_conf_on_request"] >> common.reloadConfOnRequest;
  applyCommonScalarSettings(std::move(common));

  YAML::Node proxy_provider = node["proxy_provider"];
  if (proxy_provider.IsDefined() && !proxy_provider.IsNull()) {
    if (!proxy_provider.IsMap()) {
      throw std::invalid_argument("proxy_provider 必须是配置映射。");
    }
    YAML::Node interval = proxy_provider["interval"];
    if (interval.IsDefined()) {
      if (!interval.IsScalar()) {
        throw std::invalid_argument(
            "proxy_provider.interval 必须是十进制整数。");
      }
      global.proxyProviderInterval =
          requireProxyProviderInterval(interval.as<std::string>());
    }
    YAML::Node proxy_direct = proxy_provider["proxy_direct"];
    if (proxy_direct.IsDefined()) {
      if (!proxy_direct.IsScalar()) {
        throw std::invalid_argument(
            "proxy_provider.proxy_direct 必须是布尔值。");
      }
      global.proxyProviderDirect =
          requireProxyProviderDirect(proxy_direct.as<std::string>());
    }
  }

  if (node["custom_openclash_rules"].IsDefined()) {
    section = node["custom_openclash_rules"];
    section["fallback_enabled"] >>
        global.customOpenClashRulesSourceSwitch;
  }

  if (node["userinfo"].IsDefined()) {
    section = node["userinfo"];
    if (section["stream_rule"].IsSequence()) {
      readRegexMatch(section["stream_rule"], "|", tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "|");
      safe_set_streams(configs);
      eraseElements(tempArray);
    }
    if (section["time_rule"].IsSequence()) {
      readRegexMatch(section["time_rule"], "|", tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "|");
      safe_set_times(configs);
      eraseElements(tempArray);
    }
  }

  if (node["node_pref"].IsDefined()) {
    section = node["node_pref"];
    /*
    section["udp_flag"] >> udp_flag;
    section["tcp_fast_open_flag"] >> tfo_flag;
    section["skip_cert_verify_flag"] >> scv_flag;
    */
    global.UDPFlag.set(safe_as<std::string>(section["udp_flag"]));
    global.TFOFlag.set(safe_as<std::string>(section["tcp_fast_open_flag"]));
    global.skipCertVerify.set(
        safe_as<std::string>(section["skip_cert_verify_flag"]));
    global.TLS13Flag.set(safe_as<std::string>(section["tls13_flag"]));
    section["sort_flag"] >> global.enableSort;
    section["sort_script"] >> global.sortScript;
    section["filter_deprecated_nodes"] >> global.filterDeprecated;
    section["append_sub_userinfo"] >> global.appendUserinfo;
    section["clash_use_new_field_name"] >> global.clashUseNewField;
    section["clash_proxies_style"] >> global.clashProxiesStyle;
    section["singbox_add_clash_modes"] >> global.singBoxAddClashModes;
  }

  if (section["rename_node"].IsSequence()) {
    readRegexMatch(section["rename_node"], "@", tempArray, false);
    auto configs = INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "@");
    safe_set_renames(configs);
    eraseElements(tempArray);
  }

  if (node["managed_config"].IsDefined()) {
    section = node["managed_config"];
    section["write_managed_config"] >> global.writeManagedConfig;
    section["managed_config_prefix"] >> global.managedConfigPrefix;
    section["config_update_interval"] >> global.updateInterval;
    section["config_update_strict"] >> global.updateStrict;
    section["quanx_device_id"] >> global.quanXDevID;
  }

  if (node["surge_external_proxy"].IsDefined()) {
    node["surge_external_proxy"]["surge_ssr_path"] >> global.surgeSSRPath;
    node["surge_external_proxy"]["resolve_hostname"] >>
        global.surgeResolveHostname;
  }

  if (node["remote_subscription"].IsDefined() &&
      node["remote_subscription"].IsMap()) {
    node["remote_subscription"]["surge_policy_path"] >>
        global.surgePolicyPath;
    node["remote_subscription"]["surfboard_policy_path"] >>
        global.surfboardPolicyPath;
    node["remote_subscription"]["loon_remote_proxy"] >>
        global.loonRemoteProxy;
  }

  if (node["singbox"].IsDefined() && node["singbox"].IsMap()) {
    node["singbox"]["wireguard_endpoint"] >>
        global.singBoxWireGuardEndpoint;
    node["singbox"]["snell_outbound"] >> global.singBoxSnellOutbound;
  }

  if (node["emojis"].IsDefined()) {
    section = node["emojis"];
    section["add_emoji"] >> global.addEmoji;
    section["remove_old_emoji"] >> global.removeEmoji;
    if (section["rules"].IsSequence()) {
      readEmoji(section["rules"], tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, ",");
      safe_set_emojis(configs);
      eraseElements(tempArray);
    }
  }

  const char *rulesets_title =
      node["rulesets"].IsDefined() ? "rulesets" : "ruleset";
  if (node[rulesets_title].IsDefined()) {
    section = node[rulesets_title];
    section["enabled"] >> global.enableRuleGen;
    if (!global.enableRuleGen) {
      global.overwriteOriginalRules = false;
      global.updateRulesetOnRequest = false;
    } else {
      section["overwrite_original_rules"] >> global.overwriteOriginalRules;
      section["update_ruleset_on_request"] >> global.updateRulesetOnRequest;
    }
    const char *ruleset_title =
        section["rulesets"].IsDefined() ? "rulesets" : "surge_ruleset";
    if (section[ruleset_title].IsSequence()) {
      string_array vArray;
      readRuleset(section[ruleset_title], vArray, false);
      global.customRulesets = INIBinding::from<RulesetConfig>::from_ini(vArray);
    }
  }

  const char *groups_title =
      node["proxy_groups"].IsDefined() ? "proxy_groups" : "proxy_group";
  if (node[groups_title].IsDefined() &&
      node[groups_title]["custom_proxy_group"].IsDefined()) {
    string_array vArray;
    readGroup(node[groups_title]["custom_proxy_group"], vArray, false);
    global.customProxyGroups =
        INIBinding::from<ProxyGroupConfig>::from_ini(vArray);
  }

  if (node["template"].IsDefined()) {
    node["template"]["template_path"] >> global.templatePath;
    if (node["template"]["globals"].IsSequence()) {
      eraseElements(global.templateVars);
      for (size_t i = 0; i < node["template"]["globals"].size(); i++) {
        std::string key, value;
        node["template"]["globals"][i]["key"] >> key;
        node["template"]["globals"][i]["value"] >> value;
        global.templateVars[key] = value;
      }
    }
  }

  if (node["aliases"].IsSequence()) {
    eraseElements(global.aliases);
    for (size_t i = 0; i < node["aliases"].size(); i++) {
      std::string uri, target;
      node["aliases"][i]["uri"] >> uri;
      node["aliases"][i]["target"] >> target;
      global.aliases[uri] = target;
    }
  }

  if (node["tasks"].IsSequence()) {
    string_array vArray;
    for (size_t i = 0; i < node["tasks"].size(); i++) {
      std::string name, exp, path, timeout;
      node["tasks"][i]["import"] >> name;
      if (name.size()) {
        vArray.emplace_back("!!import:" + name);
        continue;
      }
      node["tasks"][i]["name"] >> name;
      node["tasks"][i]["cronexp"] >> exp;
      node["tasks"][i]["path"] >> path;
      node["tasks"][i]["timeout"] >> timeout;
      strLine = name + "`" + exp + "`" + path + "`" + timeout;
      vArray.emplace_back(std::move(strLine));
    }
    importItems(vArray, false);
    global.enableCron = !vArray.empty();
    global.cronTasks = INIBinding::from<CronTaskConfig>::from_ini(vArray);
  }

  if (node["server"].IsDefined()) {
    node["server"]["listen"] >> global.listenAddress;
    node["server"]["port"] >> global.listenPort;
    node["server"]["serve_file_root"] >>= global.serveFileRoot;
  }

  if (node["advanced"].IsDefined()) {
    if (node["advanced"]["resource_control"].IsDefined()) {
      node["advanced"]["resource_control"] >> global.resourceControl;
      global.resourceControlSource = "file:yaml";
    }
    node["advanced"]["force_max_curve_fingerprint"] >>
        global.forceMaxCurveFingerprint;
    node["advanced"]["max_pending_connections"] >> global.maxPendingConns;
    node["advanced"]["max_concurrent_threads"] >> global.maxConcurThreads;
    node["advanced"]["max_server_threads"] >> global.maxServerThreads;
    node["advanced"]["request_deadline_ms"] >> global.requestDeadlineMs;
    node["advanced"]["max_allowed_rulesets"] >> global.maxAllowedRulesets;
    node["advanced"]["max_allowed_rules"] >> global.maxAllowedRules;
    node["advanced"]["max_allowed_download_size"] >>
        global.maxAllowedDownloadSize;
    if (node["advanced"]["enable_cache"].IsDefined()) {
      if (safe_as<bool>(node["advanced"]["enable_cache"])) {
        node["advanced"]["cache_subscription"] >> global.cacheSubscription;
        node["advanced"]["cache_config"] >> global.cacheConfig;
        node["advanced"]["cache_ruleset"] >> global.cacheRuleset;
        node["advanced"]["serve_cache_on_fetch_fail"] >>
            global.serveCacheOnFetchFail;
      } else
        global.cacheSubscription = global.cacheConfig = global.cacheRuleset =
            0; // disable cache
    }
    node["advanced"]["script_clean_context"] >> global.scriptCleanContext;
    node["advanced"]["async_fetch_ruleset"] >> global.asyncFetchRuleset;
    node["advanced"]["skip_failed_links"] >> global.skipFailedLinks;
    node["advanced"]["enable_request_coalescing"] >>
        global.enableRequestCoalescing;
    node["advanced"]["coalesce_retry_on_5xx"] >> global.coalesceRetryOn5xx;
    node["advanced"]["allow_insecure_tls"] >> global.allowInsecureTls;
    node["advanced"]["response_cache_ttl"] >> global.responseCacheTtl;
  }
  if (node["statistics"].IsDefined()) {
    YAML::Node stats = node["statistics"];
    stats["enabled"] >> global.statisticsEnabled;
    stats["data_dir"] >> global.statisticsDataDir;
    stats["flush_interval"] >> global.statisticsFlushInterval;
    if (stats["geo"].IsDefined()) {
      stats["geo"]["provider"] >> global.statisticsGeoProvider;
      if (stats["geo"]["country_headers"].IsSequence()) {
        string_array country_headers;
        stats["geo"]["country_headers"] >> country_headers;
        if (!country_headers.empty())
          global.statisticsCountryHeaders = country_headers;
      }
      if (stats["geo"]["china_region_headers"].IsSequence()) {
        string_array region_headers;
        stats["geo"]["china_region_headers"] >> region_headers;
        if (!region_headers.empty())
          global.statisticsChinaRegionHeaders = region_headers;
      }
    }
    if (stats["dashboard_auth"].IsDefined()) {
      YAML::Node auth = stats["dashboard_auth"];
      auth["enabled"] >> global.dashboardAuthEnabled;
      auth["username"] >> global.dashboardAuthUsername;
      auth["password"] >> global.dashboardAuthPassword;
      auth["max_failures"] >> global.dashboardAuthMaxFailures;
      auth["window_seconds"] >> global.dashboardAuthWindowSeconds;
      auth["lock_seconds"] >> global.dashboardAuthLockSeconds;
      if (auth["client_ip"].IsDefined()) {
        YAML::Node client_ip = auth["client_ip"];
        client_ip["header"] >> global.dashboardAuthClientIpHeader;
        if (client_ip["trusted_proxy_cidrs"].IsSequence())
          client_ip["trusted_proxy_cidrs"] >>
              global.dashboardAuthTrustedProxyCidrs;
      }
    }
  }
  if (node["security"].IsDefined()) {
    if (node["security"]["profile"].IsDefined()) {
      global.securityDiagnostics.profileSource = "file:yaml";
      global.securityDiagnostics.profileFileSource = "file:yaml";
      node["security"]["profile"] >> global.securityProfile;
    }
    if (node["security"]["allow_public_upload"].IsDefined()) {
      global.securityDiagnostics.uploadSource = "file:yaml";
      global.securityDiagnostics.uploadFileSource = "file:yaml";
      node["security"]["allow_public_upload"] >> global.allowPublicUpload;
    }
  }
  finalizeRuntimeSettings();
  writeLog(LOG_LEVEL_INFO, "已加载 YAML 格式偏好设置。");
}

template <class T, class... U>
void find_if_exist(const toml::value &v, const toml::value::key_type &k,
                   T &target, U &&...args) {
  if (v.contains(k))
    target = toml::find<T>(v, k);
  if constexpr (sizeof...(args) > 0)
    find_if_exist(v, std::forward<U>(args)...);
}

void operate_toml_kv_table(
    const std::vector<toml::table> &arr, const toml::value::key_type &key_name,
    const toml::value::key_type &value_name,
    std::function<void(const toml::value &, const toml::value &)> binary_op) {
  for (const toml::table &table : arr) {
    const auto &key = table.at(key_name), &value = table.at(value_name);
    binary_op(key, value);
  }
}

void readTOMLConf(toml::value &root,
                  ScopedLogLevelOverride &log_level_scope) {
  auto section_common = toml::find(root, "common");
  auto section_advanced = toml::find(root, "advanced");
  applyConfiguredLogLevel(
      toml::find_or<std::string>(section_advanced, "log_level", ""),
      toml::find_or<bool>(section_advanced, "print_debug_info", false),
      log_level_scope);
  string_array default_url, insert_url;
  CommonScalarSettings common = captureCommonScalarSettings();

  find_if_exist(section_common, "default_url", default_url, "insert_url",
                insert_url);
  global.defaultUrls = join(default_url, "|");
  global.insertUrls = join(insert_url, "|");

  bool filter = false;
  // api_mode and api_access_token removed - hardcoded in settings.h
  find_if_exist(
      section_common, "exclude_remarks", global.excludeRemarks,
      "include_remarks", global.includeRemarks, "enable_insert",
      global.enableInsert, "prepend_insert_url", common.prependInsert,
      "enable_filter", filter, "default_external_config",
      common.defaultExtConfig, "fallback_to_default_external_config",
      common.fallbackToDefaultExternalConfig, "base_path", common.basePath,
      "clash_rule_base",
      common.clashBase, "surge_rule_base", common.surgeBase,
      "surfboard_rule_base", common.surfboardBase, "mellow_rule_base",
      common.mellowBase, "quan_rule_base", common.quanBase, "quanx_rule_base",
      common.quanXBase, "loon_rule_base", common.loonBase, "sssub_rule_base",
      common.SSSubBase, "singbox_rule_base", common.singBoxBase,
      "stash_rule_base", common.stashBase, "proxy_config", common.proxyConfig,
      "proxy_ruleset", common.proxyRuleset,
      "proxy_subscription", common.proxySubscription, "proxy_bypass",
      common.proxyBypass, "append_proxy_type",
      common.appendType, "reload_conf_on_request", common.reloadConfOnRequest);
  applyCommonScalarSettings(std::move(common));

  if (root.contains("proxy_provider")) {
    const auto &section_proxy_provider =
        root.as_table().at("proxy_provider");
    if (!section_proxy_provider.is_table()) {
      throw std::invalid_argument("proxy_provider 必须是 TOML 表。");
    }
    if (section_proxy_provider.contains("interval")) {
      const auto &interval =
          section_proxy_provider.as_table().at("interval");
      if (!interval.is_integer()) {
        throw std::invalid_argument(
            "proxy_provider.interval 必须是 TOML 整数。");
      }
      global.proxyProviderInterval =
          requireProxyProviderInterval(interval.as_integer());
    }
    if (section_proxy_provider.contains("proxy_direct")) {
      const auto &proxy_direct =
          section_proxy_provider.as_table().at("proxy_direct");
      if (!proxy_direct.is_boolean()) {
        throw std::invalid_argument(
            "proxy_provider.proxy_direct 必须是 TOML 布尔值。");
      }
      global.proxyProviderDirect = proxy_direct.as_boolean();
    }
  }

  if (filter)
    find_if_exist(section_common, "filter_script", global.filterScript);
  else
    global.filterScript.clear();

  auto section_custom_openclash =
      toml::find_or(root, "custom_openclash_rules",
                    toml::value(toml::table()));
  find_if_exist(section_custom_openclash, "fallback_enabled",
                global.customOpenClashRulesSourceSwitch);

  safe_set_streams(toml::find_or<RegexMatchConfigs>(
      root, "userinfo", "stream_rule", RegexMatchConfigs{}));
  safe_set_times(toml::find_or<RegexMatchConfigs>(root, "userinfo", "time_rule",
                                                  RegexMatchConfigs{}));

  auto section_node_pref = toml::find(root, "node_pref");

  find_if_exist(
      section_node_pref, "udp_flag", global.UDPFlag, "tcp_fast_open_flag",
      global.TFOFlag, "skip_cert_verify_flag", global.skipCertVerify,
      "tls13_flag", global.TLS13Flag, "sort_flag", global.enableSort,
      "sort_script", global.sortScript, "filter_deprecated_nodes",
      global.filterDeprecated, "append_sub_userinfo", global.appendUserinfo,
      "clash_use_new_field_name", global.clashUseNewField,
      "clash_proxies_style", global.clashProxiesStyle,
      "singbox_add_clash_modes", global.singBoxAddClashModes);

  auto renameconfs = toml::find_or<std::vector<toml::value>>(section_node_pref,
                                                             "rename_node", {});
  importItems(renameconfs, "rename_node", false);
  safe_set_renames(toml::get<RegexMatchConfigs>(toml::value(renameconfs)));

  auto section_managed = toml::find(root, "managed_config");

  find_if_exist(section_managed, "write_managed_config",
                global.writeManagedConfig, "managed_config_prefix",
                global.managedConfigPrefix, "config_update_interval",
                global.updateInterval, "config_update_strict",
                global.updateStrict, "quanx_device_id", global.quanXDevID);

  auto section_surge_external = toml::find(root, "surge_external_proxy");
  find_if_exist(section_surge_external, "surge_ssr_path", global.surgeSSRPath,
                "resolve_hostname", global.surgeResolveHostname);

  if (root.contains("remote_subscription")) {
    const auto &section_remote_subscription =
        root.as_table().at("remote_subscription");
    if (section_remote_subscription.is_table()) {
      find_if_exist(section_remote_subscription, "surge_policy_path",
                    global.surgePolicyPath, "surfboard_policy_path",
                    global.surfboardPolicyPath, "loon_remote_proxy",
                    global.loonRemoteProxy);
    }
  }

  if (root.contains("singbox")) {
    const auto &section_singbox = root.as_table().at("singbox");
    if (section_singbox.is_table()) {
      find_if_exist(section_singbox, "wireguard_endpoint",
                    global.singBoxWireGuardEndpoint, "snell_outbound",
                    global.singBoxSnellOutbound);
    }
  }

  auto section_emojis = toml::find(root, "emojis");

  find_if_exist(section_emojis, "add_emoji", global.addEmoji,
                "remove_old_emoji", global.removeEmoji);

  auto emojiconfs =
      toml::find_or<std::vector<toml::value>>(section_emojis, "emoji", {});
  importItems(emojiconfs, "emoji", false);
  safe_set_emojis(toml::get<RegexMatchConfigs>(toml::value(emojiconfs)));

  auto groups =
      toml::find_or<std::vector<toml::value>>(root, "custom_groups", {});
  importItems(groups, "custom_groups", false);
  global.customProxyGroups = toml::get<ProxyGroupConfigs>(toml::value(groups));

  auto section_ruleset = toml::find(root, "ruleset");

  find_if_exist(section_ruleset, "enabled", global.enableRuleGen,
                "overwrite_original_rules", global.overwriteOriginalRules,
                "update_ruleset_on_request", global.updateRulesetOnRequest);

  auto rulesets = toml::find_or<std::vector<toml::value>>(root, "rulesets", {});
  importItems(rulesets, "rulesets", false);
  global.customRulesets = toml::get<RulesetConfigs>(toml::value(rulesets));

  auto section_template = toml::find(root, "template");

  global.templatePath =
      toml::find_or(section_template, "template_path", "template");

  eraseElements(global.templateVars);
  operate_toml_kv_table(
      toml::find_or<std::vector<toml::table>>(section_template, "globals", {}),
      "key", "value", [&](const toml::value &key, const toml::value &value) {
        global.templateVars[key.as_string()] = value.as_string();
      });

  eraseElements(global.aliases);
  operate_toml_kv_table(
      toml::find_or<std::vector<toml::table>>(root, "aliases", {}), "uri",
      "target", [&](const toml::value &key, const toml::value &value) {
        global.aliases[key.as_string()] = value.as_string();
      });

  auto tasks = toml::find_or<std::vector<toml::value>>(root, "tasks", {});
  importItems(tasks, "tasks", false);
  global.cronTasks = toml::get<CronTaskConfigs>(toml::value(tasks));
  global.enableCron = !global.cronTasks.empty();

  auto section_server = toml::find(root, "server");

  find_if_exist(section_server, "listen", global.listenAddress, "port",
                global.listenPort, "serve_file_root",
                global.serveFileRoot);

  bool enable_cache = true;
  int cache_subscription = global.cacheSubscription,
      cache_config = global.cacheConfig, cache_ruleset = global.cacheRuleset;

  if (section_advanced.contains("resource_control")) {
    global.resourceControl =
        toml::find<std::string>(section_advanced, "resource_control");
    global.resourceControlSource = "file:toml";
  }

  if (section_advanced.contains("force_max_curve_fingerprint"))
    global.forceMaxCurveFingerprint = toml::find<std::string>(
        section_advanced, "force_max_curve_fingerprint");

  find_if_exist(
      section_advanced, "max_pending_connections", global.maxPendingConns,
      "max_concurrent_threads", global.maxConcurThreads,
      "max_server_threads", global.maxServerThreads, "request_deadline_ms",
      global.requestDeadlineMs, "max_allowed_rulesets",
      global.maxAllowedRulesets, "max_allowed_rules", global.maxAllowedRules,
      "max_allowed_download_size", global.maxAllowedDownloadSize,
      "enable_cache", enable_cache, "cache_subscription", cache_subscription,
      "cache_config", cache_config, "cache_ruleset", cache_ruleset,
      "script_clean_context", global.scriptCleanContext, "async_fetch_ruleset",
      global.asyncFetchRuleset, "skip_failed_links", global.skipFailedLinks,
      "enable_request_coalescing", global.enableRequestCoalescing,
      "coalesce_retry_on_5xx", global.coalesceRetryOn5xx,
      "allow_insecure_tls", global.allowInsecureTls,
      "response_cache_ttl", global.responseCacheTtl);

  if (enable_cache) {
    global.cacheSubscription = cache_subscription;
    global.cacheConfig = cache_config;
    global.cacheRuleset = cache_ruleset;
  } else {
    global.cacheSubscription = global.cacheConfig = global.cacheRuleset = 0;
  }

  auto section_statistics =
      toml::find_or(root, "statistics", toml::value(toml::table()));
  find_if_exist(section_statistics, "enabled", global.statisticsEnabled,
                "data_dir", global.statisticsDataDir, "flush_interval",
                global.statisticsFlushInterval);
  auto section_statistics_geo =
      toml::find_or(section_statistics, "geo", toml::value(toml::table()));
  find_if_exist(section_statistics_geo, "provider",
                global.statisticsGeoProvider);
  string_array country_headers = toml::find_or<string_array>(
      section_statistics_geo, "country_headers", string_array{});
  if (!country_headers.empty())
    global.statisticsCountryHeaders = country_headers;
  string_array region_headers = toml::find_or<string_array>(
      section_statistics_geo, "china_region_headers", string_array{});
  if (!region_headers.empty())
    global.statisticsChinaRegionHeaders = region_headers;
  auto section_dashboard_auth =
      toml::find_or(section_statistics, "dashboard_auth",
                    toml::value(toml::table()));
  find_if_exist(section_dashboard_auth, "enabled",
                global.dashboardAuthEnabled, "username",
                global.dashboardAuthUsername, "password",
                global.dashboardAuthPassword, "max_failures",
                global.dashboardAuthMaxFailures, "window_seconds",
                global.dashboardAuthWindowSeconds, "lock_seconds",
                global.dashboardAuthLockSeconds);
  auto section_dashboard_client_ip =
      toml::find_or(section_dashboard_auth, "client_ip",
                    toml::value(toml::table()));
  find_if_exist(section_dashboard_client_ip, "header",
                global.dashboardAuthClientIpHeader);
  global.dashboardAuthTrustedProxyCidrs = toml::find_or<string_array>(
      section_dashboard_client_ip, "trusted_proxy_cidrs",
      global.dashboardAuthTrustedProxyCidrs);

  auto section_security =
      toml::find_or(root, "security", toml::value(toml::table()));
  if (section_security.contains("profile")) {
    global.securityDiagnostics.profileSource = "file:toml";
    global.securityDiagnostics.profileFileSource = "file:toml";
  }
  if (section_security.contains("allow_public_upload")) {
    global.securityDiagnostics.uploadSource = "file:toml";
    global.securityDiagnostics.uploadFileSource = "file:toml";
  }
  find_if_exist(section_security, "profile", global.securityProfile,
                "allow_public_upload", global.allowPublicUpload);
  finalizeRuntimeSettings();

  writeLog(LOG_LEVEL_INFO, "已加载 TOML 格式偏好设置。");
}

static void applyRuntimeConfiguration() {
  webServer.reset_redirect();
  for (const auto &alias : global.aliases)
    webServer.append_redirect(alias.first, alias.second);
  webServer.serve_file_root = global.serveFileRoot;
  webServer.serve_file = !webServer.serve_file_root.empty();
  webServer.set_client_ip_policy(client_ip::makePolicy(
      global.dashboardAuthClientIpHeader,
      global.dashboardAuthTrustedProxyCidrs));
  refresh_schedule();
}

bool readConf() {
  guarded_mutex guard(gMutexConfigure);
  ScopedLogLevelOverride log_level_scope;
  writeLog(LOG_LEVEL_INFO, "正在加载偏好设置...");

  Settings previous = global;

  auto restorePreviousSettings = [&](const std::string &reason) {
    safe_replace_settings(std::move(previous));
    log_level_scope.set(global.logLevel);
    writeLog(LOG_LEVEL_FATAL, reason);
    writeLog(LOG_LEVEL_FATAL, "偏好设置加载失败，已保留上一份有效配置。");
    return false;
  };

  auto resetReloadableSettings = []() {
    beginSecuritySettingsLoad();
    global.printDbgInfo = false;
    global.logLevel = LOG_LEVEL_INFO;
    eraseElements(global.excludeRemarks);
    eraseElements(global.includeRemarks);
    eraseElements(global.customProxyGroups);
    eraseElements(global.customRulesets);
    global.statisticsEnabled = false;
    global.statisticsDataDir = "stats";
    global.statisticsFlushInterval = 5;
    global.statisticsGeoProvider = "header";
    global.statisticsCountryHeaders = {"CF-IPCountry", "X-Geo-Country",
                                       "X-Vercel-IP-Country",
                                       "CloudFront-Viewer-Country"};
    global.statisticsChinaRegionHeaders = {"CF-Region-Code", "cf-region-code",
                                           "X-Geo-Subdivision"};
    global.dashboardAuthEnabled = false;
    global.dashboardAuthUsername.clear();
    global.dashboardAuthPassword.clear();
    global.dashboardAuthClientIpHeader = "none";
    global.dashboardAuthTrustedProxyCidrs.clear();
    global.dashboardAuthMaxFailures = 5;
    global.dashboardAuthWindowSeconds = 300;
    global.dashboardAuthLockSeconds = 900;
    global.resourceControl = "compat";
    global.resourceControlSource = "builtin-default";
    global.fallbackToDefaultExternalConfig = false;
    global.customOpenClashRulesSourceSwitch = false;
    // A removed proxy_bypass setting must return to the upgrade-compatible
    // default on reload instead of retaining a previous custom policy.
    global.proxyBypass = kDefaultProxyBypass;
    global.proxyProviderInterval = kDefaultProxyProviderInterval;
    global.proxyProviderDirect = kDefaultProxyProviderDirect;
    global.stashBase = kDefaultStashRuleBase;
    global.surgePolicyPath = true;
    global.surfboardPolicyPath = true;
    global.singBoxWireGuardEndpoint = false;
    global.singBoxSnellOutbound = false;
  };

  std::string prefdata;
  try {
    prefdata = fileGet(global.prefPath, false);
  } catch (std::exception &e) {
    return restorePreviousSettings("PREFERENCE_FILE_READ_FAILED detail=" +
                                   summarizeSensitiveTextForLog(e.what()));
  }
  std::string extension =
      toLower(std::filesystem::path(global.prefPath).extension().string());

  auto loadYAML = [&](YAML::Node &yaml) {
    if (!yaml.size() || !yaml["common"])
      return restorePreviousSettings(
          "YAML 偏好设置缺少必需的 common 节。");
    resetReloadableSettings();
    try {
      readYAMLConf(yaml, log_level_scope);
      applyRuntimeConfiguration();
      publishSettingsSnapshot(global);
      return true;
    } catch (std::exception &e) {
      return restorePreviousSettings("PREFERENCE_YAML_APPLY_FAILED detail=" +
                                     summarizeSensitiveTextForLog(e.what()));
    }
  };

  auto loadTOML = [&](toml::value &conf) {
    if (conf.is_empty() || !toml::find_or<int>(conf, "version", 0))
      return restorePreviousSettings(
          "TOML 偏好设置缺少有效的 version 字段。");
    resetReloadableSettings();
    try {
      readTOMLConf(conf, log_level_scope);
      applyRuntimeConfiguration();
      publishSettingsSnapshot(global);
      return true;
    } catch (std::exception &e) {
      return restorePreviousSettings("PREFERENCE_TOML_APPLY_FAILED detail=" +
                                     summarizeSensitiveTextForLog(e.what()));
    }
  };

  if (extension == ".yml" || extension == ".yaml") {
    try {
      YAML::Node yaml = YAML::Load(prefdata);
      return loadYAML(yaml);
    } catch (std::exception &e) {
      return restorePreviousSettings("PREFERENCE_YAML_PARSE_FAILED detail=" +
                                     summarizeSensitiveTextForLog(e.what()));
    }
  }

  if (extension == ".toml") {
    try {
      toml::value conf = parseToml(prefdata, global.prefPath);
      return loadTOML(conf);
    } catch (std::exception &e) {
      return restorePreviousSettings("PREFERENCE_TOML_PARSE_FAILED detail=" +
                                     summarizeSensitiveTextForLog(e.what()));
    }
  }

  if (extension != ".ini") {
    if (prefdata.find("common:") != std::string::npos) {
      try {
        YAML::Node yaml = YAML::Load(prefdata);
        return loadYAML(yaml);
      } catch (std::exception &e) {
        return restorePreviousSettings(
            "PREFERENCE_YAML_PARSE_FAILED detail=" +
            summarizeSensitiveTextForLog(e.what()));
      }
    }
    try {
      toml::value conf = parseToml(prefdata, global.prefPath);
      if (!conf.is_empty() && toml::find_or<int>(conf, "version", 0))
        return loadTOML(conf);
    } catch (std::exception &e) {
      writeLog(LOG_LEVEL_DEBUG, "PREFERENCE_TOML_PROBE_FAILED detail=" +
                      summarizeSensitiveTextForLog(e.what()));
    }
  }

  INIReader ini;
  ini.allow_dup_section_titles = true;
  // ini.do_utf8_to_gbk = true;
  int retVal = ini.parse_file(global.prefPath);
  if (retVal != INIREADER_EXCEPTION_NONE) {
    return restorePreviousSettings("PREFERENCE_INI_PARSE_FAILED detail=" +
                                   summarizeSensitiveTextForLog(
                                       ini.get_last_error()));
  }

  resetReloadableSettings();

  try {
    string_array tempArray;
    CommonScalarSettings common = captureCommonScalarSettings();

    std::string early_log_level;
    bool early_print_debug_info = false;
    if (ini.section_exist("advanced")) {
      ini.enter_section("advanced");
      ini.get_if_exist("log_level", early_log_level);
      ini.get_bool_if_exist("print_debug_info", early_print_debug_info);
    }
    applyConfiguredLogLevel(early_log_level, early_print_debug_info,
                            log_level_scope);

  ini.enter_section("common");
  // api_mode and api_access_token removed - hardcoded in settings.h
  ini.get_if_exist("default_url", global.defaultUrls);
  global.enableInsert = ini.get("enable_insert");
  ini.get_if_exist("insert_url", global.insertUrls);
  ini.get_bool_if_exist("prepend_insert_url", common.prependInsert);
  if (ini.item_prefix_exist("exclude_remarks"))
    ini.get_all("exclude_remarks", global.excludeRemarks);
  if (ini.item_prefix_exist("include_remarks"))
    ini.get_all("include_remarks", global.includeRemarks);
  global.filterScript =
      ini.get_bool("enable_filter") ? ini.get("filter_script") : "";
  ini.get_if_exist("base_path", common.basePath);
  ini.get_if_exist("clash_rule_base", common.clashBase);
  ini.get_if_exist("surge_rule_base", common.surgeBase);
  ini.get_if_exist("surfboard_rule_base", common.surfboardBase);
  ini.get_if_exist("mellow_rule_base", common.mellowBase);
  ini.get_if_exist("quan_rule_base", common.quanBase);
  ini.get_if_exist("quanx_rule_base", common.quanXBase);
  ini.get_if_exist("loon_rule_base", common.loonBase);
  ini.get_if_exist("sssub_rule_base", common.SSSubBase);
  ini.get_if_exist("singbox_rule_base", common.singBoxBase);
  ini.get_if_exist("stash_rule_base", common.stashBase);
  ini.get_if_exist("default_external_config", common.defaultExtConfig);
  ini.get_bool_if_exist("fallback_to_default_external_config",
                        common.fallbackToDefaultExternalConfig);
  ini.get_bool_if_exist("append_proxy_type", common.appendType);
  ini.get_if_exist("proxy_config", common.proxyConfig);
  ini.get_if_exist("proxy_ruleset", common.proxyRuleset);
  ini.get_if_exist("proxy_subscription", common.proxySubscription);
  ini.get_if_exist("proxy_bypass", common.proxyBypass);
  ini.get_bool_if_exist("reload_conf_on_request", common.reloadConfOnRequest);
  applyCommonScalarSettings(std::move(common));

  if (ini.section_exist("proxy_provider")) {
    ini.enter_section("proxy_provider");
    if (ini.item_exist("interval")) {
      std::string interval;
      ini.get_if_exist("interval", interval);
      global.proxyProviderInterval = requireProxyProviderInterval(interval);
    }
    if (ini.item_exist("proxy_direct")) {
      std::string proxy_direct;
      ini.get_if_exist("proxy_direct", proxy_direct);
      global.proxyProviderDirect =
          requireProxyProviderDirect(proxy_direct);
    }
  }

  if (ini.section_exist("custom_openclash_rules")) {
    ini.enter_section("custom_openclash_rules");
    ini.get_bool_if_exist("fallback_enabled",
                          global.customOpenClashRulesSourceSwitch);
  }

  if (ini.section_exist("surge_external_proxy")) {
    ini.enter_section("surge_external_proxy");
    ini.get_if_exist("surge_ssr_path", global.surgeSSRPath);
    ini.get_bool_if_exist("resolve_hostname", global.surgeResolveHostname);
  }

  if (ini.section_exist("remote_subscription")) {
    ini.enter_section("remote_subscription");
    ini.get_bool_if_exist("surge_policy_path", global.surgePolicyPath);
    ini.get_bool_if_exist("surfboard_policy_path",
                          global.surfboardPolicyPath);
    ini.get_bool_if_exist("loon_remote_proxy", global.loonRemoteProxy);
  }

  if (ini.section_exist("singbox")) {
    ini.enter_section("singbox");
    ini.get_bool_if_exist("wireguard_endpoint",
                          global.singBoxWireGuardEndpoint);
    ini.get_bool_if_exist("snell_outbound", global.singBoxSnellOutbound);
  }

  if (ini.section_exist("node_pref")) {
    ini.enter_section("node_pref");
    /*
    ini.GetBoolIfExist("udp_flag", udp_flag);
    ini.get_bool_if_exist("tcp_fast_open_flag", tfo_flag);
    ini.get_bool_if_exist("skip_cert_verify_flag", scv_flag);
    */
    global.UDPFlag.set(ini.get("udp_flag"));
    global.TFOFlag.set(ini.get("tcp_fast_open_flag"));
    global.skipCertVerify.set(ini.get("skip_cert_verify_flag"));
    global.TLS13Flag.set(ini.get("tls13_flag"));
    ini.get_bool_if_exist("sort_flag", global.enableSort);
    global.sortScript = ini.get("sort_script");
    ini.get_bool_if_exist("filter_deprecated_nodes", global.filterDeprecated);
    ini.get_bool_if_exist("append_sub_userinfo", global.appendUserinfo);
    ini.get_bool_if_exist("clash_use_new_field_name", global.clashUseNewField);
    ini.get_if_exist("clash_proxies_style", global.clashProxiesStyle);
    ini.get_bool_if_exist("singbox_add_clash_modes",
                          global.singBoxAddClashModes);
    if (ini.item_prefix_exist("rename_node")) {
      ini.get_all("rename_node", tempArray);
      importItems(tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "@");
      safe_set_renames(configs);
      eraseElements(tempArray);
    }
  }

  if (ini.section_exist("userinfo")) {
    ini.enter_section("userinfo");
    if (ini.item_prefix_exist("stream_rule")) {
      ini.get_all("stream_rule", tempArray);
      importItems(tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "|");
      safe_set_streams(configs);
      eraseElements(tempArray);
    }
    if (ini.item_prefix_exist("time_rule")) {
      ini.get_all("time_rule", tempArray);
      importItems(tempArray, false);
      auto configs =
          INIBinding::from<RegexMatchConfig>::from_ini(tempArray, "|");
      safe_set_times(configs);
      eraseElements(tempArray);
    }
  }

  ini.enter_section("managed_config");
  ini.get_bool_if_exist("write_managed_config", global.writeManagedConfig);
  ini.get_if_exist("managed_config_prefix", global.managedConfigPrefix);
  ini.get_int_if_exist("config_update_interval", global.updateInterval);
  ini.get_bool_if_exist("config_update_strict", global.updateStrict);
  ini.get_if_exist("quanx_device_id", global.quanXDevID);

  ini.enter_section("emojis");
  ini.get_bool_if_exist("add_emoji", global.addEmoji);
  ini.get_bool_if_exist("remove_old_emoji", global.removeEmoji);
  if (ini.item_prefix_exist("rule")) {
    ini.get_all("rule", tempArray);
    importItems(tempArray, false);
    auto configs = INIBinding::from<RegexMatchConfig>::from_ini(tempArray, ",");
    safe_set_emojis(configs);
    eraseElements(tempArray);
  }

  if (ini.section_exist("rulesets"))
    ini.enter_section("rulesets");
  else
    ini.enter_section("ruleset");
  global.enableRuleGen = ini.get_bool("enabled");
  if (global.enableRuleGen) {
    ini.get_bool_if_exist("overwrite_original_rules",
                          global.overwriteOriginalRules);
    ini.get_bool_if_exist("update_ruleset_on_request",
                          global.updateRulesetOnRequest);
    if (ini.item_prefix_exist("ruleset")) {
      string_array vArray;
      ini.get_all("ruleset", vArray);
      importItems(vArray, false);
      global.customRulesets = INIBinding::from<RulesetConfig>::from_ini(vArray);
    } else if (ini.item_prefix_exist("surge_ruleset")) {
      string_array vArray;
      ini.get_all("surge_ruleset", vArray);
      importItems(vArray, false);
      global.customRulesets = INIBinding::from<RulesetConfig>::from_ini(vArray);
    }
  } else {
    global.overwriteOriginalRules = false;
    global.updateRulesetOnRequest = false;
  }

  if (ini.section_exist("proxy_groups"))
    ini.enter_section("proxy_groups");
  else
    ini.enter_section("clash_proxy_group");
  if (ini.item_prefix_exist("custom_proxy_group")) {
    string_array vArray;
    ini.get_all("custom_proxy_group", vArray);
    importItems(vArray, false);
    global.customProxyGroups =
        INIBinding::from<ProxyGroupConfig>::from_ini(vArray);
  }

  ini.enter_section("template");
  ini.get_if_exist("template_path", global.templatePath);
  string_multimap tempmap;
  ini.get_items(tempmap);
  eraseElements(global.templateVars);
  for (auto &x : tempmap) {
    if (x.first == "template_path")
      continue;
    global.templateVars[x.first] = x.second;
  }
  global.templateVars["managed_config_prefix"] = global.managedConfigPrefix;

  if (ini.section_exist("aliases")) {
    ini.enter_section("aliases");
    ini.get_items(tempmap);
    eraseElements(global.aliases);
    for (auto &x : tempmap)
      global.aliases[x.first] = x.second;
  }

  if (ini.section_exist("tasks")) {
    string_array vArray;
    ini.enter_section("tasks");
    ini.get_all("task", vArray);
    importItems(vArray, false);
    global.enableCron = !vArray.empty();
    global.cronTasks = INIBinding::from<CronTaskConfig>::from_ini(vArray);
  }

  ini.enter_section("server");
  ini.get_if_exist("listen", global.listenAddress);
  ini.get_int_if_exist("port", global.listenPort);
  global.serveFileRoot = ini.get("serve_file_root");

  ini.enter_section("advanced");
  if (ini.item_exist("resource_control")) {
    ini.get_if_exist("resource_control", global.resourceControl);
    global.resourceControlSource = "file:ini";
  }
  ini.get_if_exist("force_max_curve_fingerprint",
                   global.forceMaxCurveFingerprint);
  ini.get_int_if_exist("max_pending_connections", global.maxPendingConns);
  ini.get_int_if_exist("max_concurrent_threads", global.maxConcurThreads);
  ini.get_int_if_exist("max_server_threads", global.maxServerThreads);
  ini.get_int_if_exist("request_deadline_ms", global.requestDeadlineMs);
  ini.get_number_if_exist("max_allowed_rulesets", global.maxAllowedRulesets);
  ini.get_number_if_exist("max_allowed_rules", global.maxAllowedRules);
  ini.get_number_if_exist("max_allowed_download_size",
                          global.maxAllowedDownloadSize);
  if (ini.item_exist("enable_cache")) {
    if (ini.get_bool("enable_cache")) {
      ini.get_int_if_exist("cache_subscription", global.cacheSubscription);
      ini.get_int_if_exist("cache_config", global.cacheConfig);
      ini.get_int_if_exist("cache_ruleset", global.cacheRuleset);
      ini.get_bool_if_exist("serve_cache_on_fetch_fail",
                            global.serveCacheOnFetchFail);
    } else {
      global.cacheSubscription = global.cacheConfig = global.cacheRuleset =
          0; // disable cache
      global.serveCacheOnFetchFail = false;
    }
  }
  ini.get_bool_if_exist("script_clean_context", global.scriptCleanContext);
  ini.get_bool_if_exist("async_fetch_ruleset", global.asyncFetchRuleset);
  ini.get_bool_if_exist("skip_failed_links", global.skipFailedLinks);
  ini.get_bool_if_exist("enable_request_coalescing",
                        global.enableRequestCoalescing);
  ini.get_bool_if_exist("coalesce_retry_on_5xx", global.coalesceRetryOn5xx);
  ini.get_bool_if_exist("allow_insecure_tls", global.allowInsecureTls);
  ini.get_int_if_exist("response_cache_ttl", global.responseCacheTtl);

  if (ini.section_exist("statistics")) {
    ini.enter_section("statistics");
    ini.get_bool_if_exist("enabled", global.statisticsEnabled);
    ini.get_if_exist("data_dir", global.statisticsDataDir);
    ini.get_int_if_exist("flush_interval", global.statisticsFlushInterval);
    ini.get_if_exist("geo_provider", global.statisticsGeoProvider);
    if (ini.item_exist("country_headers")) {
      string_array country_headers = split(ini.get("country_headers"), ",");
      for (std::string &header : country_headers)
        header = trimWhitespace(header, true, true);
      country_headers.erase(
          std::remove_if(country_headers.begin(), country_headers.end(),
                         [](const std::string &value) { return value.empty(); }),
          country_headers.end());
      if (!country_headers.empty())
        global.statisticsCountryHeaders = country_headers;
    }
    if (ini.item_exist("china_region_headers")) {
      string_array region_headers =
          split(ini.get("china_region_headers"), ",");
      for (std::string &header : region_headers)
        header = trimWhitespace(header, true, true);
      region_headers.erase(
          std::remove_if(region_headers.begin(), region_headers.end(),
                         [](const std::string &value) { return value.empty(); }),
          region_headers.end());
      if (!region_headers.empty())
        global.statisticsChinaRegionHeaders = region_headers;
    }
    ini.get_bool_if_exist("dashboard_auth_enabled",
                          global.dashboardAuthEnabled);
    ini.get_if_exist("dashboard_auth_username",
                     global.dashboardAuthUsername);
    ini.get_if_exist("dashboard_auth_password",
                     global.dashboardAuthPassword);
    ini.get_int_if_exist("dashboard_auth_max_failures",
                         global.dashboardAuthMaxFailures);
    ini.get_int_if_exist("dashboard_auth_window_seconds",
                         global.dashboardAuthWindowSeconds);
    ini.get_int_if_exist("dashboard_auth_lock_seconds",
                         global.dashboardAuthLockSeconds);
    ini.get_if_exist("dashboard_auth_client_ip_header",
                     global.dashboardAuthClientIpHeader);
    if (ini.item_exist("dashboard_auth_trusted_proxy_cidrs")) {
      global.dashboardAuthTrustedProxyCidrs =
          split(ini.get("dashboard_auth_trusted_proxy_cidrs"), ",");
    }
  }

  if (ini.section_exist("security")) {
    ini.enter_section("security");
    if (ini.item_exist("profile")) {
      global.securityDiagnostics.profileSource = "file:ini";
      global.securityDiagnostics.profileFileSource = "file:ini";
      ini.get_if_exist("profile", global.securityProfile);
    }
    if (ini.item_exist("allow_public_upload")) {
      global.securityDiagnostics.uploadSource = "file:ini";
      global.securityDiagnostics.uploadFileSource = "file:ini";
      const std::string raw_upload = ini.get("allow_public_upload");
      global.securityDiagnostics.uploadInput = raw_upload;
      global.securityDiagnostics.uploadInputValid =
          raw_upload == "true" || raw_upload == "false";
      ini.get_bool_if_exist("allow_public_upload", global.allowPublicUpload);
    }
  }
    finalizeRuntimeSettings();

    writeLog(LOG_LEVEL_INFO, "已加载 INI 格式偏好设置。");
    applyRuntimeConfiguration();
    publishSettingsSnapshot(global);
    return true;
  } catch (std::exception &e) {
    return restorePreviousSettings("PREFERENCE_INI_APPLY_FAILED detail=" +
                                   summarizeSensitiveTextForLog(e.what()));
  }
}

ExternalConfigLoadStatus loadExternalYAML(YAML::Node &node,
                                          ExternalConfig &ext,
                                          FetchContext context) {
  const Settings &settings = effectiveSettings();
  YAML::Node section = node["custom"], object;
  std::string name, type, url, interval;
  std::string group, strLine;

  section["clash_rule_base"] >> ext.clash_rule_base;
  section["surge_rule_base"] >> ext.surge_rule_base;
  section["surfboard_rule_base"] >> ext.surfboard_rule_base;
  section["mellow_rule_base"] >> ext.mellow_rule_base;
  section["quan_rule_base"] >> ext.quan_rule_base;
  section["quanx_rule_base"] >> ext.quanx_rule_base;
  section["loon_rule_base"] >> ext.loon_rule_base;
  section["sssub_rule_base"] >> ext.sssub_rule_base;
  section["singbox_rule_base"] >> ext.singbox_rule_base;
  section["stash_rule_base"] >> ext.stash_rule_base;

  section["enable_rule_generator"] >> ext.enable_rule_generator;
  section["overwrite_original_rules"] >> ext.overwrite_original_rules;
  section["ruleprepend"] >> ext.rule_prepend_sources;
  section["ruleappend"] >> ext.rule_append_sources;

  const char *group_name = section["proxy_groups"].IsDefined()
                               ? "proxy_groups"
                               : "custom_proxy_group";
  if (section[group_name].size()) {
    string_array vArray;
    if (readGroup(section[group_name], vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.custom_proxy_group =
        INIBinding::from<ProxyGroupConfig>::from_ini(vArray);
  }

  const char *ruleset_name =
      section["rulesets"].IsDefined() ? "rulesets" : "surge_ruleset";
  if (section[ruleset_name].size()) {
    string_array vArray;
    if (readRuleset(section[ruleset_name], vArray, settings.APIMode, context) !=
        0)
      return ExternalConfigLoadStatus::ImportFailed;
    if (settings.maxAllowedRulesets &&
        vArray.size() > settings.maxAllowedRulesets) {
      writeLog(LOG_LEVEL_WARNING, "外部配置中的规则集数量已超过限制。");
      return ExternalConfigLoadStatus::ResourceLimitExceeded;
    }
    ext.surge_ruleset = INIBinding::from<RulesetConfig>::from_ini(vArray);
  }

  if (section["rename_node"].size()) {
    string_array vArray;
    if (readRegexMatch(section["rename_node"], "@", vArray, settings.APIMode,
                       context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.rename = INIBinding::from<RegexMatchConfig>::from_ini(vArray, "@");
  }

  ext.add_emoji = safe_as<std::string>(section["add_emoji"]);
  ext.remove_old_emoji = safe_as<std::string>(section["remove_old_emoji"]);
  const char *emoji_name = section["emojis"].IsDefined() ? "emojis" : "emoji";
  if (section[emoji_name].size()) {
    string_array vArray;
    if (readEmoji(section[emoji_name], vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.emoji = INIBinding::from<RegexMatchConfig>::from_ini(vArray, ",");
  }

  section["include_remarks"] >> ext.include;
  section["exclude_remarks"] >> ext.exclude;

  if (node["template_args"].IsSequence() && ext.tpl_args != NULL) {
    std::string key, value;
    for (size_t i = 0; i < node["template_args"].size(); i++) {
      node["template_args"][i]["key"] >> key;
      node["template_args"][i]["value"] >> value;
      ext.tpl_args->local_vars[key] = value;
    }
  }

  return ExternalConfigLoadStatus::Success;
}

ExternalConfigLoadStatus loadExternalTOML(toml::value &root,
                                          ExternalConfig &ext,
                                          FetchContext context) {
  auto section = toml::find(root, "custom");
  bool import_scope_limit = isPublicFetchRestricted(context);

  find_if_exist(section, "enable_rule_generator", ext.enable_rule_generator,
                "overwrite_original_rules", ext.overwrite_original_rules,
                "ruleprepend", ext.rule_prepend_sources, "ruleappend",
                ext.rule_append_sources,
                "clash_rule_base", ext.clash_rule_base, "surge_rule_base",
                ext.surge_rule_base, "surfboard_rule_base",
                ext.surfboard_rule_base, "mellow_rule_base",
                ext.mellow_rule_base, "quan_rule_base", ext.quan_rule_base,
                "quanx_rule_base", ext.quanx_rule_base, "loon_rule_base",
                ext.loon_rule_base, "sssub_rule_base", ext.sssub_rule_base,
                "singbox_rule_base", ext.singbox_rule_base,
                "stash_rule_base", ext.stash_rule_base, "add_emoji",
                ext.add_emoji, "remove_old_emoji", ext.remove_old_emoji,
                "include_remarks", ext.include, "exclude_remarks", ext.exclude);

  if (ext.tpl_args != nullptr)
    operate_toml_kv_table(
        toml::find_or<std::vector<toml::table>>(section, "template_args", {}),
        "key", "value", [&](const toml::value &key, const toml::value &value) {
          std::string val = toml::format(value);
          ext.tpl_args->local_vars[key.as_string()] = val;
        });

  auto groups =
      toml::find_or<std::vector<toml::value>>(root, "custom_groups", {});
  if (importItems(groups, "custom_groups", import_scope_limit, context) != 0)
    return ExternalConfigLoadStatus::ImportFailed;
  ext.custom_proxy_group = toml::get<ProxyGroupConfigs>(toml::value(groups));

  auto rulesets = toml::find_or<std::vector<toml::value>>(root, "rulesets", {});
  if (importItems(rulesets, "rulesets", import_scope_limit, context) != 0)
    return ExternalConfigLoadStatus::ImportFailed;
  const Settings &settings = effectiveSettings();
  if (settings.maxAllowedRulesets &&
      rulesets.size() > settings.maxAllowedRulesets) {
    writeLog(LOG_LEVEL_WARNING, "外部配置中的规则集数量已超过限制。");
    return ExternalConfigLoadStatus::ResourceLimitExceeded;
  }
  ext.surge_ruleset = toml::get<RulesetConfigs>(toml::value(rulesets));

  auto emojiconfs = toml::find_or<std::vector<toml::value>>(root, "emoji", {});
  if (importItems(emojiconfs, "emoji", import_scope_limit, context) != 0)
    return ExternalConfigLoadStatus::ImportFailed;
  ext.emoji = toml::get<RegexMatchConfigs>(toml::value(emojiconfs));

  auto renameconfs =
      toml::find_or<std::vector<toml::value>>(root, "rename_node", {});
  if (importItems(renameconfs, "rename_node", import_scope_limit, context) !=
      0)
    return ExternalConfigLoadStatus::ImportFailed;
  ext.rename = toml::get<RegexMatchConfigs>(toml::value(renameconfs));

  return ExternalConfigLoadStatus::Success;
}

static ExternalConfigLoadStatus
parseExternalConfigContent(const std::string &path,
                           const std::string &base_content,
                           ExternalConfig &ext, FetchContext context) {
  const Settings &settings = effectiveSettings();
  ext.rule_sources_context = context;
  try {
    YAML::Node yaml = YAML::Load(base_content);
    if (yaml.size() && yaml["custom"].IsDefined())
      return loadExternalYAML(yaml, ext, context);
    toml::value conf = parseToml(base_content, path);
    if (!conf.is_empty() && toml::find_or<int>(conf, "version", 0))
      return loadExternalTOML(conf, ext, context);
  } catch (YAML::Exception &e) {
    // ignore
  } catch (toml::exception &e) {
    // ignore
  }

  INIReader ini;
  ini.store_isolated_line = true;
  ini.set_isolated_items_section("custom");
  if (ini.parse(base_content) != INIREADER_EXCEPTION_NONE) {
    // std::cerr<<"Load external configuration failed. Reason:
    // "<<ini.get_last_error()<<"\n";
    writeLog(LOG_LEVEL_ERROR, "EXTERNAL_CONFIG_INI_PARSE_FAILED detail=" +
                    summarizeSensitiveTextForLog(ini.get_last_error()));
    return ExternalConfigLoadStatus::ParseFailed;
  }

  ini.enter_section("custom");
  if (ini.item_prefix_exist("custom_proxy_group")) {
    string_array vArray;
    ini.get_all("custom_proxy_group", vArray);
    if (importItems(vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.custom_proxy_group =
        INIBinding::from<ProxyGroupConfig>::from_ini(vArray);
  }
  std::string ruleset_name =
      ini.item_prefix_exist("ruleset") ? "ruleset" : "surge_ruleset";
  if (ini.item_prefix_exist(ruleset_name)) {
    string_array vArray;
    ini.get_all(ruleset_name, vArray);
    if (importItems(vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    if (settings.maxAllowedRulesets &&
        vArray.size() > settings.maxAllowedRulesets) {
      writeLog(LOG_LEVEL_WARNING, "外部配置中的规则集数量已超过限制。");
      return ExternalConfigLoadStatus::ResourceLimitExceeded;
    }
    ext.surge_ruleset = INIBinding::from<RulesetConfig>::from_ini(vArray);
  }

  ini.get_if_exist("clash_rule_base", ext.clash_rule_base);
  ini.get_if_exist("surge_rule_base", ext.surge_rule_base);
  ini.get_if_exist("surfboard_rule_base", ext.surfboard_rule_base);
  ini.get_if_exist("mellow_rule_base", ext.mellow_rule_base);
  ini.get_if_exist("quan_rule_base", ext.quan_rule_base);
  ini.get_if_exist("quanx_rule_base", ext.quanx_rule_base);
  ini.get_if_exist("loon_rule_base", ext.loon_rule_base);
  ini.get_if_exist("sssub_rule_base", ext.sssub_rule_base);
  ini.get_if_exist("singbox_rule_base", ext.singbox_rule_base);
  ini.get_if_exist("stash_rule_base", ext.stash_rule_base);

  ini.get_bool_if_exist("overwrite_original_rules",
                        ext.overwrite_original_rules);
  ini.get_bool_if_exist("enable_rule_generator", ext.enable_rule_generator);
  ini.get_all("ruleprepend", ext.rule_prepend_sources);
  ini.get_all("ruleappend", ext.rule_append_sources);

  if (ini.item_prefix_exist("rename")) {
    string_array vArray;
    ini.get_all("rename", vArray);
    if (importItems(vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.rename = INIBinding::from<RegexMatchConfig>::from_ini(vArray, "@");
  }
  ext.add_emoji = ini.get("add_emoji");
  ext.remove_old_emoji = ini.get("remove_old_emoji");
  if (ini.item_prefix_exist("emoji")) {
    string_array vArray;
    ini.get_all("emoji", vArray);
    if (importItems(vArray, settings.APIMode, context) != 0)
      return ExternalConfigLoadStatus::ImportFailed;
    ext.emoji = INIBinding::from<RegexMatchConfig>::from_ini(vArray, ",");
  }
  if (ini.item_prefix_exist("include_remarks"))
    ini.get_all("include_remarks", ext.include);
  if (ini.item_prefix_exist("exclude_remarks"))
    ini.get_all("exclude_remarks", ext.exclude);

  if (ini.section_exist("template") && ext.tpl_args != nullptr) {
    ini.enter_section("template");
    string_multimap tempmap;
    ini.get_items(tempmap);
    for (auto &x : tempmap)
      ext.tpl_args->local_vars[x.first] = x.second;
  }

  return ExternalConfigLoadStatus::Success;
}

namespace {

constexpr size_t kExternalConfigCacheEntries = 64;
constexpr size_t kExternalConfigCacheBytes = 8 * 1024 * 1024;
constexpr const char *kExternalConfigParserIdentity =
    "external-config:auto-yaml-toml-ini:v3";

struct CachedExternalConfig {
  ExternalConfigLoadStatus status = ExternalConfigLoadStatus::ParseFailed;
  ExternalConfig config;
  string_map local_vars;
  size_t cache_bytes = 0;
};

ConcurrentLruCache<std::string, CachedExternalConfig> external_config_cache(
    kExternalConfigCacheEntries, kExternalConfigCacheBytes);

static std::string buildExternalConfigCacheKey(
    const std::string &base_content, FetchContext context,
    unsigned long long config_generation) {
  return getMD5(base_content) + ":" +
         std::to_string(static_cast<int>(context)) + ":" +
         std::to_string(config_generation) + ":" +
         kExternalConfigParserIdentity;
}

static size_t localVarsSize(const string_map &vars) {
  size_t bytes = 0;
  for (const auto &[name, value] : vars)
    bytes += name.size() + value.size();
  return bytes;
}

} // namespace

bool isExternalConfigCacheableContent(const std::string &content) {
  std::string lower = toLower(content);
  static const string_array dynamic_markers = {
      "!!import:", "!!script:", "import:", "script:",
      "import =",  "import=",    "script =", "script="};
  for (const std::string &marker : dynamic_markers) {
    if (lower.find(marker) != std::string::npos)
      return false;
  }
  return true;
}

size_t externalConfigCacheMaxEntries() {
  return kExternalConfigCacheEntries;
}

size_t externalConfigCacheMaxBytes() { return kExternalConfigCacheBytes; }

ExternalConfigLoadResult loadExternalConfig(const std::string &path,
                                            ExternalConfig &ext,
                                            FetchContext context) {
  template_args empty_tpl_args;
  template_args *request_tpl_args =
      ext.tpl_args ? ext.tpl_args : &empty_tpl_args;
  const Settings &settings = effectiveSettings();
  std::string base_content;
  ProxyPolicy proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
  std::string config =
      fetchFile(path, proxy, settings.cacheConfig, true, context);
  if (config.empty())
    return {ExternalConfigLoadStatus::FetchFailed};

  bool template_fetch_failed = false;
  if (render_template(config, *request_tpl_args, base_content,
                      settings.templatePath, context,
                      &template_fetch_failed) != 0 ||
      template_fetch_failed)
    return {ExternalConfigLoadStatus::RenderFailed};

  bool cache_enabled =
      settings.cacheConfig > 0 && isExternalConfigCacheableContent(config) &&
      isExternalConfigCacheableContent(base_content);
  const std::string key = buildExternalConfigCacheKey(
      base_content, context, settings.configGeneration);

  CachedExternalConfig cached = external_config_cache.getOrCompute(
      key, cache_enabled,
      [&] {
        CachedExternalConfig value;
        template_args parsed_tpl_args = *request_tpl_args;
        parsed_tpl_args.local_vars.clear();
        ExternalConfig parsed;
        parsed.tpl_args = &parsed_tpl_args;
        value.status =
            parseExternalConfigContent(path, base_content, parsed, context);
        value.local_vars = std::move(parsed_tpl_args.local_vars);
        parsed.tpl_args = nullptr;
        value.config = std::move(parsed);
        value.cache_bytes =
            base_content.size() + localVarsSize(value.local_vars);
        return value;
      },
      [](const CachedExternalConfig &value)
          -> ConcurrentLruCache<std::string,
                                CachedExternalConfig>::CacheSize {
        if (value.status != ExternalConfigLoadStatus::Success)
          return std::nullopt;
        return value.cache_bytes;
      });

  if (cached.status != ExternalConfigLoadStatus::Success)
    return {cached.status};

  template_args *destination_tpl_args = ext.tpl_args;
  ext = std::move(cached.config);
  ext.tpl_args = destination_tpl_args;
  if (destination_tpl_args) {
    for (const auto &[name, value] : cached.local_vars)
      destination_tpl_args->local_vars[name] = value;
  }
  return {ExternalConfigLoadStatus::Success};
}
