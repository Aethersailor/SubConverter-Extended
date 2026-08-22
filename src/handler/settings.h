#ifndef SETTINGS_H_INCLUDED
#define SETTINGS_H_INCLUDED

#include <string>

#include "config/crontask.h"
#include "config/proxygroup.h"
#include "config/regmatch.h"
#include "config/ruleset.h"
#include "handler/fetch_context.h"
#include "handler/proxy_policy.h"
#include "generator/config/ruleconvert.h"
#include "generator/template/templates.h"
#include "utils/logger.h"
#include "utils/stl_extra.h"
#include "utils/string.h"
#include "utils/tribool.h"
#include <toml.hpp>

#include "config/proxy_provider_direct.h"
#include "config/proxy_provider_interval.h"

inline constexpr char kDefaultStashRuleBase[] = "base/stash.yaml";

struct SecuritySettingsDiagnostics {
  std::string profileSource = "builtin-default";
  std::string profileFileSource;
  bool profileInputValid = true;
  bool profileUsedCompatibilityFallback = false;
  std::string uploadSource = "builtin-default";
  std::string uploadFileSource;
  std::string uploadInput;
  bool uploadInputValid = true;
};

struct Settings {
  // common settings
  std::string prefPath = "pref.ini", defaultExtConfig;
  string_array excludeRemarks, includeRemarks;
  RulesetConfigs customRulesets;
  RegexMatchConfigs streamNodeRules, timeNodeRules;
  std::vector<RulesetContent> rulesetsContent;
  std::string listenAddress = "127.0.0.1", defaultUrls, insertUrls,
              managedConfigPrefix;
  int listenPort = 25500, maxPendingConns = 10, maxConcurThreads = 16,
      maxServerThreads = 128, requestDeadlineMs = 15000;
  std::string resourceControl = "compat";
  std::string resourceControlEffective = "compat";
  std::string resourceControlSource = "builtin-default";
  std::string forceMaxCurveFingerprint;
  bool prependInsert = true, skipFailedLinks = false;
  bool fallbackToDefaultExternalConfig = false;
  bool customOpenClashRulesSourceSwitch = false;
  static constexpr bool APIMode = true; // Hardcoded for security
  bool writeManagedConfig = false, enableRuleGen = true,
       updateRulesetOnRequest = false, overwriteOriginalRules = true;
  bool printDbgInfo = false, CFWChildProcess = false, appendUserinfo = true,
       asyncFetchRuleset = false, surgeResolveHostname = true;
  // accessToken removed - token authentication is disabled
  std::string basePath = "base";
  std::string custom_group;
  LogLevel logLevel = LOG_LEVEL_INFO;
  long maxAllowedDownloadSize = 1048576L;
  string_map aliases;
  std::string serveFileRoot;

  // security profile: lan keeps legacy behavior, public restricts untrusted
  // request fetches, strict additionally disables public upload overrides.
  std::string securityProfile = "lan";
  bool allowPublicUpload = false;
  SecuritySettingsDiagnostics securityDiagnostics;

  // global variables for template
  std::string templatePath = "templates";
  string_map templateVars;

  // generator settings
  bool generatorMode = false;
  std::string generateProfiles;

  // preferences
  bool reloadConfOnRequest = false;
  RegexMatchConfigs renames, emojis;
  bool addEmoji = false, removeEmoji = false, appendType = false,
       filterDeprecated = true;
  tribool UDPFlag, TFOFlag, skipCertVerify, TLS13Flag, enableInsert;
  bool enableSort = false, updateStrict = false;
  bool clashUseNewField = false, singBoxAddClashModes = true;
  std::string clashProxiesStyle = "flow", clashProxyGroupsStyle = "block";
  std::string proxyConfig, proxyRuleset, proxySubscription;
  std::string proxyBypass = kDefaultProxyBypass;
  int updateInterval = 0;
  int proxyProviderInterval = kDefaultProxyProviderInterval;
  bool proxyProviderDirect = kDefaultProxyProviderDirect;
  bool surgePolicyPath = true;
  bool surfboardPolicyPath = true;
  bool loonRemoteProxy = true;
  // Preserve the historical sing-box WireGuard outbound by default. Newer
  // deployments can opt into the 1.11+ endpoint schema independently.
  bool singBoxWireGuardEndpoint = false;
  // Snell outbounds require sing-box 1.14+. Keep them disabled so existing
  // deployments on the current stable client retain their historical output.
  bool singBoxSnellOutbound = false;
  std::string sortScript, filterScript;

  std::string clashBase;
  ProxyGroupConfigs customProxyGroups;
  std::string surgeBase, surfboardBase, mellowBase, quanBase, quanXBase,
      loonBase, SSSubBase, singBoxBase;
  std::string stashBase = kDefaultStashRuleBase;
  std::string surgeSSRPath, quanXDevID;

  // cache system
  bool serveCacheOnFetchFail = false;
  int cacheSubscription = 60, cacheConfig = 300, cacheRuleset = 21600;

  // request coalescing and short-lived response cache
  bool enableRequestCoalescing = true, coalesceRetryOn5xx = true;
  // Secure TLS is the default. This is an explicit compatibility escape hatch
  // for outbound libcurl requests only.
  bool allowInsecureTls = false;
  int responseCacheTtl = 0;
  unsigned long long configGeneration = 0;

  // opt-in privacy-preserving statistics and dashboard
  bool statisticsEnabled = false;
  std::string statisticsDataDir = "stats";
  int statisticsFlushInterval = 5;
  std::string statisticsGeoProvider = "header";
  string_array statisticsCountryHeaders = {
      "CF-IPCountry", "X-Geo-Country", "X-Vercel-IP-Country",
      "CloudFront-Viewer-Country"};
  string_array statisticsChinaRegionHeaders = {
      "CF-Region-Code", "cf-region-code", "X-Geo-Subdivision"};
  bool dashboardAuthEnabled = false;
  std::string dashboardAuthUsername, dashboardAuthPassword;
  std::string dashboardAuthClientIpHeader = "none";
  string_array dashboardAuthTrustedProxyCidrs;
  int dashboardAuthMaxFailures = 5, dashboardAuthWindowSeconds = 300,
      dashboardAuthLockSeconds = 900;

  // limits
  size_t maxAllowedRulesets = 64, maxAllowedRules = 32768;
  bool scriptCleanContext = false;

  // cron system
  bool enableCron = false;
  CronTaskConfigs cronTasks;
};

struct ExternalConfig {
  ProxyGroupConfigs custom_proxy_group;
  RulesetConfigs surge_ruleset;
  string_array rule_prepend_sources;
  string_array rule_append_sources;
  FetchContext rule_sources_context = FetchContext::TrustedConfig;
  std::string clash_rule_base;
  std::string surge_rule_base;
  std::string surfboard_rule_base;
  std::string mellow_rule_base;
  std::string quan_rule_base;
  std::string quanx_rule_base;
  std::string loon_rule_base;
  std::string sssub_rule_base;
  std::string singbox_rule_base;
  std::string stash_rule_base;
  RegexMatchConfigs rename;
  RegexMatchConfigs emoji;
  string_array include;
  string_array exclude;
  template_args *tpl_args = nullptr;
  bool overwrite_original_rules = false;
  bool enable_rule_generator = true;
  tribool add_emoji;
  tribool remove_old_emoji;
};

enum class ExternalConfigLoadStatus {
  Success,
  FetchFailed,
  RenderFailed,
  ParseFailed,
  ImportFailed,
  ResourceLimitExceeded,
};

struct ExternalConfigLoadResult {
  ExternalConfigLoadStatus status = ExternalConfigLoadStatus::ParseFailed;

  bool ok() const { return status == ExternalConfigLoadStatus::Success; }
};

extern Settings global;

bool isPublicFetchRestricted(FetchContext context);
bool isTrustedLocalResourcePath(const std::string &path);
bool isPublicUploadAllowed();
void logSecurityPosture();
int importItems(string_array &target, bool scope_limit = true,
                FetchContext context = FetchContext::TrustedConfig);
ExternalConfigLoadResult
loadExternalConfig(const std::string &path, ExternalConfig &ext,
                   FetchContext context = FetchContext::TrustedConfig);
bool isExternalConfigCacheableContent(const std::string &content);
size_t externalConfigCacheMaxEntries();
size_t externalConfigCacheMaxBytes();
// template <class T, class... U>
// void find_if_exist(const toml::value &v, const toml::key &k, T& target,
// U&&... args)
//{
//     if(v.contains(k)) target = toml::find<T>(v, k);
//     if constexpr (sizeof...(args) > 0) find_if_exist(v,
//     std::forward<U>(args)...);
// }
template <class... Args>
void parseGroupTimes(const std::string &src, Args... args) {
  std::array<int *, sizeof...(args)> ptrs{args...};
  string_size bpos = 0, epos = src.find(",");
  for (int *x : ptrs) {
    if (x != nullptr)
      *x = to_int(src.substr(bpos, epos - bpos), 0);
    if (epos != src.npos) {
      bpos = epos + 1;
      epos = src.find(",", bpos);
    } else
      return;
  }
  return;
}

#endif // SETTINGS_H_INCLUDED
