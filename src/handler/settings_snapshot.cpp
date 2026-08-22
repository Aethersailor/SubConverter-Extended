#include "handler/settings_snapshot.h"

#include <string>

#include <nlohmann/json.hpp>

#include "handler/proxy_policy.h"
#include "handler/settings.h"
#include "utils/string.h"

namespace {

nlohmann::json sensitiveState(const std::string &value) {
  const std::string trimmed = trimWhitespace(value, true, true);
  return {
      {"configured", !trimmed.empty()},
      {"length", trimmed.size()},
  };
}

std::string triState(const tribool &value) {
  if (value.is_undef())
    return "inherit";
  return value.get() ? "true" : "false";
}

} // namespace

std::string sanitizedSettingsSnapshot(const Settings &settings) {
  nlohmann::json snapshot = {
      {"schema", 1},
      {"common",
       {
           {"base_path", settings.basePath},
           {"rule_bases",
            {
                {"clash", settings.clashBase},
                {"surge", settings.surgeBase},
                {"surfboard", settings.surfboardBase},
                {"mellow", settings.mellowBase},
                {"quan", settings.quanBase},
                {"quanx", settings.quanXBase},
                {"loon", settings.loonBase},
                {"sssub", settings.SSSubBase},
                {"singbox", settings.singBoxBase},
                {"stash", settings.stashBase},
            }},
           {"default_urls", sensitiveState(settings.defaultUrls)},
           {"insert_urls", sensitiveState(settings.insertUrls)},
           {"default_external_config",
            sensitiveState(settings.defaultExtConfig)},
           {"fallback_to_default_external_config",
            settings.fallbackToDefaultExternalConfig},
           {"enable_insert", settings.enableInsert.get(false)},
           {"prepend_insert", settings.prependInsert},
           {"append_proxy_type", settings.appendType},
           {"reload_conf_on_request", settings.reloadConfOnRequest},
           {"exclude_remarks_count", settings.excludeRemarks.size()},
           {"include_remarks_count", settings.includeRemarks.size()},
       }},
      {"node_pref",
       {
           {"udp", triState(settings.UDPFlag)},
           {"tcp_fast_open", triState(settings.TFOFlag)},
           {"skip_cert_verify", triState(settings.skipCertVerify)},
           {"tls13", triState(settings.TLS13Flag)},
           {"sort", settings.enableSort},
           {"filter_deprecated", settings.filterDeprecated},
           {"append_userinfo", settings.appendUserinfo},
           {"clash_new_fields", settings.clashUseNewField},
           {"clash_proxies_style", settings.clashProxiesStyle},
           {"singbox_add_clash_modes", settings.singBoxAddClashModes},
           {"emoji_rule_count", settings.emojis.size()},
       }},
      {"proxy_provider",
       {
           {"interval", settings.proxyProviderInterval},
           {"proxy_direct", settings.proxyProviderDirect},
       }},
      {"remote_subscription",
       {
           {"surge_policy_path", settings.surgePolicyPath},
           {"surfboard_policy_path", settings.surfboardPolicyPath},
           {"loon_remote_proxy", settings.loonRemoteProxy},
       }},
      {"singbox",
       {
           {"wireguard_endpoint", settings.singBoxWireGuardEndpoint},
           {"snell_outbound", settings.singBoxSnellOutbound},
       }},
      {"rules",
       {
           {"enabled", settings.enableRuleGen},
           {"overwrite_original", settings.overwriteOriginalRules},
           {"update_on_request", settings.updateRulesetOnRequest},
           {"ruleset_count", settings.customRulesets.size()},
           {"proxy_group_count", settings.customProxyGroups.size()},
       }},
      {"server",
       {
           {"listen", settings.listenAddress},
           {"port", settings.listenPort},
           {"serve_file_root", settings.serveFileRoot},
           {"max_pending_connections", settings.maxPendingConns},
           {"max_concurrent_threads", settings.maxConcurThreads},
           {"max_server_threads", settings.maxServerThreads},
           {"request_deadline_ms", settings.requestDeadlineMs},
       }},
      {"advanced",
       {
           {"resource_control", settings.resourceControl},
           {"resource_control_effective", settings.resourceControlEffective},
           {"force_max_curve_fingerprint",
            settings.forceMaxCurveFingerprint},
           {"max_allowed_rulesets", settings.maxAllowedRulesets},
           {"max_allowed_rules", settings.maxAllowedRules},
           {"max_allowed_download_size", settings.maxAllowedDownloadSize},
           {"cache_subscription", settings.cacheSubscription},
           {"cache_config", settings.cacheConfig},
           {"cache_ruleset", settings.cacheRuleset},
           {"serve_cache_on_fetch_fail", settings.serveCacheOnFetchFail},
           {"skip_failed_links", settings.skipFailedLinks},
           {"request_coalescing", settings.enableRequestCoalescing},
           {"coalesce_retry_on_5xx", settings.coalesceRetryOn5xx},
           {"allow_insecure_tls", settings.allowInsecureTls},
           {"response_cache_ttl", settings.responseCacheTtl},
       }},
      {"security",
       {
           {"profile", settings.securityProfile},
           {"allow_public_upload", settings.allowPublicUpload},
       }},
      {"custom_openclash_rules",
       {
           {"fallback_enabled", settings.customOpenClashRulesSourceSwitch},
       }},
      {"proxies",
       {
           {"config",
            parseProxy(settings.proxyConfig, settings.proxyBypass).describe()},
           {"ruleset",
            parseProxy(settings.proxyRuleset, settings.proxyBypass).describe()},
           {"subscription",
            parseProxy(settings.proxySubscription, settings.proxyBypass)
                .describe()},
           {"bypass", ProxyBypassPolicy::parse(settings.proxyBypass).describe()},
       }},
      {"statistics",
       {
           {"enabled", settings.statisticsEnabled},
           {"data_dir", settings.statisticsDataDir},
           {"flush_interval", settings.statisticsFlushInterval},
           {"geo_provider", settings.statisticsGeoProvider},
           {"country_header_count",
            settings.statisticsCountryHeaders.size()},
           {"china_region_header_count",
            settings.statisticsChinaRegionHeaders.size()},
           {"dashboard_auth_enabled", settings.dashboardAuthEnabled},
           {"dashboard_username_configured",
            !settings.dashboardAuthUsername.empty()},
           {"dashboard_password_configured",
            !settings.dashboardAuthPassword.empty()},
           {"dashboard_max_failures", settings.dashboardAuthMaxFailures},
           {"dashboard_window_seconds",
            settings.dashboardAuthWindowSeconds},
           {"dashboard_lock_seconds", settings.dashboardAuthLockSeconds},
           {"dashboard_client_ip_header",
            settings.dashboardAuthClientIpHeader},
           {"dashboard_trusted_proxy_count",
            settings.dashboardAuthTrustedProxyCidrs.size()},
       }},
  };
  return snapshot.dump(2) + "\n";
}
