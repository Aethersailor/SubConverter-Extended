#ifndef SUBEXPORT_H_INCLUDED
#define SUBEXPORT_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

#ifndef NO_JS_RUNTIME
#include <quickjspp.hpp>
#endif // NO_JS_RUNTIME

#include "config/proxygroup.h"
#include "config/proxy_provider_interval.h"
#include "config/proxy_provider_direct.h"
#include "config/regmatch.h"
#include "parser/config/proxy.h"
#include "ruleconvert.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/string.h"
#include "utils/yamlcpp_extra.h"

struct ProxyProvider {
  std::string name;           // provider 名称
  std::string tag;            // 原始 tag（用于重命名映射）
  std::string url;            // 订阅链接
  uint32_t interval;          // 更新间隔（秒）
  bool proxy_direct;          // 是否显式使用 DIRECT 下载/更新
  std::string filter;         // 过滤正则
  std::string exclude_filter; // 排除正则
  std::string path;           // 本地缓存路径
  std::string user_agent;     // provider 更新时使用的 User-Agent
  std::map<std::string, std::string> headers; // 显式允许转发的请求头
  int groupId;                // 所属组 ID

  ProxyProvider()
      : interval(kDefaultProxyProviderInterval),
        proxy_direct(kDefaultProxyProviderDirect), groupId(0) {}
};

struct QuanXServerRemote {
  std::string resource_tag;
  std::string requested_resource_tag;
  std::string selection_resource_tag;
  std::string source_tag;
  std::string url;
  int update_interval = 0;
  bool has_update_interval = false;
  int group_id = 0;
};

struct SurgePolicyPathResource {
  std::string url;
  std::string source_tag;
  std::string requested_name;
  int update_interval = 0;
  bool has_update_interval = false;
  int group_id = 0;
};

struct SurfboardPolicyPathResource {
  std::string url;
  std::string source_tag;
  std::string requested_name;
  int group_id = 0;
};

struct LoonRemoteProxyResource {
  std::string resource_name;
  std::string requested_name;
  std::string selection_name;
  std::string source_tag;
  std::string url;
  int group_id = 0;
};

struct StashProxyProvider {
  std::string name;
  std::string requested_name;
  std::string selection_name;
  std::string source_tag;
  std::string url;
  std::string path;
  int interval = 3600;
  int group_id = 0;
  std::map<std::string, std::string> headers;
};

struct TargetGenerationStats {
  size_t input_nodes = 0;
  size_t emitted_nodes = 0;
  size_t remote_references_emitted = 0;
  std::map<ProxyType, size_t> unsupported_by_type;

  size_t unsupported_nodes() const {
    size_t count = 0;
    for (const auto &[type, type_count] : unsupported_by_type) {
      (void)type;
      count += type_count;
    }
    return count;
  }
};

using SingleLinkTypes = std::uint32_t;
namespace SingleLinkType {
constexpr SingleLinkTypes Shadowsocks = 1U << 0;
constexpr SingleLinkTypes ShadowsocksR = 1U << 1;
constexpr SingleLinkTypes VMess = 1U << 2;
constexpr SingleLinkTypes Trojan = 1U << 3;
constexpr SingleLinkTypes Hysteria2 = 1U << 4;
constexpr SingleLinkTypes VLESS = 1U << 5;
constexpr SingleLinkTypes Mixed = Shadowsocks | ShadowsocksR | VMess | Trojan |
                                  Hysteria2 | VLESS;
} // namespace SingleLinkType

enum class V2RayClientTarget { V2RayN, V2RayNG };

struct extra_settings {
  bool enable_rule_generator = true;
  bool overwrite_original_rules = true;
  string_array rule_prepend;
  string_array rule_append;
  std::string external_rule_error;
  RegexMatchConfigs rename_array;
  bool rename_for_providers = false;
  RegexMatchConfigs emoji_array;
  bool add_emoji = false;
  bool remove_emoji = false;
  bool append_proxy_type = false;
  bool nodelist = false;
  bool sort_flag = false;
  bool filter_deprecated = false;
  bool clash_new_field_name = false;
  bool clash_script = false;
  std::string surge_ssr_path;
  std::string managed_config_prefix;
  std::string quanx_dev_id;
  tribool udp = tribool();
  tribool tfo = tribool();
  tribool xudp = tribool();
  tribool skip_cert_verify = tribool();
  tribool tls13 = tribool();
  tribool stash_request_udp = tribool();
  tribool stash_request_tfo = tribool();
  tribool stash_request_tls13 = tribool();
  bool clash_classical_ruleset = false;
  std::string sort_script;
  std::string clash_proxies_style = "flow";
  std::string clash_proxy_groups_style = "flow";
  bool use_proxy_provider = true;       // 默认启用 proxy-provider 模式
  bool provider_proxy_direct = true;    // proxy-provider 默认使用 DIRECT 更新
  std::vector<ProxyProvider> providers; // provider 列表
  std::vector<QuanXServerRemote> quanx_server_remotes;
  std::vector<SurgePolicyPathResource> surge_policy_paths;
  std::vector<SurfboardPolicyPathResource> surfboard_policy_paths;
  std::vector<LoonRemoteProxyResource> loon_remote_proxies;
  std::vector<StashProxyProvider> stash_proxy_providers;
  StashRuleConversionStats stash_rule_stats;
  TargetGenerationStats target_generation_stats;
  TargetGenerationStats surge_generation_stats;
  TargetGenerationStats surfboard_generation_stats;
  TargetGenerationStats loon_generation_stats;
  bool authorized = false;
  RuleConversionStats *rule_stats = nullptr;

  extra_settings() = default;
  extra_settings(const extra_settings &) = delete;
  extra_settings(extra_settings &&) = delete;

#ifndef NO_JS_RUNTIME
  qjs::Runtime *js_runtime = nullptr;
  qjs::Context *js_context = nullptr;

  ~extra_settings() {
    delete js_context;
    delete js_runtime;
  }
#endif // NO_JS_RUNTIME
};

bool matchRange(const std::string &range, int target);

std::string proxyToClash(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         bool clashR, extra_settings &ext);
void proxyToClash(std::vector<Proxy> &nodes, YAML::Node &yamlnode,
                  const ProxyGroupConfigs &extra_proxy_group, bool clashR,
                  extra_settings &ext);
std::string proxyToSurge(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         int surge_ver, extra_settings &ext);
std::string proxyToMellow(std::vector<Proxy> &nodes,
                          const std::string &base_conf,
                          std::vector<RulesetContent> &ruleset_content_array,
                          const ProxyGroupConfigs &extra_proxy_group,
                          extra_settings &ext);
void proxyToMellow(std::vector<Proxy> &nodes, INIReader &ini,
                   std::vector<RulesetContent> &ruleset_content_array,
                   const ProxyGroupConfigs &extra_proxy_group,
                   extra_settings &ext);
std::string proxyToLoon(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext);
std::string proxyToStash(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext);
std::string proxyToSSSub(std::string base_conf, std::vector<Proxy> &nodes,
                         extra_settings &ext);
std::string proxyToSingle(const std::vector<Proxy> &nodes,
                          SingleLinkTypes types,
                           extra_settings &ext);
std::string proxyToShadowrocket(const std::vector<Proxy> &nodes,
                                extra_settings &ext);
std::string proxyToV2RayClient(std::vector<Proxy> &nodes,
                               V2RayClientTarget target,
                               extra_settings &ext);
std::string proxyToQuanX(std::vector<Proxy> &nodes,
                         const std::string &base_conf,
                         std::vector<RulesetContent> &ruleset_content_array,
                         const ProxyGroupConfigs &extra_proxy_group,
                         extra_settings &ext);
void proxyToQuanX(std::vector<Proxy> &nodes, INIReader &ini,
                  std::vector<RulesetContent> &ruleset_content_array,
                  const ProxyGroupConfigs &extra_proxy_group,
                  extra_settings &ext);
std::string proxyToQuan(std::vector<Proxy> &nodes, const std::string &base_conf,
                        std::vector<RulesetContent> &ruleset_content_array,
                        const ProxyGroupConfigs &extra_proxy_group,
                        extra_settings &ext);
void proxyToQuan(std::vector<Proxy> &nodes, INIReader &ini,
                 std::vector<RulesetContent> &ruleset_content_array,
                 const ProxyGroupConfigs &extra_proxy_group,
                 extra_settings &ext);
std::string proxyToSSD(std::vector<Proxy> &nodes, std::string &group,
                       std::string &userinfo, extra_settings &ext);
std::string proxyToSingBox(std::vector<Proxy> &nodes,
                           const std::string &base_conf,
                           std::vector<RulesetContent> &ruleset_content_array,
                           const ProxyGroupConfigs &extra_proxy_group,
                           extra_settings &ext);
void replaceAll(std::string &input, const std::string &search,
                const std::string &replace);
#endif // SUBEXPORT_H_INCLUDED
