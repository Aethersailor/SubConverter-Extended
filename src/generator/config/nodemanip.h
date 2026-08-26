#ifndef NODEMANIP_H_INCLUDED
#define NODEMANIP_H_INCLUDED

#include <cstddef>
#include <functional>
#include <string>
#include <vector>
#include <limits.h>

#ifndef NO_JS_RUNTIME
#include <quickjspp.hpp>
#endif // NO_JS_RUNTIME

#include "config/regmatch.h"
#include "handler/fetch_context.h"
#include "handler/proxy_policy.h"
#include "parser/config/proxy.h"
#include "utils/map_extra.h"
#include "utils/string.h"

enum class NodeParserMode {
    LegacyOnly,
    MihomoOnly,
};

struct NodeParserStats {
    std::size_t invocations = 0;
    std::size_t failures = 0;
};

struct UnresolvedSubscriptionSource
{
    std::string url;
    FetchContext context = FetchContext::TrustedConfig;
    string_icase_map request_headers;
};

using ResolvedSubscriptionLookup = std::function<bool(
    const std::string &, FetchContext, const string_icase_map &,
    std::string &, std::string &)>;

inline constexpr int kAddNodesNeedsFetch = -2;

struct parse_settings
{
    ProxyPolicy *proxy = nullptr;
    string_array *exclude_remarks = nullptr;
    string_array *include_remarks = nullptr;
    RegexMatchConfigs *stream_rules = nullptr;
    RegexMatchConfigs *time_rules = nullptr;
    std::string *sub_info = nullptr;
    bool authorized = false;
    NodeParserMode parser_mode = NodeParserMode::LegacyOnly;
    bool force_direct_link = false;
    NodeParserStats *parser_stats = nullptr;
    FetchContext fetch_context = FetchContext::TrustedConfig;
    string_icase_map *request_header = nullptr;
    const std::string *resolved_subscription_content = nullptr;
    const std::string *resolved_subscription_headers = nullptr;
    ResolvedSubscriptionLookup resolved_subscription_lookup;
    std::vector<UnresolvedSubscriptionSource> *missing_subscription_sources =
        nullptr;
    bool require_resolved_subscription = false;
#ifndef NO_JS_RUNTIME
    qjs::Runtime *js_runtime = nullptr;
    qjs::Context *js_context = nullptr;
#endif // NO_JS_RUNTIME
};

int addNodes(std::string link, std::vector<Proxy> &allNodes, int groupID, parse_settings &parse_set);
void filterNodes(std::vector<Proxy> &nodes, string_array &exclude_remarks, string_array &include_remarks, int groupID);
bool applyMatcher(const std::string &rule, std::string &real_rule, const Proxy &node);
void preprocessNodes(std::vector<Proxy> &nodes, extra_settings &ext);

#endif // NODEMANIP_H_INCLUDED
