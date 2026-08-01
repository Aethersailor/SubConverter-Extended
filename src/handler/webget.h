#ifndef WEBGET_H_INCLUDED
#define WEBGET_H_INCLUDED

#include <string>
#include <map>
#include <vector>

#include "handler/fetch_context.h"
#include "handler/proxy_policy.h"
#include "utils/map_extra.h"
#include "utils/string.h"

enum http_method
{
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PATCH
};

struct FetchArgument
{
    const http_method method;
    const std::string url;
    const ProxyPolicy proxy;
    const std::string *post_data = nullptr;
    const string_icase_map *request_headers = nullptr;
    std::string *cookies = nullptr;
    const unsigned int cache_ttl = 0;
    const bool keep_resp_on_fail = false;
    const FetchContext context = FetchContext::TrustedConfig;
    // When true, a successful network response is returned but is not written
    // to the persistent fetch cache until the caller validates the content.
    const bool defer_cache_commit = false;
};

struct FetchResult
{
    int *status_code;
    std::string *content = nullptr;
    std::string *response_headers = nullptr;
    std::string *cookies = nullptr;
};

enum class FetchFailureCategory {
    None,
    RequestRejected,
    SourceUnavailable,
    NotFound,
    ContentInvalid,
    Internal
};

struct FetchAttempt
{
    std::string source_kind;
    std::string effective_url;
    int status_code = 0;
    int curl_code = 0;
    FetchFailureCategory failure = FetchFailureCategory::None;
};

struct FetchOutcome
{
    bool success = false;
    int status_code = 0;
    std::string content;
    std::string response_headers;
    std::string cookies;
    std::string requested_url;
    std::string effective_url;
    std::string logical_resource;
    std::string failure_reason;
    FetchFailureCategory failure = FetchFailureCategory::None;
    bool cocr_rewrite_used = false;
    bool raw_to_jsdelivr_used = false;
    std::string effective_source;
    bool fresh_cache_used = false;
    bool stale_cache_used = false;
    bool cache_commit_pending = false;
    std::string cache_path;
    std::string cache_header_path;
    std::vector<FetchAttempt> attempts;
    // Fetches performed while validating this resource (for example template
    // `fetch()` calls or imported configuration fragments).  They remain
    // provisional until the owning resource has completed semantic
    // validation, so a parent parse/render failure can discard the complete
    // dependency tree atomically.
    std::vector<FetchOutcome> deferred_dependencies;
};

struct FetchCacheTransaction
{
    std::vector<FetchOutcome> pending;
};

class FetchCacheTransactionScope
{
public:
    explicit FetchCacheTransactionScope(FetchCacheTransaction &transaction);
    ~FetchCacheTransactionScope();

    FetchCacheTransactionScope(const FetchCacheTransactionScope &) = delete;
    FetchCacheTransactionScope &operator=(const FetchCacheTransactionScope &) = delete;

private:
    FetchCacheTransaction *previous_;
};

int webGet(const FetchArgument& argument, FetchResult &result);
int fetchRemote(const FetchArgument &argument, FetchOutcome &outcome);
bool commitFetchOutcomeCache(const FetchOutcome &outcome);
void discardFetchOutcomeCache(const FetchOutcome &outcome);
FetchCacheTransaction *currentFetchCacheTransaction();
void deferFetchOutcomeCache(FetchOutcome outcome);
void commitFetchCacheTransaction(FetchCacheTransaction &transaction);
void discardFetchCacheTransaction(FetchCacheTransaction &transaction);
std::string webGet(const std::string &url, const ProxyPolicy &proxy,
                   unsigned int cache_ttl = 0,
                   std::string *response_headers = nullptr,
                   string_icase_map *request_headers = nullptr,
                   FetchContext context = FetchContext::TrustedConfig);
bool isFetchUrlAllowed(const std::string &url, FetchContext context);
void flushCache();
int webPost(const std::string &url, const std::string &data,
            const ProxyPolicy &proxy, const string_icase_map &request_headers,
            std::string *retData);
int webPatch(const std::string &url, const std::string &data,
             const ProxyPolicy &proxy, const string_icase_map &request_headers,
             std::string *retData);
std::string buildSocks5ProxyString(const std::string &addr, int port, const std::string &username, const std::string &password);

// Unimplemented: (CURLOPT_HTTPHEADER: Host:)
std::string httpGet(const std::string &host, const std::string &addr, const std::string &uri);
std::string httpsGet(const std::string &host, const std::string &addr, const std::string &uri);

#endif // WEBGET_H_INCLUDED
