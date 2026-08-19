#ifndef WEBGET_H_INCLUDED
#define WEBGET_H_INCLUDED

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <map>
#include <utility>

#include "handler/fetch_context.h"
#include "handler/proxy_policy.h"
#include "server/request_context.h"
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
    FetchArgument(
        http_method method, std::string url, ProxyPolicy proxy,
        const std::string *post_data = nullptr,
        const string_icase_map *request_headers = nullptr,
        std::string *cookies = nullptr, unsigned int cache_ttl = 0,
        bool keep_resp_on_fail = false,
        FetchContext context = FetchContext::TrustedConfig,
        std::chrono::steady_clock::time_point deadline =
            std::chrono::steady_clock::time_point::max(),
        RequestCancellationToken cancellation = {})
        : method(method), url(std::move(url)), proxy(std::move(proxy)),
          post_data(post_data), request_headers(request_headers),
          cookies(cookies), cache_ttl(cache_ttl),
          keep_resp_on_fail(keep_resp_on_fail), context(context),
          deadline(deadline), cancellation(std::move(cancellation)) {}

    const http_method method;
    const std::string url;
    const ProxyPolicy proxy;
    const std::string *post_data = nullptr;
    const string_icase_map *request_headers = nullptr;
    std::string *cookies = nullptr;
    const unsigned int cache_ttl = 0;
    const bool keep_resp_on_fail = false;
    const FetchContext context = FetchContext::TrustedConfig;
    const std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::time_point::max();
    const RequestCancellationToken cancellation;
};

struct FetchResult
{
    int *status_code;
    std::string *content = nullptr;
    std::string *response_headers = nullptr;
    std::string *cookies = nullptr;
};

enum class AsyncFetchFailure
{
    None,
    Cancelled,
    Deadline,
    SizeLimit,
    Capacity,
    Dns,
    Tls,
    Proxy,
    Transport,
    Shutdown
};

struct AsyncFetchRequest
{
    http_method method = HTTP_GET;
    std::string url;
    ProxyPolicy proxy;
    std::string post_data;
    string_icase_map request_headers;
    std::string cookies;
    bool has_post_data = false;
    bool capture_content = true;
    bool capture_response_headers = false;
    bool capture_cookies = false;
    bool keep_resp_on_fail = false;
    FetchContext context = FetchContext::TrustedConfig;
    bool public_fetch_restricted = false;
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::time_point::max();
    RequestCancellationToken cancellation;
    std::shared_ptr<RequestContext> request_context;
};

struct AsyncFetchResult
{
    int status_code = 0;
    int transport_code = 0;
    AsyncFetchFailure failure = AsyncFetchFailure::None;
    std::string content;
    std::string response_headers;
    std::string cookies;
    bool used_proxy = false;
    long proxy_error = 0;
    RetainedResponseByteLease retained_bytes;
};

struct AsyncFetchEngineSnapshot
{
    bool available = false;
    uint64_t pending = 0;
    uint64_t active = 0;
    uint64_t buffered_bytes = 0;
};

using SharedAsyncFetchResult = std::shared_ptr<AsyncFetchResult>;
using AsyncFetchFuture = std::shared_future<SharedAsyncFetchResult>;

AsyncFetchFuture webGetAsync(AsyncFetchRequest request);
bool asyncFetchEngineAvailable() noexcept;
AsyncFetchEngineSnapshot asyncFetchEngineSnapshot() noexcept;

int webGet(const FetchArgument& argument, FetchResult &result);
std::string webGet(const std::string &url, const ProxyPolicy &proxy,
                   unsigned int cache_ttl = 0,
                   std::string *response_headers = nullptr,
                   string_icase_map *request_headers = nullptr,
                   FetchContext context = FetchContext::TrustedConfig);
bool isFetchUrlAllowed(const std::string &url, FetchContext context);
void requestOutboundFetchShutdown() noexcept;
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
