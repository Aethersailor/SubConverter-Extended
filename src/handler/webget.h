#ifndef WEBGET_H_INCLUDED
#define WEBGET_H_INCLUDED

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
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
#include "utils/workload_scheduler.h"

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
    // Keep response bytes alive with the returned result instead of charging
    // them to whichever request context happened to submit the transfer.
    // Async cache owners use this so one consumer's cancellation/lifetime
    // cannot invalidate the payload shared with the remaining consumers.
    bool retain_result_bytes = false;
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
    bool wakeup_available = false;
    uint64_t pending = 0;
    uint64_t active = 0;
    uint64_t running = 0;
    uint64_t handle_window = 0;
    uint64_t active_connection_limit = 0;
    uint64_t open_connection_limit = 0;
    uint64_t connection_cache_limit = 0;
    uint64_t recoverable_retry_limit = 0;
    uint64_t buffered_bytes = 0;
};

using SharedAsyncFetchResult = std::shared_ptr<AsyncFetchResult>;
using AsyncFetchFuture = std::shared_future<SharedAsyncFetchResult>;
using AsyncFetchCompletion =
    std::function<void(SharedAsyncFetchResult)>;

struct OwnedWebGetRequest
{
    enum class RetentionPolicy
    {
        CurrentRequest,
        Result,
    };

    std::string url;
    ProxyPolicy proxy;
    unsigned int cache_ttl = 0;
    bool capture_response_headers = false;
    std::string initial_response_headers;
    bool has_request_headers = false;
    string_icase_map request_headers;
    FetchContext context = FetchContext::TrustedConfig;
    RetentionPolicy retention = RetentionPolicy::CurrentRequest;
    bool high_cardinality_cache_admission = false;
};

struct OwnedWebGetResult
{
    int status_code = 0;
    AsyncFetchFailure failure = AsyncFetchFailure::None;
    std::string content;
    std::string response_headers;
    bool response_headers_touched = false;
    RetainedResponseByteLease retained_bytes;
};

struct OwnedWebGetAsyncPayload
{
    int status_code = 0;
    AsyncFetchFailure failure = AsyncFetchFailure::None;
    std::string content;
    std::string response_headers;
    bool response_headers_touched = false;
    RetainedResponseByteLease retained_bytes;
};
using SharedOwnedWebGetAsyncPayload =
    std::shared_ptr<const OwnedWebGetAsyncPayload>;

struct OwnedWebGetAsyncOutcome
{
    SharedOwnedWebGetAsyncPayload payload;
    AsyncFetchFailure failure = AsyncFetchFailure::None;
    RequestCancellationReason cancellation =
        RequestCancellationReason::None;
};
using OwnedWebGetAsyncCompletion =
    std::function<void(OwnedWebGetAsyncOutcome)>;

struct CacheFetchPayloadSnapshot
{
    uint64_t retained_bytes = 0;
    uint64_t peak_retained_bytes = 0;
    uint64_t registry_entries = 0;
};

struct SubscriptionCacheAdmissionSnapshot
{
    bool enabled = false;
    uint64_t entries = 0;
    uint64_t first_seen_bypassed_total = 0;
    uint64_t reuse_admitted_total = 0;
};

struct CacheFetchOperationProbeSnapshot
{
    uint64_t success_callbacks = 0;
    uint64_t exception_callbacks = 0;
    uint64_t unsubscribed_callbacks = 0;
    bool duplicate_publish_rejected = false;
    bool exception_rethrown_to_waiter = false;
    bool no_consumers_cancelled = false;
    bool owner_kinds_isolated = false;
};

struct OwnedWebGetAsyncConsumerProbeSnapshot
{
    uint64_t raced_completions = 0;
    uint64_t precancelled_completions = 0;
    bool payload_lease_released = false;
};

void webGetAsync(AsyncFetchRequest request, AsyncFetchCompletion completion);
AsyncFetchFuture webGetAsync(AsyncFetchRequest request);
void webGetOwnedAsync(OwnedWebGetRequest request,
                      std::shared_ptr<RequestContext> consumer_context,
                      OwnedWebGetAsyncCompletion completion);
// Synchronous ownership boundary used to share prepare/cache/finalize logic.
// CurrentRequest preserves the legacy request-scoped accounting; Result makes
// the move-only result own its byte lease for later continuation work.
OwnedWebGetResult webGetOwned(OwnedWebGetRequest request);
CacheFetchPayloadSnapshot cacheFetchPayloadSnapshot() noexcept;
SubscriptionCacheAdmissionSnapshot
subscriptionCacheAdmissionSnapshot() noexcept;
CacheFetchOperationProbeSnapshot cacheFetchOperationProbe();
OwnedWebGetAsyncConsumerProbeSnapshot ownedWebGetAsyncConsumerProbe();
struct OwnedWebGetContinuationRuntimeSnapshot
{
    bool initialized = false;
    bool stopping = false;
    bool joining = false;
    bool joined = false;
    size_t workers = 0;
    size_t max_entries = 0;
    uint64_t max_bytes = 0;
    uint64_t completion_exception_total = 0;
    WorkloadSchedulerSnapshot scheduler;
};
struct OwnedWebGetContinuationBudget
{
    size_t workers = 0;
    size_t max_entries = 0;
    uint64_t max_bytes = 0;

    bool operator==(const OwnedWebGetContinuationBudget &) const = default;
};
enum class OwnedWebGetContinuationInitStatus
{
    Initialized,
    AlreadyInitialized,
    InvalidBudget,
    BudgetMismatch,
    InitializationFailed,
    Stopping,
};
using OwnedWebGetContinuation = std::function<void()>;
using OwnedWebGetContinuationCompletion =
    std::function<void(SchedulerSubmitStatus, std::exception_ptr)>;
OwnedWebGetContinuationInitStatus initializeOwnedWebGetContinuationRuntime(
    OwnedWebGetContinuationBudget budget);
SchedulerSubmitStatus submitOwnedWebGetContinuation(
    RequestCostClass cost, uint64_t bytes,
    std::chrono::steady_clock::time_point deadline,
    RequestCancellationToken cancellation,
    OwnedWebGetContinuation continuation,
    OwnedWebGetContinuationCompletion completion);
OwnedWebGetContinuationRuntimeSnapshot
ownedWebGetContinuationRuntimeSnapshot();
void requestOwnedWebGetContinuationShutdown() noexcept;
bool joinOwnedWebGetContinuationRuntime() noexcept;
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
