#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <atomic>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdint>

#include <curl/curl.h>

#include "handler/cocr_source_url.h"
#include "handler/cache_storage.h"
#include "handler/curl_handle_pool.h"
#include "handler/settings.h"
#include "handler/settings_view.h"
#include "server/client_ip.h"
#include "server/request_context.h"
#include "utils/base64/base64.h"
#include "utils/cooperative_cpu.h"
#include "utils/defer.h"
#include "utils/file_extra.h"
#include "utils/lock.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/resource_control.h"
#include "utils/system.h"
#include "utils/urlencode.h"
#include "version.h"
#include "webget.h"

#ifdef _WIN32
#ifndef _stat
#define _stat stat
#endif // _stat
#endif // _WIN32

/*
using guarded_mutex = std::lock_guard<std::mutex>;
std::mutex cache_rw_lock;
*/

RWLock cache_rw_lock;

//std::string user_agent_str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36";
static auto user_agent_str = "clash.meta";

struct curl_progress_data
{
    long size_limit = 0L;
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::time_point::max();
    RequestCancellationToken cancellation;
    std::shared_ptr<RequestContext> request_context;
    RetainedResponseByteLease retained_bytes;
    AsyncFetchFailure abort_reason = AsyncFetchFailure::None;
};

static std::atomic<uint64_t> cache_fetch_payload_retained_bytes{0};
static std::atomic<uint64_t> cache_fetch_payload_peak_retained_bytes{0};

struct CacheFetchPayload
{
    int status_code = 0;
    AsyncFetchFailure failure = AsyncFetchFailure::None;
    std::string content;
    std::string response_headers;
    RetainedResponseByteLease retained_bytes;

    ~CacheFetchPayload()
    {
        cache_fetch_payload_retained_bytes.fetch_sub(
            retained_bytes.bytes(), std::memory_order_relaxed);
    }

    bool retainPayloadBytes()
    {
        const uint64_t bytes = content.size() + response_headers.size();
        if(!retained_bytes.retain(bytes))
            return false;
        const uint64_t current = cache_fetch_payload_retained_bytes.fetch_add(
                                     bytes, std::memory_order_relaxed) +
                                 bytes;
        uint64_t peak = cache_fetch_payload_peak_retained_bytes.load(
            std::memory_order_relaxed);
        while(current > peak &&
              !cache_fetch_payload_peak_retained_bytes.compare_exchange_weak(
                  peak, current, std::memory_order_relaxed,
                  std::memory_order_relaxed))
        {
        }
        return true;
    }
};

using SharedCacheFetchPayload = std::shared_ptr<const CacheFetchPayload>;

class CacheFetchOperation
{
public:
    using Callback = std::function<void(SharedCacheFetchPayload,
                                        std::exception_ptr)>;

    SharedCacheFetchPayload wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return done_; });
        const std::exception_ptr error = error_;
        SharedCacheFetchPayload payload = payload_;
        lock.unlock();
        if(error)
            std::rethrow_exception(error);
        return payload;
    }

    void subscribe(Callback callback)
    {
        if(!callback)
            return;
        SharedCacheFetchPayload payload;
        std::exception_ptr error;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(!done_)
            {
                callbacks_.emplace_back(std::move(callback));
                return;
            }
            payload = payload_;
            error = error_;
        }
        invoke(callback, std::move(payload), std::move(error));
    }

    bool publish(SharedCacheFetchPayload payload)
    {
        return finish(std::move(payload), {});
    }

    bool publishException(std::exception_ptr error)
    {
        return finish({}, std::move(error));
    }

private:
    static void invoke(Callback &callback, SharedCacheFetchPayload payload,
                       std::exception_ptr error) noexcept
    {
        try
        {
            callback(std::move(payload), std::move(error));
        }
        catch(...)
        {
        }
    }

    bool finish(SharedCacheFetchPayload payload, std::exception_ptr error)
    {
        std::vector<Callback> callbacks;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(done_)
                return false;
            payload_ = std::move(payload);
            error_ = std::move(error);
            done_ = true;
            callbacks.swap(callbacks_);
        }
        condition_.notify_all();
        for(Callback &callback : callbacks)
            invoke(callback, payload_, error_);
        return true;
    }

    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    SharedCacheFetchPayload payload_;
    std::exception_ptr error_;
    std::vector<Callback> callbacks_;
};

struct GitHubFileRef
{
    std::string owner;
    std::string repo;
    std::string ref;
    std::string path;
};

struct HttpUrlTarget
{
    bool valid = false;
    std::string host;
};

static CURLcode curl_init();
static std::string dataGet(const std::string &url);
static void shutdownAsyncFetchEngine() noexcept;

static bool has_control_character(const std::string &value)
{
    for(unsigned char ch : value)
    {
        if(std::iscntrl(ch))
            return true;
    }
    return false;
}

static std::string normalize_http_host(std::string host)
{
    host = toLower(host);
    // A single trailing dot is the DNS absolute-name spelling of the same
    // host. Repeated dots remain distinct and are never granted a bypass.
    if(host.size() > 1 && host.back() == '.' && host[host.size() - 2] != '.')
        host.pop_back();
    return host;
}

static bool valid_http_port(const std::string &port)
{
    if(port.empty())
        return false;
    unsigned int value = 0;
    for(unsigned char ch : port)
    {
        if(!std::isdigit(ch))
            return false;
        value = value * 10u + static_cast<unsigned int>(ch - '0');
        if(value > 65535u)
            return false;
    }
    return value != 0;
}

static bool has_invalid_http_host_character(const std::string &host)
{
    for(unsigned char ch : host)
    {
        if(std::iscntrl(ch) || std::isspace(ch) || ch == '/' || ch == '?' ||
           ch == '#' || ch == '@' || ch == '[' || ch == ']' || ch == '%')
            return true;
    }
    return false;
}

#if LIBCURL_VERSION_NUM >= 0x073e00
static bool get_curl_url_part(CURLU *handle, CURLUPart part,
                              unsigned int flags, std::string &value)
{
    char *raw = nullptr;
    if(curl_url_get(handle, part, &raw, flags) != CURLUE_OK)
        return false;
    value.assign(raw);
    curl_free(raw);
    return true;
}
#endif

static HttpUrlTarget parse_http_url_target(const std::string &url)
{
    HttpUrlTarget result;
    if(url.empty() || has_control_character(url))
        return result;

#if LIBCURL_VERSION_NUM >= 0x073e00
    if(curl_init() != CURLE_OK)
        return result;
    CURLU *handle = curl_url();
    if(handle == nullptr)
        return result;
    const CURLUcode set_result =
        curl_url_set(handle, CURLUPART_URL, url.c_str(), 0);
    std::string scheme;
    std::string host;
    bool valid = set_result == CURLUE_OK &&
                 get_curl_url_part(handle, CURLUPART_SCHEME, 0, scheme) &&
                 get_curl_url_part(handle, CURLUPART_HOST, 0, host);
    if(valid)
    {
        scheme = toLower(scheme);
        valid = scheme == "http" || scheme == "https";
    }
    if(valid && host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    if(valid && (host.empty() || has_invalid_http_host_character(host)))
        valid = false;

    char *raw_port = nullptr;
    if(valid)
    {
        const CURLUcode port_result =
            curl_url_get(handle, CURLUPART_PORT, &raw_port, 0);
        if(port_result == CURLUE_OK)
        {
            const std::string port(raw_port);
            curl_free(raw_port);
            raw_port = nullptr;
            valid = valid_http_port(port);
        }
        else if(port_result != CURLUE_NO_PORT)
            valid = false;
    }
    if(raw_port != nullptr)
        curl_free(raw_port);
    curl_url_cleanup(handle);
    if(!valid)
        return result;
    result.host = normalize_http_host(host);
#else
    // curl's URL API was introduced in 7.62. Older supported builds use a
    // deliberately conservative parser: ambiguous or encoded hosts are not
    // eligible for a loopback bypass and restricted requests reject them.
    const size_t scheme_end = url.find("://");
    if(scheme_end == std::string::npos || scheme_end == 0)
        return result;
    const std::string scheme = toLower(url.substr(0, scheme_end));
    if(scheme != "http" && scheme != "https")
        return result;
    const size_t authority_start = scheme_end + 3;
    const size_t authority_end = url.find_first_of("/?#", authority_start);
    std::string authority = url.substr(
        authority_start, authority_end == std::string::npos
                             ? std::string::npos
                             : authority_end - authority_start);
    const size_t userinfo_end = authority.rfind('@');
    if(userinfo_end != std::string::npos)
        authority.erase(0, userinfo_end + 1);
    if(authority.empty())
        return result;

    std::string host;
    std::string port;
    if(authority.front() == '[')
    {
        const size_t close = authority.find(']');
        if(close == std::string::npos || close == 1)
            return result;
        host = authority.substr(1, close - 1);
        if(close + 1 < authority.size())
        {
            if(authority[close + 1] != ':')
                return result;
            port = authority.substr(close + 2);
        }
    }
    else
    {
        const size_t colon = authority.rfind(':');
        if(colon != std::string::npos)
        {
            if(authority.find(':') != colon)
                return result;
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        }
        else
            host = authority;
    }
    if(host.empty() || has_invalid_http_host_character(host) ||
       (!port.empty() && !valid_http_port(port)) || authority.back() == ':')
        return result;
    result.host = normalize_http_host(host);
#endif

    result.valid = !result.host.empty();
    return result;
}

enum class LoopbackKind
{
    None,
    Hostname,
    Ipv4,
    Ipv6,
};

static LoopbackKind classify_loopback_host(const std::string &host)
{
    if(host == "localhost" || endsWith(host, ".localhost"))
        return LoopbackKind::Hostname;

    const client_ip::Address address = client_ip::parseAddress(host);
    if(address.family == client_ip::Family::IPv4 && address.bytes[0] == 127)
        return host.find(':') == std::string::npos ? LoopbackKind::Ipv4
                                                   : LoopbackKind::Ipv6;
    if(address.family != client_ip::Family::IPv6 || address.bytes[15] != 1)
        return LoopbackKind::None;
    for(size_t index = 0; index < 15; ++index)
    {
        if(address.bytes[index] != 0)
            return LoopbackKind::None;
    }
    return LoopbackKind::Ipv6;
}

static std::string initial_bypass_no_proxy_pattern(const std::string &host)
{
    const client_ip::Address address = client_ip::parseAddress(host);
    if(!address.valid())
        // Hostname bypass rules use label-boundary matching before this point.
        // Passing only the actual initial host keeps redirect-time expansion
        // inside that already-authorized domain subtree.
        return host;

#if LIBCURL_VERSION_NUM >= 0x075600
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if(version != nullptr && version->version_num >= 0x075600)
        return host + (host.find(':') == std::string::npos ? "/32" : "/128");
#endif
    // Before 7.86 libcurl cannot express an exact numeric NOPROXY match. A
    // plain IP entry also matches hostname suffixes, so fail closed instead.
    return "";
}

enum class NoProxyDirective
{
    None,
    InheritEnvironment,
    ForceProxy,
    InitialBypass,
};

struct ResolvedProxyRoute
{
    ResolvedProxyPolicy proxy;
    NoProxyDirective no_proxy = NoProxyDirective::None;
    std::string bypass_host;
    std::string bypass_rule;
    std::string no_proxy_pattern;
    std::string inherited_no_proxy;

    std::string cacheIdentity() const
    {
        std::string identity = "routing-v3\n" + proxy.cacheIdentity() +
                               "\nnoproxy=";
        switch(no_proxy)
        {
        case NoProxyDirective::None:
            identity += "none";
            break;
        case NoProxyDirective::InheritEnvironment:
            identity += "inherit:" + inherited_no_proxy;
            break;
        case NoProxyDirective::ForceProxy:
            identity += "force";
            break;
        case NoProxyDirective::InitialBypass:
            identity += "bypass:" + no_proxy_pattern + ":" + bypass_rule;
            break;
        }
        return identity;
    }
};

static ResolvedProxyRoute resolveProxyRoute(
    const ResolvedProxyPolicy &snapshot, const std::string &url,
    FetchContext context)
{
    ResolvedProxyRoute route;
    route.proxy = snapshot;
    switch(snapshot.mode)
    {
    case ProxyMode::Direct:
    case ProxyMode::Cors:
        break;
    case ProxyMode::System:
        if(isPublicFetchRestricted(context) && !snapshot.endpoint.empty())
            // A public request must not inherit a redirect-time bypass that
            // can turn a proxied remote URL into a direct loopback request.
            route.no_proxy = NoProxyDirective::ForceProxy;
        else
        {
            route.no_proxy = NoProxyDirective::InheritEnvironment;
            route.inherited_no_proxy = getEnv("no_proxy");
            if(route.inherited_no_proxy.empty())
                route.inherited_no_proxy = getEnv("NO_PROXY");
        }
        break;
    case ProxyMode::Explicit:
        route.no_proxy = NoProxyDirective::ForceProxy;
        if(!isPublicFetchRestricted(context))
        {
            const HttpUrlTarget target = parse_http_url_target(url);
            const ProxyBypassMatch match =
                target.valid ? snapshot.bypass.matchHost(target.host)
                             : ProxyBypassMatch {};
            const std::string pattern = match.matched
                                            ? initial_bypass_no_proxy_pattern(
                                                  target.host)
                                            : "";
            if(!pattern.empty())
            {
                route.no_proxy = NoProxyDirective::InitialBypass;
                route.bypass_host = target.host;
                route.bypass_rule = match.rule;
                route.no_proxy_pattern = pattern;
            }
        }
        break;
    }
    return route;
}

static std::mutex cache_fetch_mutex;
static std::map<std::string, std::shared_ptr<CacheFetchOperation>>
    cache_fetches;
static std::atomic_bool outbound_fetch_shutdown_requested {false};

void requestOutboundFetchShutdown() noexcept
{
    outbound_fetch_shutdown_requested.store(true, std::memory_order_relaxed);
    shutdownAsyncFetchEngine();
}

class CacheFetchOwnerCleanup
{
public:
    CacheFetchOwnerCleanup(bool owner, std::string key,
                           std::shared_ptr<CacheFetchOperation> operation)
        : owner_(owner), key_(std::move(key)),
          operation_(std::move(operation)) {}
    ~CacheFetchOwnerCleanup()
    {
        if(!owner_)
            return;
        std::lock_guard<std::mutex> lock(cache_fetch_mutex);
        auto iter = cache_fetches.find(key_);
        if(iter != cache_fetches.end() && iter->second == operation_)
            cache_fetches.erase(iter);
    }

private:
    bool owner_;
    std::string key_;
    std::shared_ptr<CacheFetchOperation> operation_;
};

static CURLcode curl_init()
{
    static std::once_flag init_flag;
    static CURLcode init_result = CURLE_FAILED_INIT;
    std::call_once(init_flag, []() {
        init_result = curl_global_init(CURL_GLOBAL_ALL);
    });
    return init_result;
}

static std::string build_cache_key(const std::string &url,
                                   const ResolvedProxyRoute &route,
                                   const string_icase_map *request_headers)
{
    if(route.proxy.mode == ProxyMode::Direct &&
       (!request_headers || request_headers->empty()))
        return getMD5(url);

    std::string identity = "url:" + std::to_string(url.size()) + ":" + url;
    const std::string proxy_identity = route.cacheIdentity();
    identity += "\nproxy:" + std::to_string(proxy_identity.size()) + ":" + proxy_identity;
    identity += "\nheaders:";
    if(request_headers)
    {
        for(const auto &header : *request_headers)
        {
            std::string name = toLower(header.first);
            identity += "\n" + name + ":" + std::to_string(header.second.size()) + ":" +
                        header.second;
        }
        if(!request_headers->contains("User-Agent"))
        {
            std::string default_user_agent = user_agent_str;
            identity += "\nuser-agent:" + std::to_string(default_user_agent.size()) + ":" +
                        default_user_agent;
        }
    }
    return getMD5(identity);
}

static std::string strip_url_query_fragment(const std::string &url)
{
    std::string::size_type pos = url.find_first_of("?#");
    if(pos == std::string::npos)
        return url;
    return url.substr(0, pos);
}

static std::string join_path_segments(const string_array &segments, size_t start,
                                      size_t end)
{
    std::string result;
    for(size_t i = start; i < end; i++)
    {
        if(!result.empty())
            result += "/";
        result += segments[i];
    }
    return result;
}

static bool split_github_ref_path(const string_array &segments, size_t ref_start,
                                  std::string &ref, std::string &path)
{
    if(segments.size() <= ref_start + 1)
        return false;

    size_t path_start = ref_start + 1;
    if(segments[ref_start] == "refs" &&
       (segments[ref_start + 1] == "heads" ||
        segments[ref_start + 1] == "tags"))
    {
        if(segments.size() <= ref_start + 3)
            return false;
        ref = join_path_segments(segments, ref_start, ref_start + 3);
        path_start = ref_start + 3;
    }
    else
        ref = segments[ref_start];

    if(path_start >= segments.size())
        return false;

    path = join_path_segments(segments, path_start, segments.size());
    return !ref.empty() && !path.empty();
}

static bool parse_raw_githubusercontent_url(const std::string &url,
                                            GitHubFileRef &file_ref)
{
    const std::string https_prefix = "https://raw.githubusercontent.com/";
    const std::string http_prefix = "http://raw.githubusercontent.com/";
    std::string content_path;

    if(startsWith(url, https_prefix))
        content_path = url.substr(https_prefix.size());
    else if(startsWith(url, http_prefix))
        content_path = url.substr(http_prefix.size());
    else
        return false;

    string_array segments = split(content_path, "/");
    if(segments.size() < 4)
        return false;

    file_ref.owner = segments[0];
    file_ref.repo = segments[1];
    return split_github_ref_path(segments, 2, file_ref.ref, file_ref.path);
}

static bool parse_github_file_url(const std::string &url, GitHubFileRef &file_ref)
{
    const std::string https_prefix = "https://github.com/";
    const std::string http_prefix = "http://github.com/";
    std::string content_path;

    if(startsWith(url, https_prefix))
        content_path = url.substr(https_prefix.size());
    else if(startsWith(url, http_prefix))
        content_path = url.substr(http_prefix.size());
    else
        return false;

    string_array segments = split(content_path, "/");
    if(segments.size() < 5)
        return false;
    if(segments[2] != "raw" && segments[2] != "blob")
        return false;

    file_ref.owner = segments[0];
    file_ref.repo = segments[1];
    return split_github_ref_path(segments, 3, file_ref.ref, file_ref.path);
}

static bool build_jsdelivr_github_url(const std::string &url,
                                      std::string &fallback_url)
{
    GitHubFileRef file_ref;
    std::string clean_url = strip_url_query_fragment(url);
    if(!parse_raw_githubusercontent_url(clean_url, file_ref) &&
       !parse_github_file_url(clean_url, file_ref))
        return false;

    const std::string scheme = startsWith(clean_url, "http://") ? "http" : "https";
    fallback_url = scheme + "://cdn.jsdelivr.net/gh/" + file_ref.owner + "/" +
                   file_ref.repo + "@" + file_ref.ref + "/" + file_ref.path;
    return true;
}

static bool parse_ipv4_address(const std::string &address, uint32_t &value)
{
    if(!isIPv4(address))
        return false;
    string_array octets = split(address, ".");
    if(octets.size() != 4)
        return false;
    value = 0;
    for(const std::string &octet : octets)
    {
        int part = to_int(octet, -1);
        if(part < 0 || part > 255)
            return false;
        value = (value << 8) | static_cast<uint32_t>(part);
    }
    return true;
}

static bool ipv4_in_cidr(uint32_t address, uint32_t network, unsigned int bits)
{
    uint32_t mask = bits == 0 ? 0 : (0xffffffffu << (32 - bits));
    return (address & mask) == network;
}

static bool is_blocked_ipv4(const std::string &address)
{
    uint32_t ip = 0;
    if(!parse_ipv4_address(address, ip))
        return false;

    return ipv4_in_cidr(ip, 0x00000000u, 8) ||     // 0.0.0.0/8
           ipv4_in_cidr(ip, 0x0a000000u, 8) ||     // 10.0.0.0/8
           ipv4_in_cidr(ip, 0x64400000u, 10) ||    // 100.64.0.0/10
           ipv4_in_cidr(ip, 0x7f000000u, 8) ||     // 127.0.0.0/8
           ipv4_in_cidr(ip, 0xa9fe0000u, 16) ||    // 169.254.0.0/16
           ipv4_in_cidr(ip, 0xac100000u, 12) ||    // 172.16.0.0/12
           ipv4_in_cidr(ip, 0xc0a80000u, 16) ||    // 192.168.0.0/16
           ipv4_in_cidr(ip, 0xc6120000u, 15) ||    // 198.18.0.0/15
           ipv4_in_cidr(ip, 0xe0000000u, 4) ||     // 224.0.0.0/4
           ipv4_in_cidr(ip, 0xf0000000u, 4) ||     // 240.0.0.0/4
           ip == 0xffffffffu;
}

static bool is_fake_ipv4(const std::string &address)
{
    uint32_t ip = 0;
    return parse_ipv4_address(address, ip) && ipv4_in_cidr(ip, 0xc6120000u, 15);
}

static bool is_blocked_ipv6(const std::string &address)
{
    std::string value = toLower(trimWhitespace(address, true, true));
    if(value == "::" || value == "::1")
        return true;
    if(startsWith(value, "fe80:") || startsWith(value, "fe80::"))
        return true;
    if(value.size() >= 2 && value[0] == 'f' &&
       (value[1] == 'c' || value[1] == 'd'))
        return true;
    std::string::size_type mapped = value.rfind(':');
    if(mapped != std::string::npos)
        return is_blocked_ipv4(value.substr(mapped + 1));
    return false;
}

static bool is_blocked_ip_address(const std::string &address,
                                  bool allow_fake_ip = false)
{
    if(allow_fake_ip && is_fake_ipv4(address))
        return false;
    return is_blocked_ipv4(address) || is_blocked_ipv6(address);
}

static bool is_blocked_hostname(const std::string &host)
{
    if(host == "localhost" || endsWith(host, ".localhost"))
        return true;
    if(endsWith(host, ".local") || endsWith(host, ".localdomain") ||
       endsWith(host, ".home.arpa"))
        return true;
    return false;
}

bool isFetchUrlAllowed(const std::string &url, FetchContext context)
{
    if(!isPublicFetchRestricted(context))
        return true;
    std::string checked_url = trimWhitespace(url, true, true);
    std::string log_url = summarizeUrlForLog(checked_url);
    if(checked_url.empty() || checked_url != url || has_control_character(checked_url))
    {
        writeLog(LOG_LEVEL_WARNING, "已阻止公开请求获取格式异常的 URL：" + log_url);
        return false;
    }

    std::string lower_url = toLower(checked_url);
    if(startsWith(lower_url, "data:"))
        return true;
    if(!startsWith(lower_url, "http://") && !startsWith(lower_url, "https://"))
    {
        writeLog(LOG_LEVEL_WARNING, "已阻止公开请求获取不支持协议的 URL：" + log_url);
        return false;
    }

    const HttpUrlTarget target = parse_http_url_target(checked_url);
    if(!target.valid)
    {
        writeLog(LOG_LEVEL_WARNING,
                 "已阻止公开请求获取格式异常的 HTTP(S) URL：" + log_url);
        return false;
    }

    const std::string &host = target.host;
    if(classify_loopback_host(host) != LoopbackKind::None ||
       is_blocked_hostname(host) ||
       is_blocked_ip_address(host))
    {
        writeLog(LOG_LEVEL_WARNING, "已阻止公开请求访问本地或私有主机：" + log_url);
        return false;
    }

    std::string resolved = hostnameToIPAddr(host);
    if(!resolved.empty() && is_blocked_ip_address(resolved, true))
    {
        writeLog(LOG_LEVEL_WARNING,
                 "已阻止公开请求：目标主机解析到本地或私有地址：" + log_url);
        return false;
    }
    return true;
}

#if LIBCURL_VERSION_NUM >= 0x075000
struct curl_prereq_data
{
    bool restricted = false;
};

static int public_fetch_prereq_callback(void *clientp, char *conn_primary_ip,
                                        char *conn_local_ip,
                                        int conn_primary_port,
                                        int conn_local_port)
{
    auto *context = static_cast<curl_prereq_data *>(clientp);
    if(context && context->restricted && conn_primary_ip &&
       is_blocked_ip_address(conn_primary_ip, true))
    {
        writeLog(LOG_LEVEL_WARNING,
                 "已阻止公开请求连接本地或私有地址：" +
                     std::string(conn_primary_ip));
        return CURL_PREREQFUNC_ABORT;
    }
    return CURL_PREREQFUNC_OK;
}
#endif

static bool should_try_jsdelivr_fallback(CURLcode ret_code, int status_code)
{
    if(ret_code != CURLE_OK)
    {
        switch(ret_code)
        {
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_URL_MALFORMAT:
        case CURLE_FAILED_INIT:
        case CURLE_OUT_OF_MEMORY:
        case CURLE_ABORTED_BY_CALLBACK:
        case CURLE_FILESIZE_EXCEEDED:
        case CURLE_WRITE_ERROR:
            return false;
        default:
            return true;
        }
    }

    return status_code == 0 || status_code == 429 || status_code >= 500;
}

static void clear_fetch_output(FetchResult &result)
{
    if(result.content)
        result.content->clear();
    if(result.response_headers)
        result.response_headers->clear();
    if(result.cookies)
        result.cookies->clear();
}

struct curl_writer_data
{
    std::string *output = nullptr;
    curl_progress_data *progress = nullptr;
};

static int writer(char *data, size_t size, size_t nmemb, void *user_data)
{
    auto *writerData = static_cast<curl_writer_data *>(user_data);
    if(writerData == nullptr || writerData->output == nullptr)
        return 0;
    const size_t bytes = size * nmemb;
    if(writerData->progress)
    {
        auto &progress = *writerData->progress;
        const bool retained = progress.request_context
            ? progress.request_context->retainResponseBytes(bytes)
            : progress.retained_bytes.retain(bytes);
        if(!retained)
        {
            progress.abort_reason = AsyncFetchFailure::Capacity;
            return 0;
        }
    }
    writerData->output->append(data, bytes);
    return static_cast<int>(bytes);
}

static int dummy_writer(char *, size_t size, size_t nmemb, void *)
{
    /// dummy writer, do not save anything
    return static_cast<int>(size * nmemb);
}

//static int size_checker(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
static int size_checker(void *clientp, curl_off_t, curl_off_t dlnow, curl_off_t, curl_off_t)
{
    if(outbound_fetch_shutdown_requested.load(std::memory_order_relaxed))
    {
        if(clientp)
            reinterpret_cast<curl_progress_data*>(clientp)->abort_reason =
                AsyncFetchFailure::Shutdown;
        return 1;
    }
    if(clientp)
    {
        auto *data = reinterpret_cast<curl_progress_data*>(clientp);
        if(data->cancellation.isCancellationRequested())
        {
            data->abort_reason = AsyncFetchFailure::Cancelled;
            return 1;
        }
        if(data->deadline != std::chrono::steady_clock::time_point::max() &&
           std::chrono::steady_clock::now() >= data->deadline)
        {
            data->abort_reason = AsyncFetchFailure::Deadline;
            return 1;
        }
        if(data->size_limit)
        {
            if(dlnow > data->size_limit)
            {
                data->abort_reason = AsyncFetchFailure::SizeLimit;
                return 1;
            }
        }
    }
    return 0;
}

static int logger(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
    (void)handle;
    (void)userptr;
    std::string prefix;
    switch(type)
    {
    case CURLINFO_TEXT:
        prefix = "CURL 信息：";
        break;
    case CURLINFO_HEADER_IN:
        prefix = "CURL 响应头：< ";
        break;
    case CURLINFO_HEADER_OUT:
        prefix = "CURL 请求头：> ";
        break;
    case CURLINFO_DATA_IN:
    case CURLINFO_DATA_OUT:
    default:
        return 0;
    }
    std::string content(data, size);
    if(type == CURLINFO_TEXT)
        // Redact the complete callback before splitting physical lines. Curl
        // can decode escaped userinfo into CR/LF inside its auth diagnostic.
        content = redactSensitiveLogText(content);
    auto safe_header_line = [](const std::string &line) {
        std::string value = trimWhitespace(line);
        if(value.empty() || startsWith(value, "HTTP/"))
            return value;
        const std::string::size_type colon = value.find(':');
        if(colon != std::string::npos)
            return value.substr(0, colon) + ": <redacted>";
        const std::string::size_type first_space = value.find(' ');
        const std::string::size_type last_space = value.rfind(' ');
        if(first_space != std::string::npos && last_space > first_space)
            return value.substr(0, first_space) + " <redacted> " +
                   value.substr(last_space + 1);
        return std::string("<redacted>");
    };
    if(content.find("\r\n") != std::string::npos)
    {
        string_array lines = split(content, "\r\n");
        for(auto &x : lines)
        {
            std::string log_content = prefix;
            log_content += type == CURLINFO_TEXT ? x : safe_header_line(x);
            writeLog(LOG_LEVEL_VERBOSE, log_content);
        }
    }
    else
    {
        std::string log_content = prefix;
        log_content += type == CURLINFO_TEXT ? trimWhitespace(content)
                                             : safe_header_line(content);
        writeLog(LOG_LEVEL_VERBOSE, log_content);
    }
    return 0;
}

static CURLcode curl_set_platform_tls_trust(CURL *curl_handle)
{
#if defined(_WIN32) && LIBCURL_VERSION_NUM >= 0x074700
    // Official Windows artifacts use libcurl with OpenSSL.  Ask libcurl to
    // consult the Windows certificate stores in addition to any build-time CA
    // locations so a portable archive does not depend on an MSYS2 path that is
    // absent on the target machine.  Keep the runtime guard for installations
    // that provide an older libcurl DLL than the headers used to compile us.
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if(version == nullptr || version->version_num < 0x074700)
        return CURLE_OK;

    const long ssl_options = static_cast<long>(CURLSSLOPT_NATIVE_CA);
    CURLcode result = curl_easy_setopt(curl_handle, CURLOPT_SSL_OPTIONS,
                                       ssl_options);
    if(result != CURLE_OK)
        return result;

    // HTTPS proxies have an independent TLS connection and option set.
    return curl_easy_setopt(curl_handle, CURLOPT_PROXY_SSL_OPTIONS,
                            ssl_options);
#else
    (void)curl_handle;
    return CURLE_OK;
#endif
}

static std::chrono::steady_clock::time_point networkFetchDeadline(
    std::chrono::steady_clock::time_point requested)
{
    const std::shared_ptr<RequestContext> context =
        captureCurrentRequestContext();
    const auto context_deadline =
        context ? context->deadline()
                : std::chrono::steady_clock::time_point::max();
    if(requested == std::chrono::steady_clock::time_point::max())
    {
        if(context_deadline !=
           std::chrono::steady_clock::time_point::max())
            requested = context_deadline;
        else
            requested = std::chrono::steady_clock::now() +
                        std::chrono::seconds(15);
    }
    if(context_deadline != std::chrono::steady_clock::time_point::max())
        requested = std::min(requested, context_deadline);
    return requested;
}

static inline void curl_set_common_options(CURL *curl_handle, const char *url,
                                           curl_progress_data *data,
                                           bool allow_insecure_tls)
{
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, shouldLog(LOG_LEVEL_VERBOSE) ? 1L : 0L);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, logger);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 20L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl_handle, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl_handle, CURLOPT_REDIR_PROTOCOLS,
                     static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER,
                     allow_insecure_tls ? 0L : 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST,
                     allow_insecure_tls ? 0L : 2L);
    long timeout_ms = 15000L;
    if(data && data->deadline !=
                   std::chrono::steady_clock::time_point::max())
    {
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(data->deadline -
                                      std::chrono::steady_clock::now());
        timeout_ms = static_cast<long>(
            std::clamp<int64_t>(remaining.count(), 1,
                                static_cast<int64_t>(LONG_MAX)));
    }
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl_handle, CURLOPT_COOKIEFILE, "");
    if(data)
    {
        if(data->size_limit)
            curl_easy_setopt(curl_handle, CURLOPT_MAXFILESIZE, data->size_limit);
        curl_easy_setopt(curl_handle, CURLOPT_XFERINFOFUNCTION, size_checker);
        curl_easy_setopt(curl_handle, CURLOPT_XFERINFODATA, data);
    }
}

static CURLcode apply_curl_proxy_policy(CURL *curl_handle,
                                         const ResolvedProxyRoute &route,
                                         std::string &url)
{
    const ResolvedProxyPolicy &effective = route.proxy;
    if(!effective.valid)
    {
        writeLog(LOG_LEVEL_ERROR, "出站代理配置无效：" + effective.describe() + "。");
        return CURLE_URL_MALFORMAT;
    }

    switch(effective.mode)
    {
    case ProxyMode::Direct:
        // CURLOPT_PROXY="" is libcurl's documented way to suppress every
        // environment-derived proxy for this request.
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, "");
        break;
    case ProxyMode::System:
        if(effective.endpoint.empty())
            curl_easy_setopt(curl_handle, CURLOPT_PROXY, "");
        else
            curl_easy_setopt(curl_handle, CURLOPT_PROXY,
                             effective.endpoint.c_str());
        if(route.no_proxy == NoProxyDirective::ForceProxy)
            curl_easy_setopt(curl_handle, CURLOPT_NOPROXY, "");
        else if(route.no_proxy == NoProxyDirective::InheritEnvironment)
            // Apply the value captured with the proxy snapshot so the cache
            // identity and actual transfer cannot observe different state.
            curl_easy_setopt(curl_handle, CURLOPT_NOPROXY,
                             route.inherited_no_proxy.c_str());
        break;
    case ProxyMode::Explicit:
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, effective.endpoint.c_str());
        if(route.no_proxy == NoProxyDirective::InitialBypass)
            curl_easy_setopt(curl_handle, CURLOPT_NOPROXY,
                             route.no_proxy_pattern.c_str());
        else
            // An explicitly configured proxy is fail-closed and must not be
            // bypassed by an inherited NO_PROXY/no_proxy environment variable.
            curl_easy_setopt(curl_handle, CURLOPT_NOPROXY, "");
        break;
    case ProxyMode::Cors:
        // cors: names an HTTP relay URL, not a libcurl network proxy.  Its
        // transport is direct so ambient proxy variables cannot alter it.
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, "");
        url = effective.endpoint + url;
        break;
    }

    if(shouldLog(LOG_LEVEL_VERBOSE))
    {
        std::string description = "出站代理策略：" + effective.describe();
        if(effective.mode == ProxyMode::Explicit)
            description += "；proxy_bypass：" +
                           effective.bypass.describe();
        if(route.no_proxy == NoProxyDirective::InitialBypass)
            description += "；初始主机按 proxy_bypass 直连：" +
                           route.bypass_host + "；匹配规则：" +
                           route.bypass_rule;
        writeLog(LOG_LEVEL_VERBOSE, description + "。");
    }
    return CURLE_OK;
}

static const char *classify_curl_error(CURLcode code)
{
    switch(code)
    {
    case CURLE_OK:
        return "none";
    case CURLE_COULDNT_RESOLVE_PROXY:
        return "proxy_dns";
#if LIBCURL_VERSION_NUM >= 0x074900
    case CURLE_PROXY:
        return "proxy";
#endif
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
        return "tls";
    case CURLE_SSL_CACERT_BADFILE:
        return "tls_trust_store";
    case CURLE_LOGIN_DENIED:
        return "authentication";
    default:
        return "transport";
    }
}

// A single retry is intentionally limited to idempotent transfers and errors
// that can plausibly be transient.  Authentication, TLS, policy validation,
// HTTP status failures, and non-idempotent uploads never take this path.
static bool is_recoverable_curl_error(CURLcode code)
{
    switch(code)
    {
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_CONNECT:
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_PARTIAL_FILE:
        return true;
    default:
        return false;
    }
}

static AsyncFetchFailure classify_async_failure(
    CURLcode code, const curl_progress_data &progress)
{
    if(progress.abort_reason != AsyncFetchFailure::None)
        return progress.abort_reason;
    switch(code)
    {
    case CURLE_OK:
        return AsyncFetchFailure::None;
    case CURLE_ABORTED_BY_CALLBACK:
        return AsyncFetchFailure::Cancelled;
    case CURLE_OPERATION_TIMEDOUT:
        return AsyncFetchFailure::Deadline;
    case CURLE_FILESIZE_EXCEEDED:
        return AsyncFetchFailure::SizeLimit;
    case CURLE_WRITE_ERROR:
        return progress.abort_reason == AsyncFetchFailure::None
                   ? AsyncFetchFailure::Transport
                   : progress.abort_reason;
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
        return AsyncFetchFailure::Dns;
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CACERT_BADFILE:
        return AsyncFetchFailure::Tls;
#if LIBCURL_VERSION_NUM >= 0x074900
    case CURLE_PROXY:
#endif
    case CURLE_LOGIN_DENIED:
        return AsyncFetchFailure::Proxy;
    default:
        return AsyncFetchFailure::Transport;
    }
}

namespace {

class CurlMultiEngine;
std::atomic<CurlMultiEngine *> multi_engine_instance{nullptr};

class CurlMultiEngine
{
    struct Transfer
    {
        AsyncFetchRequest request;
        ResolvedProxyRoute route;
        bool allow_insecure_tls = false;
        long size_limit = 0;
        CURL *easy = nullptr;
        curl_slist *header_list = nullptr;
        std::string effective_url;
        curl_prereq_data prereq_context;
        curl_progress_data progress;
        RequestCancellationRegistration cancellation_registration;
        SharedAsyncFetchResult result =
            std::make_shared<AsyncFetchResult>();
        AsyncFetchCompletion completion;
        std::atomic<bool> completed{false};
        bool retry_attempted = false;
        std::chrono::steady_clock::time_point retry_at =
            std::chrono::steady_clock::time_point::max();
    };

public:
    CurlMultiEngine()
    {
        multi_engine_instance.store(this, std::memory_order_release);
        if(curl_init() != CURLE_OK)
            return;
        const curl_version_info_data *version =
            curl_version_info(CURLVERSION_NOW);
        if(version == nullptr ||
           (version->features & CURL_VERSION_ASYNCHDNS) == 0)
        {
            writeLog(LOG_LEVEL_ERROR,
                     "OUTBOUND_MULTI_DISABLED reason=blocking-resolver");
            return;
        }
        multi_ = curl_multi_init();
        if(multi_ == nullptr)
            return;
        const ResourceControlSnapshot resources = resourceControlSnapshot();
        const long total_connections =
            resources.effective_mode == "force_max" &&
                resources.startup_budget_applied
                ? static_cast<long>(std::clamp<uint64_t>(
                      resources.suggested_outbound_connections, 1,
                      static_cast<uint64_t>(LONG_MAX)))
                : 64L;
        const long host_connections =
            resources.effective_mode == "force_max" &&
                resources.startup_budget_applied
                ? total_connections
                : std::min(16L, total_connections);
        curl_multi_setopt(multi_, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                          total_connections);
        curl_multi_setopt(multi_, CURLMOPT_MAX_HOST_CONNECTIONS,
                          host_connections);
        curl_multi_setopt(multi_, CURLMOPT_MAXCONNECTS, total_connections);
#ifdef CURLPIPE_MULTIPLEX
        curl_multi_setopt(multi_, CURLMOPT_PIPELINING,
                          static_cast<long>(CURLPIPE_MULTIPLEX));
#endif
        available_.store(true, std::memory_order_release);
        worker_ = std::thread([this]() { run(); });
        writeLog(LOG_LEVEL_INFO,
                 "OUTBOUND_MULTI_ENGINE resolver=asynchronous "
                 "total_connections=" + std::to_string(total_connections) +
                 " host_connections=" + std::to_string(host_connections) +
                 " wakeup=" +
                 (wakeupAvailable() ? "enabled" : "legacy-poll"));
    }

    ~CurlMultiEngine()
    {
        shutdown();
        if(multi_)
            curl_multi_cleanup(multi_);
        multi_engine_instance.store(nullptr, std::memory_order_release);
    }

    CurlMultiEngine(const CurlMultiEngine &) = delete;
    CurlMultiEngine &operator=(const CurlMultiEngine &) = delete;

    bool available() const noexcept
    {
        return available_.load(std::memory_order_acquire);
    }

    void submit(
        AsyncFetchRequest request, ResolvedProxyRoute route,
        bool allow_insecure_tls, long size_limit,
        AsyncFetchCompletion completion)
    {
        auto transfer = std::make_shared<Transfer>();
        transfer->request = std::move(request);
        transfer->route = std::move(route);
        transfer->allow_insecure_tls = allow_insecure_tls;
        transfer->size_limit = size_limit;
        transfer->completion = std::move(completion);
        transfer->cancellation_registration =
            transfer->request.cancellation.registerCallback(
                [this] { wakeWorker(); });
        bool rejected = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(stopping_ || !available())
            {
                transfer->result->transport_code = CURLE_ABORTED_BY_CALLBACK;
                transfer->result->failure = stopping_
                    ? AsyncFetchFailure::Shutdown
                    : AsyncFetchFailure::Transport;
                rejected = true;
            }
            else
            {
                pending_.emplace_back(transfer);
                pending_count_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        if(rejected)
        {
            complete(transfer);
            return;
        }
        wakeWorker();
    }

    AsyncFetchFuture submit(
        AsyncFetchRequest request, ResolvedProxyRoute route,
        bool allow_insecure_tls, long size_limit)
    {
        auto promise =
            std::make_shared<std::promise<SharedAsyncFetchResult>>();
        AsyncFetchFuture future = promise->get_future().share();
        submit(std::move(request), std::move(route), allow_insecure_tls,
               size_limit,
               [promise](SharedAsyncFetchResult result) noexcept {
                   try
                   {
                       promise->set_value(std::move(result));
                   }
                   catch(...)
                   {
                   }
               });
        return future;
    }

    void shutdown() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(stopping_)
                return;
            stopping_ = true;
        }
        wakeWorker();
        if(worker_.joinable())
            worker_.join();
        available_.store(false, std::memory_order_release);
    }

    AsyncFetchEngineSnapshot snapshot() const noexcept
    {
        const RetainedResponseByteSnapshot retained =
            retainedResponseByteSnapshot();
        return AsyncFetchEngineSnapshot{
            available(), wakeupAvailable(),
            pending_count_.load(std::memory_order_relaxed),
            active_count_.load(std::memory_order_relaxed),
            retained.used};
    }

private:
    static constexpr bool wakeupAvailable() noexcept
    {
#if LIBCURL_VERSION_NUM >= 0x074400
        return true;
#else
        return false;
#endif
    }

    void wakeWorker() noexcept
    {
        wake_generation_.fetch_add(1, std::memory_order_release);
        condition_.notify_all();
#if LIBCURL_VERSION_NUM >= 0x074400
        if(multi_)
            (void)curl_multi_wakeup(multi_);
#endif
    }

    static size_t bodyWriter(char *data, size_t size, size_t nmemb,
                             void *user_data)
    {
        auto *transfer = static_cast<Transfer *>(user_data);
        const size_t bytes = size * nmemb;
        if(!transfer->request.capture_content)
            return bytes;
        if(transfer->size_limit > 0 &&
           bytes > static_cast<size_t>(transfer->size_limit) -
                       std::min<size_t>(
                           transfer->result->content.size(),
                           static_cast<size_t>(transfer->size_limit)))
        {
            transfer->progress.abort_reason = AsyncFetchFailure::SizeLimit;
            return 0;
        }
        const bool retained = transfer->request.request_context
            ? transfer->request.request_context->retainResponseBytes(bytes)
            : transfer->result->retained_bytes.retain(bytes);
        if(!retained)
        {
            transfer->progress.abort_reason = AsyncFetchFailure::Capacity;
            return 0;
        }
        transfer->result->content.append(data, bytes);
        return bytes;
    }

    static size_t headerWriter(char *data, size_t size, size_t nmemb,
                               void *user_data)
    {
        auto *transfer = static_cast<Transfer *>(user_data);
        const size_t bytes = size * nmemb;
        if(transfer->request.capture_response_headers)
        {
            const bool retained = transfer->request.request_context
                ? transfer->request.request_context->retainResponseBytes(bytes)
                : transfer->result->retained_bytes.retain(bytes);
            if(!retained)
            {
                transfer->progress.abort_reason = AsyncFetchFailure::Capacity;
                return 0;
            }
            transfer->result->response_headers.append(data, bytes);
        }
        return bytes;
    }

    CURLcode configure(const std::shared_ptr<Transfer> &transfer)
    {
        transfer->easy = curl_easy_init();
        if(transfer->easy == nullptr)
            return CURLE_FAILED_INIT;
        transfer->effective_url = transfer->request.url;
        CURLcode code = apply_curl_proxy_policy(
            transfer->easy, transfer->route, transfer->effective_url);
        if(code != CURLE_OK)
            return code;

        transfer->progress.size_limit = transfer->size_limit;
        transfer->progress.deadline = transfer->request.deadline;
        transfer->progress.cancellation = transfer->request.cancellation;
        curl_set_common_options(transfer->easy,
                                transfer->effective_url.c_str(),
                                &transfer->progress,
                                transfer->allow_insecure_tls);
        code = curl_set_platform_tls_trust(transfer->easy);
        if(code != CURLE_OK)
            return code;

        if(transfer->route.proxy.mode == ProxyMode::Cors)
            transfer->header_list = curl_slist_append(
                transfer->header_list,
                "X-Requested-With: SubConverter-Extended " VERSION);
        transfer->header_list = curl_slist_append(
            transfer->header_list,
            "Content-Type: application/json;charset=utf-8");
        for(const auto &header : transfer->request.request_headers)
        {
            const std::string value = header.first + ": " + header.second;
            transfer->header_list = curl_slist_append(
                transfer->header_list, value.c_str());
        }
        if(!transfer->request.request_headers.contains("User-Agent"))
            curl_easy_setopt(transfer->easy, CURLOPT_USERAGENT,
                             user_agent_str);
        if(transfer->header_list)
            curl_easy_setopt(transfer->easy, CURLOPT_HTTPHEADER,
                             transfer->header_list);

        curl_easy_setopt(transfer->easy, CURLOPT_WRITEFUNCTION, bodyWriter);
        curl_easy_setopt(transfer->easy, CURLOPT_WRITEDATA, transfer.get());
        curl_easy_setopt(transfer->easy, CURLOPT_HEADERFUNCTION, headerWriter);
        curl_easy_setopt(transfer->easy, CURLOPT_HEADERDATA, transfer.get());

        if(!transfer->request.cookies.empty())
        {
            for(const std::string &cookie :
                split(transfer->request.cookies, "\r\n"))
                curl_easy_setopt(transfer->easy, CURLOPT_COOKIELIST,
                                 cookie.c_str());
        }

#if LIBCURL_VERSION_NUM >= 0x075000
        transfer->prereq_context.restricted =
            transfer->request.public_fetch_restricted;
        if(transfer->request.public_fetch_restricted &&
           (transfer->route.proxy.mode == ProxyMode::Direct ||
            (transfer->route.proxy.mode == ProxyMode::System &&
             transfer->route.proxy.endpoint.empty())))
        {
            curl_easy_setopt(transfer->easy, CURLOPT_PREREQFUNCTION,
                             public_fetch_prereq_callback);
            curl_easy_setopt(transfer->easy, CURLOPT_PREREQDATA,
                             &transfer->prereq_context);
        }
#endif

        switch(transfer->request.method)
        {
        case HTTP_POST:
            curl_easy_setopt(transfer->easy, CURLOPT_POST, 1L);
            if(transfer->request.has_post_data)
            {
                curl_easy_setopt(transfer->easy, CURLOPT_POSTFIELDS,
                                 transfer->request.post_data.data());
                curl_easy_setopt(transfer->easy, CURLOPT_POSTFIELDSIZE,
                                 transfer->request.post_data.size());
            }
            break;
        case HTTP_PATCH:
            curl_easy_setopt(transfer->easy, CURLOPT_CUSTOMREQUEST, "PATCH");
            if(transfer->request.has_post_data)
            {
                curl_easy_setopt(transfer->easy, CURLOPT_POSTFIELDS,
                                 transfer->request.post_data.data());
                curl_easy_setopt(transfer->easy, CURLOPT_POSTFIELDSIZE,
                                 transfer->request.post_data.size());
            }
            break;
        case HTTP_HEAD:
            curl_easy_setopt(transfer->easy, CURLOPT_NOBODY, 1L);
            break;
        case HTTP_GET:
            break;
        }
        return CURLE_OK;
    }

    void finish(std::shared_ptr<Transfer> transfer, CURLcode code,
                bool added)
    {
        transfer->cancellation_registration.reset();
        if(added)
            active_count_.fetch_sub(1, std::memory_order_relaxed);
        if(added && multi_ && transfer->easy)
            curl_multi_remove_handle(multi_, transfer->easy);
        if(transfer->easy)
        {
            long status = 0;
            curl_easy_getinfo(transfer->easy, CURLINFO_HTTP_CODE, &status);
            transfer->result->status_code = static_cast<int>(status);
#if LIBCURL_VERSION_NUM >= 0x080700
            long used_proxy = 0;
            if(curl_easy_getinfo(transfer->easy, CURLINFO_USED_PROXY,
                                 &used_proxy) == CURLE_OK)
                transfer->result->used_proxy = used_proxy != 0;
#endif
#if LIBCURL_VERSION_NUM >= 0x074900
            curl_easy_getinfo(transfer->easy, CURLINFO_PROXY_ERROR,
                              &transfer->result->proxy_error);
#endif
            if(transfer->request.capture_cookies)
            {
                curl_slist *cookies = nullptr;
                curl_easy_getinfo(transfer->easy, CURLINFO_COOKIELIST,
                                  &cookies);
                for(curl_slist *item = cookies; item; item = item->next)
                {
                    transfer->result->cookies.append(item->data);
                    transfer->result->cookies += "\r\n";
                }
                curl_slist_free_all(cookies);
            }
        }
        transfer->result->transport_code = static_cast<int>(code);
        transfer->result->failure = classify_async_failure(
            code, transfer->progress);
        const bool retry = code != CURLE_OK && !transfer->retry_attempted &&
            (transfer->request.method == HTTP_GET ||
             transfer->request.method == HTTP_HEAD) &&
            is_recoverable_curl_error(code) &&
            !stopping_.load(std::memory_order_acquire) &&
            !transfer->request.cancellation.isCancellationRequested() &&
            std::chrono::steady_clock::now() + std::chrono::milliseconds(200) <
                transfer->request.deadline;
        if(!transfer->request.keep_resp_on_fail &&
           (code != CURLE_OK || transfer->result->status_code != 200))
            transfer->result->content.clear();
        curl_slist_free_all(transfer->header_list);
        transfer->header_list = nullptr;
        if(transfer->easy)
        {
            active_.erase(transfer->easy);
            curl_easy_cleanup(transfer->easy);
            transfer->easy = nullptr;
        }
        if(retry)
        {
            writeLog(LOG_LEVEL_WARNING,
                     "出站请求遇到可恢复网络错误，200ms 后重试一次。");
            if(!transfer->result->cookies.empty())
                transfer->request.cookies = transfer->result->cookies;
            transfer->result = std::make_shared<AsyncFetchResult>();
            transfer->progress = {};
            transfer->prereq_context = {};
            transfer->cancellation_registration =
                transfer->request.cancellation.registerCallback(
                    [this] { wakeWorker(); });
            transfer->retry_attempted = true;
            transfer->retry_at = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(200);
            delayed_.emplace_back(std::move(transfer));
            pending_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        complete(transfer);
    }

    static void complete(const std::shared_ptr<Transfer> &transfer) noexcept
    {
        if(!transfer ||
           transfer->completed.exchange(true, std::memory_order_acq_rel))
            return;
        AsyncFetchCompletion completion = std::move(transfer->completion);
        if(!completion)
            return;
        try
        {
            completion(std::move(transfer->result));
        }
        catch(...)
        {
        }
    }

    void processPending()
    {
        std::deque<std::shared_ptr<Transfer>> pending;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending.swap(pending_);
            pending_count_.fetch_sub(pending.size(),
                                     std::memory_order_relaxed);
        }
        for(auto &transfer : pending)
            startTransfer(std::move(transfer));
    }

    void startTransfer(std::shared_ptr<Transfer> transfer)
    {
        if(!transfer)
            return;
        transfer->retry_at = std::chrono::steady_clock::time_point::max();
        if(stopping_)
        {
            transfer->progress.abort_reason = AsyncFetchFailure::Shutdown;
            finish(transfer, CURLE_ABORTED_BY_CALLBACK, false);
            return;
        }
        if(transfer->request.cancellation.isCancellationRequested())
        {
            transfer->progress.abort_reason =
                transfer->request.cancellation.reason() ==
                        RequestCancellationReason::Shutdown
                    ? AsyncFetchFailure::Shutdown
                    : AsyncFetchFailure::Cancelled;
            finish(transfer, CURLE_ABORTED_BY_CALLBACK, false);
            return;
        }
        if(transfer->request.deadline !=
               std::chrono::steady_clock::time_point::max() &&
           std::chrono::steady_clock::now() >= transfer->request.deadline)
        {
            transfer->progress.abort_reason = AsyncFetchFailure::Deadline;
            finish(transfer, CURLE_OPERATION_TIMEDOUT, false);
            return;
        }
        const CURLcode code = configure(transfer);
        if(code != CURLE_OK)
        {
            finish(transfer, code, false);
            return;
        }
        const CURLMcode multi_code =
            curl_multi_add_handle(multi_, transfer->easy);
        if(multi_code != CURLM_OK)
        {
            finish(transfer, CURLE_FAILED_INIT, false);
            return;
        }
        active_[transfer->easy] = transfer;
        active_count_.fetch_add(1, std::memory_order_relaxed);
    }

    void processDelayed()
    {
        const auto now = std::chrono::steady_clock::now();
        for(auto iter = delayed_.begin(); iter != delayed_.end();)
        {
            const std::shared_ptr<Transfer> transfer = *iter;
            if(stopping_ ||
               transfer->request.cancellation.isCancellationRequested() ||
               (transfer->request.deadline !=
                    std::chrono::steady_clock::time_point::max() &&
                now >= transfer->request.deadline))
            {
                iter = delayed_.erase(iter);
                pending_count_.fetch_sub(1, std::memory_order_relaxed);
                if(stopping_ || transfer->request.cancellation.reason() ==
                                     RequestCancellationReason::Shutdown)
                    transfer->progress.abort_reason =
                        AsyncFetchFailure::Shutdown;
                else if(transfer->request.cancellation.reason() ==
                            RequestCancellationReason::Deadline ||
                        now >= transfer->request.deadline)
                    transfer->progress.abort_reason =
                        AsyncFetchFailure::Deadline;
                else
                    transfer->progress.abort_reason =
                        AsyncFetchFailure::Cancelled;
                finish(transfer,
                       transfer->progress.abort_reason ==
                               AsyncFetchFailure::Deadline
                           ? CURLE_OPERATION_TIMEDOUT
                           : CURLE_ABORTED_BY_CALLBACK,
                       false);
                continue;
            }
            if(now < transfer->retry_at)
            {
                ++iter;
                continue;
            }
            iter = delayed_.erase(iter);
            pending_count_.fetch_sub(1, std::memory_order_relaxed);
            startTransfer(transfer);
        }
    }

    void performTransfers()
    {
        CURLMcode code;
        do
        {
            code = curl_multi_perform(multi_, &running_handles_);
        }
        while(code == CURLM_CALL_MULTI_PERFORM);
        drainMessages();
    }

    void drainMessages()
    {
        int remaining = 0;
        while(CURLMsg *message = curl_multi_info_read(multi_, &remaining))
        {
            if(message->msg != CURLMSG_DONE)
                continue;
            auto found = active_.find(message->easy_handle);
            if(found != active_.end())
                finish(found->second, message->data.result, true);
        }
    }

    void waitForActivity()
    {
        if(active_.empty())
        {
            std::unique_lock<std::mutex> lock(mutex_);
            const uint64_t generation =
                wake_generation_.load(std::memory_order_acquire);
            if(stopping_ || !pending_.empty())
                return;
            for(const auto &transfer : delayed_)
            {
                if(transfer->request.cancellation.isCancellationRequested() ||
                   (transfer->request.deadline !=
                        std::chrono::steady_clock::time_point::max() &&
                    std::chrono::steady_clock::now() >=
                        transfer->request.deadline))
                    return;
            }
            const auto awakened = [this, generation]() {
                return stopping_ || !pending_.empty() ||
                       wake_generation_.load(std::memory_order_acquire) !=
                           generation;
            };
            if(delayed_.empty())
                condition_.wait(lock, awakened);
            else
            {
                const auto next = std::min_element(
                    delayed_.begin(), delayed_.end(),
                    [](const auto &left, const auto &right) {
                        return left->retry_at < right->retry_at;
                    });
                condition_.wait_until(lock, (*next)->retry_at, awakened);
            }
            return;
        }

        int timeout_ms = 50;
#if LIBCURL_VERSION_NUM >= 0x074400
        timeout_ms = 1000;
        long curl_timeout_ms = -1;
        if(curl_multi_timeout(multi_, &curl_timeout_ms) == CURLM_OK &&
           curl_timeout_ms >= 0)
            timeout_ms = static_cast<int>(
                std::clamp<long>(curl_timeout_ms, 0, timeout_ms));
        const auto now = std::chrono::steady_clock::now();
        for(const auto &[easy, transfer] : active_)
        {
            (void)easy;
            if(transfer->request.deadline ==
               std::chrono::steady_clock::time_point::max())
                continue;
            const auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(transfer->request.deadline - now);
            const int deadline_timeout = static_cast<int>(
                std::clamp<int64_t>(remaining.count(), 0, timeout_ms));
            timeout_ms = std::min(timeout_ms, deadline_timeout);
        }
        for(const auto &transfer : delayed_)
        {
            const auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(transfer->retry_at - now);
            timeout_ms = std::min(
                timeout_ms, static_cast<int>(std::clamp<int64_t>(
                                remaining.count(), 0, timeout_ms)));
        }
#endif
        int ready = 0;
        // Let libcurl use poll-capable primitives. The HTTP server may already
        // hold thousands of client sockets, so outbound descriptors can exceed
        // FD_SETSIZE even when the multi handle itself has few connections.
#if LIBCURL_VERSION_NUM >= 0x074200
        const CURLMcode code =
            curl_multi_poll(multi_, nullptr, 0, timeout_ms, &ready);
#else
        const CURLMcode code =
            curl_multi_wait(multi_, nullptr, 0, timeout_ms, &ready);
#endif
        if(code != CURLM_OK)
            writeLog(LOG_LEVEL_ERROR,
                     "OUTBOUND_MULTI_POLL_ERROR code=" +
                         std::to_string(static_cast<int>(code)));
    }

    void cancelActive()
    {
        std::vector<std::shared_ptr<Transfer>> active;
        active.reserve(active_.size());
        for(const auto &[easy, transfer] : active_)
        {
            (void)easy;
            active.emplace_back(transfer);
        }
        for(auto &transfer : active)
        {
            transfer->progress.abort_reason = AsyncFetchFailure::Shutdown;
            finish(transfer, CURLE_ABORTED_BY_CALLBACK, true);
        }
    }

    void cancelExpired()
    {
        std::vector<std::pair<std::shared_ptr<Transfer>, CURLcode>> cancelled;
        const auto now = std::chrono::steady_clock::now();
        for(const auto &[easy, transfer] : active_)
        {
            (void)easy;
            if(transfer->request.cancellation.isCancellationRequested())
            {
                transfer->progress.abort_reason =
                    transfer->request.cancellation.reason() ==
                            RequestCancellationReason::Shutdown
                        ? AsyncFetchFailure::Shutdown
                        : AsyncFetchFailure::Cancelled;
                cancelled.emplace_back(transfer, CURLE_ABORTED_BY_CALLBACK);
            }
            else if(transfer->request.deadline !=
                        std::chrono::steady_clock::time_point::max() &&
                    now >= transfer->request.deadline)
            {
                transfer->progress.abort_reason = AsyncFetchFailure::Deadline;
                cancelled.emplace_back(transfer, CURLE_OPERATION_TIMEDOUT);
            }
        }
        for(auto &[transfer, code] : cancelled)
            finish(std::move(transfer), code, true);
    }

    void run()
    {
        for(;;)
        {
            processPending();
            processDelayed();
            performTransfers();
            cancelExpired();
            bool stopping = false;
            std::deque<std::shared_ptr<Transfer>> pending;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping = stopping_;
                if(stopping)
                {
                    pending.swap(pending_);
                    pending_count_.fetch_sub(pending.size(),
                                             std::memory_order_relaxed);
                }
            }
            if(stopping)
            {
                cancelActive();
                for(auto &transfer : pending)
                {
                    transfer->progress.abort_reason =
                        AsyncFetchFailure::Shutdown;
                    finish(transfer, CURLE_ABORTED_BY_CALLBACK, false);
                }
                while(!delayed_.empty())
                {
                    auto transfer = std::move(delayed_.front());
                    delayed_.pop_front();
                    pending_count_.fetch_sub(1, std::memory_order_relaxed);
                    transfer->progress.abort_reason =
                        AsyncFetchFailure::Shutdown;
                    finish(transfer, CURLE_ABORTED_BY_CALLBACK, false);
                }
                break;
            }
            waitForActivity();
        }
    }

    CURLM *multi_ = nullptr;
    std::atomic<bool> available_{false};
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::shared_ptr<Transfer>> pending_;
    std::deque<std::shared_ptr<Transfer>> delayed_;
    std::unordered_map<CURL *, std::shared_ptr<Transfer>> active_;
    std::atomic<uint64_t> pending_count_{0};
    std::atomic<uint64_t> active_count_{0};
    std::atomic<uint64_t> wake_generation_{0};
    std::atomic<bool> stopping_{false};
    int running_handles_ = 0;
};

CurlMultiEngine &multiEngine()
{
    static CurlMultiEngine engine;
    return engine;
}

} // namespace

bool asyncFetchEngineAvailable() noexcept
{
    return multiEngine().available();
}

AsyncFetchEngineSnapshot asyncFetchEngineSnapshot() noexcept
{
    if(CurlMultiEngine *engine =
           multi_engine_instance.load(std::memory_order_acquire))
        return engine->snapshot();
    const RetainedResponseByteSnapshot retained =
        retainedResponseByteSnapshot();
    return {false, false, 0, 0, retained.used};
}

void webGetAsync(AsyncFetchRequest request, AsyncFetchCompletion completion)
{
    if(!completion)
        return;
    if(!request.request_context)
        request.request_context = captureCurrentRequestContext();
    request.public_fetch_restricted =
        isPublicFetchRestricted(request.context);
    if(!isFetchUrlAllowed(request.url, request.context))
    {
        AsyncFetchResult result;
        result.status_code = 403;
        completion(std::make_shared<AsyncFetchResult>(std::move(result)));
        return;
    }
    if(request.method == HTTP_GET)
    {
        const CocrSourceResolution source = resolveCocrSourceUrl(
            request.url,
            effectiveSettings().customOpenClashRulesSourceSwitch);
        request.url = source.effective_url;
    }
    if(startsWith(request.url, "data:"))
    {
        AsyncFetchResult result;
        if(request.capture_content)
            result.content = dataGet(request.url);
        if(!result.content.empty())
        {
            const bool retained = request.request_context
                ? request.request_context->retainResponseBytes(
                      result.content.size())
                : result.retained_bytes.retain(result.content.size());
            if(!retained)
            {
                result.content.clear();
                result.failure = AsyncFetchFailure::Capacity;
            }
        }
        result.status_code = !request.capture_content || !result.content.empty()
                                 ? 200
                                 : 400;
        completion(std::make_shared<AsyncFetchResult>(std::move(result)));
        return;
    }
    if(request.deadline == std::chrono::steady_clock::time_point::max())
        request.deadline = networkFetchDeadline(request.deadline);
    if(!request.cancellation.valid())
    {
        if(auto context = captureCurrentRequestContext())
            request.cancellation = context->cancellationToken();
    }
    const Settings &settings = effectiveSettings();
    const ResolvedProxyPolicy snapshot = request.proxy.snapshot();
    ResolvedProxyRoute route =
        resolveProxyRoute(snapshot, request.url, request.context);
    multiEngine().submit(std::move(request), std::move(route),
                         settings.allowInsecureTls,
                         settings.maxAllowedDownloadSize,
                         std::move(completion));
}

AsyncFetchFuture webGetAsync(AsyncFetchRequest request)
{
    auto promise =
        std::make_shared<std::promise<SharedAsyncFetchResult>>();
    AsyncFetchFuture future = promise->get_future().share();
    webGetAsync(std::move(request),
                [promise](SharedAsyncFetchResult result) noexcept {
                    try
                    {
                        promise->set_value(std::move(result));
                    }
                    catch(...)
                    {
                    }
                });
    return future;
}

static void shutdownAsyncFetchEngine() noexcept
{
    if(CurlMultiEngine *engine =
           multi_engine_instance.load(std::memory_order_acquire))
        engine->shutdown();
}

//static std::string curlGet(const std::string &url, const std::string &proxy, std::string &response_headers, CURLcode &return_code, const string_map &request_headers)
static int curlGetSyncLegacy(const FetchArgument &argument,
                             const ResolvedProxyRoute &route,
                             FetchResult &result,
                             CURLcode *return_code = nullptr,
                             AsyncFetchFailure *return_failure = nullptr)
{
    CURL *curl_handle;
    std::string new_url = argument.url;
    curl_slist *header_list = nullptr;
    defer(curl_slist_free_all(header_list);)
    CURLcode retVal;

    if(outbound_fetch_shutdown_requested.load(std::memory_order_relaxed))
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = CURLE_ABORTED_BY_CALLBACK;
        if(return_failure)
            *return_failure = AsyncFetchFailure::Shutdown;
        return 0;
    }

    retVal = curl_init();
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        if(return_failure)
        {
            curl_progress_data progress;
            *return_failure = classify_async_failure(retVal, progress);
        }
        writeLog(LOG_LEVEL_ERROR, "curl_global_init 失败：" + std::string(curl_easy_strerror(retVal)));
        return 0;
    }

    CurlHandleLease curl_lease =
        globalCurlHandlePool(
            static_cast<size_t>(
                std::max(1, effectiveSettings().maxConcurThreads)))
            .acquire();
    curl_handle = curl_lease.get();
    if(curl_handle == nullptr)
    {
        retVal = CURLE_FAILED_INIT;
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        if(return_failure)
        {
            curl_progress_data progress;
            *return_failure = classify_async_failure(retVal, progress);
        }
        writeLog(LOG_LEVEL_ERROR, "curl_easy_init 失败。");
        return 0;
    }
    retVal = apply_curl_proxy_policy(curl_handle, route, new_url);
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        if(return_failure)
        {
            curl_progress_data progress;
            *return_failure = classify_async_failure(retVal, progress);
        }
        return 0;
    }
    if(route.proxy.mode == ProxyMode::Cors)
        header_list = curl_slist_append(header_list,
                                        "X-Requested-With: SubConverter-Extended " VERSION);
    curl_progress_data limit;
    limit.size_limit = effectiveSettings().maxAllowedDownloadSize;
    limit.deadline = networkFetchDeadline(argument.deadline);
    limit.cancellation = argument.cancellation.valid()
                             ? argument.cancellation
                             : (captureCurrentRequestContext()
                                    ? captureCurrentRequestContext()
                                          ->cancellationToken()
                                    : RequestCancellationToken());
    limit.request_context = captureCurrentRequestContext();
    curl_set_common_options(curl_handle, new_url.data(), &limit,
                            effectiveSettings().allowInsecureTls);
    retVal = curl_set_platform_tls_trust(curl_handle);
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        if(return_failure)
            *return_failure = classify_async_failure(retVal, limit);
        writeLog(LOG_LEVEL_ERROR,
                 "Windows 原生 TLS 信任库配置失败：" +
                     std::string(curl_easy_strerror(retVal)));
        return 0;
    }
#if LIBCURL_VERSION_NUM >= 0x075000
    curl_prereq_data prereq_context {
        isPublicFetchRestricted(argument.context)};
    if(prereq_context.restricted &&
       (route.proxy.mode == ProxyMode::Direct ||
        (route.proxy.mode == ProxyMode::System &&
         route.proxy.endpoint.empty())))
    {
        curl_easy_setopt(curl_handle, CURLOPT_PREREQFUNCTION,
                         public_fetch_prereq_callback);
        curl_easy_setopt(curl_handle, CURLOPT_PREREQDATA, &prereq_context);
    }
#endif
    header_list = curl_slist_append(header_list, "Content-Type: application/json;charset=utf-8");
    if(argument.request_headers)
    {
        for(auto &x : *argument.request_headers)
        {
            auto header = x.first + ": " + x.second;
            header_list = curl_slist_append(header_list, header.data());
        }
        if(!argument.request_headers->contains("User-Agent"))
            curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, user_agent_str);
    }
    else
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, user_agent_str);
    if(header_list)
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, header_list);

    curl_writer_data content_writer {result.content, &limit};
    curl_writer_data header_writer {result.response_headers, &limit};
    if(result.content)
    {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &content_writer);
    }
    else
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, dummy_writer);
    if(result.response_headers)
    {
        curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, writer);
        curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, &header_writer);
    }
    else
        curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, dummy_writer);

    if(argument.cookies)
    {
        string_array cookies = split(*argument.cookies, "\r\n");
        for(auto &x : cookies)
            curl_easy_setopt(curl_handle, CURLOPT_COOKIELIST, x.c_str());
    }

    switch(argument.method)
    {
    case HTTP_POST:
        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
        if(argument.post_data)
        {
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, argument.post_data->data());
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, argument.post_data->size());
        }
        break;
    case HTTP_PATCH:
        curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "PATCH");
        if(argument.post_data)
        {
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, argument.post_data->data());
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, argument.post_data->size());
        }
        break;
    case HTTP_HEAD:
        curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
        break;
    case HTTP_GET:
        break;
    }

    retVal = curl_easy_perform(curl_handle);
    if(retVal != CURLE_OK &&
       !outbound_fetch_shutdown_requested.load(std::memory_order_relaxed) &&
       (argument.method == HTTP_GET || argument.method == HTTP_HEAD) &&
       is_recoverable_curl_error(retVal))
    {
        writeLog(LOG_LEVEL_WARNING, "出站请求遇到可恢复网络错误，200ms 后重试一次。");
        if(result.content)
            result.content->clear();
        if(result.response_headers)
            result.response_headers->clear();
        sleepMs(200);
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(limit.deadline -
                                      std::chrono::steady_clock::now());
        if(outbound_fetch_shutdown_requested.load(std::memory_order_relaxed) ||
           limit.cancellation.isCancellationRequested())
            retVal = CURLE_ABORTED_BY_CALLBACK;
        else if(remaining.count() <= 0)
            retVal = CURLE_OPERATION_TIMEDOUT;
        else
        {
            curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS,
                             static_cast<long>(std::clamp<int64_t>(
                                 remaining.count(), 1,
                                 static_cast<int64_t>(LONG_MAX))));
            retVal = curl_easy_perform(curl_handle);
        }
    }

    long code = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CODE, &code);
    *result.status_code = code;
    if(return_code)
        *return_code = retVal;
    if(return_failure)
        *return_failure = classify_async_failure(retVal, limit);

#if LIBCURL_VERSION_NUM >= 0x080700
    long used_proxy = 0;
    if(curl_easy_getinfo(curl_handle, CURLINFO_USED_PROXY, &used_proxy) == CURLE_OK &&
       shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(LOG_LEVEL_VERBOSE, std::string("出站代理实际使用：") +
                        (used_proxy ? "是" : "否") + "。");
#endif
#if LIBCURL_VERSION_NUM >= 0x074900
    long proxy_error = 0;
    if(curl_easy_getinfo(curl_handle, CURLINFO_PROXY_ERROR, &proxy_error) == CURLE_OK &&
       proxy_error != 0 && shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(LOG_LEVEL_VERBOSE, "出站代理错误代码：" + std::to_string(proxy_error) + "。");
#endif
    if(retVal != CURLE_OK && shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(LOG_LEVEL_VERBOSE, "出站请求错误类别：" +
                        std::string(classify_curl_error(retVal)) + "。");
    if(retVal == CURLE_SSL_CACERT_BADFILE)
    {
        static std::atomic<bool> trust_store_warning_logged {false};
        bool expected = false;
        if(trust_store_warning_logged.compare_exchange_strong(expected, true))
            writeLog(LOG_LEVEL_WARNING,
                     "TLS 信任源不可用，无法验证远程证书；请检查当前系统的受信任根证书配置。");
    }

    if(result.cookies)
    {
        curl_slist *cookies = nullptr;
        curl_easy_getinfo(curl_handle, CURLINFO_COOKIELIST, &cookies);
        if(cookies)
        {
            auto each = cookies;
            while(each)
            {
                result.cookies->append(each->data);
                *result.cookies += "\r\n";
                each = each->next;
            }
        }
        curl_slist_free_all(cookies);
    }

    if(result.content && !argument.keep_resp_on_fail)
    {
        if(retVal != CURLE_OK || *result.status_code != 200)
            result.content->clear();
    }

    return *result.status_code;
}

static AsyncFetchRequest makeAsyncFetchRequest(
    const FetchArgument &argument, const FetchResult &result)
{
    AsyncFetchRequest request;
    request.method = argument.method;
    request.url = argument.url;
    request.proxy = argument.proxy;
    if(argument.post_data)
    {
        request.post_data = *argument.post_data;
        request.has_post_data = true;
    }
    if(argument.request_headers)
        request.request_headers = *argument.request_headers;
    if(argument.cookies)
        request.cookies = *argument.cookies;
    request.capture_content = result.content != nullptr;
    request.capture_response_headers = result.response_headers != nullptr;
    request.capture_cookies = result.cookies != nullptr;
    request.keep_resp_on_fail = argument.keep_resp_on_fail;
    request.context = argument.context;
    request.public_fetch_restricted =
        isPublicFetchRestricted(argument.context);
    request.deadline = networkFetchDeadline(argument.deadline);
    request.cancellation = argument.cancellation;
    request.request_context = captureCurrentRequestContext();
    if(!request.cancellation.valid())
    {
        if(auto context = captureCurrentRequestContext())
            request.cancellation = context->cancellationToken();
    }
    return request;
}

static void copyAsyncFetchResult(AsyncFetchResult &&source,
                                 FetchResult &destination,
                                 CURLcode *return_code)
{
    *destination.status_code = source.status_code;
    if(destination.content)
        *destination.content = std::move(source.content);
    if(destination.response_headers)
        *destination.response_headers = std::move(source.response_headers);
    if(destination.cookies)
        *destination.cookies = std::move(source.cookies);
    if(return_code)
        *return_code = static_cast<CURLcode>(source.transport_code);
}

static void applyAsyncFetchFailure(
    const std::shared_ptr<RequestContext> &context,
    AsyncFetchFailure failure,
    const RequestCancellationToken &cancellation) noexcept
{
    if(!context)
        return;
    switch(failure)
    {
    case AsyncFetchFailure::Cancelled:
        if(cancellation.reason() == RequestCancellationReason::None)
        {
            context->suggestFailure(RequestFailureAttribution::Upstream);
        }
        else if(cancellation.reason() == RequestCancellationReason::Shutdown)
        {
            context->requestCancellation(RequestCancellationReason::Shutdown);
            context->suggestFailure(RequestFailureAttribution::Server);
        }
        else if(cancellation.reason() == RequestCancellationReason::Deadline)
        {
            context->requestCancellation(RequestCancellationReason::Deadline);
            context->suggestFailure(RequestFailureAttribution::Client);
        }
        else
        {
            context->requestCancellation(
                RequestCancellationReason::ClientDisconnected);
            context->suggestFailure(RequestFailureAttribution::Client);
        }
        break;
    case AsyncFetchFailure::Deadline:
        if(cancellation.reason() == RequestCancellationReason::Deadline ||
           context->deadlineExceeded())
        {
            context->requestCancellation(RequestCancellationReason::Deadline);
            context->suggestFailure(RequestFailureAttribution::Client);
        }
        else
            context->suggestFailure(RequestFailureAttribution::Upstream);
        break;
    case AsyncFetchFailure::Shutdown:
        context->requestCancellation(RequestCancellationReason::Shutdown);
        context->suggestFailure(RequestFailureAttribution::Server);
        break;
    case AsyncFetchFailure::Dns:
    case AsyncFetchFailure::Tls:
    case AsyncFetchFailure::Proxy:
    case AsyncFetchFailure::Transport:
        context->suggestFailure(RequestFailureAttribution::Upstream);
        break;
    case AsyncFetchFailure::SizeLimit:
        context->suggestFailure(RequestFailureAttribution::User);
        break;
    case AsyncFetchFailure::Capacity:
        context->suggestFailure(RequestFailureAttribution::Capacity);
        break;
    case AsyncFetchFailure::None:
        break;
    }
}

static int curlGet(const FetchArgument &argument,
                   const ResolvedProxyRoute &route, FetchResult &result,
                   CURLcode *return_code = nullptr,
                   AsyncFetchFailure *return_failure = nullptr)
{
    const std::string engine = toLower(getEnv("SUBCONVERTER_FETCH_ENGINE"));
    bool use_sync = engine == "sync";
    if(!engine.empty() && engine != "sync" && engine != "multi")
    {
        static std::atomic<bool> invalid_engine_logged{false};
        bool expected = false;
        if(invalid_engine_logged.compare_exchange_strong(expected, true))
            writeLog(LOG_LEVEL_ERROR,
                     "FETCH_ENGINE_INVALID value_length=" +
                         std::to_string(engine.size()) +
                         " fallback=sync");
        use_sync = true;
    }
    if(use_sync || !asyncFetchEngineAvailable())
    {
        CURLcode sync_code = CURLE_OK;
        AsyncFetchFailure sync_failure = AsyncFetchFailure::None;
        const int status = waitWithoutCpuPermit([&] {
            return curlGetSyncLegacy(argument, route, result, &sync_code,
                                     &sync_failure);
        });
        if(return_code)
            *return_code = sync_code;
        if(return_failure)
            *return_failure = sync_failure;
        return status;
    }

    AsyncFetchRequest request = makeAsyncFetchRequest(argument, result);
    const Settings &settings = effectiveSettings();
    AsyncFetchResult fetched;
    try
    {
        AsyncFetchFuture future = multiEngine().submit(
            request, route, settings.allowInsecureTls,
            settings.maxAllowedDownloadSize);
        if(!future.valid())
            throw std::future_error(std::future_errc::no_state);
        SharedAsyncFetchResult shared =
            waitWithoutCpuPermit([&] { return future.get(); });
        if(!shared)
            throw std::future_error(std::future_errc::broken_promise);
        fetched = std::move(*shared);
    }
    catch(const std::future_error &error)
    {
        writeLog(LOG_LEVEL_ERROR, "ASYNC_FETCH_FUTURE_ERROR code=" +
                     std::to_string(error.code().value()));
        throw;
    }
    CURLcode code = static_cast<CURLcode>(fetched.transport_code);

    if(shouldLog(LOG_LEVEL_VERBOSE))
    {
        writeLog(LOG_LEVEL_VERBOSE,
                 std::string("出站代理实际使用：") +
                     (fetched.used_proxy ? "是" : "否") + "。");
        if(fetched.proxy_error != 0)
            writeLog(LOG_LEVEL_VERBOSE, "出站代理错误代码：" +
                         std::to_string(fetched.proxy_error) + "。");
        if(code != CURLE_OK)
            writeLog(LOG_LEVEL_VERBOSE, "出站请求错误类别：" +
                         std::string(classify_curl_error(code)) + "。");
    }
    applyAsyncFetchFailure(captureCurrentRequestContext(), fetched.failure,
                           request.cancellation);
    if(return_failure)
        *return_failure = fetched.failure;
    const int status = fetched.status_code;
    copyAsyncFetchResult(std::move(fetched), result, return_code);
    return status;
}

static int curlGetWithGitHubFallback(
    const FetchArgument &argument, const ResolvedProxyPolicy &snapshot,
    const ResolvedProxyRoute &initial_route, FetchResult &result,
    AsyncFetchFailure *return_failure = nullptr)
{
    CURLcode original_code = CURLE_OK;
    AsyncFetchFailure original_failure = AsyncFetchFailure::None;
    int original_status =
        curlGet(argument, initial_route, result, &original_code,
                &original_failure);
    if(return_failure)
        *return_failure = original_failure;

    std::string fallback_url;
    if(argument.method != HTTP_GET || argument.keep_resp_on_fail ||
       original_status == 200 ||
       outbound_fetch_shutdown_requested.load(std::memory_order_relaxed) ||
       !should_try_jsdelivr_fallback(original_code, original_status) ||
       !build_jsdelivr_github_url(argument.url, fallback_url))
        return original_status;

    std::string original_headers, original_cookies;
    if(result.response_headers)
        original_headers = *result.response_headers;
    if(result.cookies)
        original_cookies = *result.cookies;

    writeLog(LOG_LEVEL_WARNING,
             "GitHub Raw 获取失败，正在尝试 jsDelivr 回退源：" +
                  summarizeUrlForLog(fallback_url));
    clear_fetch_output(result);

    FetchArgument fallback_argument {HTTP_GET, fallback_url, argument.proxy,
                                     nullptr, argument.request_headers,
                                     argument.cookies, argument.cache_ttl,
                                     argument.keep_resp_on_fail,
                                      argument.context, argument.deadline,
                                      argument.cancellation};
    const ResolvedProxyRoute fallback_route =
        resolveProxyRoute(snapshot, fallback_url, argument.context);
    CURLcode fallback_code = CURLE_OK;
    int fallback_status =
        curlGet(fallback_argument, fallback_route, result, &fallback_code);
    if(fallback_code == CURLE_OK && fallback_status == 200)
    {
        if(return_failure)
            *return_failure = AsyncFetchFailure::None;
        writeLog(LOG_LEVEL_INFO,
                 "GitHub Raw 已通过 jsDelivr 回退源获取成功：" +
                      summarizeUrlForLog(fallback_url));
        return fallback_status;
    }

    writeLog(LOG_LEVEL_WARNING,
             "GitHub Raw 通过 jsDelivr 回退源获取失败：" +
                 summarizeUrlForLog(fallback_url));
    clear_fetch_output(result);
    if(result.response_headers)
        *result.response_headers = original_headers;
    if(result.cookies)
        *result.cookies = original_cookies;
    *result.status_code = original_status;
    return original_status;
}

static int executeNetworkFetch(const FetchArgument &argument,
                               FetchResult &result)
{
    const auto deadline = networkFetchDeadline(argument.deadline);
    RequestCancellationToken cancellation = argument.cancellation;
    if(!cancellation.valid())
    {
        if(auto context = captureCurrentRequestContext())
            cancellation = context->cancellationToken();
    }
    FetchArgument budgeted_argument {
        argument.method, argument.url, argument.proxy, argument.post_data,
        argument.request_headers, argument.cookies, argument.cache_ttl,
        argument.keep_resp_on_fail, argument.context, deadline, cancellation};
    const ResolvedProxyPolicy snapshot = budgeted_argument.proxy.snapshot();
    const ResolvedProxyRoute route =
        resolveProxyRoute(snapshot, budgeted_argument.url,
                          budgeted_argument.context);
    return curlGetWithGitHubFallback(budgeted_argument, snapshot, route,
                                     result);
}

// data:[<mediatype>][;base64],<data>
static std::string dataGet(const std::string &url)
{
    if (!startsWith(url, "data:"))
        return "";
    std::string::size_type comma = url.find(',');
    if (comma == std::string::npos || comma == url.size() - 1)
        return "";

    std::string data = urlDecode(url.substr(comma + 1));
    const long max_download_size = effectiveSettings().maxAllowedDownloadSize;
    if (max_download_size > 0 &&
        data.size() > static_cast<size_t>(max_download_size)) {
        writeLog(LOG_LEVEL_WARNING, "已阻止 data URL：内容超过最大下载大小。");
        return "";
    }
    if (endsWith(url.substr(0, comma), ";base64")) {
        std::string decoded = urlSafeBase64Decode(data);
        if (max_download_size > 0 &&
            decoded.size() > static_cast<size_t>(max_download_size)) {
            writeLog(LOG_LEVEL_WARNING,
                     "已阻止解码后的 data URL：内容超过最大下载大小。");
            return "";
        }
        return decoded;
    } else {
        return data;
    }
}

static bool retainCurrentFetchBytes(uint64_t bytes)
{
    if(auto context = captureCurrentRequestContext())
        return context->retainResponseBytes(bytes);
    return true;
}

std::string buildSocks5ProxyString(const std::string &addr, int port, const std::string &username, const std::string &password)
{
    std::string authstr = username.size() && password.size() ? username + ":" + password + "@" : "";
    std::string proxystr = "socks5://" + authstr + addr + ":" + std::to_string(port);
    return proxystr;
}

namespace
{

class OwnedWebGetState
{
public:
    explicit OwnedWebGetState(OwnedWebGetRequest request)
        : request_(std::move(request))
    {
        request_context_ = captureCurrentRequestContext();
        if(request_.capture_response_headers)
            result_.response_headers = request_.initial_response_headers;
    }

    OwnedWebGetResult runSync()
    {
        RequestStageTimer fetch_timer(RequestStage::Fetch);
        if(!prepare())
            return std::move(result_);
        if(prepared_data_)
            return std::move(result_);
        if(request_.cache_ttl > 0)
            executeCached();
        else
            executeNetwork();
        return std::move(result_);
    }

    bool prepare()
    {
        if(!isFetchUrlAllowed(request_.url, request_.context))
            return false;
        const CocrSourceResolution source = resolveCocrSourceUrl(
            request_.url,
            effectiveSettings().customOpenClashRulesSourceSwitch);
        effective_url_ = source.effective_url;
        if(source.rewritten && shouldLog(LOG_LEVEL_VERBOSE))
            writeLog(LOG_LEVEL_VERBOSE,
                     "COCR 服务端取源切换：" +
                         summarizeUrlForLog(request_.url) + " -> " +
                         summarizeUrlForLog(effective_url_) + "。");
        if(startsWith(effective_url_, "data:"))
        {
            result_.content = dataGet(effective_url_);
            if(!retainBytes(result_.content.size()))
                handleRetentionFailure();
            result_.status_code = result_.content.empty() ? 400 : 200;
            prepared_data_ = true;
            return true;
        }
        proxy_snapshot_ = request_.proxy.snapshot();
        initial_route_ = resolveProxyRoute(
            proxy_snapshot_, effective_url_, request_.context);
        return true;
    }

    bool loadFreshCache(const std::string &path,
                        const std::string &header_path)
    {
        struct stat information {};
        if(stat(path.c_str(), &information) != 0)
            return false;
        const time_t now = time(nullptr);
        if(difftime(now, information.st_mtime) > request_.cache_ttl)
        {
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(LOG_LEVEL_VERBOSE,
                         "缓存过期：" + summarizeUrlForLog(effective_url_) +
                             "，正在创建新缓存。");
            return false;
        }
        if(shouldLog(LOG_LEVEL_VERBOSE))
            writeLog(LOG_LEVEL_VERBOSE,
                     "缓存命中：" + summarizeUrlForLog(effective_url_) +
                         "，使用本地缓存。");
        cache_rw_lock.readLock();
        defer(cache_rw_lock.readUnlock();)
        std::string cached_headers;
        if(request_.capture_response_headers)
        {
            cached_headers = readCachedResponseHeaders(header_path);
            result_.response_headers = cached_headers;
            result_.response_headers_touched = true;
        }
        result_.content = fileGet(path, true);
        if(!retainBytes(result_.content.size() + cached_headers.size()))
            handleRetentionFailure();
        result_.status_code = result_.content.empty() ? 0 : 200;
        return true;
    }

    void finalizeCached(const std::string &path,
                        const std::string &header_path,
                        const CacheFetchPayload &fetched, bool owner)
    {
        if(result_.status_code == 200)
        {
            if(!owner)
                return;
            cache_rw_lock.writeLock();
            defer(cache_rw_lock.writeUnlock();)
            const CacheUpdateResult cache_update = updateCacheFiles(
                path, header_path, result_.content,
                fetched.response_headers);
            if(cache_update == CacheUpdateResult::Unchanged)
                writeLog(LOG_LEVEL_WARNING,
                         "CACHE_UPDATE_FAILED body=unchanged headers=unchanged; "
                         "本次已获取内容仍将直接返回。");
            else if(cache_update ==
                    CacheUpdateResult::UnchangedHeadersInvalidated)
                writeLog(LOG_LEVEL_WARNING,
                         "CACHE_UPDATE_FAILED body=unchanged "
                         "headers=invalidated; 本次已获取内容仍将直接返回。");
            else if(cache_update == CacheUpdateResult::BodyCommittedUnsynced)
                writeLog(LOG_LEVEL_WARNING,
                         "CACHE_BODY_COMMITTED durability=unconfirmed "
                         "headers=invalidated; 本次已获取内容仍将直接返回。");
            else if(cache_update == CacheUpdateResult::HeadersInvalidated)
                writeLog(LOG_LEVEL_WARNING,
                         "CACHE_BODY_COMMITTED durability=confirmed "
                         "headers=invalidated; 本次已获取内容仍将直接返回。");
            return;
        }

        if(fileExist(path) && effectiveSettings().serveCacheOnFetchFail)
        {
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(LOG_LEVEL_VERBOSE, "获取失败，返回缓存内容。");
            cache_rw_lock.readLock();
            defer(cache_rw_lock.readUnlock();)
            result_.retained_bytes.reset();
            result_.content = fileGet(path, true);
            if(request_.capture_response_headers)
            {
                result_.response_headers = readCachedResponseHeaders(
                    header_path);
                result_.response_headers_touched = true;
            }
            if(!retainBytes(
                   result_.content.size() + result_.response_headers.size()))
                handleRetentionFailure();
        }
        else if(shouldLog(LOG_LEVEL_VERBOSE))
            writeLog(LOG_LEVEL_VERBOSE,
                     "获取失败，且没有可用的本地缓存。");
    }

    const OwnedWebGetRequest &request() const noexcept { return request_; }
    OwnedWebGetResult &result() noexcept { return result_; }
    const std::string &effectiveUrl() const noexcept { return effective_url_; }
    const ResolvedProxyPolicy &proxySnapshot() const noexcept {
        return proxy_snapshot_;
    }
    const ResolvedProxyRoute &initialRoute() const noexcept {
        return initial_route_;
    }
    bool preparedData() const noexcept { return prepared_data_; }

public:
    string_icase_map *requestHeaders() noexcept
    {
        return request_.has_request_headers ? &request_.request_headers
                                            : nullptr;
    }

    FetchArgument fetchArgument() const
    {
        return FetchArgument{
            HTTP_GET, effective_url_, request_.proxy, nullptr,
            request_.has_request_headers ? &request_.request_headers : nullptr,
            nullptr, request_.cache_ttl, false, request_.context,
            request_context_ ? request_context_->deadline()
                             : RequestContext::Clock::time_point::max(),
            request_context_ ? request_context_->cancellationToken()
                             : RequestCancellationToken{}};
    }

    void executeNetwork()
    {
        FetchArgument argument = fetchArgument();
        FetchResult fetch_result{
            &result_.status_code, &result_.content,
            request_.capture_response_headers ? &result_.response_headers
                                              : nullptr,
            nullptr};
        AsyncFetchFailure failure = AsyncFetchFailure::None;
        if(request_.retention ==
           OwnedWebGetRequest::RetentionPolicy::Result)
        {
            ScopedRequestContext no_request_context(
                std::shared_ptr<RequestContext>{});
            curlGetWithGitHubFallback(argument, proxy_snapshot_,
                                      initial_route_, fetch_result, &failure);
            applyAsyncFetchFailure(request_context_, failure,
                                   argument.cancellation);
        }
        else
            curlGetWithGitHubFallback(argument, proxy_snapshot_,
                                      initial_route_, fetch_result);
        if(request_.capture_response_headers &&
           result_.response_headers != request_.initial_response_headers)
            result_.response_headers_touched = true;
        if(request_.retention ==
               OwnedWebGetRequest::RetentionPolicy::Result &&
           !retainBytes(result_.content.size() +
                        result_.response_headers.size()))
            handleRetentionFailure();
    }

    bool retainBytes(uint64_t bytes)
    {
        if(request_.retention ==
           OwnedWebGetRequest::RetentionPolicy::CurrentRequest)
            return retainCurrentFetchBytes(bytes);
        return result_.retained_bytes.retain(bytes);
    }

    void handleRetentionFailure()
    {
        if(request_.retention ==
           OwnedWebGetRequest::RetentionPolicy::Result)
        {
            std::string().swap(result_.content);
            std::string().swap(result_.response_headers);
            result_.response_headers_touched =
                request_.capture_response_headers;
            result_.retained_bytes.reset();
            return;
        }
        result_.content.clear();
    }

    void executeCached()
    {
        md("cache");
        const std::string cache_key = build_cache_key(
            effective_url_, initial_route_, requestHeaders());
        const std::string path = "cache/" + cache_key;
        const std::string header_path = path + "_header";
        if(loadFreshCache(path, header_path))
            return;
        if(!fileExist(path) && shouldLog(LOG_LEVEL_VERBOSE))
            writeLog(LOG_LEVEL_VERBOSE,
                     "缓存不存在：" + summarizeUrlForLog(effective_url_) +
                         "，正在创建新缓存。");

        std::shared_ptr<CacheFetchOperation> operation;
        bool owner = false;
        {
            std::lock_guard<std::mutex> lock(cache_fetch_mutex);
            auto iter = cache_fetches.find(cache_key);
            if(iter == cache_fetches.end())
            {
                operation = std::make_shared<CacheFetchOperation>();
                cache_fetches.emplace(cache_key, operation);
                owner = true;
            }
            else
                operation = iter->second;
        }
        CacheFetchOwnerCleanup owner_cleanup(owner, cache_key, operation);
        if(owner)
        {
            try
            {
                auto fetched = std::make_shared<CacheFetchPayload>();
                FetchArgument argument = fetchArgument();
                FetchResult fetch_result{
                    &fetched->status_code, &fetched->content,
                    &fetched->response_headers, nullptr};
                {
                    ScopedRequestContext no_request_context(
                        std::shared_ptr<RequestContext>{});
                    curlGetWithGitHubFallback(argument, proxy_snapshot_,
                                              initial_route_, fetch_result,
                                              &fetched->failure);
                }
                if(!fetched->retainPayloadBytes())
                {
                    std::string().swap(fetched->content);
                    std::string().swap(fetched->response_headers);
                    fetched->status_code = 0;
                    fetched->failure = AsyncFetchFailure::Capacity;
                }
                operation->publish(
                    std::static_pointer_cast<const CacheFetchPayload>(fetched));
            }
            catch(...)
            {
                operation->publishException(std::current_exception());
            }
        }

        SharedCacheFetchPayload fetched =
            waitWithoutCpuPermit([&] { return operation->wait(); });
        if(!fetched)
            throw std::future_error(std::future_errc::broken_promise);
        applyAsyncFetchFailure(request_context_, fetched->failure,
                               request_context_
                                   ? request_context_->cancellationToken()
                                   : RequestCancellationToken{});
        result_.status_code = fetched->status_code;
        result_.content = fetched->content;
        if(request_.capture_response_headers)
        {
            result_.response_headers = fetched->response_headers;
            result_.response_headers_touched = true;
        }
        if(!retainBytes(result_.content.size() + result_.response_headers.size()))
        {
            handleRetentionFailure();
            return;
        }
        finalizeCached(path, header_path, *fetched, owner);
    }

private:
    OwnedWebGetRequest request_;
    OwnedWebGetResult result_;
    std::shared_ptr<RequestContext> request_context_;
    std::string effective_url_;
    ResolvedProxyPolicy proxy_snapshot_;
    ResolvedProxyRoute initial_route_;
    bool prepared_data_ = false;
};

} // namespace

OwnedWebGetResult webGetOwned(OwnedWebGetRequest request)
{
    return OwnedWebGetState(std::move(request)).runSync();
}

CacheFetchPayloadSnapshot cacheFetchPayloadSnapshot() noexcept
{
    return {
        cache_fetch_payload_retained_bytes.load(std::memory_order_relaxed),
        cache_fetch_payload_peak_retained_bytes.load(
            std::memory_order_relaxed),
    };
}

CacheFetchOperationProbeSnapshot cacheFetchOperationProbe()
{
    CacheFetchOperationProbeSnapshot snapshot;
    auto success = std::make_shared<CacheFetchOperation>();
    success->subscribe([&](SharedCacheFetchPayload payload,
                           std::exception_ptr error) {
        if(!payload || error)
            return;
        ++snapshot.success_callbacks;
        success->subscribe([&](SharedCacheFetchPayload nested_payload,
                               std::exception_ptr nested_error) {
            if(nested_payload && !nested_error)
                ++snapshot.success_callbacks;
        });
    });
    auto payload = std::make_shared<CacheFetchPayload>();
    payload->status_code = 200;
    payload->content = "probe";
    success->publish(
        std::static_pointer_cast<const CacheFetchPayload>(payload));
    snapshot.duplicate_publish_rejected = !success->publish({});

    auto failure = std::make_shared<CacheFetchOperation>();
    failure->subscribe([&](SharedCacheFetchPayload failed_payload,
                           std::exception_ptr error) {
        if(!failed_payload && error)
            ++snapshot.exception_callbacks;
    });
    failure->publishException(
        std::make_exception_ptr(std::runtime_error("cache fetch probe")));
    try
    {
        (void)failure->wait();
    }
    catch(const std::runtime_error &)
    {
        snapshot.exception_rethrown_to_waiter = true;
    }
    return snapshot;
}

std::string webGet(const std::string &url, const ProxyPolicy &proxy,
                   unsigned int cache_ttl, std::string *response_headers,
                   string_icase_map *request_headers, FetchContext context)
{
    OwnedWebGetRequest request;
    request.url = url;
    request.proxy = proxy;
    request.cache_ttl = cache_ttl;
    request.capture_response_headers = response_headers != nullptr;
    if(response_headers)
        request.initial_response_headers = *response_headers;
    request.has_request_headers = request_headers != nullptr;
    if(request_headers)
        request.request_headers = *request_headers;
    request.context = context;
    OwnedWebGetResult result = webGetOwned(std::move(request));
    if(response_headers && result.response_headers_touched)
        *response_headers = std::move(result.response_headers);
    return std::move(result.content);
}

void flushCache()
{
    //guarded_mutex guard(cache_rw_lock);
    cache_rw_lock.writeLock();
    defer(cache_rw_lock.writeUnlock();)
    operateFiles("cache", [](const std::string &file){ remove(("cache/" + file).data()); return 0; });
}

int webPost(const std::string &url, const std::string &data, const ProxyPolicy &proxy, const string_icase_map &request_headers, std::string *retData)
{
    //return curlPost(url, data, proxy, request_headers, retData);
    int return_code = 0;
    FetchArgument argument {HTTP_POST, url, proxy, &data, &request_headers, nullptr, 0, true};
    FetchResult fetch_res {&return_code, retData, nullptr, nullptr};
    return webGet(argument, fetch_res);
}

int webPatch(const std::string &url, const std::string &data, const ProxyPolicy &proxy, const string_icase_map &request_headers, std::string *retData)
{
    //return curlPatch(url, data, proxy, request_headers, retData);
    int return_code = 0;
    FetchArgument argument {HTTP_PATCH, url, proxy, &data, &request_headers, nullptr, 0, true};
    FetchResult fetch_res {&return_code, retData, nullptr, nullptr};
    return webGet(argument, fetch_res);
}

int webHead(const std::string &url, const ProxyPolicy &proxy, const string_icase_map &request_headers, std::string &response_headers)
{
    //return curlHead(url, proxy, request_headers, response_headers);
    int return_code = 0;
    FetchArgument argument {HTTP_HEAD, url, proxy, nullptr, &request_headers, nullptr, 0};
    FetchResult fetch_res {&return_code, nullptr, &response_headers, nullptr};
    return webGet(argument, fetch_res);
}

string_array headers_map_to_array(const string_map &headers)
{
    string_array result;
    for(auto &kv : headers)
        result.push_back(kv.first + ": " + kv.second);
    return result;
}

int webGet(const FetchArgument& argument, FetchResult &result)
{
    RequestStageTimer fetch_timer(RequestStage::Fetch);
    if (!isFetchUrlAllowed(argument.url, argument.context)) {
        *result.status_code = 403;
        if (result.content)
            result.content->clear();
        return 403;
    }
    CocrSourceResolution source =
        argument.method == HTTP_GET
            ? resolveCocrSourceUrl(
                  argument.url,
                  effectiveSettings().customOpenClashRulesSourceSwitch)
            : CocrSourceResolution{argument.url, false};
    if (startsWith(source.effective_url, "data:")) {
        if (result.content)
            *result.content = dataGet(source.effective_url);
        *result.status_code =
            result.content && !result.content->empty() ? 200 : 400;
        return *result.status_code;
    }
    if (!source.rewritten)
        return executeNetworkFetch(argument, result);

    if(shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(LOG_LEVEL_VERBOSE, "COCR 服务端取源切换：" +
                        summarizeUrlForLog(argument.url) + " -> " +
                        summarizeUrlForLog(source.effective_url) + "。");
    FetchArgument effective_argument {
        argument.method, source.effective_url, argument.proxy,
        argument.post_data, argument.request_headers, argument.cookies,
        argument.cache_ttl, argument.keep_resp_on_fail, argument.context,
        argument.deadline, argument.cancellation};
    return executeNetworkFetch(effective_argument, result);
}
