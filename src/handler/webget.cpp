#include <algorithm>
#include <future>
#include <iostream>
#include <map>
#include <unistd.h>
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include <utility>
#include <atomic>
#include <cctype>
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
#include "utils/defer.h"
#include "utils/file_extra.h"
#include "utils/lock.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/redact.h"
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
};

struct CacheFetchResult
{
    int status_code = 0;
    std::string content;
    std::string response_headers;
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
static std::map<std::string, std::shared_future<CacheFetchResult>> cache_fetches;
static std::atomic_bool outbound_fetch_shutdown_requested {false};

void requestOutboundFetchShutdown() noexcept
{
    outbound_fetch_shutdown_requested.store(true, std::memory_order_relaxed);
}

class CacheFetchOwnerCleanup
{
public:
    CacheFetchOwnerCleanup(bool owner, std::string key)
        : owner_(owner), key_(std::move(key)) {}
    ~CacheFetchOwnerCleanup()
    {
        if(!owner_)
            return;
        std::lock_guard<std::mutex> lock(cache_fetch_mutex);
        cache_fetches.erase(key_);
    }

private:
    bool owner_;
    std::string key_;
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
static int public_fetch_prereq_callback(void *clientp, char *conn_primary_ip,
                                        char *conn_local_ip,
                                        int conn_primary_port,
                                        int conn_local_port)
{
    FetchContext *context = static_cast<FetchContext *>(clientp);
    if(context && isPublicFetchRestricted(*context) && conn_primary_ip &&
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

static int writer(char *data, size_t size, size_t nmemb, std::string *writerData)
{
    if(writerData == nullptr)
        return 0;

    writerData->append(data, size*nmemb);

    return static_cast<int>(size * nmemb);
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
        return 1;
    if(clientp)
    {
        auto *data = reinterpret_cast<curl_progress_data*>(clientp);
        if(data->size_limit)
        {
            if(dlnow > data->size_limit)
                return 1;
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

static inline void curl_set_common_options(CURL *curl_handle, const char *url, curl_progress_data *data)
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
                     effectiveSettings().allowInsecureTls ? 0L : 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST,
                     effectiveSettings().allowInsecureTls ? 0L : 2L);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 15L);
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

//static std::string curlGet(const std::string &url, const std::string &proxy, std::string &response_headers, CURLcode &return_code, const string_map &request_headers)
static int curlGet(const FetchArgument &argument,
                   const ResolvedProxyRoute &route, FetchResult &result,
                   CURLcode *return_code = nullptr)
{
    CURL *curl_handle;
    std::string *data = result.content, new_url = argument.url;
    curl_slist *header_list = nullptr;
    defer(curl_slist_free_all(header_list);)
    CURLcode retVal;

    if(outbound_fetch_shutdown_requested.load(std::memory_order_relaxed))
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = CURLE_ABORTED_BY_CALLBACK;
        return 0;
    }

    retVal = curl_init();
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
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
        writeLog(LOG_LEVEL_ERROR, "curl_easy_init 失败。");
        return 0;
    }
    retVal = apply_curl_proxy_policy(curl_handle, route, new_url);
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        return 0;
    }
    if(route.proxy.mode == ProxyMode::Cors)
        header_list = curl_slist_append(header_list,
                                        "X-Requested-With: SubConverter-Extended " VERSION);
    curl_progress_data limit;
    limit.size_limit = effectiveSettings().maxAllowedDownloadSize;
    curl_set_common_options(curl_handle, new_url.data(), &limit);
    retVal = curl_set_platform_tls_trust(curl_handle);
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        writeLog(LOG_LEVEL_ERROR,
                 "Windows 原生 TLS 信任库配置失败：" +
                     std::string(curl_easy_strerror(retVal)));
        return 0;
    }
#if LIBCURL_VERSION_NUM >= 0x075000
    FetchContext prereq_context = argument.context;
    if(isPublicFetchRestricted(argument.context) &&
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

    if(result.content)
    {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, result.content);
    }
    else
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, dummy_writer);
    if(result.response_headers)
    {
        curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, writer);
        curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, result.response_headers);
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
        if(outbound_fetch_shutdown_requested.load(std::memory_order_relaxed))
            retVal = CURLE_ABORTED_BY_CALLBACK;
        else
            retVal = curl_easy_perform(curl_handle);
    }

    long code = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CODE, &code);
    *result.status_code = code;
    if(return_code)
        *return_code = retVal;

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

    if(data && !argument.keep_resp_on_fail)
    {
        if(retVal != CURLE_OK || *result.status_code != 200)
            data->clear();
    }

    return *result.status_code;
}

static int curlGetWithGitHubFallback(
    const FetchArgument &argument, const ResolvedProxyPolicy &snapshot,
    const ResolvedProxyRoute &initial_route, FetchResult &result)
{
    CURLcode original_code = CURLE_OK;
    int original_status =
        curlGet(argument, initial_route, result, &original_code);

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
                                      argument.context};
    const ResolvedProxyRoute fallback_route =
        resolveProxyRoute(snapshot, fallback_url, argument.context);
    CURLcode fallback_code = CURLE_OK;
    int fallback_status =
        curlGet(fallback_argument, fallback_route, result, &fallback_code);
    if(fallback_code == CURLE_OK && fallback_status == 200)
    {
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
    const ResolvedProxyPolicy snapshot = argument.proxy.snapshot();
    const ResolvedProxyRoute route =
        resolveProxyRoute(snapshot, argument.url, argument.context);
    return curlGetWithGitHubFallback(argument, snapshot, route, result);
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

std::string buildSocks5ProxyString(const std::string &addr, int port, const std::string &username, const std::string &password)
{
    std::string authstr = username.size() && password.size() ? username + ":" + password + "@" : "";
    std::string proxystr = "socks5://" + authstr + addr + ":" + std::to_string(port);
    return proxystr;
}

std::string webGet(const std::string &url, const ProxyPolicy &proxy, unsigned int cache_ttl, std::string *response_headers, string_icase_map *request_headers, FetchContext context)
{
    RequestStageTimer fetch_timer(RequestStage::Fetch);
    int return_code = 0;
    std::string content;

    if (!isFetchUrlAllowed(url, context))
        return "";

    CocrSourceResolution source =
        resolveCocrSourceUrl(
            url, effectiveSettings().customOpenClashRulesSourceSwitch);
    const std::string &effective_url = source.effective_url;
    if(source.rewritten && shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(LOG_LEVEL_VERBOSE, "COCR 服务端取源切换：" + summarizeUrlForLog(url) +
                        " -> " + summarizeUrlForLog(effective_url) + "。");

    FetchArgument argument {HTTP_GET, effective_url, proxy, nullptr,
                            request_headers, nullptr, cache_ttl, false,
                            context};
    FetchResult fetch_res {&return_code, &content, response_headers, nullptr};

    if (startsWith(effective_url, "data:"))
        return dataGet(effective_url);

    const ResolvedProxyPolicy proxy_snapshot = proxy.snapshot();
    const ResolvedProxyRoute initial_route =
        resolveProxyRoute(proxy_snapshot, effective_url, context);
    // cache system
    if(cache_ttl > 0)
    {
        md("cache");
        const std::string url_md5 =
            build_cache_key(effective_url, initial_route, request_headers);
        const std::string path = "cache/" + url_md5, path_header = path + "_header";
        struct stat result {};
        if(stat(path.data(), &result) == 0) // cache exist
        {
            time_t mtime = result.st_mtime, now = time(nullptr); // get cache modified time and current time
            if(difftime(now, mtime) <= cache_ttl) // within TTL
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(LOG_LEVEL_VERBOSE,
                             "缓存命中：" +
                                 summarizeUrlForLog(effective_url) +
                                 "，使用本地缓存。");
                //guarded_mutex guard(cache_rw_lock);
                cache_rw_lock.readLock();
                defer(cache_rw_lock.readUnlock();)
                if(response_headers)
                    *response_headers =
                        readCachedResponseHeaders(path_header);
                return fileGet(path, true);
            }
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(LOG_LEVEL_VERBOSE,
                         "缓存过期：" + summarizeUrlForLog(effective_url) +
                             "，正在创建新缓存。"); // out of TTL
        }
        else
        {
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(LOG_LEVEL_VERBOSE,
                         "缓存不存在：" +
                             summarizeUrlForLog(effective_url) +
                             "，正在创建新缓存。");
        }
        std::shared_future<CacheFetchResult> fetch_future;
        std::shared_ptr<std::promise<CacheFetchResult>> fetch_promise;
        bool owner = false;
        {
            std::lock_guard<std::mutex> lock(cache_fetch_mutex);
            auto iter = cache_fetches.find(url_md5);
            if(iter == cache_fetches.end())
            {
                fetch_promise =
                    std::make_shared<std::promise<CacheFetchResult>>();
                fetch_future = fetch_promise->get_future().share();
                cache_fetches.emplace(url_md5, fetch_future);
                owner = true;
            }
            else
                fetch_future = iter->second;
        }
        CacheFetchOwnerCleanup owner_cleanup(owner, url_md5);

        if(owner)
        {
            try
            {
                CacheFetchResult result;
                FetchResult fetch_result {
                    &result.status_code, &result.content,
                    &result.response_headers, nullptr};
                curlGetWithGitHubFallback(argument, proxy_snapshot,
                                          initial_route, fetch_result);
                fetch_promise->set_value(std::move(result));
            }
            catch(...)
            {
                fetch_promise->set_exception(std::current_exception());
            }
        }

        CacheFetchResult fetched = fetch_future.get();
        return_code = fetched.status_code;
        content = std::move(fetched.content);
        if(response_headers)
            *response_headers = fetched.response_headers;
        if(return_code == 200) // success, save new cache
        {
            if(owner)
            {
                //guarded_mutex guard(cache_rw_lock);
                cache_rw_lock.writeLock();
                defer(cache_rw_lock.writeUnlock();)
                const CacheUpdateResult cache_update = updateCacheFiles(
                    path, path_header, content, fetched.response_headers);
                if(cache_update == CacheUpdateResult::Unchanged) {
                    writeLog(LOG_LEVEL_WARNING,
                             "CACHE_UPDATE_FAILED body=unchanged headers=unchanged; "
                             "本次已获取内容仍将直接返回。");
                }
                else if(cache_update ==
                        CacheUpdateResult::UnchangedHeadersInvalidated) {
                    writeLog(LOG_LEVEL_WARNING,
                             "CACHE_UPDATE_FAILED body=unchanged "
                             "headers=invalidated; 本次已获取内容仍将直接返回。");
                }
                else if(cache_update ==
                        CacheUpdateResult::BodyCommittedUnsynced) {
                    writeLog(LOG_LEVEL_WARNING,
                             "CACHE_BODY_COMMITTED durability=unconfirmed "
                             "headers=invalidated; 本次已获取内容仍将直接返回。");
                }
                else if(cache_update == CacheUpdateResult::HeadersInvalidated) {
                    writeLog(LOG_LEVEL_WARNING,
                             "CACHE_BODY_COMMITTED durability=confirmed "
                             "headers=invalidated; 本次已获取内容仍将直接返回。");
                }
            }
        }
        else
        {
            if(fileExist(path) && effectiveSettings().serveCacheOnFetchFail) // failed, check if cache exist
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(LOG_LEVEL_VERBOSE,
                             "获取失败，返回缓存内容。"); // cache exist, serving cache
                //guarded_mutex guard(cache_rw_lock);
                cache_rw_lock.readLock();
                defer(cache_rw_lock.readUnlock();)
                content = fileGet(path, true);
                if(response_headers)
                    *response_headers =
                        readCachedResponseHeaders(path_header);
            }
            else
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(LOG_LEVEL_VERBOSE,
                             "获取失败，且没有可用的本地缓存。"); // cache not exist or not allow to serve cache, serving nothing
            }
        }
        return content;
    }
    //return curlGet(url, proxy, response_headers, return_code);
    curlGetWithGitHubFallback(argument, proxy_snapshot, initial_route,
                              fetch_res);
    return content;
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
        argument.cache_ttl, argument.keep_resp_on_fail, argument.context};
    return executeNetworkFetch(effective_argument, result);
}
