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
#include <cstdint>

#include <curl/curl.h>

#include "handler/settings.h"
#include "handler/curl_handle_pool.h"
#include "handler/remote_source.h"
#include "utils/base64/base64.h"
#include "utils/defer.h"
#include "utils/file_extra.h"
#include "utils/lock.h"
#include "utils/logger.h"
#include "utils/network.h"
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

using CacheFetchResult = FetchOutcome;

static std::mutex cache_fetch_mutex;
static std::map<std::string, std::shared_future<CacheFetchResult>> cache_fetches;

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

static std::string build_cache_key(const std::string &url, const ProxyPolicy &proxy,
                                   const string_icase_map *request_headers,
                                   FetchContext context = FetchContext::TrustedConfig,
                                   bool cocr_fallback = false)
{
    std::string identity = "remote-fetch-v2\nurl:" + std::to_string(url.size()) + ":" + url;
    const std::string proxy_identity = proxy.cacheIdentity();
    identity += "\nproxy:" + std::to_string(proxy_identity.size()) + ":" + proxy_identity;
    identity += "\ncontext:" + std::to_string(static_cast<int>(context));
    identity += "\ncocr-fallback:" + std::to_string(cocr_fallback ? 1 : 0);
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

static std::string normalize_fetch_host(std::string host)
{
    host = toLower(trimWhitespace(host, true, true));
    while(!host.empty() && host.back() == '.')
        host.pop_back();
    return host;
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

static bool has_control_character(const std::string &value)
{
    for(unsigned char ch : value)
    {
        if(std::iscntrl(ch))
            return true;
    }
    return false;
}

bool isFetchUrlAllowed(const std::string &url, FetchContext context)
{
    if(!isPublicFetchRestricted(context))
        return true;
    std::string checked_url = trimWhitespace(url, true, true);
    std::string log_url = remote_source::redactForLog(checked_url);
    if(checked_url.empty() || checked_url != url || has_control_character(checked_url))
    {
        writeLog(0, "已阻止公开请求获取格式异常的 URL：" + log_url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    const size_t scheme_end = checked_url.find("://");
    const size_t authority_begin = scheme_end == std::string::npos
                                       ? std::string::npos
                                       : scheme_end + 3;
    const size_t authority_end = authority_begin == std::string::npos
                                     ? std::string::npos
                                     : checked_url.find_first_of("/?#", authority_begin);
    if (authority_begin != std::string::npos &&
        checked_url.substr(authority_begin,
                           authority_end == std::string::npos
                               ? std::string::npos
                               : authority_end - authority_begin)
                .find('@') != std::string::npos) {
        writeLog(0, "已阻止公开请求使用带凭据的 URL：" + log_url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    std::string lower_url = toLower(checked_url);
    if(startsWith(lower_url, "data:"))
        return true;
    if(!startsWith(lower_url, "http://") && !startsWith(lower_url, "https://"))
    {
        writeLog(0, "已阻止公开请求获取不支持协议的 URL：" + log_url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    std::string parsed_url = checked_url, host, path;
    int port = 0;
    bool is_tls = false;
    urlParse(parsed_url, host, path, port, is_tls);
    host = normalize_fetch_host(host);
    if(host.empty() || is_blocked_hostname(host) || is_blocked_ip_address(host))
    {
        writeLog(0, "已阻止公开请求访问本地或私有主机：" + log_url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    std::string resolved = hostnameToIPAddr(host);
    if(!resolved.empty() && is_blocked_ip_address(resolved, true))
    {
        writeLog(0,
                 "已阻止公开请求：目标主机解析到本地或私有地址：" + log_url,
                 LOG_LEVEL_WARNING);
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
        writeLog(0,
                 "已阻止公开请求连接本地或私有地址：" +
                     std::string(conn_primary_ip),
                 LOG_LEVEL_WARNING);
        return CURL_PREREQFUNC_ABORT;
    }
    return CURL_PREREQFUNC_OK;
}
#endif

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
    if(content.find("\r\n") != std::string::npos)
    {
        string_array lines = split(content, "\r\n");
        for(auto &x : lines)
        {
            std::string log_content = prefix;
            log_content += x;
            writeLog(0, log_content, LOG_LEVEL_VERBOSE);
        }
    }
    else
    {
        std::string log_content = prefix;
        log_content += trimWhitespace(content);
        writeLog(0, log_content, LOG_LEVEL_VERBOSE);
    }
    return 0;
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
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER,
                     global.allowInsecureTls ? 0L : 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST,
                     global.allowInsecureTls ? 0L : 2L);
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
                                        const ProxyPolicy &requested,
                                        std::string &url,
                                        ProxyPolicy &effective)
{
    effective = requested.resolved();
    if(!effective.valid)
    {
        writeLog(0, "出站代理配置无效：" + effective.describe() + "。",
                 LOG_LEVEL_ERROR);
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
        // Do not set CURLOPT_NOPROXY here: System intentionally preserves the
        // platform's NO_PROXY/no_proxy behaviour.
        break;
    case ProxyMode::Explicit:
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, effective.endpoint.c_str());
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
        writeLog(0, "出站代理策略：" + effective.describe() + "。",
                 LOG_LEVEL_VERBOSE);
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
static int curlGet(const FetchArgument &argument, FetchResult &result, CURLcode *return_code = nullptr)
{
    CURL *curl_handle;
    std::string *data = result.content, new_url = argument.url;
    curl_slist *header_list = nullptr;
    defer(curl_slist_free_all(header_list);)
    CURLcode retVal;

    retVal = curl_init();
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        writeLog(0, "curl_global_init 失败：" + std::string(curl_easy_strerror(retVal)), LOG_LEVEL_ERROR);
        return 0;
    }

    CurlHandleLease curl_lease =
        globalCurlHandlePool(
            static_cast<size_t>(std::max(1, global.maxConcurThreads)))
            .acquire();
    curl_handle = curl_lease.get();
    if(curl_handle == nullptr)
    {
        retVal = CURLE_FAILED_INIT;
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        writeLog(0, "curl_easy_init 失败。", LOG_LEVEL_ERROR);
        return 0;
    }
    ProxyPolicy effective_proxy;
    retVal = apply_curl_proxy_policy(curl_handle, argument.proxy, new_url,
                                     effective_proxy);
    if(retVal != CURLE_OK)
    {
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        return 0;
    }
    if(effective_proxy.mode == ProxyMode::Cors)
        header_list = curl_slist_append(header_list,
                                        "X-Requested-With: SubConverter-Extended " VERSION);
    curl_progress_data limit;
    limit.size_limit = global.maxAllowedDownloadSize;
    curl_set_common_options(curl_handle, new_url.data(), &limit);
#if LIBCURL_VERSION_NUM >= 0x075000
    FetchContext prereq_context = argument.context;
    if(isPublicFetchRestricted(argument.context) &&
       (effective_proxy.mode == ProxyMode::Direct ||
        (effective_proxy.mode == ProxyMode::System &&
         effective_proxy.endpoint.empty())))
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
       (argument.method == HTTP_GET || argument.method == HTTP_HEAD) &&
       is_recoverable_curl_error(retVal))
    {
        writeLog(0, "出站请求遇到可恢复网络错误，200ms 后重试一次。",
                 LOG_LEVEL_WARNING);
        if(result.content)
            result.content->clear();
        if(result.response_headers)
            result.response_headers->clear();
        sleepMs(200);
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
        writeLog(0, std::string("出站代理实际使用：") +
                        (used_proxy ? "是" : "否") + "。",
                 LOG_LEVEL_VERBOSE);
#endif
#if LIBCURL_VERSION_NUM >= 0x074900
    long proxy_error = 0;
    if(curl_easy_getinfo(curl_handle, CURLINFO_PROXY_ERROR, &proxy_error) == CURLE_OK &&
       proxy_error != 0 && shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(0, "出站代理错误代码：" + std::to_string(proxy_error) + "。",
                 LOG_LEVEL_VERBOSE);
#endif
    if(retVal != CURLE_OK && shouldLog(LOG_LEVEL_VERBOSE))
        writeLog(0, "出站请求错误类别：" +
                        std::string(classify_curl_error(retVal)) + "。",
                 LOG_LEVEL_VERBOSE);

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

// data:[<mediatype>][;base64],<data>
static std::string dataGet(const std::string &url)
{
    if (!startsWith(url, "data:"))
        return "";
    std::string::size_type comma = url.find(',');
    if (comma == std::string::npos || comma == url.size() - 1)
        return "";

    std::string data = urlDecode(url.substr(comma + 1));
    if (global.maxAllowedDownloadSize > 0 &&
        data.size() > static_cast<size_t>(global.maxAllowedDownloadSize)) {
        writeLog(0, "已阻止 data URL：内容超过最大下载大小。",
                 LOG_LEVEL_WARNING);
        return "";
    }
    if (endsWith(url.substr(0, comma), ";base64")) {
        std::string decoded = urlSafeBase64Decode(data);
        if (global.maxAllowedDownloadSize > 0 &&
            decoded.size() >
                static_cast<size_t>(global.maxAllowedDownloadSize)) {
            writeLog(0,
                     "已阻止解码后的 data URL：内容超过最大下载大小。",
                     LOG_LEVEL_WARNING);
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

/* Legacy cache wrapper removed; retained below only as historical context.
std::string webGetLegacy(const std::string &url, const ProxyPolicy &proxy, unsigned int cache_ttl, std::string *response_headers, string_icase_map *request_headers, FetchContext context)
{
    int return_code = 0;
    std::string content;

    if (!isFetchUrlAllowed(url, context))
        return "";

    FetchArgument argument {HTTP_GET, url, proxy, nullptr, request_headers,
                            nullptr, cache_ttl, false, context};
    FetchResult fetch_res {&return_code, &content, response_headers, nullptr};

    if (startsWith(url, "data:"))
        return dataGet(url);
    // cache system
    if(cache_ttl > 0)
    {
        md("cache");
        const std::string url_md5 = build_cache_key(url, proxy, request_headers);
        const std::string path = "cache/" + url_md5, path_header = path + "_header";
        struct stat result {};
        if(stat(path.data(), &result) == 0) // cache exist
        {
            time_t mtime = result.st_mtime, now = time(nullptr); // get cache modified time and current time
            if(difftime(now, mtime) <= cache_ttl) // within TTL
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(0, "缓存命中：'" + url + "'，使用本地缓存。");
                //guarded_mutex guard(cache_rw_lock);
                cache_rw_lock.readLock();
                defer(cache_rw_lock.readUnlock();)
                if(response_headers)
                    *response_headers = fileGet(path_header, true);
                return fileGet(path, true);
            }
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(0, "缓存过期：'" + url + "'，正在创建新缓存。"); // out of TTL
        }
        else
        {
            if(shouldLog(LOG_LEVEL_VERBOSE))
                writeLog(0, "缓存不存在：'" + url + "'，正在创建新缓存。");
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
                curlGetWithGitHubFallback(argument, fetch_result);
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
                fileWrite(path, content, true);
                if(!fetched.response_headers.empty())
                    fileWrite(path_header, fetched.response_headers, true);
            }
        }
        else
        {
            if(fileExist(path) && global.serveCacheOnFetchFail) // failed, check if cache exist
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(0, "获取失败，返回缓存内容。"); // cache exist, serving cache
                //guarded_mutex guard(cache_rw_lock);
                cache_rw_lock.readLock();
                defer(cache_rw_lock.readUnlock();)
                content = fileGet(path, true);
                if(response_headers)
                    *response_headers = fileGet(path_header, true);
            }
            else
            {
                if(shouldLog(LOG_LEVEL_VERBOSE))
                    writeLog(0, "获取失败，且没有可用的本地缓存。"); // cache not exist or not allow to serve cache, serving nothing
            }
        }
        return content;
    }
    //return curlGet(url, proxy, response_headers, return_code);
    curlGetWithGitHubFallback(argument, fetch_res);
    return content;
}
*/

namespace {

struct StaleCacheCandidate {
    std::string path;
    std::string header_path;
    time_t mtime = 0;
    std::string url;
    std::string source_kind;
};

static bool is_http_get(const FetchArgument &argument) {
    return argument.method == HTTP_GET;
}

static FetchFailureCategory classify_fetch_failure(CURLcode code, int status) {
    if (code != CURLE_OK) {
        switch (code) {
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_URL_MALFORMAT:
        case CURLE_FAILED_INIT:
        case CURLE_OUT_OF_MEMORY:
        case CURLE_FILESIZE_EXCEEDED:
            return FetchFailureCategory::Internal;
        case CURLE_ABORTED_BY_CALLBACK:
            return FetchFailureCategory::RequestRejected;
        default:
            return FetchFailureCategory::SourceUnavailable;
        }
    }
    if (status == 404)
        return FetchFailureCategory::NotFound;
    if (status == 0 || status == 408 || status == 429 || status >= 500)
        return FetchFailureCategory::SourceUnavailable;
    // Authentication and permission failures are request-level decisions. Do
    // not mirror them, serve stale data, or replace the request with a
    // different default template.
    if (status == 401 || status == 403 || (status >= 400 && status < 500))
        return FetchFailureCategory::RequestRejected;
    if (status != 200)
        return FetchFailureCategory::RequestRejected;
    return FetchFailureCategory::None;
}

static bool can_try_next_source(FetchFailureCategory failure) {
    return failure == FetchFailureCategory::SourceUnavailable ||
           failure == FetchFailureCategory::NotFound;
}

static std::string failure_name(FetchFailureCategory failure) {
    switch (failure) {
    case FetchFailureCategory::RequestRejected: return "request_rejected";
    case FetchFailureCategory::SourceUnavailable: return "source_unavailable";
    case FetchFailureCategory::NotFound: return "not_found";
    case FetchFailureCategory::ContentInvalid: return "content_invalid";
    case FetchFailureCategory::Internal: return "internal";
    case FetchFailureCategory::None: default: return "none";
    }
}

static std::string cache_path_for(const FetchArgument &argument,
                                  const remote_source::FetchCandidate &candidate) {
    const std::string key = build_cache_key(
        candidate.url, argument.proxy, argument.request_headers,
        argument.context, global.customOpenClashRulesFallback);
    return "cache/" + key;
}

static bool read_cache_candidate(const std::string &path,
                                 const std::string &header_path,
                                 unsigned int cache_ttl,
                                 std::string &content,
                                 std::string &headers,
                                 time_t *mtime_out = nullptr) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0)
        return false;
    content = fileGet(path, true);
    // An empty cached config is never a valid fresh source. This also keeps a
    // partially-created file from suppressing the source chain.
    if (content.empty())
        return false;
    if (mtime_out)
        *mtime_out = st.st_mtime;
    if (cache_ttl > 0 &&
        difftime(time(nullptr), st.st_mtime) > cache_ttl)
        return false;
    headers = fileGet(header_path, true);
    return true;
}

static void write_cache_candidate(const FetchOutcome &outcome) {
    if (outcome.cache_path.empty() || !outcome.success || outcome.stale_cache_used)
        return;
    md("cache");
    cache_rw_lock.writeLock();
    defer(cache_rw_lock.writeUnlock();)
    fileWrite(outcome.cache_path, outcome.content, true);
    if (!outcome.response_headers.empty())
        fileWrite(outcome.cache_header_path, outcome.response_headers, true);
}

static FetchOutcome perform_fetch(const FetchArgument &argument) {
    FetchOutcome outcome;
    outcome.requested_url = argument.url;

    const std::string lower_url = toLower(trimWhitespace(argument.url, true, true));
    if (startsWith(lower_url, "data:")) {
        outcome.content = dataGet(argument.url);
        outcome.status_code = outcome.content.empty() ? 400 : 200;
        outcome.success = outcome.status_code == 200;
        outcome.effective_url = argument.url;
        outcome.effective_source = "generic";
        outcome.failure = outcome.success ? FetchFailureCategory::None
                                           : FetchFailureCategory::RequestRejected;
        outcome.failure_reason = failure_name(outcome.failure);
        return outcome;
    }

    if (!isFetchUrlAllowed(argument.url, argument.context)) {
        outcome.status_code = 403;
        outcome.failure = FetchFailureCategory::RequestRejected;
        outcome.failure_reason = failure_name(outcome.failure);
        return outcome;
    }

    const remote_source::ParsedUrl parsed = remote_source::parse(argument.url);
    if (!parsed.valid && parsed.recognized_host) {
        outcome.status_code = 400;
        outcome.failure = FetchFailureCategory::RequestRejected;
        outcome.failure_reason = failure_name(outcome.failure);
        return outcome;
    }

    const auto plan = remote_source::buildFetchPlan(
        argument.url, parsed, global.customOpenClashRulesFallback,
        argument.method == HTTP_GET);
    outcome.cocr_rewrite_used = plan.cocr_rewrite_used;
    outcome.logical_resource = plan.logical_resource;
    if (plan.cocr_rewrite_failed) {
        outcome.status_code = 502;
        outcome.failure = FetchFailureCategory::Internal;
        outcome.failure_reason = "cocr_rewrite_failed";
        return outcome;
    }
    const auto &candidates = plan.candidates;
    outcome.raw_to_jsdelivr_used = false;

    const bool cache_enabled = argument.cache_ttl > 0 && is_http_get(argument);
    std::vector<StaleCacheCandidate> stale;
    FetchFailureCategory last_failure = FetchFailureCategory::SourceUnavailable;
    int last_status = 0;

    for (size_t index = 0; index < candidates.size(); ++index) {
        const auto &candidate = candidates[index];
        outcome.effective_url = candidate.url;
        outcome.effective_source = candidate.source_kind;
        if (index > 0 && candidate.source_kind == "jsdelivr")
            outcome.raw_to_jsdelivr_used = true;
        if (!isFetchUrlAllowed(candidate.url, argument.context)) {
            outcome.status_code = 403;
            outcome.effective_url = candidate.url;
            outcome.failure = FetchFailureCategory::RequestRejected;
            outcome.failure_reason = failure_name(outcome.failure);
            outcome.attempts.push_back({candidate.source_kind,
                                        remote_source::redactForLog(candidate.url),
                                        outcome.status_code, 0, outcome.failure});
            break;
        }

        std::string cache_path, cache_header_path;
        if (cache_enabled) {
            cache_path = cache_path_for(argument, candidate);
            cache_header_path = cache_path + "_header";
            std::string cached_content, cached_headers;
            if (read_cache_candidate(cache_path, cache_header_path,
                                     argument.cache_ttl, cached_content,
                                     cached_headers)) {
                outcome.success = true;
                outcome.status_code = 200;
                outcome.content = std::move(cached_content);
                outcome.response_headers = std::move(cached_headers);
                outcome.effective_url = candidate.url;
                outcome.effective_source = candidate.source_kind;
                outcome.fresh_cache_used = true;
                outcome.cache_path = cache_path;
                outcome.cache_header_path = cache_header_path;
                outcome.failure = FetchFailureCategory::None;
                outcome.attempts.push_back({candidate.source_kind, "cache", 200, 0,
                                            FetchFailureCategory::None});
                return outcome;
            }
            time_t stale_mtime = 0;
            std::string stale_content, stale_headers;
            if (read_cache_candidate(cache_path, cache_header_path, 0,
                                     stale_content, stale_headers,
                                     &stale_mtime)) {
                stale.push_back({cache_path, cache_header_path, stale_mtime,
                                 candidate.url, candidate.source_kind});
            }
        }

        int status = 0;
        std::string content, headers, cookies;
        FetchResult result{&status, &content, &headers, &cookies};
        FetchArgument request{argument.method,
                              candidate.url,
                              argument.proxy,
                              argument.post_data,
                              argument.request_headers,
                              argument.cookies,
                              argument.cache_ttl,
                              argument.keep_resp_on_fail,
                              argument.context,
                              argument.defer_cache_commit};
        CURLcode curl_code = CURLE_OK;
        const int returned_status = curlGet(request, result, &curl_code);
        status = returned_status;
        const auto failure = (curl_code == CURLE_OK && status == 200)
                                 ? FetchFailureCategory::None
                                 : classify_fetch_failure(curl_code, status);
        outcome.attempts.push_back({candidate.source_kind,
                                    remote_source::redactForLog(candidate.url),
                                    status, static_cast<int>(curl_code), failure});
        if (failure == FetchFailureCategory::None) {
            outcome.success = true;
            outcome.status_code = 200;
            outcome.content = std::move(content);
            outcome.response_headers = std::move(headers);
            outcome.cookies = std::move(cookies);
            outcome.effective_url = candidate.url;
            outcome.effective_source = candidate.source_kind;
            outcome.failure = FetchFailureCategory::None;
            if (cache_enabled) {
                outcome.cache_path = cache_path;
                outcome.cache_header_path = cache_header_path;
                if (argument.defer_cache_commit)
                    outcome.cache_commit_pending = true;
                else
                    write_cache_candidate(outcome);
            }
            return outcome;
        }

        last_failure = failure;
        last_status = status;
        if (!can_try_next_source(failure) || index + 1 >= candidates.size())
            break;
        writeLog(0, "远程来源失败，尝试下一允许来源：" +
                         remote_source::redactForLog(candidate.url),
                 LOG_LEVEL_WARNING);
    }

    if (!stale.empty() && global.serveCacheOnFetchFail &&
        can_try_next_source(last_failure)) {
        const auto stale_iter = std::max_element(
            stale.begin(), stale.end(),
            [](const StaleCacheCandidate &lhs, const StaleCacheCandidate &rhs) {
                return lhs.mtime < rhs.mtime;
            });
        cache_rw_lock.readLock();
        defer(cache_rw_lock.readUnlock();)
        outcome.success = true;
        outcome.status_code = 200;
        outcome.content = fileGet(stale_iter->path, true);
        outcome.response_headers = fileGet(stale_iter->header_path, true);
        outcome.effective_url = stale_iter->url;
        outcome.effective_source = stale_iter->source_kind;
        outcome.stale_cache_used = !outcome.content.empty();
        if (outcome.stale_cache_used) {
            outcome.failure = FetchFailureCategory::None;
            outcome.failure_reason = "stale_cache";
            return outcome;
        }
    }

    outcome.success = false;
    outcome.status_code = last_status == 0
                              ? (last_failure == FetchFailureCategory::RequestRejected ? 403 : 502)
                              : last_status;
    outcome.failure = last_failure;
    outcome.failure_reason = failure_name(last_failure);
    return outcome;
}

} // namespace

bool commitFetchOutcomeCache(const FetchOutcome &outcome) {
    if (!outcome.cache_commit_pending || !outcome.success ||
        outcome.cache_path.empty())
        return false;
    write_cache_candidate(outcome);
    return true;
}

void discardFetchOutcomeCache(const FetchOutcome &outcome) {
    // Deferred network responses are held in memory and are never written to
    // the final cache path until commitFetchOutcomeCache is called. Discarding
    // therefore preserves any older stale entry; a semantically invalid fresh
    // cache entry is removed so it cannot poison later requests.
    if (!outcome.fresh_cache_used || outcome.cache_path.empty())
        return;
    cache_rw_lock.writeLock();
    defer(cache_rw_lock.writeUnlock();)
    remove(outcome.cache_path.c_str());
    if (!outcome.cache_header_path.empty())
        remove(outcome.cache_header_path.c_str());
}

int fetchRemote(const FetchArgument &argument, FetchOutcome &outcome) {
    if (argument.cache_ttl == 0 || argument.method != HTTP_GET) {
        outcome = perform_fetch(argument);
        return outcome.status_code;
    }

    const std::string key = build_cache_key(
        argument.url, argument.proxy, argument.request_headers,
        argument.context, global.customOpenClashRulesFallback);
    std::shared_future<CacheFetchResult> fetch_future;
    std::shared_ptr<std::promise<CacheFetchResult>> fetch_promise;
    bool owner = false;
    {
        std::lock_guard<std::mutex> lock(cache_fetch_mutex);
        const auto iter = cache_fetches.find(key);
        if (iter == cache_fetches.end()) {
            fetch_promise = std::make_shared<std::promise<CacheFetchResult>>();
            fetch_future = fetch_promise->get_future().share();
            cache_fetches.emplace(key, fetch_future);
            owner = true;
        } else {
            fetch_future = iter->second;
        }
    }
    CacheFetchOwnerCleanup owner_cleanup(owner, key);
    if (owner) {
        try {
            fetch_promise->set_value(perform_fetch(argument));
        } catch (...) {
            fetch_promise->set_exception(std::current_exception());
        }
    }
    outcome = fetch_future.get();
    return outcome.status_code;
}

std::string webGet(const std::string &url, const ProxyPolicy &proxy,
                   unsigned int cache_ttl, std::string *response_headers,
                   string_icase_map *request_headers, FetchContext context) {
    FetchArgument argument{HTTP_GET, url, proxy, nullptr, request_headers,
                           nullptr, cache_ttl, false, context};
    FetchOutcome outcome;
    fetchRemote(argument, outcome);
    if (response_headers)
        *response_headers = outcome.response_headers;
    return outcome.success ? outcome.content : "";
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
    FetchOutcome outcome;
    const int status = fetchRemote(argument, outcome);
    if (result.status_code)
        *result.status_code = status;
    if (result.content)
        *result.content = outcome.success ? outcome.content : "";
    if (result.response_headers)
        *result.response_headers = outcome.response_headers;
    if (result.cookies)
        *result.cookies = outcome.cookies;
    return status;
}
