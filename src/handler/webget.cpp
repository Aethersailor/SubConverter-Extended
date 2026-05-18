#include <future>
#include <iostream>
#include <map>
#include <unistd.h>
#include <sys/stat.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>

#include <curl/curl.h>

#include "handler/settings.h"
#include "utils/base64/base64.h"
#include "utils/defer.h"
#include "utils/file_extra.h"
#include "utils/lock.h"
#include "utils/logger.h"
#include "utils/network.h"
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

static std::mutex cache_fetch_mutex;
static std::map<std::string, std::shared_future<CacheFetchResult>> cache_fetches;

static CURLcode curl_init()
{
    static std::once_flag init_flag;
    static CURLcode init_result = CURLE_FAILED_INIT;
    std::call_once(init_flag, []() {
        init_result = curl_global_init(CURL_GLOBAL_ALL);
    });
    return init_result;
}

static std::string build_cache_key(const std::string &url, const std::string &proxy,
                                   const string_icase_map *request_headers)
{
    if(proxy.empty() && (!request_headers || request_headers->empty()))
        return getMD5(url);

    std::string identity = "url:" + std::to_string(url.size()) + ":" + url;
    identity += "\nproxy:" + std::to_string(proxy.size()) + ":" + proxy;
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

    fallback_url = "https://cdn.jsdelivr.net/gh/" + file_ref.owner + "/" +
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

bool isFetchUrlAllowed(const std::string &url, FetchContext context)
{
    if(!isPublicFetchRestricted(context))
        return true;
    if(startsWith(url, "data:"))
        return true;
    if(!startsWith(url, "http://") && !startsWith(url, "https://"))
    {
        writeLog(0, "已阻止公开请求获取不支持协议的 URL：" + url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    std::string parsed_url = url, host, path;
    int port = 0;
    bool is_tls = false;
    urlParse(parsed_url, host, path, port, is_tls);
    host = normalize_fetch_host(host);
    if(host.empty() || is_blocked_hostname(host) || is_blocked_ip_address(host))
    {
        writeLog(0, "已阻止公开请求访问本地或私有主机：" + url,
                 LOG_LEVEL_WARNING);
        return false;
    }

    std::string resolved = hostnameToIPAddr(host);
    if(!resolved.empty() && is_blocked_ip_address(resolved, true))
    {
        writeLog(0,
                 "已阻止公开请求：目标主机解析到本地或私有地址：" + url,
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
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
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

    curl_handle = curl_easy_init();
    if(curl_handle == nullptr)
    {
        retVal = CURLE_FAILED_INIT;
        *result.status_code = 0;
        if(return_code)
            *return_code = retVal;
        writeLog(0, "curl_easy_init 失败。", LOG_LEVEL_ERROR);
        return 0;
    }
    if(!argument.proxy.empty())
    {
        if(startsWith(argument.proxy, "cors:"))
        {
            header_list = curl_slist_append(header_list, "X-Requested-With: SubConverter-Extended " VERSION);
            new_url = argument.proxy.substr(5) + argument.url;
        }
        else
            curl_easy_setopt(curl_handle, CURLOPT_PROXY, argument.proxy.data());
    }
    curl_progress_data limit;
    limit.size_limit = global.maxAllowedDownloadSize;
    curl_set_common_options(curl_handle, new_url.data(), &limit);
#if LIBCURL_VERSION_NUM >= 0x075000
    FetchContext prereq_context = argument.context;
    if(isPublicFetchRestricted(argument.context) && argument.proxy.empty())
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

    unsigned int fail_count = 0, max_fails = 1;
    while(true)
    {
        retVal = curl_easy_perform(curl_handle);
        if(retVal == CURLE_OK || max_fails <= fail_count || global.APIMode)
            break;
        else
            fail_count++;
    }

    long code = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CODE, &code);
    *result.status_code = code;
    if(return_code)
        *return_code = retVal;

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

    curl_easy_cleanup(curl_handle);

    if(data && !argument.keep_resp_on_fail)
    {
        if(retVal != CURLE_OK || *result.status_code != 200)
            data->clear();
        data->shrink_to_fit();
    }

    return *result.status_code;
}

static int curlGetWithGitHubFallback(const FetchArgument &argument, FetchResult &result)
{
    CURLcode original_code = CURLE_OK;
    int original_status = curlGet(argument, result, &original_code);

    std::string fallback_url;
    if(argument.method != HTTP_GET || argument.keep_resp_on_fail ||
       original_status == 200 ||
       !should_try_jsdelivr_fallback(original_code, original_status) ||
       !build_jsdelivr_github_url(argument.url, fallback_url))
        return original_status;

    std::string original_headers, original_cookies;
    if(result.response_headers)
        original_headers = *result.response_headers;
    if(result.cookies)
        original_cookies = *result.cookies;

    writeLog(0,
             "GitHub Raw 获取失败，正在尝试 jsDelivr 回退源：" +
                 fallback_url,
             LOG_LEVEL_WARNING);
    clear_fetch_output(result);

    FetchArgument fallback_argument {HTTP_GET, fallback_url, argument.proxy,
                                     nullptr, argument.request_headers,
                                     argument.cookies, argument.cache_ttl,
                                     argument.keep_resp_on_fail,
                                     argument.context};
    CURLcode fallback_code = CURLE_OK;
    int fallback_status = curlGet(fallback_argument, result, &fallback_code);
    if(fallback_code == CURLE_OK && fallback_status == 200)
    {
        writeLog(0,
                 "GitHub Raw 已通过 jsDelivr 回退源获取成功：" +
                     fallback_url,
                 LOG_LEVEL_INFO);
        return fallback_status;
    }

    writeLog(0,
             "GitHub Raw 通过 jsDelivr 回退源获取失败：" + fallback_url,
             LOG_LEVEL_WARNING);
    clear_fetch_output(result);
    if(result.response_headers)
        *result.response_headers = original_headers;
    if(result.cookies)
        *result.cookies = original_cookies;
    *result.status_code = original_status;
    return original_status;
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

std::string webGet(const std::string &url, const std::string &proxy, unsigned int cache_ttl, std::string *response_headers, string_icase_map *request_headers, FetchContext context)
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
        bool owner = false;
        {
            std::lock_guard<std::mutex> lock(cache_fetch_mutex);
            auto iter = cache_fetches.find(url_md5);
            if(iter == cache_fetches.end())
            {
                fetch_future = std::async(std::launch::async, [argument]() {
                    CacheFetchResult result;
                    FetchResult fetch_result {&result.status_code, &result.content,
                                               &result.response_headers, nullptr};
                    curlGetWithGitHubFallback(argument, fetch_result);
                    return result;
                }).share();
                cache_fetches.emplace(url_md5, fetch_future);
                owner = true;
            }
            else
                fetch_future = iter->second;
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
        if(owner)
        {
            std::lock_guard<std::mutex> lock(cache_fetch_mutex);
            cache_fetches.erase(url_md5);
        }
        return content;
    }
    //return curlGet(url, proxy, response_headers, return_code);
    curlGetWithGitHubFallback(argument, fetch_res);
    return content;
}

void flushCache()
{
    //guarded_mutex guard(cache_rw_lock);
    cache_rw_lock.writeLock();
    defer(cache_rw_lock.writeUnlock();)
    operateFiles("cache", [](const std::string &file){ remove(("cache/" + file).data()); return 0; });
}

int webPost(const std::string &url, const std::string &data, const std::string &proxy, const string_icase_map &request_headers, std::string *retData)
{
    //return curlPost(url, data, proxy, request_headers, retData);
    int return_code = 0;
    FetchArgument argument {HTTP_POST, url, proxy, &data, &request_headers, nullptr, 0, true};
    FetchResult fetch_res {&return_code, retData, nullptr, nullptr};
    return webGet(argument, fetch_res);
}

int webPatch(const std::string &url, const std::string &data, const std::string &proxy, const string_icase_map &request_headers, std::string *retData)
{
    //return curlPatch(url, data, proxy, request_headers, retData);
    int return_code = 0;
    FetchArgument argument {HTTP_PATCH, url, proxy, &data, &request_headers, nullptr, 0, true};
    FetchResult fetch_res {&return_code, retData, nullptr, nullptr};
    return webGet(argument, fetch_res);
}

int webHead(const std::string &url, const std::string &proxy, const string_icase_map &request_headers, std::string &response_headers)
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
    if (!isFetchUrlAllowed(argument.url, argument.context)) {
        *result.status_code = 403;
        if (result.content)
            result.content->clear();
        return 403;
    }
    if (startsWith(argument.url, "data:")) {
        if (result.content)
            *result.content = dataGet(argument.url);
        *result.status_code = result.content && !result.content->empty() ? 200 : 400;
        return *result.status_code;
    }
    return curlGetWithGitHubFallback(argument, result);
}
