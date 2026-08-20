#ifndef WEBSERVER_H_INCLUDED
#define WEBSERVER_H_INCLUDED

#include <string>
#include <utility>
#include <vector>
#include <map>
#include <atomic>
#include <memory>
#include <mutex>
#include <curl/curlver.h>
#include <functional>

#include "server/client_ip.h"
#include "server/request_context.h"
#include "utils/map_extra.h"
#include "utils/string.h"
#include "version.h"

struct Request
{
    std::string method;
    std::string url;
    std::string remote_addr;
    int remote_port = 0;
    client_ip::Address client_address;
    string_multimap argument;
    string_icase_map headers;
    std::string postdata;
    std::shared_ptr<RequestContext> context;
};

struct ImmutableResponseBody
{
    std::string content;
    RetainedResponseByteLease retained_bytes;
};

using shared_response_body = std::shared_ptr<const ImmutableResponseBody>;

struct Response
{
    int status_code = 200;
    std::string content_type;
    string_icase_map headers;
    shared_response_body shared_body;
};

struct RequestAdmissionSnapshot
{
    uint64_t active_entries = 0;
    uint64_t active_bytes = 0;
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    uint64_t max_entries = 0;
    uint64_t max_bytes = 0;
};

RequestAdmissionSnapshot requestAdmissionSnapshot() noexcept;
void configureRequestAdmissionLimits(uint64_t max_entries,
                                     uint64_t max_bytes) noexcept;
bool tryRequestAdmission(uint64_t bytes) noexcept;
void releaseRequestAdmission(uint64_t bytes) noexcept;

using response_callback = std::string (*)(Request&, Response&); //process arguments and POST data and return served-content
using async_response_completion =
    std::function<void(Response, std::string)>;
using async_response_callback =
    std::function<void(Request, async_response_completion)>;

#define RESPONSE_CALLBACK_ARGS Request &request, Response &response

struct listener_args
{
    std::string listen_address;
    int port;
    int max_conn;
    int max_workers;
    void (*looper_callback)() = nullptr;
    uint32_t looper_interval = 200;
    uint32_t request_deadline_ms = 15000;
    void (*shutdown_callback)() = nullptr;
    void (*drain_callback)() = nullptr;
};

struct RequestCancellationResponse
{
    int status_code = 0;
    std::string body;
    string_icase_map headers;
};

bool requestCancellationResponse(
    const std::shared_ptr<RequestContext> &context,
    RequestCancellationResponse &response) noexcept;

struct responseRoute
{
    std::string method;
    std::string path;
    std::string content_type;
    response_callback rc {};
    async_response_callback async_rc;
};

const responseRoute *findResponseRoute(
    const std::vector<responseRoute> &routes, const std::string &method,
    const std::string &path, bool allow_head_as_get = true) noexcept;
std::string invokeResponseRoute(const responseRoute &route, Request &request,
                                Response &response);
void parseHttpTarget(const std::string &target, std::string &path,
                     string_multimap &arguments);
std::string httpStaticContentType(const std::string &path);

class WebServer
{
public:
    std::string user_agent_str = "SubConverter-Extended/" VERSION " cURL/" LIBCURL_VERSION;
    std::atomic_bool SERVER_EXIT_FLAG{false};

    // file server
    bool serve_file = false;
    std::string serve_file_root;

    // basic authentication
    bool require_auth = false;
    std::string auth_user, auth_password, auth_realm = "Please enter username and password:";

    void stop_web_server();

    void append_response(const std::string &method, const std::string &uri, const std::string &content_type, response_callback response)
    {
        responseRoute rr;
        rr.method = method;
        rr.path = uri;
        rr.content_type = content_type;
        rr.rc = response;
        responses.emplace_back(std::move(rr));
    }

    void append_async_response(const std::string &method,
                               const std::string &uri,
                               const std::string &content_type,
                               response_callback sync_response,
                               async_response_callback async_response)
    {
        responseRoute rr;
        rr.method = method;
        rr.path = uri;
        rr.content_type = content_type;
        rr.rc = sync_response;
        rr.async_rc = std::move(async_response);
        responses.emplace_back(std::move(rr));
    }

    void append_redirect(const std::string &uri, const std::string &target)
    {
        redirect_map[uri] = target;
    }

    void reset_redirect()
    {
        std::map<std::string, std::string>().swap(redirect_map);
    }

    int start_web_server(listener_args *args);
    int start_web_server_multi(listener_args *args);
    void set_client_ip_policy(const client_ip::Policy &policy);
    client_ip::Policy client_ip_policy() const;

    std::vector<responseRoute> responses;
    string_map redirect_map;

private:
    mutable std::mutex client_ip_policy_mutex_;
    client_ip::Policy client_ip_policy_;
};

#endif // WEBSERVER_H_INCLUDED
