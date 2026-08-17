#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <functional>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#ifdef MALLOC_TRIM
#include <malloc.h>
#endif // MALLOC_TRIM
#ifndef CPPHTTPLIB_LISTEN_BACKLOG
#define CPPHTTPLIB_LISTEN_BACKLOG 10240
#endif // CPPHTTPLIB_LISTEN_BACKLOG
#define CPPHTTPLIB_MAX_LINE_LENGTH 819200
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 819200
#define CPPHTTPLIB_HEADER_MAX_LENGTH 819200
#define CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH 819200
#include "httplib.h"

#include "utils/base64/base64.h"
#include "utils/logger.h"
#include "utils/redact.h"
#include "utils/stl_extra.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "handler/settings.h"
#include "webserver.h"


static const char *request_header_blacklist[] = {"host", "accept",
                                                 "accept-encoding"};

namespace {

constexpr const char *kRequestTelemetryKey = "subconverter.request.telemetry";

class RequestAdmissionController {
public:
  bool tryAcquire(uint64_t bytes) noexcept {
    const uint64_t previous_entries =
        active_entries_.fetch_add(1, std::memory_order_acq_rel);
    if (previous_entries >= kMaxEntries) {
      active_entries_.fetch_sub(1, std::memory_order_acq_rel);
      rejected_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    uint64_t current = active_bytes_.load(std::memory_order_acquire);
    while (bytes <= kMaxBytes && current <= kMaxBytes - bytes) {
      if (active_bytes_.compare_exchange_weak(
              current, current + bytes, std::memory_order_acq_rel,
              std::memory_order_acquire)) {
        accepted_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
    }
    active_entries_.fetch_sub(1, std::memory_order_acq_rel);
    rejected_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  void release(uint64_t bytes) noexcept {
    active_bytes_.fetch_sub(bytes, std::memory_order_acq_rel);
    active_entries_.fetch_sub(1, std::memory_order_acq_rel);
  }

  RequestAdmissionSnapshot snapshot() const noexcept {
    return {active_entries_.load(std::memory_order_relaxed),
            active_bytes_.load(std::memory_order_relaxed),
            accepted_.load(std::memory_order_relaxed),
            rejected_.load(std::memory_order_relaxed)};
  }

private:
  static constexpr uint64_t kMaxEntries = 2048;
  static constexpr uint64_t kMaxBytes = UINT64_C(64) * 1024 * 1024;
  std::atomic<uint64_t> active_entries_{0};
  std::atomic<uint64_t> active_bytes_{0};
  std::atomic<uint64_t> accepted_{0};
  std::atomic<uint64_t> rejected_{0};
};

RequestAdmissionController request_admission;

uint64_t requestAdmissionBytes(const httplib::Request &request) {
  uint64_t bytes = UINT64_C(1024) + request.target.size() +
                   request.body.size();
  for (const auto &header : request.headers)
    bytes += header.first.size() + header.second.size();
  return bytes;
}

struct HttpRequestTelemetry {
  std::string request_id;
  std::chrono::steady_clock::time_point started_at;
  std::shared_ptr<RequestContext> context;

  struct Completion {
    std::shared_ptr<RequestContext> context;
    std::string request_id;
    std::chrono::steady_clock::time_point sending_started_at =
        std::chrono::steady_clock::time_point::min();
    std::function<bool()> is_connection_closed;
    int status_code = 500;
    bool prepared = false;
    bool admission_acquired = false;
    uint64_t admission_bytes = 0;

    ~Completion() {
      if (!context)
        return;
      if (sending_started_at !=
          std::chrono::steady_clock::time_point::min())
        context->addStageDuration(RequestStage::Send,
                                  std::chrono::steady_clock::now() -
                                      sending_started_at);

      bool response_sent = true;
      if (is_connection_closed) {
        try {
          response_sent = !is_connection_closed();
        } catch (...) {
          response_sent = false;
        }
      }
      if (!prepared)
        response_sent = false;
      if (context->finalizeResponse(status_code, response_sent) &&
          !response_sent) {
        ScopedLogRequestContext request_log_scope(request_id);
        writeLog(LOG_LEVEL_WARNING,
                 "HTTP_RESPONSE_SEND_FAILED terminal=cancelled "
                 "failure=client");
      }
      if (admission_acquired)
        request_admission.release(admission_bytes);
    }

    void prepare(const httplib::Request &request, int response_status) {
      status_code = response_status;
      sending_started_at = std::chrono::steady_clock::now();
      is_connection_closed = request.is_connection_closed;
      prepared = true;
      if (context)
        context->setCurrentStage(RequestStage::Send);
    }
  };

  std::shared_ptr<Completion> completion;
};

uint64_t requestProcessNonce() {
  static const uint64_t nonce = [] {
    uint64_t value = static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    value ^= static_cast<uint64_t>(getpid()) << 32;
    try {
      std::random_device random;
      value ^= static_cast<uint64_t>(random()) << 32;
      value ^= static_cast<uint64_t>(random());
    } catch (...) {
      // Correlation IDs are not credentials. Time, PID, and the atomic counter
      // still provide process-local uniqueness if the random source is absent.
    }
    return value;
  }();
  return nonce;
}

std::string fixedHex(uint64_t value) {
  std::ostringstream stream;
  stream << std::hex << std::nouppercase << std::setfill('0') << std::setw(16)
         << value;
  return stream.str();
}

std::string nextRequestId() {
  static std::atomic<uint64_t> counter{0};
  return fixedHex(requestProcessNonce()) +
         fixedHex(counter.fetch_add(1, std::memory_order_relaxed) + 1);
}

HttpRequestTelemetry &ensureRequestTelemetry(const httplib::Request &request,
                                             httplib::Response &response) {
  if (auto *existing =
          response.user_data.get<HttpRequestTelemetry>(kRequestTelemetryKey))
    return *existing;

  HttpRequestTelemetry telemetry;
  telemetry.request_id = nextRequestId();
  telemetry.started_at = request.start_time_;
  if (telemetry.started_at ==
      std::chrono::steady_clock::time_point::min())
    telemetry.started_at = std::chrono::steady_clock::now();
  telemetry.context = std::make_shared<RequestContext>(
      telemetry.request_id, telemetry.started_at);
  telemetry.completion = std::make_shared<HttpRequestTelemetry::Completion>();
  telemetry.completion->context = telemetry.context;
  telemetry.completion->request_id = telemetry.request_id;
  response.user_data.set(kRequestTelemetryKey, std::move(telemetry));
  return *response.user_data.get<HttpRequestTelemetry>(kRequestTelemetryKey);
}

void setRequestTelemetryHeaders(httplib::Response &response,
                                const std::string &request_id) {
  response.headers.erase("X-Request-ID");
  response.set_header("X-Request-ID", request_id);

  const std::string current =
      response.get_header_value("Access-Control-Expose-Headers");
  bool request_id_exposed = false;
  for (const std::string &token : split(current, ",")) {
    if (toLower(trimWhitespace(token, true, true)) == "x-request-id") {
      request_id_exposed = true;
      break;
    }
  }
  if (!request_id_exposed) {
    response.headers.erase("Access-Control-Expose-Headers");
    response.set_header("Access-Control-Expose-Headers",
                        current.empty() ? "X-Request-ID"
                                        : current + ", X-Request-ID");
  }
}

std::string requestPathForLog(const std::string &path) {
  static constexpr size_t kMaxVisiblePath = 256;
  if (!path.empty() && path.size() <= kMaxVisiblePath &&
      std::all_of(path.begin(), path.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '/' || ch == '.' || ch == '_' ||
               ch == '-' || ch == '~';
      }))
    return path;
  return "<redacted> path_length=" + std::to_string(path.size());
}

bool hasNoStoreDirective(const std::string &cache_control) {
  for (std::string directive : split(cache_control, ",")) {
    directive = toLower(trimWhitespace(directive, true, true));
    const std::string::size_type equals = directive.find('=');
    if (equals != std::string::npos)
      directive.erase(equals);
    if (trimWhitespace(directive, true, true) == "no-store")
      return true;
  }
  return false;
}

bool isExplainRequest(const httplib::Request &request) {
  if (!request.has_param("explain"))
    return false;
  const std::string value = toLower(
      trimWhitespace(request.get_param_value("explain"), true, true));
  return value == "1" || value == "true" || value == "yes" || value == "on";
}

} // namespace

RequestAdmissionSnapshot requestAdmissionSnapshot() noexcept {
  return request_admission.snapshot();
}

static inline bool is_request_header_blacklisted(const std::string &header) {
  for (auto &x : request_header_blacklist) {
    if (strcasecmp(x, header.c_str()) == 0) {
      return true;
    }
  }
  return false;
}

void WebServer::stop_web_server() { SERVER_EXIT_FLAG = true; }

void WebServer::set_client_ip_policy(const client_ip::Policy &policy) {
  std::lock_guard<std::mutex> lock(client_ip_policy_mutex_);
  client_ip_policy_ = policy;
}

client_ip::Policy WebServer::client_ip_policy() const {
  std::lock_guard<std::mutex> lock(client_ip_policy_mutex_);
  return client_ip_policy_;
}

static httplib::Server::Handler makeHandler(const responseRoute &rr,
                                            const WebServer *web_server) {
  return [rr, web_server](const httplib::Request &request,
                          httplib::Response &response) {
    HttpRequestTelemetry &telemetry =
        ensureRequestTelemetry(request, response);
    ScopedLogRequestContext request_log_scope(telemetry.request_id);
    ScopedRequestContext request_context_scope(telemetry.context);
    Request req;
    Response resp;
    req.method = request.method;
    req.url = request.path;
    req.remote_addr = request.remote_addr;
    req.remote_port = request.remote_port;
    req.client_address = client_ip::parseAddress(request.remote_addr);
    req.context = telemetry.context;
    if (request.path == "/healthz" || request.path == "/version" ||
        request.path == "/inspect")
      telemetry.context->setCostClass(RequestCostClass::Low);
    else if (request.path == "/getruleset")
      telemetry.context->setCostClass(RequestCostClass::Medium);
    const client_ip::Policy policy = web_server->client_ip_policy();
    if (policy.enabled()) {
      std::vector<std::string> values;
      const char *name = client_ip::headerName(policy.header);
      const std::size_t count = request.get_header_value_count(name);
      values.reserve(count);
      for (std::size_t index = 0; index < count; ++index)
        values.push_back(request.get_header_value(name, "", index));
      req.client_address =
          client_ip::resolve(req.client_address, values, policy).address;
    }
    for (auto &h : request.headers) {
      if (startsWith(h.first, "LOCAL_") || startsWith(h.first, "REMOTE_") ||
          is_request_header_blacklisted(h.first)) {
        continue;
      }
      req.headers.emplace(h.first.data(), h.second.data());
    }
    for (const auto &param : request.params) {
      req.argument.emplace(param.first, param.second);
    }
    if (request.method == "POST" || request.method == "PUT" ||
        request.method == "PATCH") {
      if (request.get_header_value("Content-Type") ==
          "application/x-www-form-urlencoded") {
        req.postdata = urlDecode(request.body);
      } else {
        req.postdata = request.body;
      }
    }
    auto result = rr.rc(req, resp);
    RequestStageTimer serialize_timer(telemetry.context,
                                      RequestStage::Serialize);
    response.status = resp.status_code;
    if (resp.status_code >= 400) {
      const auto cache_control = resp.headers.find("Cache-Control");
      if (cache_control == resp.headers.end() ||
          !hasNoStoreDirective(cache_control->second))
        resp.headers["Cache-Control"] = "private, no-store";
    }
    for (auto &h : resp.headers) {
      response.set_header(h.first, h.second);
    }
    auto content_type = resp.content_type;
    if (content_type.empty()) {
      content_type = rr.content_type;
    }
    response.set_content(std::move(result), content_type);
  };
}

static void setUnhandledExceptionResponse(httplib::Response &response) {
  response.status = 500;
  response.set_header("Cache-Control", "private, no-store");
  response.set_content("Internal server error while processing request.\n"
                       "处理请求时发生内部服务器错误。\n",
                       "text/plain; charset=utf-8");
}

int WebServer::start_web_server_multi(listener_args *args) {
  httplib::Server server;
  for (auto &x : responses) {
    switch (hash_(x.method)) {
    case "GET"_hash:
    case "HEAD"_hash:
      server.Get(x.path, makeHandler(x, this));
      break;
    case "POST"_hash:
      server.Post(x.path, makeHandler(x, this));
      break;
    case "PUT"_hash:
      server.Put(x.path, makeHandler(x, this));
      break;
    case "DELETE"_hash:
      server.Delete(x.path, makeHandler(x, this));
      break;
    case "PATCH"_hash:
      server.Patch(x.path, makeHandler(x, this));
      break;
    }
  }
  server.Options(R"(.*)",
                 [&](const httplib::Request &req, httplib::Response &res) {
                   auto path = req.path;
                   std::string allowed;
                   for (auto &rr : responses) {
                     if (rr.path == path) {
                       allowed += rr.method + ",";
                     }
                   }
                   if (!allowed.empty()) {
                     allowed.pop_back();
                     res.status = 200;
                     res.set_header("Access-Control-Allow-Methods", allowed);
                     res.set_header("Access-Control-Allow-Origin", "*");
                     res.set_header("Access-Control-Allow-Headers",
                                    "Content-Type,Authorization");
                   } else {
                     res.status = 404;
                   }
                 });
  server.set_pre_routing_handler([&](const httplib::Request &req,
                                     httplib::Response &res) {
    HttpRequestTelemetry &telemetry = ensureRequestTelemetry(req, res);
    setRequestTelemetryHeaders(res, telemetry.request_id);
    ScopedLogRequestContext request_log_scope(telemetry.request_id);
    ScopedRequestContext request_context_scope(telemetry.context);
    telemetry.context->recordAdmissionOnce(std::chrono::steady_clock::now());
    if (req.path != "/healthz" &&
        !telemetry.completion->admission_acquired) {
      const uint64_t admission_bytes = requestAdmissionBytes(req);
      telemetry.context->setEstimatedBytes(admission_bytes);
      if (!request_admission.tryAcquire(admission_bytes)) {
        telemetry.context->suggestFailure(
            RequestFailureAttribution::Capacity);
        res.status = 503;
        res.set_header("Cache-Control", "private, no-store");
        res.set_header("Retry-After", "1");
        res.set_content(
            "Service temporarily unavailable: request capacity is full.\n"
            "服务暂时不可用：请求容量已满。\n",
            "text/plain; charset=utf-8");
        return httplib::Server::HandlerResponse::Handled;
      }
      telemetry.completion->admission_acquired = true;
      telemetry.completion->admission_bytes = admission_bytes;
    }
    if (shouldLog(LOG_LEVEL_DEBUG)) {
      writeLog(LOG_LEVEL_DEBUG,
               "接受客户端连接：" + req.remote_addr + ":" +
                   std::to_string(req.remote_port));
    }

    if (req.has_header("SubConverter-Request")) {
      res.status = 500;
      res.set_content("Internal error: loop request detected.\n"
                      "内部错误：检测到循环请求。\n"
                      "Please check subscription URLs and proxy settings to "
                      "avoid routing the service back to itself.\n"
                      "请检查订阅链接和代理设置，避免服务请求回到自身。",
                       "text/plain");
      res.set_header("Cache-Control", "private, no-store");
      return httplib::Server::HandlerResponse::Handled;
    }
    res.set_header("Server",
                   "SubConverter-Extended/" VERSION " cURL/" LIBCURL_VERSION);
    if (require_auth) {
      static std::string auth_token =
          "Basic " + base64Encode(auth_user + ":" + auth_password);
      auto auth = req.get_header_value("Authorization");
      if (auth != auth_token) {
        res.status = 401;
        res.set_header("WWW-Authenticate",
                       "Basic realm=" + auth_realm + ", charset=\"UTF-8\"");
        res.set_content("Unauthorized: missing or invalid credentials.\n"
                        "未授权：认证凭据缺失或无效。",
                        "text/plain");
        return httplib::Server::HandlerResponse::Handled;
      }
    }
    res.set_header("X-Client-IP", req.remote_addr);
    if (req.has_header("Access-Control-Request-Headers")) {
      res.set_header("Access-Control-Allow-Headers",
                     req.get_header_value("Access-Control-Request-Headers"));
    }
    res.set_header("Access-Control-Allow-Origin", "*");
    return httplib::Server::HandlerResponse::Unhandled;
  });
  for (auto &x : redirect_map) {
    server.Get(x.first,
               [x](const httplib::Request &req, httplib::Response &res) {
                 auto arguments = req.params;
                 auto query = x.second;
                 auto pos = query.find('?');
                 query += pos == std::string::npos ? '?' : '&';
                 for (auto &p : arguments) {
                   query += p.first + "=" + urlEncode(p.second) + "&";
                 }
                 if (!query.empty()) {
                   query.pop_back();
                 }
                 res.set_redirect(query);
               });
  }
  server.set_exception_handler([](const httplib::Request &req,
                                   httplib::Response &res,
                                   const std::exception_ptr &e) {
    HttpRequestTelemetry &telemetry = ensureRequestTelemetry(req, res);
    ScopedLogRequestContext request_log_scope(telemetry.request_id);
    ScopedRequestContext request_context_scope(telemetry.context);
    telemetry.context->suggestFailure(RequestFailureAttribution::Server);
    try {
      if (e)
        std::rethrow_exception(e);
    } catch (const std::exception &ex) {
      writeLog(LOG_LEVEL_ERROR,
               "HTTP_UNEXPECTED_EXCEPTION method=" + req.method +
                   " path=" + requestPathForLog(req.path) +
                   " parameter_count=" + std::to_string(req.params.size()) +
                   " exception=" + type(ex) +
                    " detail=" + summarizeSensitiveTextForLog(ex.what()));
    } catch (...) {
      writeLog(LOG_LEVEL_ERROR,
               "HTTP_UNEXPECTED_EXCEPTION method=" + req.method +
                   " path=" + requestPathForLog(req.path) +
                   " parameter_count=" + std::to_string(req.params.size()) +
                   " exception=unknown");
    }
    setUnhandledExceptionResponse(res);
  });
  server.set_post_routing_handler([](const httplib::Request &req,
                                     httplib::Response &res) {
    HttpRequestTelemetry &telemetry = ensureRequestTelemetry(req, res);
    setRequestTelemetryHeaders(res, telemetry.request_id);
    ScopedLogRequestContext request_log_scope(telemetry.request_id);
    ScopedRequestContext request_context_scope(telemetry.context);
    telemetry.context->recordAdmissionOnce(std::chrono::steady_clock::now());

    // This also covers errors produced before a route callback (authentication,
    // OPTIONS and the built-in 404 path), which do not pass through makeHandler.
    if (isExplainRequest(req)) {
      res.headers.erase("Cache-Control");
      res.set_header("Cache-Control", "private, no-store, max-age=0");
      res.headers.erase("Pragma");
      res.set_header("Pragma", "no-cache");
    } else if (res.status >= 400 &&
        !hasNoStoreDirective(res.get_header_value("Cache-Control"))) {
      res.headers.erase("Cache-Control");
      res.set_header("Cache-Control", "private, no-store");
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - telemetry.started_at);
    uint64_t response_bytes = 0;
    bool response_bytes_known = true;
    if (req.method != "HEAD") {
      response_bytes = static_cast<uint64_t>(res.body.size());
      if (response_bytes == 0 && res.has_header("Content-Length"))
        response_bytes = res.get_header_value_u64("Content-Length", 0);
      else if (response_bytes == 0 && res.status != 204 && res.status != 304)
        response_bytes_known = false;
    }
    const LogLevel completion_level =
        res.status >= 500 ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO;
    writeLog(completion_level,
             "HTTP_RESPONSE_PREPARED method=" + req.method +
                 " path=" + requestPathForLog(req.path) +
                 " status=" + std::to_string(res.status) +
                 " duration_ms=" +
                 std::to_string(std::max<int64_t>(0, elapsed.count())) +
                 " response_bytes=" + std::to_string(response_bytes) +
                 " response_bytes_known=" +
                 std::string(response_bytes_known ? "true" : "false"));
    telemetry.completion->prepare(req, res.status);
  });
  if (serve_file) {
    server.set_mount_point("/", serve_file_root);
  }
  server.new_task_queue = [args] {
    return new httplib::ThreadPool(args->max_workers,
                                   global.maxServerThreads,
                                   static_cast<size_t>(
                                       std::max(10240, args->max_conn)));
  };
  if (!server.bind_to_port(args->listen_address, args->port, 0)) {
    writeLog(LOG_LEVEL_FATAL,
             "无法绑定 HTTP 服务地址：" + args->listen_address + ":" +
                 std::to_string(args->port));
    return 1;
  }

  std::thread thread([&]() {
    if (!server.listen_after_bind() && !SERVER_EXIT_FLAG) {
      writeLog(LOG_LEVEL_ERROR, "HTTP 服务在接受请求前停止。");
      SERVER_EXIT_FLAG = true;
    }
  });

  while (!SERVER_EXIT_FLAG) {
    if (args->looper_callback) {
      args->looper_callback();
    }
    if (SERVER_EXIT_FLAG)
      break;
    std::this_thread::sleep_for(
        std::chrono::milliseconds(args->looper_interval));
  }

  server.stop();
  thread.join();
  return 0;
}

int WebServer::start_web_server(listener_args *args) {
  return start_web_server_multi(args);
}
