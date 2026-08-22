#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <functional>
#include <memory>
#include <random>
#include <unordered_map>
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
#include "webserver_beast.h"
#include "utils/system.h"


static const char *request_header_blacklist[] = {"host", "accept",
                                                 "accept-encoding"};

namespace {

constexpr const char *kRequestTelemetryKey = "subconverter.request.telemetry";
std::atomic<uint32_t> request_deadline_ms{15000};

class RequestCancellationMonitor {
public:
  RequestCancellationMonitor() : thread_([this] { run(); }) {}
  ~RequestCancellationMonitor() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    condition_.notify_all();
    if (thread_.joinable())
      thread_.join();
  }

  uint64_t add(const std::shared_ptr<RequestContext> &context,
               std::function<bool()> connection_closed) {
    if (!context)
      return 0;
    const uint64_t id = next_.fetch_add(1, std::memory_order_relaxed) + 1;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      entries_.emplace(id, Entry{context, std::move(connection_closed)});
    }
    condition_.notify_all();
    return id;
  }

  void remove(uint64_t id) noexcept {
    if (id == 0)
      return;
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(id);
  }

private:
  struct Entry {
    std::weak_ptr<RequestContext> context;
    std::function<bool()> connection_closed;
  };

  void run() noexcept {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stopping_) {
      condition_.wait_for(lock, std::chrono::milliseconds(10),
                          [this] { return stopping_; });
      if (stopping_)
        break;
      std::vector<std::pair<std::shared_ptr<RequestContext>,
                            std::function<bool()>>> checks;
      for (auto iter = entries_.begin(); iter != entries_.end();) {
        if (auto context = iter->second.context.lock()) {
          checks.emplace_back(context, iter->second.connection_closed);
          ++iter;
        } else {
          iter = entries_.erase(iter);
        }
      }
      lock.unlock();
      const auto now = RequestContext::Clock::now();
      for (auto &[context, connection_closed] : checks) {
        if (context->terminalState() != RequestTerminalState::None)
          continue;
        if (context->deadlineExceeded(now)) {
          context->requestCancellation(RequestCancellationReason::Deadline);
          continue;
        }
        if (!connection_closed)
          continue;
        try {
          if (connection_closed())
            context->requestCancellation(
                RequestCancellationReason::ClientDisconnected);
        } catch (...) {
          context->requestCancellation(
              RequestCancellationReason::ClientDisconnected);
        }
      }
      lock.lock();
    }
  }

  std::atomic<uint64_t> next_{0};
  std::mutex mutex_;
  std::condition_variable condition_;
  std::unordered_map<uint64_t, Entry> entries_;
  std::thread thread_;
  bool stopping_ = false;
};

RequestCancellationMonitor &requestCancellationMonitor() {
  static RequestCancellationMonitor monitor;
  return monitor;
}

class RequestAdmissionController {
public:
  bool tryAcquire(uint64_t bytes) noexcept {
    const uint64_t max_entries =
        max_entries_.load(std::memory_order_acquire);
    const uint64_t max_bytes = max_bytes_.load(std::memory_order_acquire);
    const uint64_t previous_entries =
        active_entries_.fetch_add(1, std::memory_order_acq_rel);
    if (previous_entries >= max_entries) {
      active_entries_.fetch_sub(1, std::memory_order_acq_rel);
      rejected_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    uint64_t current = active_bytes_.load(std::memory_order_acquire);
    while (bytes <= max_bytes && current <= max_bytes - bytes) {
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
            rejected_.load(std::memory_order_relaxed),
            max_entries_.load(std::memory_order_relaxed),
            max_bytes_.load(std::memory_order_relaxed)};
  }

  void configure(uint64_t max_entries, uint64_t max_bytes) noexcept {
    max_entries_.store(std::max<uint64_t>(1, max_entries),
                       std::memory_order_release);
    max_bytes_.store(std::max<uint64_t>(1, max_bytes),
                     std::memory_order_release);
  }

private:
  std::atomic<uint64_t> max_entries_{2048};
  std::atomic<uint64_t> max_bytes_{UINT64_C(64) * 1024 * 1024};
  std::atomic<uint64_t> active_entries_{0};
  std::atomic<uint64_t> active_bytes_{0};
  std::atomic<uint64_t> accepted_{0};
  std::atomic<uint64_t> rejected_{0};
};

RequestAdmissionController request_admission;

class NormalHandlerController {
public:
  void configure(uint64_t limit) noexcept {
    limit_.store(std::max<uint64_t>(1, limit), std::memory_order_release);
  }

  bool tryAcquire() noexcept {
    const uint64_t limit = limit_.load(std::memory_order_acquire);
    uint64_t active = active_.load(std::memory_order_acquire);
    while (active < limit) {
      if (active_.compare_exchange_weak(active, active + 1,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire))
        return true;
    }
    return false;
  }

  void release() noexcept {
    active_.fetch_sub(1, std::memory_order_acq_rel);
  }

private:
  std::atomic<uint64_t> limit_{1};
  std::atomic<uint64_t> active_{0};
};

NormalHandlerController normal_handlers;

class NormalHandlerPermit {
public:
  explicit NormalHandlerPermit(bool required)
      : required_(required),
        acquired_(!required || normal_handlers.tryAcquire()) {}
  ~NormalHandlerPermit() {
    if (acquired_ && required_)
      normal_handlers.release();
  }
  NormalHandlerPermit(const NormalHandlerPermit &) = delete;
  NormalHandlerPermit &operator=(const NormalHandlerPermit &) = delete;

  bool acquired() const noexcept { return acquired_; }

private:
  bool required_ = false;
  bool acquired_ = false;
};

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
    uint64_t cancellation_monitor_id = 0;

    ~Completion() {
      requestCancellationMonitor().remove(cancellation_monitor_id);
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
        releaseRequestAdmission(admission_bytes);
    }

    void prepare(const httplib::Request &, int response_status) {
      status_code = response_status;
      sending_started_at = std::chrono::steady_clock::now();
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
      telemetry.request_id, telemetry.started_at,
      telemetry.started_at + std::chrono::milliseconds(
                                 request_deadline_ms.load(
                                     std::memory_order_acquire)));
  telemetry.completion = std::make_shared<HttpRequestTelemetry::Completion>();
  telemetry.completion->context = telemetry.context;
  telemetry.completion->request_id = telemetry.request_id;
  telemetry.completion->is_connection_closed = request.is_connection_closed;
  telemetry.completion->cancellation_monitor_id =
      requestCancellationMonitor().add(telemetry.context,
                                       request.is_connection_closed);
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

bool requestCancellationResponse(
    const std::shared_ptr<RequestContext> &context,
    RequestCancellationResponse &response) noexcept {
  if (!context)
    return false;
  RequestCancellationReason reason = context->cancellationToken().reason();
  if (reason == RequestCancellationReason::None &&
      context->deadlineExceeded()) {
    context->requestCancellation(RequestCancellationReason::Deadline);
    reason = context->cancellationToken().reason();
  }
  response.headers = {{"Cache-Control", "private, no-store"}};
  switch (reason) {
  case RequestCancellationReason::Deadline:
    context->suggestFailure(RequestFailureAttribution::Client);
    response.status_code = 504;
    response.body = "Gateway timeout: request deadline exceeded.\n"
                    "网关超时：请求已超过截止时间。\n";
    return true;
  case RequestCancellationReason::ClientDisconnected:
  case RequestCancellationReason::NoConsumers:
    context->suggestFailure(RequestFailureAttribution::Client);
    response.status_code = 499;
    response.body = "Client closed request.\n客户端已关闭请求。\n";
    return true;
  case RequestCancellationReason::Shutdown:
    context->suggestFailure(RequestFailureAttribution::Server);
    response.status_code = 503;
    response.body = "Service is shutting down.\n服务正在关闭。\n";
    return true;
  case RequestCancellationReason::None:
    return false;
  }
  return false;
}

RequestAdmissionSnapshot requestAdmissionSnapshot() noexcept {
  return request_admission.snapshot();
}

void configureRequestAdmissionLimits(uint64_t max_entries,
                                     uint64_t max_bytes) noexcept {
  request_admission.configure(max_entries, max_bytes);
}

bool tryRequestAdmission(uint64_t bytes) noexcept {
  return request_admission.tryAcquire(bytes);
}

void releaseRequestAdmission(uint64_t bytes) noexcept {
  request_admission.release(bytes);
}

const responseRoute *findResponseRoute(
    const std::vector<responseRoute> &routes, const std::string &method,
    const std::string &path, bool allow_head_as_get) noexcept {
  for (const auto &route : routes) {
    if (route.path == path &&
        (route.method == method ||
         (allow_head_as_get && method == "HEAD" && route.method == "GET")))
      return &route;
  }
  return nullptr;
}

std::string invokeResponseRoute(const responseRoute &route, Request &request,
                                Response &response) {
  std::string content = route.rc(request, response);
  if (response.content_type.empty())
    response.content_type = route.content_type;
  return content;
}

void parseHttpTarget(const std::string &target, std::string &path,
                     string_multimap &arguments) {
  std::string normalized = target;
  const std::size_t fragment = normalized.find('#');
  if (fragment != std::string::npos)
    normalized.erase(fragment);
  httplib::detail::divide(
      normalized, '?',
      [&](const char *path_data, std::size_t path_size, const char *query_data,
          std::size_t query_size) {
        path = httplib::decode_path_component(
            std::string(path_data, path_size));
        httplib::Params parsed;
        httplib::detail::parse_query_text(query_data, query_size, parsed);
        arguments.insert(parsed.begin(), parsed.end());
      });
}

std::string httpStaticContentType(const std::string &path) {
  static const std::map<std::string, std::string> custom_types;
  return httplib::detail::find_content_type(path, custom_types,
                                             "application/octet-stream");
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
    const bool normal_route = request.path != "/healthz";
    NormalHandlerPermit handler_permit(normal_route);
    if (!handler_permit.acquired()) {
      telemetry.context->suggestFailure(RequestFailureAttribution::Capacity);
      response.status = 503;
      response.set_header("Cache-Control", "private, no-store");
      response.set_header("Retry-After", "1");
      response.set_content(
          "Service temporarily unavailable: HTTP handler capacity is full.\n"
          "服务暂时不可用：HTTP 处理容量已满。\n",
          "text/plain; charset=utf-8");
      return;
    }
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
    auto result = invokeResponseRoute(rr, req, resp);
    if (telemetry.context->suggestedFailure() ==
        RequestFailureAttribution::Capacity) {
      resp.shared_body.reset();
      resp.status_code = 503;
      resp.content_type = "text/plain; charset=utf-8";
      resp.headers = {{"Cache-Control", "private, no-store"},
                      {"Retry-After", "1"}};
      std::string capacity_result =
          "Service temporarily unavailable: retained byte or execution "
          "capacity is full.\n"
          "服务暂时不可用：保留字节或执行容量已满。\n";
      result.swap(capacity_result);
    }
    RequestCancellationResponse cancellation_response;
    if (requestCancellationResponse(telemetry.context,
                                    cancellation_response)) {
      resp.shared_body.reset();
      resp.status_code = cancellation_response.status_code;
      resp.content_type = "text/plain; charset=utf-8";
      resp.headers = std::move(cancellation_response.headers);
      result = std::move(cancellation_response.body);
    }
    if (resp.shared_body)
      result = resp.shared_body->content;
    if (telemetry.context &&
        !telemetry.context->retainResponseBytes(result.size())) {
      resp.shared_body.reset();
      resp.status_code = 503;
      resp.content_type = "text/plain; charset=utf-8";
      resp.headers = {{"Cache-Control", "private, no-store"},
                      {"Retry-After", "1"}};
      std::string capacity_result =
          "Service temporarily unavailable: retained response byte "
          "capacity is full.\n"
          "服务暂时不可用：响应字节容量已满。\n";
      result.swap(capacity_result);
    }
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
    response.set_content(std::move(result), resp.content_type);
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
  std::string backend = toLower(getEnv("SUBCONVERTER_HTTP_BACKEND"));
  if (backend.empty())
    backend = "beast";
  if (backend == "beast")
    return startBeastWebServer(*this, args);
  if (!backend.empty() && backend != "httplib") {
    writeLog(LOG_LEVEL_FATAL,
             "HTTP_BACKEND_INVALID value_length=" +
                 std::to_string(backend.size()));
    return 1;
  }
  httplib::Server server;
  request_deadline_ms.store(std::max<uint32_t>(1, args->request_deadline_ms),
                            std::memory_order_release);
  server.set_read_timeout(std::chrono::milliseconds(
      std::min<uint32_t>(1000, std::max<uint32_t>(1, args->request_deadline_ms))));
  server.set_write_timeout(std::chrono::milliseconds(
      std::min<uint32_t>(1000,
                         std::max<uint32_t>(1, args->request_deadline_ms))));
  const uint64_t httplib_thread_limit = static_cast<uint64_t>(
      std::max(global.maxServerThreads, args->max_workers));
  normal_handlers.configure(httplib_thread_limit > 1
                                ? httplib_thread_limit - 1
                                : 1);
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
      if (!tryRequestAdmission(admission_bytes)) {
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
    const size_t base_workers = static_cast<size_t>(
        std::max(args->max_workers, 1));
    const size_t bounded_max = static_cast<size_t>(
        std::max(global.maxServerThreads, args->max_workers));
    return new httplib::ThreadPool(base_workers,
                                   std::max(base_workers + 1, bounded_max),
                                   static_cast<size_t>(
                                       global.resourceControlEffective ==
                                               "compat"
                                           ? std::max(10240, args->max_conn)
                                           : std::max(1, args->max_conn)));
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
  if (args->shutdown_callback)
    args->shutdown_callback();
  if (args->drain_callback)
    args->drain_callback();
  thread.join();
  return 0;
}

int WebServer::start_web_server(listener_args *args) {
  return start_web_server_multi(args);
}
