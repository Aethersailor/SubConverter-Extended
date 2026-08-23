#define BOOST_ERROR_CODE_HEADER_ONLY
#define BOOST_SYSTEM_NO_DEPRECATED

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include "handler/settings.h"
#include "server/webserver.h"
#include "server/webserver_beast.h"
#include "utils/base64/base64.h"
#include "utils/file.h"
#include "utils/logger.h"
#include "utils/redact.h"
#include "utils/string.h"
#include "utils/urlencode.h"

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

namespace {

constexpr std::size_t kMaxHeaderBytes = 819200;
constexpr std::size_t kMaxFormBytes = 819200;
constexpr std::size_t kMaxRequestBodyBytes = 100 * 1024 * 1024;

std::string nextBeastRequestId() {
  static const uint64_t prefix = static_cast<uint64_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  static std::atomic<uint64_t> counter{0};
  std::ostringstream value;
  value << std::hex << std::nouppercase << std::setfill('0') << std::setw(16)
        << prefix << std::setw(16)
        << counter.fetch_add(1, std::memory_order_relaxed) + 1;
  return value.str();
}

bool blacklistedHeader(const std::string &name) {
  const std::string lower = toLower(name);
  return lower == "host" || lower == "accept" || lower == "accept-encoding";
}

std::string requestPathForLog(const std::string &path) {
  if (!path.empty() && path.size() <= 256 &&
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

bool isExplainRequest(const string_multimap &arguments) {
  const auto range = arguments.equal_range("explain");
  if (range.first == range.second)
    return false;
  const std::string value = toLower(
      trimWhitespace(range.first->second, true, true));
  return value == "1" || value == "true" || value == "yes" ||
         value == "on";
}

bool isHealthTarget(beast::string_view target) {
  constexpr beast::string_view path = "/healthz";
  return target.size() >= path.size() && target.substr(0, path.size()) == path &&
         (target.size() == path.size() || target[path.size()] == '?');
}

template <class Body>
void appendExposeHeader(http::response<Body> &response,
                        const std::string &name) {
  std::string current = response[http::field::access_control_expose_headers];
  if (!current.empty())
    current += ", ";
  current += name;
  response.set(http::field::access_control_expose_headers, current);
}

enum class StaticFileResult { NotFound, File, Redirect, Forbidden };

StaticFileResult safeStaticFile(const std::string &root, const std::string &path,
                                std::string &content,
                                std::string &content_type) {
  if (root.empty() || path.empty())
    return StaticFileResult::NotFound;
  try {
    const std::filesystem::path canonical_root =
        std::filesystem::weakly_canonical(root);
    std::string relative_path = path.front() == '/' ? path.substr(1) : path;
    if (path.back() == '/')
      relative_path += "index.html";
    const std::filesystem::path candidate = std::filesystem::weakly_canonical(
        canonical_root / relative_path);
    const std::filesystem::path relative =
        std::filesystem::relative(candidate, canonical_root);
    const std::string relative_text = relative.generic_string();
    if (relative.is_absolute() || relative_text == ".." ||
        startsWith(relative_text, "../"))
      return StaticFileResult::Forbidden;
    if (std::filesystem::is_directory(candidate))
      return StaticFileResult::Redirect;
    if (!std::filesystem::is_regular_file(candidate))
      return StaticFileResult::NotFound;
    std::ifstream file(candidate, std::ios::binary);
    content.assign(std::istreambuf_iterator<char>(file),
                   std::istreambuf_iterator<char>());
    content_type = httpStaticContentType(candidate.string());
    return static_cast<bool>(file) || file.eof()
               ? StaticFileResult::File
               : StaticFileResult::NotFound;
  } catch (...) {
    return StaticFileResult::NotFound;
  }
}

class BeastServerState;

class BeastSession : public std::enable_shared_from_this<BeastSession> {
public:
  BeastSession(tcp::socket socket, std::shared_ptr<BeastServerState> state);
  ~BeastSession();

  void start();
  void beginShutdown();

private:
  void read();
  void resetParser();
  void onRead(beast::error_code error, std::size_t bytes);
  void process();
  void completeAsyncResponse(Response response, std::string body,
                             bool explain_request,
                             std::string client_address);
  void armCancellationObservers();
  void writeHealthResponse();
  void writeImmediateError(http::status status, const std::string &body,
                           const char *retry_after = nullptr);
  void writeResponse(http::response<http::string_body> response);
  void writeSharedResponse(http::response<http::buffer_body> response,
                           shared_response_body body);
  void onWrite(bool keep_alive, beast::error_code error, std::size_t bytes);
  void finish(bool response_sent = false);

  beast::tcp_stream stream_;
  asio::steady_timer deadline_timer_;
  beast::flat_buffer buffer_;
  std::unique_ptr<http::request_parser<http::string_body>> parser_;
  std::shared_ptr<BeastServerState> state_;
  std::shared_ptr<RequestContext> context_;
  std::string request_id_;
  RequestContext::Clock::time_point started_at_{};
  RequestContext::Clock::time_point sending_started_at_{};
  uint64_t admission_bytes_ = 0;
  bool admitted_ = false;
  int response_status_ = 500;
  std::atomic<bool> processing_{false};
  std::atomic<bool> finished_{false};
  std::atomic<bool> async_completed_{false};
};

class BeastServerState : public std::enable_shared_from_this<BeastServerState> {
public:
  BeastServerState(WebServer &server, listener_args *args)
      : server(server), args(args), context(1),
        work_guard(asio::make_work_guard(context)), acceptor(context),
        handlers(static_cast<std::size_t>(
            std::max(args->max_workers, 1))),
        connection_limit(static_cast<std::size_t>(
            global.resourceControlEffective == "compat"
                ? std::max(10240, args->max_conn)
                : std::max(1, args->max_conn))) {}

  bool bind() {
    beast::error_code error;
    const asio::ip::address address =
        asio::ip::make_address(args->listen_address, error);
    if (error)
      return false;
    tcp::endpoint endpoint(address, static_cast<unsigned short>(args->port));
    acceptor.open(endpoint.protocol(), error);
    if (error)
      return false;
    acceptor.set_option(asio::socket_base::reuse_address(true), error);
    if (error)
      return false;
    acceptor.bind(endpoint, error);
    if (error)
      return false;
    acceptor.listen(global.resourceControlEffective == "compat"
                        ? std::max(10240, args->max_conn)
                        : std::max(1, args->max_conn),
                    error);
    return !error;
  }

  void accept() {
    acceptor.async_accept(asio::make_strand(context),
                          [self = shared_from_this()](
                              beast::error_code error, tcp::socket socket) {
                            if (!error && !self->stopping.load() &&
                                self->active_sessions.load(
                                    std::memory_order_relaxed) <
                                    self->connection_limit) {
                              auto session = std::make_shared<BeastSession>(
                                  std::move(socket), self);
                              self->addSession(session);
                              session->start();
                            } else if (!error) {
                              beast::error_code ignored;
                              socket.shutdown(tcp::socket::shutdown_both,
                                              ignored);
                              socket.close(ignored);
                            }
                            if (!self->stopping.load())
                              self->accept();
                          });
  }

  void stop() {
    stopping.store(true);
    auto stopped = std::make_shared<std::promise<void>>();
    std::future<void> stopped_future = stopped->get_future();
    asio::post(context, [self = shared_from_this(), stopped] {
      beast::error_code ignored;
      self->acceptor.cancel(ignored);
      self->acceptor.close(ignored);
      std::vector<std::shared_ptr<BeastSession>> live;
      {
        std::lock_guard<std::mutex> lock(self->sessions_mutex);
        for (auto &[key, session] : self->sessions) {
          (void)key;
          if (auto retained = session.lock())
            live.emplace_back(std::move(retained));
        }
      }
      for (auto &session : live)
        session->beginShutdown();
      stopped->set_value();
    });
    (void)stopped_future.wait_for(std::chrono::seconds(1));
  }

  void addSession(const std::shared_ptr<BeastSession> &session) {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    sessions.emplace(session.get(), session);
  }

  void sessionFinished(BeastSession *session) {
    {
      std::lock_guard<std::mutex> lock(sessions_mutex);
      sessions.erase(session);
    }
    active_sessions.fetch_sub(1, std::memory_order_relaxed);
  }

  WebServer &server;
  listener_args *args;
  asio::io_context context;
  asio::executor_work_guard<asio::io_context::executor_type> work_guard;
  tcp::acceptor acceptor;
  asio::thread_pool handlers;
  const std::size_t connection_limit;
  std::atomic<bool> stopping{false};
  std::atomic<uint64_t> active_sessions{0};
  std::mutex sessions_mutex;
  std::unordered_map<BeastSession *, std::weak_ptr<BeastSession>> sessions;
};

BeastSession::BeastSession(tcp::socket socket,
                           std::shared_ptr<BeastServerState> state)
    : stream_(std::move(socket)), deadline_timer_(stream_.get_executor()),
      state_(std::move(state)) {
  state_->active_sessions.fetch_add(1, std::memory_order_relaxed);
  resetParser();
}

BeastSession::~BeastSession() {
  if (admitted_)
    releaseRequestAdmission(admission_bytes_);
  state_->sessionFinished(this);
}

void BeastSession::start() { read(); }

void BeastSession::beginShutdown() {
  asio::post(stream_.get_executor(), [self = shared_from_this()] {
    if (self->context_)
      self->context_->requestCancellation(RequestCancellationReason::Shutdown);
    if (!self->processing_.load(std::memory_order_acquire)) {
      beast::error_code ignored;
      self->stream_.socket().shutdown(tcp::socket::shutdown_both, ignored);
      self->stream_.socket().close(ignored);
    }
  });
}

void BeastSession::read() {
  if (context_ &&
      context_->deadline() != RequestContext::Clock::time_point::max())
    stream_.expires_at(context_->deadline());
  else
    stream_.expires_after(std::chrono::seconds(15));
  http::async_read(stream_, buffer_, *parser_,
                   beast::bind_front_handler(&BeastSession::onRead,
                                             shared_from_this()));
}

void BeastSession::resetParser() {
  parser_ =
      std::make_unique<http::request_parser<http::string_body>>();
  parser_->body_limit(kMaxRequestBodyBytes);
  parser_->header_limit(kMaxHeaderBytes);
}

void BeastSession::onRead(beast::error_code error, std::size_t) {
  if (error == http::error::end_of_stream || error == asio::error::eof) {
    finish(false);
    return;
  }
  if (error == beast::error::timeout ||
      error == asio::error::operation_aborted) {
    finish(false);
    return;
  }
  if (error) {
    request_id_ = nextBeastRequestId();
    started_at_ = RequestContext::Clock::now();
    context_ = std::make_shared<RequestContext>(
        request_id_, started_at_,
        started_at_ +
            std::chrono::milliseconds(state_->args->request_deadline_ms));
    context_->recordAdmissionOnce(RequestContext::Clock::now());
    context_->suggestFailure(RequestFailureAttribution::User);
    writeImmediateError(error == http::error::body_limit
                            ? http::status::payload_too_large
                            : http::status::bad_request,
                        error == http::error::body_limit
                            ? "Payload too large.\n请求正文过大。\n"
                            : "Bad request.\n请求格式错误。\n");
    return;
  }
  request_id_ = nextBeastRequestId();
  started_at_ = RequestContext::Clock::now();
  context_ = std::make_shared<RequestContext>(
      request_id_, started_at_,
      started_at_ +
          std::chrono::milliseconds(state_->args->request_deadline_ms));
  context_->recordAdmissionOnce(RequestContext::Clock::now());
  if (parser_->get()[http::field::content_type] ==
          "application/x-www-form-urlencoded" &&
      parser_->get().body().size() > kMaxFormBytes) {
    context_->suggestFailure(RequestFailureAttribution::User);
    writeImmediateError(http::status::payload_too_large,
                        "Payload too large.\n请求正文过大。\n");
    return;
  }
  if (isHealthTarget(parser_->get().target()) &&
      (parser_->get().method() == http::verb::get ||
       parser_->get().method() == http::verb::head)) {
    context_->setCostClass(RequestCostClass::Low);
    processing_.store(true, std::memory_order_release);
    writeHealthResponse();
    return;
  }
  admission_bytes_ = UINT64_C(1024) + parser_->get().target().size() +
                     parser_->get().body().size();
  for (const auto &header : parser_->get())
    admission_bytes_ += header.name_string().size() + header.value().size();
  if (!isHealthTarget(parser_->get().target())) {
    admitted_ = tryRequestAdmission(admission_bytes_);
    context_->setEstimatedBytes(admission_bytes_);
    if (!admitted_) {
      context_->suggestFailure(RequestFailureAttribution::Capacity);
      writeImmediateError(
          http::status::service_unavailable,
          "Service temporarily unavailable: request capacity is full.\n"
          "服务暂时不可用：请求容量已满。\n",
          "1");
      return;
    }
  }
  processing_.store(true, std::memory_order_release);
  armCancellationObservers();
  asio::post(state_->handlers,
             [self = shared_from_this()] { self->process(); });
}

void BeastSession::armCancellationObservers() {
  if (!context_)
    return;
  const std::shared_ptr<RequestContext> observed = context_;
  deadline_timer_.expires_at(observed->deadline());
  deadline_timer_.async_wait(
      [self = shared_from_this(), observed](beast::error_code error) {
        if (!error && self->context_ == observed &&
            observed->terminalState() == RequestTerminalState::None)
          observed->requestCancellation(RequestCancellationReason::Deadline);
      });
  stream_.socket().async_wait(
      tcp::socket::wait_read,
      [self = shared_from_this(), observed](beast::error_code error) {
        if (error || self->context_ != observed ||
            observed->terminalState() != RequestTerminalState::None)
          return;
        std::array<char, 1> probe{};
        beast::error_code probe_error;
        const std::size_t bytes = self->stream_.socket().receive(
            asio::buffer(probe), asio::socket_base::message_peek,
            probe_error);
        if (bytes == 0 || probe_error == asio::error::eof ||
            probe_error == asio::error::connection_reset ||
            (probe_error && probe_error != asio::error::eof &&
             probe_error != asio::error::would_block &&
             probe_error != asio::error::try_again))
          observed->requestCancellation(
              RequestCancellationReason::ClientDisconnected);
      });
}

void BeastSession::writeHealthResponse() {
  const auto &incoming = parser_->get();
  http::response<http::string_body> response{http::status::ok,
                                             incoming.version()};
  response.keep_alive(incoming.keep_alive() && !state_->stopping.load());
  response.set(http::field::server,
               "SubConverter-Extended/" VERSION " cURL/" LIBCURL_VERSION);
  response.set(http::field::content_type, "text/plain; charset=utf-8");
  response.set(http::field::access_control_allow_origin, "*");
  response.set("X-Request-ID", request_id_);
  appendExposeHeader(response, "X-Request-ID");
  if (state_->server.require_auth &&
      incoming[http::field::authorization] !=
          "Basic " + base64Encode(state_->server.auth_user + ":" +
                                    state_->server.auth_password)) {
    response.result(http::status::unauthorized);
    response.set(http::field::www_authenticate,
                 "Basic realm=" + state_->server.auth_realm +
                     ", charset=\"UTF-8\"");
    response.body() = "Unauthorized: missing or invalid credentials.\n"
                      "未授权：认证凭据缺失或无效。";
  } else {
    response.body() = "ok";
  }
  writeLog(response.result_int() >= 500 ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO,
           "HTTP_RESPONSE_PREPARED method=" +
               std::string(incoming.method_string()) +
               " path=/healthz status=" +
               std::to_string(response.result_int()) +
               " duration_ms=0 response_bytes=" +
               std::to_string(response.body().size()) +
               " response_bytes_known=true");
  const std::size_t body_size = response.body().size();
  response.prepare_payload();
  if (incoming.method() == http::verb::head) {
    response.body().clear();
    response.content_length(body_size);
  }
  writeResponse(std::move(response));
}

void BeastSession::process() {
  ScopedLogRequestContext log_scope(request_id_);
  ScopedRequestContext request_scope(context_);
  const auto &incoming = parser_->get();
  http::response<http::string_body> outgoing{http::status::ok,
                                             incoming.version()};
  outgoing.keep_alive(incoming.keep_alive() && !state_->stopping.load());
  outgoing.set(http::field::server,
               "SubConverter-Extended/" VERSION " cURL/" LIBCURL_VERSION);
  outgoing.set(http::field::access_control_allow_origin, "*");
  if (incoming.find(http::field::access_control_request_headers) !=
      incoming.end())
    outgoing.set(http::field::access_control_allow_headers,
                 incoming[http::field::access_control_request_headers]);
  outgoing.set("X-Request-ID", request_id_);
  appendExposeHeader(outgoing, "X-Request-ID");
  bool explain_request = false;

  try {
    ::Request request;
    Response response;
    request.method = incoming.method_string();
    parseHttpTarget(std::string(incoming.target()), request.url,
                    request.argument);
    explain_request = isExplainRequest(request.argument);
    const tcp::endpoint peer = stream_.socket().remote_endpoint();
    request.remote_addr = peer.address().to_string();
    request.remote_port = peer.port();
    request.client_address = client_ip::parseAddress(request.remote_addr);
    request.context = context_;
    if (request.url == "/healthz" || request.url == "/version" ||
        request.url == "/inspect")
      context_->setCostClass(RequestCostClass::Low);
    else if (request.url == "/getruleset")
      context_->setCostClass(RequestCostClass::Medium);
    const client_ip::Policy policy = state_->server.client_ip_policy();
    if (policy.enabled()) {
      std::vector<std::string> values;
      const char *header = client_ip::headerName(policy.header);
      auto field = incoming.begin();
      const auto field_end = incoming.end();
      if (field != field_end) {
        const std::string normalized_header = toLower(header);
        do {
          if (toLower(std::string(field->name_string())) == normalized_header)
            values.emplace_back(field->value());
        } while (++field != field_end);
      }
      request.client_address =
          client_ip::resolve(request.client_address, values, policy).address;
    }
    for (const auto &field : incoming) {
      const std::string name(field.name_string());
      if (startsWith(name, "LOCAL_") || startsWith(name, "REMOTE_") ||
          blacklistedHeader(name))
        continue;
      request.headers.emplace(name, std::string(field.value()));
    }
    if (incoming.method() == http::verb::post ||
        incoming.method() == http::verb::put ||
        incoming.method() == http::verb::patch) {
      request.postdata = incoming[http::field::content_type] ==
                                 "application/x-www-form-urlencoded"
                             ? urlDecode(incoming.body())
                             : incoming.body();
    }

    if (incoming.find("SubConverter-Request") != incoming.end()) {
      response.status_code = 500;
      response.content_type = "text/plain";
      response.headers["Cache-Control"] = "private, no-store";
      outgoing.body() = "Internal error: loop request detected.\n"
                        "内部错误：检测到循环请求。\n";
    } else if (state_->server.require_auth &&
               incoming[http::field::authorization] !=
                   "Basic " + base64Encode(state_->server.auth_user + ":" +
                                             state_->server.auth_password)) {
      response.status_code = 401;
      response.content_type = "text/plain";
      response.headers["WWW-Authenticate"] =
          "Basic realm=" + state_->server.auth_realm + ", charset=\"UTF-8\"";
      outgoing.body() = "Unauthorized: missing or invalid credentials.\n"
                        "未授权：认证凭据缺失或无效。";
    } else if (incoming.method() == http::verb::options) {
      std::string allowed;
      for (const auto &route : state_->server.responses) {
        if (route.path == request.url) {
          if (!allowed.empty())
            allowed += ',';
          allowed += route.method;
        }
      }
      response.status_code = allowed.empty() ? 404 : 200;
      if (!allowed.empty()) {
        response.headers["Access-Control-Allow-Methods"] = allowed;
        response.headers["Access-Control-Allow-Headers"] =
            "Content-Type,Authorization";
      }
    } else {
      bool routed = false;
      if (const responseRoute *route = findResponseRoute(
              state_->server.responses, request.method, request.url)) {
        routed = true;
        if (route->async_rc) {
          const std::string client_address = request.remote_addr;
          const std::string default_content_type = route->content_type;
          auto self = shared_from_this();
          try {
            route->async_rc(
                std::move(request),
                [self, explain_request, default_content_type,
                 client_address](Response async_response,
                                 std::string body) mutable {
                  if (async_response.content_type.empty())
                    async_response.content_type = default_content_type;
                  asio::post(
                      self->stream_.get_executor(),
                      [self, response = std::move(async_response),
                       body = std::move(body), explain_request,
                       client_address]() mutable {
                        self->completeAsyncResponse(
                            std::move(response), std::move(body),
                            explain_request, std::move(client_address));
                      });
                });
          } catch (...) {
            Response failure;
            failure.status_code = 500;
            failure.content_type = "text/plain; charset=utf-8";
            failure.headers["Cache-Control"] = "private, no-store";
            asio::post(
                self->stream_.get_executor(),
                [self, failure = std::move(failure), explain_request,
                 client_address]() mutable {
                  self->completeAsyncResponse(
                      std::move(failure),
                      "Internal server error while processing request.\n"
                      "处理请求时发生内部服务器错误。\n",
                      explain_request, std::move(client_address));
                });
          }
          return;
        }
        outgoing.body() = invokeResponseRoute(*route, request, response);
        if (response.shared_body) {
          asio::post(
              stream_.get_executor(),
              [self = shared_from_this(), response = std::move(response),
               body = std::move(outgoing.body()), explain_request,
               client_address = request.remote_addr]() mutable {
                self->completeAsyncResponse(
                    std::move(response), std::move(body), explain_request,
                    std::move(client_address));
              });
          return;
        }
      }
      if (!routed) {
        const auto redirect = state_->server.redirect_map.find(request.url);
        if (incoming.method() == http::verb::get &&
            redirect != state_->server.redirect_map.end()) {
          routed = true;
          std::string location = redirect->second;
          location += location.find('?') == std::string::npos ? '?' : '&';
          for (const auto &[name, value] : request.argument)
            location += name + "=" + urlEncode(value) + "&";
          if (!location.empty() && location.back() == '&')
            location.pop_back();
          response.status_code = 302;
          response.headers["Location"] = location;
        } else if ((incoming.method() == http::verb::get ||
                    incoming.method() == http::verb::head) &&
                   state_->server.serve_file) {
          const StaticFileResult static_result = safeStaticFile(
              state_->server.serve_file_root, request.url, outgoing.body(),
              response.content_type);
          if (static_result == StaticFileResult::File) {
            routed = true;
            response.status_code = 200;
          } else if (static_result == StaticFileResult::Redirect) {
            routed = true;
            response.status_code = 301;
            response.headers["Location"] = request.url + "/";
          } else if (static_result == StaticFileResult::Forbidden) {
            routed = true;
            response.status_code = 403;
          }
        }
      }
      if (!routed)
        response.status_code = 404;
    }

    outgoing.result(static_cast<http::status>(response.status_code));
    for (const auto &[name, value] : response.headers)
      outgoing.set(name, value);
    if (!response.content_type.empty())
      outgoing.set(http::field::content_type, response.content_type);
    if (response.status_code >= 400 &&
        !hasNoStoreDirective(
            std::string(outgoing[http::field::cache_control])))
      outgoing.set(http::field::cache_control, "private, no-store");
    outgoing.set("X-Client-IP", request.remote_addr);
  } catch (const std::exception &error) {
    context_->suggestFailure(RequestFailureAttribution::Server);
    writeLog(LOG_LEVEL_ERROR,
             "HTTP_UNEXPECTED_EXCEPTION backend=beast detail=" +
                 summarizeSensitiveTextForLog(error.what()));
    outgoing.result(http::status::internal_server_error);
    outgoing.set(http::field::content_type, "text/plain; charset=utf-8");
    outgoing.set(http::field::cache_control, "private, no-store");
    outgoing.body() = "Internal server error while processing request.\n"
                      "处理请求时发生内部服务器错误。\n";
  } catch (...) {
    context_->suggestFailure(RequestFailureAttribution::Server);
    outgoing.result(http::status::internal_server_error);
    outgoing.set(http::field::content_type, "text/plain; charset=utf-8");
    outgoing.set(http::field::cache_control, "private, no-store");
    outgoing.body() = "Internal server error while processing request.\n"
                      "处理请求时发生内部服务器错误。\n";
  }

  if (context_->suggestedFailure() == RequestFailureAttribution::Capacity) {
    outgoing.result(http::status::service_unavailable);
    outgoing.set(http::field::content_type, "text/plain; charset=utf-8");
    outgoing.set(http::field::cache_control, "private, no-store");
    outgoing.set(http::field::retry_after, "1");
    outgoing.body() =
        "Service temporarily unavailable: retained byte or execution "
        "capacity is full.\n服务暂时不可用：保留字节或执行容量已满。\n";
  }

  RequestCancellationResponse cancellation_response;
  if (requestCancellationResponse(context_, cancellation_response)) {
    outgoing.result(
        static_cast<http::status>(cancellation_response.status_code));
    outgoing.set(http::field::content_type, "text/plain; charset=utf-8");
    for (const auto &[name, value] : cancellation_response.headers)
      outgoing.set(name, value);
    outgoing.body() = std::move(cancellation_response.body);
  }
  if (context_ && !context_->retainResponseBytes(outgoing.body().size())) {
    outgoing.result(http::status::service_unavailable);
    outgoing.set(http::field::content_type, "text/plain; charset=utf-8");
    outgoing.set(http::field::cache_control, "private, no-store");
    outgoing.set(http::field::retry_after, "1");
    outgoing.body() =
        "Service temporarily unavailable: retained response byte capacity "
        "is full.\n服务暂时不可用：响应字节容量已满。\n";
  }

  if (explain_request) {
    outgoing.set(http::field::cache_control,
                 "private, no-store, max-age=0");
    outgoing.set(http::field::pragma, "no-cache");
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      RequestContext::Clock::now() - started_at_);
  const uint64_t response_bytes =
      parser_->get().method() == http::verb::head
          ? 0
          : static_cast<uint64_t>(outgoing.body().size());
  writeLog(outgoing.result_int() >= 500 ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO,
           "HTTP_RESPONSE_PREPARED method=" +
               std::string(parser_->get().method_string()) + " path=" +
               requestPathForLog(std::string(parser_->get().target()).substr(
                   0, parser_->get().target().find('?'))) +
               " status=" + std::to_string(outgoing.result_int()) +
               " duration_ms=" +
               std::to_string(std::max<int64_t>(0, elapsed.count())) +
               " response_bytes=" + std::to_string(response_bytes) +
               " response_bytes_known=true");

  const std::size_t body_size = outgoing.body().size();
  outgoing.prepare_payload();
  if (parser_->get().method() == http::verb::head) {
    outgoing.body().clear();
    outgoing.content_length(body_size);
  }
  asio::post(state_->context,
             [self = shared_from_this(), response = std::move(outgoing)]() mutable {
               self->writeResponse(std::move(response));
             });
}

void BeastSession::completeAsyncResponse(Response response,
                                         std::string body,
                                         bool explain_request,
                                         std::string client_address) {
  if (async_completed_.exchange(true, std::memory_order_acq_rel) ||
      finished_.load(std::memory_order_acquire))
    return;
  ScopedLogRequestContext log_scope(request_id_);
  ScopedRequestContext request_scope(context_);
  const auto &incoming = parser_->get();
  shared_response_body shared_body = std::move(response.shared_body);

  if (context_->suggestedFailure() == RequestFailureAttribution::Capacity) {
    shared_body.reset();
    response.status_code = 503;
    response.content_type = "text/plain; charset=utf-8";
    response.headers = {{"Cache-Control", "private, no-store"},
                        {"Retry-After", "1"}};
    std::string capacity_body =
        "Service temporarily unavailable: retained byte or execution "
        "capacity is full.\n服务暂时不可用：保留字节或执行容量已满。\n";
    body.swap(capacity_body);
  }

  RequestCancellationResponse cancellation_response;
  if (requestCancellationResponse(context_, cancellation_response)) {
    shared_body.reset();
    response.status_code = cancellation_response.status_code;
    response.content_type = "text/plain; charset=utf-8";
    for (const auto &[name, value] : cancellation_response.headers)
      response.headers[name] = value;
    body = std::move(cancellation_response.body);
  }
  if (!shared_body && !context_->retainResponseBytes(body.size())) {
    response.status_code = 503;
    response.content_type = "text/plain; charset=utf-8";
    response.headers = {{"Cache-Control", "private, no-store"},
                        {"Retry-After", "1"}};
    std::string capacity_body =
        "Service temporarily unavailable: retained response byte capacity "
        "is full.\n服务暂时不可用：响应字节容量已满。\n";
    body.swap(capacity_body);
  }
  if (explain_request) {
    response.headers["Cache-Control"] = "private, no-store, max-age=0";
    response.headers["Pragma"] = "no-cache";
  }
  if (response.status_code >= 400) {
    const auto cache_control = response.headers.find("Cache-Control");
    if (cache_control == response.headers.end() ||
        !hasNoStoreDirective(cache_control->second))
      response.headers["Cache-Control"] = "private, no-store";
  }

  const std::size_t body_size =
      shared_body ? shared_body->content.size() : body.size();
  auto configure_outgoing = [&](auto &outgoing) {
    outgoing.keep_alive(incoming.keep_alive() && !state_->stopping.load());
    outgoing.set(http::field::server,
                 "SubConverter-Extended/" VERSION " cURL/" LIBCURL_VERSION);
    outgoing.set(http::field::access_control_allow_origin, "*");
    if (incoming.find(http::field::access_control_request_headers) !=
        incoming.end())
      outgoing.set(http::field::access_control_allow_headers,
                   incoming[http::field::access_control_request_headers]);
    outgoing.set("X-Request-ID", request_id_);
    appendExposeHeader(outgoing, "X-Request-ID");
    outgoing.result(static_cast<http::status>(response.status_code));
    for (const auto &[name, value] : response.headers)
      outgoing.set(name, value);
    if (!response.content_type.empty())
      outgoing.set(http::field::content_type, response.content_type);
    outgoing.set("X-Client-IP", client_address);
  };

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      RequestContext::Clock::now() - started_at_);
  const uint64_t response_bytes =
      incoming.method() == http::verb::head
          ? 0
          : static_cast<uint64_t>(body_size);
  writeLog(response.status_code >= 500 ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO,
           "HTTP_RESPONSE_PREPARED method=" +
               std::string(incoming.method_string()) + " path=" +
               requestPathForLog(std::string(incoming.target()).substr(
                   0, incoming.target().find('?'))) +
               " status=" + std::to_string(response.status_code) +
               " duration_ms=" +
               std::to_string(std::max<int64_t>(0, elapsed.count())) +
               " response_bytes=" + std::to_string(response_bytes) +
               " response_bytes_known=true");

  if (shared_body) {
    http::response<http::buffer_body> outgoing{http::status::ok,
                                               incoming.version()};
    configure_outgoing(outgoing);
    outgoing.content_length(body_size);
    if (incoming.method() == http::verb::head || body_size == 0) {
      outgoing.body().data = nullptr;
      outgoing.body().size = 0;
    } else {
      outgoing.body().data =
          const_cast<char *>(shared_body->content.data());
      outgoing.body().size = body_size;
    }
    outgoing.body().more = false;
    writeSharedResponse(std::move(outgoing), std::move(shared_body));
  } else {
    http::response<http::string_body> outgoing{http::status::ok,
                                               incoming.version()};
    configure_outgoing(outgoing);
    outgoing.body() = std::move(body);
    outgoing.prepare_payload();
    if (incoming.method() == http::verb::head) {
      outgoing.body().clear();
      outgoing.content_length(body_size);
    }
    writeResponse(std::move(outgoing));
  }
}

void BeastSession::writeImmediateError(http::status status,
                                       const std::string &body,
                                       const char *retry_after) {
  const unsigned version = parser_->get().version() == 0
                               ? 11
                               : parser_->get().version();
  http::response<http::string_body> response{status, version};
  response.keep_alive(false);
  response.set(http::field::content_type, "text/plain; charset=utf-8");
  response.set(http::field::cache_control, "private, no-store");
  response.set("X-Request-ID", request_id_);
  appendExposeHeader(response, "X-Request-ID");
  if (retry_after)
    response.set(http::field::retry_after, retry_after);
  response.body() = body;
  response.prepare_payload();
  writeLog(status >= http::status::internal_server_error ? LOG_LEVEL_ERROR
                                                          : LOG_LEVEL_INFO,
           "HTTP_RESPONSE_PREPARED method=<unavailable> path=<redacted> "
           "status=" +
               std::to_string(static_cast<unsigned>(status)) +
               " duration_ms=0 response_bytes=" +
               std::to_string(body.size()) + " response_bytes_known=true");
  writeResponse(std::move(response));
}

void BeastSession::writeResponse(http::response<http::string_body> response) {
  if (finished_.load())
    return;
  processing_.store(true, std::memory_order_release);
  context_->setCurrentStage(RequestStage::Send);
  sending_started_at_ = RequestContext::Clock::now();
  response_status_ = response.result_int();
  auto retained = std::make_shared<http::response<http::string_body>>(
      std::move(response));
  const bool keep_alive = retained->keep_alive();
  if (context_->deadline() != RequestContext::Clock::time_point::max()) {
    const auto now = RequestContext::Clock::now();
    if (now >= context_->deadline())
      stream_.expires_after(std::chrono::milliseconds(250));
    else
      stream_.expires_at(context_->deadline());
  } else
    stream_.expires_after(std::chrono::seconds(15));
  http::async_write(stream_, *retained,
                    [self = shared_from_this(), retained, keep_alive](
                        beast::error_code error, std::size_t bytes) {
                      self->onWrite(keep_alive, error, bytes);
                    });
}

void BeastSession::writeSharedResponse(
    http::response<http::buffer_body> response,
    shared_response_body body) {
  if (finished_.load())
    return;
  processing_.store(true, std::memory_order_release);
  context_->setCurrentStage(RequestStage::Send);
  sending_started_at_ = RequestContext::Clock::now();
  response_status_ = response.result_int();
  auto retained_response =
      std::make_shared<http::response<http::buffer_body>>(
          std::move(response));
  auto serializer =
      std::make_shared<http::response_serializer<http::buffer_body>>(
          *retained_response);
  const bool keep_alive = retained_response->keep_alive();
  if (context_->deadline() != RequestContext::Clock::time_point::max()) {
    const auto now = RequestContext::Clock::now();
    if (now >= context_->deadline())
      stream_.expires_after(std::chrono::milliseconds(250));
    else
      stream_.expires_at(context_->deadline());
  } else {
    stream_.expires_after(std::chrono::seconds(15));
  }
  http::async_write(
      stream_, *serializer,
      [self = shared_from_this(), retained_response, serializer,
       body = std::move(body), keep_alive](beast::error_code error,
                                           std::size_t bytes) {
        self->onWrite(keep_alive, error, bytes);
      });
}

void BeastSession::onWrite(bool keep_alive, beast::error_code error,
                           std::size_t) {
  if (context_) {
    context_->addStageDuration(RequestStage::Send,
                               RequestContext::Clock::now() -
                                   sending_started_at_);
    if (context_->finalizeResponse(error ? 500 : response_status_, !error) &&
        error) {
      ScopedLogRequestContext log_scope(request_id_);
      writeLog(LOG_LEVEL_WARNING,
               "HTTP_RESPONSE_SEND_FAILED terminal=cancelled failure=client");
    }
  }
  processing_.store(false, std::memory_order_release);
  deadline_timer_.cancel();
  if (error || !keep_alive || state_->stopping.load()) {
    finish(!error);
    return;
  }
  if (admitted_) {
    releaseRequestAdmission(admission_bytes_);
    admitted_ = false;
  }
  context_.reset();
  request_id_.clear();
  admission_bytes_ = 0;
  async_completed_.store(false, std::memory_order_release);
  resetParser();
  read();
}

void BeastSession::finish(bool) {
  bool expected = false;
  if (!finished_.compare_exchange_strong(expected, true))
    return;
  if (context_ && context_->terminalState() == RequestTerminalState::None)
    context_->finalizeResponse(500, false);
  deadline_timer_.cancel();
  beast::error_code ignored;
  stream_.socket().shutdown(tcp::socket::shutdown_both, ignored);
  stream_.socket().close(ignored);
}

} // namespace

int startBeastWebServer(WebServer &server, listener_args *args) {
  auto state = std::make_shared<BeastServerState>(server, args);
  if (!state->bind()) {
    writeLog(LOG_LEVEL_FATAL,
             "无法绑定 Beast HTTP 服务地址：" + args->listen_address + ":" +
                 std::to_string(args->port));
    return 1;
  }
  writeLog(LOG_LEVEL_INFO,
           "HTTP_BACKEND_ACTIVE backend=beast io_threads=1 handler_threads=" +
                std::to_string(std::max(args->max_workers, 1)));
  state->accept();
  std::thread io_thread([state] { state->context.run(); });
  while (!server.SERVER_EXIT_FLAG) {
    if (args->looper_callback)
      args->looper_callback();
    if (!server.SERVER_EXIT_FLAG)
      std::this_thread::sleep_for(
          std::chrono::milliseconds(args->looper_interval));
  }
  state->stop();
  if (args->shutdown_callback)
    args->shutdown_callback();
  state->handlers.join();
  if (args->drain_callback)
    args->drain_callback();
  for (int attempt = 0; attempt < 300 && state->active_sessions.load() != 0;
       ++attempt)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  state->work_guard.reset();
  if (state->active_sessions.load() != 0)
    state->context.stop();
  if (io_thread.joinable())
    io_thread.join();
  return 0;
}
