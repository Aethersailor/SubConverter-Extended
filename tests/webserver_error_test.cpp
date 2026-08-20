#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "httplib.h"
#include "server/socket.h"
#include "server/webserver.h"

Settings global;

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::string throwingHandler(Request &, Response &) {
  throw std::runtime_error(
      "exception-secret https://example.test/private-exception-token");
}

std::string okHandler(Request &request, Response &response) {
  if (!request.context)
    throw std::runtime_error("request context was not propagated");
  response.headers["X-Test-Request-Context-ID"] = request.context->requestId();
  RequestStageTimer parse_timer(request.context, RequestStage::Parse);
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
  return "ok";
}

std::string sharedSyncHandler(Request &request, Response &response) {
  if (!request.context)
    throw std::runtime_error("shared sync handler lost request context");
  auto body = std::make_shared<ImmutableResponseBody>();
  body->content = "shared-sync-ok";
  require(body->retained_bytes.acquire(body->content.size()),
          "shared sync test could not retain its body");
  response.shared_body = std::move(body);
  return {};
}

std::string asyncSyncHandler(Request &request, Response &response) {
  if (!request.context)
    throw std::runtime_error("async sync fallback lost request context");
  response.headers["X-Test-Request-Context-ID"] = request.context->requestId();
  return "async-ok";
}

void asyncHandler(Request request, async_response_completion completion) {
  std::thread([request = std::move(request),
               completion = std::move(completion)]() mutable {
    Response response;
    if (!request.context) {
      response.status_code = 500;
      completion(std::move(response), "missing-context");
      return;
    }
    response.headers["X-Test-Request-Context-ID"] =
        request.context->requestId();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    auto shared_body = std::make_shared<ImmutableResponseBody>();
    shared_body->content = "async-ok";
    require(shared_body->retained_bytes.acquire(shared_body->content.size()),
            "async test could not retain its shared body");
    response.shared_body = std::move(shared_body);
    completion(std::move(response), {});
  }).detach();
}

std::atomic<bool> blocking_started{false};
std::atomic<bool> blocking_release{false};
std::atomic<bool> cancellation_started{false};
std::atomic<RequestCancellationReason> observed_cancellation{
    RequestCancellationReason::None};

std::string healthHandler(Request &, Response &) { return "ok"; }

std::string blockingHandler(Request &, Response &) {
  blocking_started.store(true, std::memory_order_release);
  while (!blocking_release.load(std::memory_order_acquire))
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  return "released";
}

std::string delayedHandler(Request &, Response &) {
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  return "half-close-ok";
}

std::string cancellationHandler(Request &request, Response &) {
  require(static_cast<bool>(request.context),
          "cancellation handler lost request context");
  cancellation_started.store(true, std::memory_order_release);
  const auto stop = std::chrono::steady_clock::now() +
                    std::chrono::seconds(2);
  while (!request.context->cancellationToken().isCancellationRequested() &&
         std::chrono::steady_clock::now() < stop)
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  observed_cancellation.store(request.context->cancellationToken().reason(),
                              std::memory_order_release);
  return "cancelled";
}

bool validRequestId(const std::string &value) {
  return value.size() == 32 &&
         std::all_of(value.begin(), value.end(), [](unsigned char ch) {
           return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
         });
}

int unusedPort() {
#ifdef _WIN32
  WSADATA data;
  require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed");
#endif
  SOCKET socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  require(socket_fd != INVALID_SOCKET, "socket failed");
  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  require(bind(socket_fd, reinterpret_cast<sockaddr *>(&address),
               sizeof(address)) == 0,
          "bind failed");
#ifdef _WIN32
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  require(getsockname(socket_fd, reinterpret_cast<sockaddr *>(&address),
                      &length) == 0,
          "getsockname failed");
  const int port = ntohs(address.sin_port);
  closesocket(socket_fd);
  return port;
}

bool waitFlag(const std::atomic<bool> &flag,
              std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!flag.load(std::memory_order_acquire) &&
         std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  return flag.load(std::memory_order_acquire);
}

void waitReady(int port) {
  httplib::Client client("127.0.0.1", port);
  client.set_connection_timeout(0, 100000);
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (auto response = client.Get("/healthz"); response &&
        response->status == 200)
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("test server did not become ready");
}

void testIndependentHealthChannel() {
  blocking_started.store(false);
  blocking_release.store(false);
  global.maxServerThreads = 1;
  WebServer server;
  server.append_response("GET", "/healthz", "text/plain", healthHandler);
  server.append_response("GET", "/block", "text/plain", blockingHandler);
  listener_args args;
  args.listen_address = "127.0.0.1";
  args.port = unusedPort();
  args.max_conn = 8;
  args.max_workers = 1;
  args.looper_interval = 5;
  args.request_deadline_ms = 2000;
  std::thread server_thread([&] { server.start_web_server_multi(&args); });
  waitReady(args.port);

  auto blocked = std::async(std::launch::async, [&] {
    httplib::Client client("127.0.0.1", args.port);
    client.set_read_timeout(3, 0);
    return client.Get("/block");
  });
  require(waitFlag(blocking_started, std::chrono::seconds(1)),
          "blocking route did not occupy the sole normal handler");
  httplib::Client health_client("127.0.0.1", args.port);
  health_client.set_read_timeout(0, 500000);
  const auto started = std::chrono::steady_clock::now();
  httplib::Result health = health_client.Get("/healthz");
  const auto elapsed = std::chrono::steady_clock::now() - started;
  blocking_release.store(true, std::memory_order_release);
  httplib::Result blocked_response = blocked.get();
  server.stop_web_server();
  server_thread.join();
  require(health && health->status == 200 && health->body == "ok",
          "health channel was blocked by the normal handler pool");
  require(elapsed < std::chrono::milliseconds(500),
          "health channel exceeded its strict response deadline");
  require(blocked_response && blocked_response->status == 200,
          "blocking route did not finish after release");
}

void testAbsoluteDeadline() {
  cancellation_started.store(false);
  observed_cancellation.store(RequestCancellationReason::None);
  WebServer server;
  server.append_response("GET", "/healthz", "text/plain", healthHandler);
  server.append_response("GET", "/deadline", "text/plain",
                         cancellationHandler);
  listener_args args;
  args.listen_address = "127.0.0.1";
  args.port = unusedPort();
  args.max_conn = 8;
  args.max_workers = 1;
  args.looper_interval = 5;
  args.request_deadline_ms = 100;
  std::thread server_thread([&] { server.start_web_server_multi(&args); });
  waitReady(args.port);
  httplib::Client client("127.0.0.1", args.port);
  client.set_read_timeout(2, 0);
  httplib::Result response = client.Get("/deadline");
  server.stop_web_server();
  server_thread.join();
  require(response && response->status == 504,
          "absolute request deadline did not produce HTTP 504");
  require(observed_cancellation.load() == RequestCancellationReason::Deadline,
          "absolute deadline did not reach the handler cancellation token");
}

void testClientDisconnectCancellation() {
  cancellation_started.store(false);
  observed_cancellation.store(RequestCancellationReason::None);
  WebServer server;
  server.append_response("GET", "/healthz", "text/plain", healthHandler);
  server.append_response("GET", "/disconnect", "text/plain",
                         cancellationHandler);
  listener_args args;
  args.listen_address = "127.0.0.1";
  args.port = unusedPort();
  args.max_conn = 8;
  args.max_workers = 1;
  args.looper_interval = 5;
  args.request_deadline_ms = 2000;
  std::thread server_thread([&] { server.start_web_server_multi(&args); });
  waitReady(args.port);

  SOCKET socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  require(socket_fd != INVALID_SOCKET, "disconnect socket failed");
  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(static_cast<unsigned short>(args.port));
  require(connect(socket_fd, reinterpret_cast<sockaddr *>(&address),
                  sizeof(address)) == 0,
          "disconnect client connect failed");
  const std::string request =
      "GET /disconnect HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  require(send(socket_fd, request.data(), static_cast<int>(request.size()), 0) ==
              static_cast<int>(request.size()),
          "disconnect client send failed");
  require(waitFlag(cancellation_started, std::chrono::seconds(1)),
          "disconnect handler did not start");
  closesocket(socket_fd);
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(1);
  while (observed_cancellation.load() == RequestCancellationReason::None &&
         std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  server.stop_web_server();
  server_thread.join();
  require(observed_cancellation.load() ==
              RequestCancellationReason::ClientDisconnected,
          "socket disconnect did not reach the request cancellation token");
}

void testClientHalfCloseStillReceivesResponse() {
  WebServer server;
  server.append_response("GET", "/healthz", "text/plain", healthHandler);
  server.append_response("GET", "/half-close", "text/plain", delayedHandler);
  listener_args args;
  args.listen_address = "127.0.0.1";
  args.port = unusedPort();
  args.max_conn = 8;
  args.max_workers = 1;
  args.looper_interval = 5;
  args.request_deadline_ms = 1000;
  std::thread server_thread([&] { server.start_web_server_multi(&args); });
  waitReady(args.port);

  SOCKET socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  require(socket_fd != INVALID_SOCKET, "half-close socket failed");
  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(static_cast<unsigned short>(args.port));
  require(connect(socket_fd, reinterpret_cast<sockaddr *>(&address),
                  sizeof(address)) == 0,
          "half-close client connect failed");
  const std::string request =
      "GET /half-close HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  require(send(socket_fd, request.data(), static_cast<int>(request.size()), 0) ==
              static_cast<int>(request.size()),
          "half-close client send failed");
#ifdef _WIN32
  require(shutdown(socket_fd, SD_SEND) == 0, "half-close shutdown failed");
#else
  require(shutdown(socket_fd, SHUT_WR) == 0, "half-close shutdown failed");
#endif
  std::string response;
  std::array<char, 1024> buffer{};
  for (;;) {
    const int received =
        recv(socket_fd, buffer.data(), static_cast<int>(buffer.size()), 0);
    if (received <= 0)
      break;
    response.append(buffer.data(), static_cast<size_t>(received));
  }
  closesocket(socket_fd);
  server.stop_web_server();
  server_thread.join();
  require(response.find(" 499 ") != std::string::npos &&
              response.find("Client closed request") != std::string::npos,
          "client half-close did not enter the cancellation path");
}

} // namespace

int main() {
  resetRequestLifecycleMetricsForTests();
  global.logLevel = LOG_LEVEL_VERBOSE;
  publishSettingsSnapshot(global);
  bool other_thread_kept_published_level = false;
  {
    ScopedLogLevelOverride candidate_level;
    candidate_level.set(LOG_LEVEL_ERROR);
    require(!shouldLog(LOG_LEVEL_INFO),
            "candidate log level did not apply to the loader thread");
    std::thread observer([&] {
      other_thread_kept_published_level = shouldLog(LOG_LEVEL_VERBOSE);
    });
    observer.join();
  }
  require(other_thread_kept_published_level,
          "candidate log level leaked into another thread");
  require(shouldLog(LOG_LEVEL_VERBOSE),
          "candidate log level was not restored after its scope");
  WebServer server;
  server.append_response("GET", "/throw", "text/plain", throwingHandler);
  server.append_response("GET", "/ok", "text/plain", okHandler);
  server.append_response("GET", "/shared", "text/plain", sharedSyncHandler);
  server.append_async_response("GET", "/async", "text/plain",
                               asyncSyncHandler, asyncHandler);

  listener_args args;
  args.listen_address = "127.0.0.1";
  args.port = unusedPort();
  args.max_conn = 16;
  args.max_workers = 2;
  args.looper_interval = 10;

  std::ostringstream captured;
  std::streambuf *original = std::cerr.rdbuf(captured.rdbuf());
  std::thread server_thread([&] { server.start_web_server_multi(&args); });

  httplib::Client client("127.0.0.1", args.port);
  client.set_connection_timeout(0, 100000);
  client.set_read_timeout(2, 0);
  httplib::Result response;
  const httplib::Headers request_headers = {
      {"Authorization", "Bearer authorization-header-secret"},
      {"Cookie", "session=cookie-header-secret"},
      {"X-Request-ID", "forged-request-id"},
      {"X-Provider-Secret", "header-secret"}};
  for (int attempt = 0; attempt < 100 && !response; ++attempt) {
    response = client.Get(
        "/throw?target=clash&url=https%3A%2F%2Fexample.test%2Frequest-secret"
        "&token=query-secret&userinfo=userinfo-secret",
        request_headers);
    if (!response)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  const httplib::Result not_found =
      client.Get("/missing?token=missing-route-secret");
  const httplib::Result ok = client.Get("/ok");
  const httplib::Result shared = client.Get("/shared");
  const httplib::Result shared_head = client.Head("/shared");
  const httplib::Result async_first = client.Get("/async");
  const httplib::Result async_second = client.Get("/async");
  const httplib::Result head = client.Head("/ok");
  const httplib::Result options = client.Options("/ok");
  const httplib::Result explain_error = client.Get("/throw?explain=true");

  server.stop_web_server();
  server_thread.join();
  std::cerr.rdbuf(original);
#ifdef _WIN32
  WSACleanup();
#endif

  require(static_cast<bool>(response), "request did not receive a response");
  require(response->status == 500, "unexpected status");
  require(response->get_header_value("Content-Type").find("text/plain") !=
              std::string::npos,
          "unexpected content type");
  require(response->get_header_value("Cache-Control") == "private, no-store",
          "missing no-store response policy");
  const std::string exception_request_id =
      response->get_header_value("X-Request-ID");
  require(validRequestId(exception_request_id),
          "exception response request ID is invalid");
  require(exception_request_id != "forged-request-id",
          "inbound request ID was trusted");
  require(response->get_header_value("Access-Control-Expose-Headers")
              .find("X-Request-ID") != std::string::npos,
          "request ID is not exposed to browser clients");
  require(static_cast<bool>(not_found), "missing route did not receive a response");
  require(not_found->status == 404, "missing route returned unexpected status");
  require(not_found->get_header_value("Cache-Control") == "private, no-store",
          "built-in 404 is missing the no-store response policy");
  require(not_found->body.find("missing-route-secret") == std::string::npos,
          "missing route secret leaked in body");
  const std::string missing_request_id =
      not_found->get_header_value("X-Request-ID");
  require(validRequestId(missing_request_id),
          "missing route request ID is invalid");
  require(missing_request_id != exception_request_id,
          "request ID was reused across requests");
  require(static_cast<bool>(ok), "normal route did not receive a response");
  require(ok->status == 200 && ok->body == "ok", "normal route failed");
  const std::string ok_request_id = ok->get_header_value("X-Request-ID");
  require(validRequestId(ok_request_id), "normal route request ID is invalid");
  require(ok->get_header_value("X-Test-Request-Context-ID") == ok_request_id,
          "route request context does not match its response request ID");
  require(ok_request_id != exception_request_id &&
              ok_request_id != missing_request_id,
           "normal route reused a request ID");
  require(static_cast<bool>(shared) && shared->status == 200 &&
              shared->body == "shared-sync-ok",
          "sync shared-body route failed");
  require(shared->get_header_value("Content-Type").find("text/plain") !=
              std::string::npos,
          "sync shared-body route lost its default content type");
  require(static_cast<bool>(shared_head) && shared_head->status == 200 &&
              shared_head->body.empty() &&
              shared_head->get_header_value_u64("Content-Length") ==
                  std::string("shared-sync-ok").size(),
          "sync shared-body HEAD route failed");
  require(static_cast<bool>(async_first) && async_first->status == 200 &&
              async_first->body == "async-ok",
          "first async route failed");
  require(async_first->get_header_value("Content-Type").find("text/plain") !=
              std::string::npos,
          "async route lost its default content type");
  require(static_cast<bool>(async_second) && async_second->status == 200 &&
              async_second->body == "async-ok",
          "second keep-alive async route failed");
  const std::string async_first_id =
      async_first->get_header_value("X-Request-ID");
  const std::string async_second_id =
      async_second->get_header_value("X-Request-ID");
  require(validRequestId(async_first_id) && validRequestId(async_second_id) &&
              async_first_id != async_second_id,
          "async route request IDs are invalid or reused");
  require(async_first->get_header_value("X-Test-Request-Context-ID") ==
              async_first_id &&
              async_second->get_header_value("X-Test-Request-Context-ID") ==
                  async_second_id,
          "async route lost its owned request context");
  require(static_cast<bool>(head) && head->status == 200,
          "HEAD route failed");
  const std::string head_request_id = head->get_header_value("X-Request-ID");
  require(validRequestId(head_request_id), "HEAD request ID is invalid");
  require(head_request_id != ok_request_id &&
              head_request_id != exception_request_id &&
              head_request_id != missing_request_id,
          "HEAD route reused a request ID");
  require(static_cast<bool>(options) && options->status == 200,
          "OPTIONS route failed");
  const std::string options_request_id =
      options->get_header_value("X-Request-ID");
  require(validRequestId(options_request_id), "OPTIONS request ID is invalid");
  require(options_request_id != head_request_id &&
              options_request_id != ok_request_id &&
              options_request_id != exception_request_id &&
              options_request_id != missing_request_id,
          "OPTIONS route reused a request ID");
  require(static_cast<bool>(explain_error) && explain_error->status == 500,
          "explain exception route failed");
  const std::string explain_error_request_id =
      explain_error->get_header_value("X-Request-ID");
  require(validRequestId(explain_error_request_id),
          "explain exception request ID is invalid");
  require(explain_error_request_id != options_request_id &&
              explain_error_request_id != head_request_id &&
              explain_error_request_id != ok_request_id &&
              explain_error_request_id != exception_request_id &&
              explain_error_request_id != missing_request_id,
          "explain exception reused a request ID");
  require(explain_error->get_header_value("Cache-Control") ==
              "private, no-store, max-age=0",
          "explain exception lost its no-store cache policy");
  require(explain_error->get_header_value("Pragma") == "no-cache",
          "explain exception lost its legacy no-cache policy");
  require(response->body.find("Internal server error") != std::string::npos,
          "generic error body missing");
  require(response->body.find("request-secret") == std::string::npos,
          "request target leaked in body");
  require(response->body.find("query-secret") == std::string::npos,
          "query secret leaked in body");
  require(response->body.find("userinfo-secret") == std::string::npos,
          "userinfo leaked in body");
  require(response->body.find("exception-secret") == std::string::npos,
          "exception detail leaked in body");

  const std::string logs = captured.str();
  require(logs.find("HTTP_UNEXPECTED_EXCEPTION") != std::string::npos,
          "exception event missing from logs");
  require(logs.find("request_id=" + exception_request_id +
                    " HTTP_UNEXPECTED_EXCEPTION") != std::string::npos,
          "exception event lost its response request ID");
  require(logs.find("request_id=" + exception_request_id +
                    " HTTP_RESPONSE_PREPARED method=GET path=/throw status=500") !=
              std::string::npos,
          "exception completion event lost request correlation");
  require(logs.find("request_id=" + missing_request_id +
                    " HTTP_RESPONSE_PREPARED method=GET path=/missing status=404") !=
              std::string::npos,
          "missing route completion event lost request correlation");
  require(logs.find("request_id=" + ok_request_id +
                    " HTTP_RESPONSE_PREPARED method=GET path=/ok status=200") !=
              std::string::npos,
          "normal route completion event lost request correlation");
  require(logs.find("request_id=" + head_request_id +
                    " HTTP_RESPONSE_PREPARED method=HEAD path=/ok status=200") !=
              std::string::npos,
          "HEAD completion event lost request correlation");
  require(logs.find("request_id=" + options_request_id +
                    " HTTP_RESPONSE_PREPARED method=OPTIONS path=/ok status=200") !=
              std::string::npos,
          "OPTIONS completion event lost request correlation");
  require(logs.find("request_id=" + explain_error_request_id +
                    " HTTP_RESPONSE_PREPARED method=GET path=/throw status=500") !=
              std::string::npos,
          "explain exception completion event lost request correlation");
  require(logs.find("X-Provider-Secret") == std::string::npos,
          "request header name leaked in logs");
  require(logs.find("forged-request-id") == std::string::npos,
          "untrusted inbound request ID leaked in logs");
  require(logs.find("request-secret") == std::string::npos,
          "request target leaked in logs");
  require(logs.find("query-secret") == std::string::npos,
          "query secret leaked in logs");
  require(logs.find("userinfo-secret") == std::string::npos,
          "userinfo leaked in logs");
  require(logs.find("header-secret") == std::string::npos,
          "request header value leaked in logs");
  require(logs.find("authorization-header-secret") == std::string::npos,
          "Authorization value leaked in logs");
  require(logs.find("cookie-header-secret") == std::string::npos,
          "Cookie value leaked in logs");
  require(logs.find("exception-secret") == std::string::npos,
          "exception detail leaked in logs");
  require(logs.find("private-exception-token") == std::string::npos,
          "exception URL leaked in logs");
  require(logs.find("missing-route-secret") == std::string::npos,
          "missing route query leaked in logs");
  const RequestLifecycleMetricsSnapshot lifecycle =
      requestLifecycleMetricsSnapshot();
  uint64_t terminal_total = 0;
  for (uint64_t count : lifecycle.terminal)
    terminal_total += count;
  require(terminal_total == 10,
          "HTTP requests did not each reach exactly one terminal state");
  require(lifecycle.terminal[static_cast<std::size_t>(
              RequestTerminalState::Completed)] == 8 &&
              lifecycle.terminal[static_cast<std::size_t>(
                  RequestTerminalState::Failed)] == 2 &&
              lifecycle.terminal[static_cast<std::size_t>(
                  RequestTerminalState::Cancelled)] == 0,
          "HTTP terminal attribution changed across normal and error paths");
  require(lifecycle.stage_samples[static_cast<std::size_t>(
              RequestStage::Admission)] == 10,
          "HTTP admission timing did not cover every response path");
  require(lifecycle.stage_samples[static_cast<std::size_t>(
              RequestStage::Send)] == 10,
          "HTTP send timing did not cover every response path");
  require(lifecycle.stage_samples[static_cast<std::size_t>(
              RequestStage::Parse)] >= 1,
          "route-level parse timing was not propagated into the handler");
  const RequestAdmissionSnapshot admission = requestAdmissionSnapshot();
  require(admission.active_entries == 0 && admission.active_bytes == 0,
          "request admission permits leaked after server shutdown");
  require(admission.accepted == 10 && admission.rejected == 0,
          "request admission did not account for every response path");
  require(retainedResponseByteSnapshot().used == 0,
          "shared response byte lease leaked after server shutdown");
  resetRequestLifecycleMetricsForTests();
  testIndependentHealthChannel();
  resetRequestLifecycleMetricsForTests();
  testAbsoluteDeadline();
  resetRequestLifecycleMetricsForTests();
  testClientDisconnectCancellation();
  resetRequestLifecycleMetricsForTests();
  testClientHalfCloseStillReceivesResponse();
  return 0;
}
