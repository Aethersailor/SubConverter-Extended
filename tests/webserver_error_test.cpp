#include <algorithm>
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

std::string okHandler(Request &, Response &) { return "ok"; }

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

} // namespace

int main() {
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
  require(ok_request_id != exception_request_id &&
              ok_request_id != missing_request_id,
          "normal route reused a request ID");
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
  return 0;
}
