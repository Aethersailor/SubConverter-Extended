#include <chrono>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include "handler/settings.h"
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
  WebServer server;
  server.append_response("GET", "/throw", "text/plain", throwingHandler);

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
      {"X-Provider-Secret", "header-secret"}};
  for (int attempt = 0; attempt < 100 && !response; ++attempt) {
    response = client.Get(
        "/throw?target=clash&url=https%3A%2F%2Fexample.test%2Frequest-secret"
        "&token=query-secret&userinfo=userinfo-secret",
        request_headers);
    if (!response)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

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
  require(logs.find("X-Provider-Secret") != std::string::npos,
          "request header name missing from logs");
  require(logs.find("request-secret") == std::string::npos,
          "request target leaked in logs");
  require(logs.find("query-secret") == std::string::npos,
          "query secret leaked in logs");
  require(logs.find("userinfo-secret") == std::string::npos,
          "userinfo leaked in logs");
  require(logs.find("header-secret") == std::string::npos,
          "request header value leaked in logs");
  require(logs.find("exception-secret") == std::string::npos,
          "exception detail leaked in logs");
  require(logs.find("private-exception-token") == std::string::npos,
          "exception URL leaked in logs");
  return 0;
}
