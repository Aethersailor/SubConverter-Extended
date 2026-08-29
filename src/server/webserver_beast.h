#ifndef WEBSERVER_BEAST_H_INCLUDED
#define WEBSERVER_BEAST_H_INCLUDED

#include <cstdint>

struct listener_args;
class WebServer;

struct BeastConnectionSnapshot {
  bool running = false;
  bool wait_on_connection_capacity = false;
  bool accept_paused = false;
  uint64_t active_sessions = 0;
  uint64_t accepted_limit = 0;
  uint64_t business_sessions = 0;
  uint64_t reserved_sessions = 0;
  uint64_t capacity_503_total = 0;
  uint64_t accept_pauses_total = 0;
  uint64_t accept_resumes_total = 0;
};

BeastConnectionSnapshot beastConnectionSnapshot() noexcept;
int startBeastWebServer(WebServer &server, listener_args *args);

#endif // WEBSERVER_BEAST_H_INCLUDED
