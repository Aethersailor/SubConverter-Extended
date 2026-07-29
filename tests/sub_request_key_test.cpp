#include <cassert>
#include <string>

#include "handler/sub_request_key.h"

static Request baseRequest(const std::string &url) {
  Request request;
  request.method = "GET";
  request.url = "/sub";
  request.argument.emplace("target", "clash");
  request.argument.emplace("url", url);
  request.headers.emplace("User-Agent", "Clash.Meta/1.0");
  return request;
}

static std::string key(const Request &request, const std::string &age = "",
                       uint64_t generation = 7) {
  return buildSubRequestKey(request, age, generation, "https://managed.test");
}

int main() {
  Request private_a = baseRequest("data:,ss://private-a");
  Request private_b = baseRequest("data:,ss://private-b");
  assert(key(private_a) != key(private_b));

  Request transport_a = private_a;
  transport_a.headers["CF-Ray"] = "ray-a";
  transport_a.headers["X-Forwarded-For"] = "198.51.100.1";
  transport_a.headers["X-Request-ID"] = "trace-a";
  transport_a.headers["Cookie"] = "secret=a";
  Request transport_b = private_a;
  transport_b.headers["CF-Ray"] = "ray-b";
  transport_b.headers["X-Forwarded-For"] = "203.0.113.2";
  transport_b.headers["X-Request-ID"] = "trace-b";
  transport_b.headers["Cookie"] = "secret=b";
  assert(key(transport_a) == key(transport_b));

  Request user_agent = private_a;
  user_agent.headers["User-Agent"] = "Clash.Meta/2.0";
  assert(key(private_a) != key(user_agent));
  assert(key(private_a, "age-a") != key(private_a, "age-b"));
  assert(key(private_a, "", 7) != key(private_a, "", 8));

  Request provider_a = private_a;
  provider_a.argument.emplace("provider_headers", "x-hwid");
  provider_a.headers["X-HWID"] = "device-a";
  Request provider_b = provider_a;
  provider_b.headers["X-HWID"] = "device-b";
  assert(key(provider_a) != key(provider_b));

  Request unselected_a = private_a;
  unselected_a.headers["X-HWID"] = "device-a";
  Request unselected_b = private_a;
  unselected_b.headers["X-HWID"] = "device-b";
  assert(key(unselected_a) == key(unselected_b));

  Request order_a = baseRequest("data:,ss://same");
  order_a.argument.emplace("config", "data:,enable_rule_generator=false");
  order_a.argument.emplace("list", "true");
  Request order_b;
  order_b.method = "GET";
  order_b.url = "/sub";
  order_b.argument.emplace("list", "true");
  order_b.argument.emplace("url", "data:,ss://same");
  order_b.argument.emplace("target", "clash");
  order_b.argument.emplace("config", "data:,enable_rule_generator=false");
  order_b.headers.emplace("User-Agent", "Clash.Meta/1.0");
  assert(key(order_a) == key(order_b));

  Request framed_a = baseRequest("value\narg_name:1:x");
  Request framed_b = baseRequest("value");
  framed_b.argument.emplace("x", "x");
  assert(key(framed_a) != key(framed_b));

  Request selected_order_a = private_a;
  selected_order_a.argument.emplace("provider_headers", "x-hwid, authorization");
  selected_order_a.headers["X-HWID"] = "device";
  selected_order_a.headers["Authorization"] = "Bearer one";
  Request selected_order_b = private_a;
  selected_order_b.argument.emplace("provider_headers", "authorization,x-hwid");
  selected_order_b.headers["X-HWID"] = "device";
  selected_order_b.headers["Authorization"] = "Bearer one";
  assert(key(selected_order_a) != key(selected_order_b));
  return 0;
}
