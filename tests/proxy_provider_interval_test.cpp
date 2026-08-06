#include <cassert>
#include <climits>
#include <string>

#include "config/proxy_provider_interval.h"

static void assertAccepted(const std::string &input, int expected) {
  int value = -1;
  assert(parseProxyProviderInterval(input, value));
  assert(value == expected);
}

static void assertRejected(const std::string &input) {
  int value = 123;
  assert(!parseProxyProviderInterval(input, value));
  assert(value == 123);
}

int main() {
  assert(kDefaultProxyProviderInterval == 3600);
  assertAccepted("0", 0);
  assertAccepted("3600", 3600);
  assertAccepted(" 7200 ", 7200);
  assertAccepted(std::to_string(INT_MAX), INT_MAX);

  assertRejected("");
  assertRejected(" ");
  assertRejected("-1");
  assertRejected("+1");
  assertRejected("none");
  assertRejected("1h");
  assertRejected("1.5");
  assertRejected("2147483648");
  return 0;
}
