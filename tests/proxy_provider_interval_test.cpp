#include <climits>
#include <iostream>
#include <string>

#include "config/proxy_provider_interval.h"

static bool expectAccepted(const std::string &input, int expected) {
  int value = -1;
  if (!parseProxyProviderInterval(input, value)) {
    std::cerr << "expected accepted provider interval: " << input << '\n';
    return false;
  }
  if (value != expected) {
    std::cerr << "unexpected provider interval for: " << input << '\n';
    return false;
  }
  return true;
}

static bool expectRejected(const std::string &input) {
  int value = 123;
  if (parseProxyProviderInterval(input, value)) {
    std::cerr << "expected rejected provider interval: " << input << '\n';
    return false;
  }
  if (value != 123) {
    std::cerr << "rejected provider interval mutated output: " << input
              << '\n';
    return false;
  }
  return true;
}

int main() {
  bool ok = kDefaultProxyProviderInterval == 3600;
  ok = expectAccepted("0", 0) && ok;
  ok = expectAccepted("3600", 3600) && ok;
  ok = expectAccepted(" 7200 ", 7200) && ok;
  ok = expectAccepted(std::to_string(INT_MAX), INT_MAX) && ok;

  ok = expectRejected("") && ok;
  ok = expectRejected(" ") && ok;
  ok = expectRejected("-1") && ok;
  ok = expectRejected("+1") && ok;
  ok = expectRejected("none") && ok;
  ok = expectRejected("1h") && ok;
  ok = expectRejected("1.5") && ok;
  ok = expectRejected("2147483648") && ok;
  return ok ? 0 : 1;
}
