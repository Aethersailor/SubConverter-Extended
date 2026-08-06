#include <iostream>
#include <string>

#include "config/proxy_provider_direct.h"

static bool expectAccepted(const std::string &input, bool expected) {
  bool value = !expected;
  if (!parseProxyProviderDirect(input, value)) {
    std::cerr << "expected accepted proxy_direct value: " << input << '\n';
    return false;
  }
  if (value != expected) {
    std::cerr << "unexpected proxy_direct value for: " << input << '\n';
    return false;
  }
  return true;
}

static bool expectRejected(const std::string &input) {
  bool value = true;
  if (parseProxyProviderDirect(input, value)) {
    std::cerr << "expected rejected proxy_direct value: " << input << '\n';
    return false;
  }
  if (!value) {
    std::cerr << "rejected proxy_direct value mutated output: " << input
              << '\n';
    return false;
  }
  return true;
}

int main() {
  bool ok = kDefaultProxyProviderDirect;
  ok = expectAccepted("true", true) && ok;
  ok = expectAccepted("false", false) && ok;
  ok = expectAccepted("1", true) && ok;
  ok = expectAccepted("0", false) && ok;
  ok = expectAccepted(" TRUE ", true) && ok;
  ok = expectAccepted(" False ", false) && ok;

  ok = expectRejected("") && ok;
  ok = expectRejected(" ") && ok;
  ok = expectRejected("yes") && ok;
  ok = expectRejected("on") && ok;
  ok = expectRejected("none") && ok;
  ok = expectRejected("2") && ok;
  return ok ? 0 : 1;
}
