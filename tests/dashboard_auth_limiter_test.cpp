#include "handler/dashboard_auth_limiter.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;

void require(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

client_ip::Address address(const std::string &value) {
  return client_ip::parseAddress(value);
}

void lockAndClear() {
  dashboard_auth::FailureLimiter limiter(8);
  const auto now = dashboard_auth::FailureLimiter::TimePoint(
      std::chrono::seconds(100));
  const auto key = address("192.0.2.1");
  require(limiter.evaluate(key, false, 3, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Unauthorized,
          "first failure is unauthorized");
  require(limiter.evaluate(key, false, 3, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Unauthorized,
          "second failure is unauthorized");
  require(limiter.evaluate(key, true, 3, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Allowed,
          "successful Basic Auth clears the source bucket");
  require(limiter.evaluate(key, false, 3, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Unauthorized,
          "failure count restarts after success");
  (void)limiter.evaluate(key, false, 3, 30, 60, now);
  const auto locked = limiter.evaluate(key, false, 3, 30, 60, now);
  require(locked.result == dashboard_auth::FailureLimiter::Result::Locked &&
              locked.retry_after_seconds == 60,
          "threshold locks source with retry time");
  require(limiter.evaluate(key, true, 3, 30, 60,
                           now + std::chrono::seconds(1))
              .result == dashboard_auth::FailureLimiter::Result::Locked,
          "correct credentials do not bypass an active lock");
  require(limiter.evaluate(key, true, 3, 30, 60,
                           now + std::chrono::seconds(61))
              .result == dashboard_auth::FailureLimiter::Result::Allowed,
          "expired lock permits valid credentials");
}

void clientsAreIndependent() {
  dashboard_auth::FailureLimiter limiter(8);
  const auto now = dashboard_auth::FailureLimiter::TimePoint(
      std::chrono::seconds(200));
  const auto first = address("192.0.2.1");
  const auto second = address("192.0.2.2");
  (void)limiter.evaluate(first, false, 2, 30, 60, now);
  require(limiter.evaluate(first, false, 2, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Locked,
          "first proxy client is locked");
  require(limiter.evaluate(second, false, 2, 30, 60, now).result ==
              dashboard_auth::FailureLimiter::Result::Unauthorized,
          "second proxy client has an independent bucket");
}

void capacityAndExpiry() {
  dashboard_auth::FailureLimiter limiter(2);
  const auto now = dashboard_auth::FailureLimiter::TimePoint(
      std::chrono::seconds(300));
  (void)limiter.evaluate(address("192.0.2.1"), false, 2, 30, 60, now);
  (void)limiter.evaluate(address("192.0.2.2"), false, 2, 30, 60, now);
  require(limiter.evaluate(address("192.0.2.3"), false, 2, 30, 60, now)
              .result == dashboard_auth::FailureLimiter::Result::Unauthorized,
          "overflow bucket receives a new source");
  require(limiter.evaluate(address("192.0.2.4"), false, 2, 30, 60, now)
              .result == dashboard_auth::FailureLimiter::Result::Locked,
          "overflow bucket fails closed under bucket spray");
  require(limiter.bucketCount() == 2 && limiter.overflowActive(),
          "normal bucket count remains bounded");
  require(limiter.evaluate(address("192.0.2.5"), true, 2, 30, 60,
                           now + std::chrono::seconds(1))
              .result == dashboard_auth::FailureLimiter::Result::Locked,
          "overflow lock cannot be bypassed with a fresh key");
  require(limiter.evaluate(address("192.0.2.5"), true, 2, 30, 60,
                           now + std::chrono::seconds(91))
              .result == dashboard_auth::FailureLimiter::Result::Allowed,
          "expired overflow state is cleaned");
  require(!limiter.overflowActive(), "overflow state expires");
}

void concurrentFailures() {
  dashboard_auth::FailureLimiter limiter(8);
  const auto now = dashboard_auth::FailureLimiter::TimePoint(
      std::chrono::seconds(500));
  const auto key = address("2001:db8::1");
  std::atomic<int> locked{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 16; ++i) {
    threads.emplace_back([&]() {
      if (limiter.evaluate(key, false, 8, 30, 60, now).result ==
          dashboard_auth::FailureLimiter::Result::Locked)
        ++locked;
    });
  }
  for (auto &thread : threads)
    thread.join();
  require(locked.load() == 9,
          "concurrent failures are serialized without losing increments");
  require(limiter.bucketCount() == 1,
          "concurrent failures share one canonical bucket");
}

} // namespace

int main() {
  lockAndClear();
  clientsAreIndependent();
  capacityAndExpiry();
  concurrentFailures();
  if (failures != 0)
    return 1;
  std::cout << "dashboard auth limiter tests passed\n";
  return 0;
}
