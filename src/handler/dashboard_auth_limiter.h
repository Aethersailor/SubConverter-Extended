#ifndef DASHBOARD_AUTH_LIMITER_H_INCLUDED
#define DASHBOARD_AUTH_LIMITER_H_INCLUDED

#include <chrono>
#include <cstddef>
#include <mutex>
#include <unordered_map>

#include "server/client_ip.h"

namespace dashboard_auth {

class FailureLimiter {
public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  enum class Result { Allowed, Unauthorized, Locked };

  struct Decision {
    Result result = Result::Unauthorized;
    long long retry_after_seconds = 0;
  };

  explicit FailureLimiter(std::size_t capacity = 4096)
      : capacity_(capacity) {}

  Decision evaluate(const client_ip::Address &key, bool credentials_valid,
                    int max_failures, int window_seconds, int lock_seconds,
                    TimePoint now = Clock::now());

#ifdef DASHBOARD_AUTH_LIMITER_TESTING
  std::size_t bucketCount() const;
  bool overflowActive() const;
#endif

private:
  struct FailureState {
    int failures = 0;
    TimePoint window_start{};
    TimePoint locked_until{};
  };

  bool expired(const FailureState &state, TimePoint now,
               int window_seconds) const;
  Decision evaluateState(FailureState &state, bool credentials_valid,
                         int max_failures, int window_seconds,
                         int lock_seconds, TimePoint now, bool clear_on_success,
                         bool *erase);
  void cleanup(TimePoint now, int window_seconds);

  const std::size_t capacity_;
  mutable std::mutex mutex_;
  std::unordered_map<client_ip::Address, FailureState, client_ip::AddressHash>
      failures_;
  FailureState overflow_;
  bool overflow_active_ = false;
  TimePoint next_cleanup_{};
};

} // namespace dashboard_auth

#endif // DASHBOARD_AUTH_LIMITER_H_INCLUDED
