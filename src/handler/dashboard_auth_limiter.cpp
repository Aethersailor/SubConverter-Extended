#include "handler/dashboard_auth_limiter.h"

#include <algorithm>

namespace dashboard_auth {

bool FailureLimiter::expired(const FailureState &state, TimePoint now,
                             int window_seconds) const {
  return state.locked_until <= now && state.window_start != TimePoint{} &&
         now - state.window_start > std::chrono::seconds(window_seconds);
}

void FailureLimiter::cleanup(TimePoint now, int window_seconds) {
  for (auto iter = failures_.begin(); iter != failures_.end();) {
    if (expired(iter->second, now, window_seconds))
      iter = failures_.erase(iter);
    else
      ++iter;
  }
  if (overflow_active_ && expired(overflow_, now, window_seconds)) {
    overflow_ = FailureState{};
    overflow_active_ = false;
  }
  next_cleanup_ = now + std::chrono::seconds(45);
}

FailureLimiter::Decision FailureLimiter::evaluateState(
    FailureState &state, bool credentials_valid, int max_failures,
    int window_seconds, int lock_seconds, TimePoint now, bool clear_on_success,
    bool *erase) {
  if (state.locked_until > now) {
    const auto retry = std::chrono::duration_cast<std::chrono::seconds>(
                           state.locked_until - now)
                           .count();
    return {Result::Locked, std::max<long long>(1, retry)};
  }
  if (credentials_valid) {
    if (clear_on_success && erase)
      *erase = true;
    return {Result::Allowed, 0};
  }
  if (state.window_start == TimePoint{} ||
      now - state.window_start > std::chrono::seconds(window_seconds)) {
    state = FailureState{};
    state.window_start = now;
  }
  ++state.failures;
  if (state.failures >= max_failures) {
    state.locked_until = now + std::chrono::seconds(lock_seconds);
    return {Result::Locked, lock_seconds};
  }
  return {Result::Unauthorized, 0};
}

FailureLimiter::Decision FailureLimiter::evaluate(
    const client_ip::Address &key, bool credentials_valid, int max_failures,
    int window_seconds, int lock_seconds, TimePoint now) {
  std::lock_guard<std::mutex> lock(mutex_);
  max_failures = std::max(1, max_failures);
  window_seconds = std::max(1, window_seconds);
  lock_seconds = std::max(1, lock_seconds);
  if (next_cleanup_ == TimePoint{} || now >= next_cleanup_ ||
      failures_.size() >= capacity_)
    cleanup(now, window_seconds);

  auto iter = failures_.find(key);
  if (iter != failures_.end()) {
    bool erase = false;
    Decision decision = evaluateState(iter->second, credentials_valid,
                                      max_failures, window_seconds, lock_seconds,
                                      now, true, &erase);
    if (erase)
      failures_.erase(iter);
    return decision;
  }

  if (failures_.size() < capacity_) {
    if (credentials_valid)
      return {Result::Allowed, 0};
    auto inserted = failures_.emplace(key, FailureState{});
    return evaluateState(inserted.first->second, false, max_failures,
                         window_seconds, lock_seconds, now, true, nullptr);
  }

  if (!overflow_active_) {
    overflow_ = FailureState{};
    overflow_active_ = true;
  }
  return evaluateState(overflow_, credentials_valid, max_failures,
                       window_seconds, lock_seconds, now, false, nullptr);
}

#ifdef DASHBOARD_AUTH_LIMITER_TESTING
std::size_t FailureLimiter::bucketCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return failures_.size();
}

bool FailureLimiter::overflowActive() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return overflow_active_;
}
#endif

} // namespace dashboard_auth
