#ifndef REQUEST_CONTEXT_H_INCLUDED
#define REQUEST_CONTEXT_H_INCLUDED

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

enum class RequestCostClass : uint8_t {
  Unclassified,
  Low,
  Medium,
  High,
  Count,
};

enum class RequestStage : uint8_t {
  Admission,
  Queue,
  Fetch,
  Parse,
  Template,
  Rules,
  Serialize,
  Send,
  Count,
};

enum class RequestTerminalState : uint8_t {
  None,
  Completed,
  Rejected,
  Cancelled,
  DeadlineExceeded,
  Failed,
  Count,
};

enum class RequestFailureAttribution : uint8_t {
  None,
  Server,
  Upstream,
  User,
  Client,
  Capacity,
  Count,
};

enum class RequestSingleflightRole : uint8_t {
  None,
  Owner,
  Follower,
};

enum class RequestCancellationReason : uint8_t {
  None,
  ClientDisconnected,
  Deadline,
  Shutdown,
  NoConsumers,
};

inline constexpr std::size_t kRequestStageCount =
    static_cast<std::size_t>(RequestStage::Count);
inline constexpr std::size_t kRequestTerminalStateCount =
    static_cast<std::size_t>(RequestTerminalState::Count);
inline constexpr std::size_t kRequestFailureAttributionCount =
    static_cast<std::size_t>(RequestFailureAttribution::Count);

inline const char *requestCostClassName(RequestCostClass value) noexcept {
  switch (value) {
  case RequestCostClass::Unclassified:
    return "unclassified";
  case RequestCostClass::Low:
    return "low";
  case RequestCostClass::Medium:
    return "medium";
  case RequestCostClass::High:
    return "high";
  case RequestCostClass::Count:
    break;
  }
  return "invalid";
}

inline const char *requestStageName(RequestStage value) noexcept {
  switch (value) {
  case RequestStage::Admission:
    return "admission";
  case RequestStage::Queue:
    return "queue";
  case RequestStage::Fetch:
    return "fetch";
  case RequestStage::Parse:
    return "parse";
  case RequestStage::Template:
    return "template";
  case RequestStage::Rules:
    return "rules";
  case RequestStage::Serialize:
    return "serialize";
  case RequestStage::Send:
    return "send";
  case RequestStage::Count:
    break;
  }
  return "invalid";
}

inline const char *requestTerminalStateName(
    RequestTerminalState value) noexcept {
  switch (value) {
  case RequestTerminalState::None:
    return "none";
  case RequestTerminalState::Completed:
    return "completed";
  case RequestTerminalState::Rejected:
    return "rejected";
  case RequestTerminalState::Cancelled:
    return "cancelled";
  case RequestTerminalState::DeadlineExceeded:
    return "deadline_exceeded";
  case RequestTerminalState::Failed:
    return "failed";
  case RequestTerminalState::Count:
    break;
  }
  return "invalid";
}

inline const char *requestFailureAttributionName(
    RequestFailureAttribution value) noexcept {
  switch (value) {
  case RequestFailureAttribution::None:
    return "none";
  case RequestFailureAttribution::Server:
    return "server";
  case RequestFailureAttribution::Upstream:
    return "upstream";
  case RequestFailureAttribution::User:
    return "user";
  case RequestFailureAttribution::Client:
    return "client";
  case RequestFailureAttribution::Capacity:
    return "capacity";
  case RequestFailureAttribution::Count:
    break;
  }
  return "invalid";
}

inline const char *requestSingleflightRoleName(
    RequestSingleflightRole value) noexcept {
  switch (value) {
  case RequestSingleflightRole::None:
    return "none";
  case RequestSingleflightRole::Owner:
    return "owner";
  case RequestSingleflightRole::Follower:
    return "follower";
  }
  return "invalid";
}

struct RequestCancellationState {
  std::atomic<RequestCancellationReason> reason{RequestCancellationReason::None};
};

class RequestCancellationToken {
public:
  RequestCancellationToken() = default;

  bool valid() const noexcept { return static_cast<bool>(state_); }

  bool isCancellationRequested() const noexcept {
    return reason() != RequestCancellationReason::None;
  }

  RequestCancellationReason reason() const noexcept {
    return state_ ? state_->reason.load(std::memory_order_acquire)
                  : RequestCancellationReason::None;
  }

private:
  explicit RequestCancellationToken(
      std::shared_ptr<RequestCancellationState> state)
      : state_(std::move(state)) {}

  std::shared_ptr<RequestCancellationState> state_;
  friend class RequestCancellationSource;
};

class RequestCancellationSource {
public:
  RequestCancellationSource()
      : state_(std::make_shared<RequestCancellationState>()) {}

  RequestCancellationToken token() const {
    return RequestCancellationToken(state_);
  }

  bool cancel(RequestCancellationReason reason) noexcept {
    if (reason == RequestCancellationReason::None)
      return false;
    RequestCancellationReason expected = RequestCancellationReason::None;
    return state_->reason.compare_exchange_strong(
        expected, reason, std::memory_order_acq_rel, std::memory_order_acquire);
  }

private:
  std::shared_ptr<RequestCancellationState> state_;
};

struct RequestLifecycleMetricsSnapshot {
  std::array<uint64_t, kRequestTerminalStateCount> terminal{};
  std::array<uint64_t, kRequestFailureAttributionCount> failure{};
  std::array<uint64_t, kRequestStageCount> stage_nanoseconds{};
  std::array<uint64_t, kRequestStageCount> stage_samples{};
};

namespace request_lifecycle_metrics {
inline std::array<std::atomic<uint64_t>, kRequestTerminalStateCount>
    terminal_counts{};
inline std::array<std::atomic<uint64_t>, kRequestFailureAttributionCount>
    failure_counts{};
inline std::array<std::atomic<uint64_t>, kRequestStageCount>
    stage_nanoseconds{};
inline std::array<std::atomic<uint64_t>, kRequestStageCount> stage_samples{};
} // namespace request_lifecycle_metrics

inline RequestLifecycleMetricsSnapshot requestLifecycleMetricsSnapshot() {
  RequestLifecycleMetricsSnapshot result;
  for (std::size_t index = 0; index < result.terminal.size(); ++index)
    result.terminal[index] = request_lifecycle_metrics::terminal_counts[index]
                                 .load(std::memory_order_relaxed);
  for (std::size_t index = 0; index < result.failure.size(); ++index)
    result.failure[index] = request_lifecycle_metrics::failure_counts[index]
                                .load(std::memory_order_relaxed);
  for (std::size_t index = 0; index < result.stage_nanoseconds.size(); ++index) {
    result.stage_nanoseconds[index] =
        request_lifecycle_metrics::stage_nanoseconds[index].load(
            std::memory_order_relaxed);
    result.stage_samples[index] = request_lifecycle_metrics::stage_samples[index]
                                      .load(std::memory_order_relaxed);
  }
  return result;
}

inline void resetRequestLifecycleMetricsForTests() noexcept {
  for (auto &value : request_lifecycle_metrics::terminal_counts)
    value.store(0, std::memory_order_relaxed);
  for (auto &value : request_lifecycle_metrics::failure_counts)
    value.store(0, std::memory_order_relaxed);
  for (auto &value : request_lifecycle_metrics::stage_nanoseconds)
    value.store(0, std::memory_order_relaxed);
  for (auto &value : request_lifecycle_metrics::stage_samples)
    value.store(0, std::memory_order_relaxed);
}

class RequestContext {
public:
  using Clock = std::chrono::steady_clock;

  RequestContext(std::string request_id, Clock::time_point received_at,
                 Clock::time_point deadline = Clock::time_point::max())
      : request_id_(std::move(request_id)), received_at_(received_at),
        deadline_(deadline) {
    for (auto &value : stage_nanoseconds_)
      value.store(0, std::memory_order_relaxed);
  }

  const std::string &requestId() const noexcept { return request_id_; }
  Clock::time_point receivedAt() const noexcept { return received_at_; }
  Clock::time_point deadline() const noexcept { return deadline_; }

  bool deadlineExceeded(Clock::time_point now = Clock::now()) const noexcept {
    return deadline_ != Clock::time_point::max() && now >= deadline_;
  }

  RequestCancellationToken cancellationToken() const {
    return cancellation_source_.token();
  }

  bool requestCancellation(RequestCancellationReason reason) noexcept {
    return cancellation_source_.cancel(reason);
  }

  void setCostClass(RequestCostClass value) noexcept {
    if (value != RequestCostClass::Count)
      cost_class_.store(value, std::memory_order_release);
  }

  RequestCostClass costClass() const noexcept {
    return cost_class_.load(std::memory_order_acquire);
  }

  void setEstimatedBytes(uint64_t value) noexcept {
    estimated_bytes_.store(value, std::memory_order_release);
  }

  uint64_t estimatedBytes() const noexcept {
    return estimated_bytes_.load(std::memory_order_acquire);
  }

  void setSingleflightRole(RequestSingleflightRole value) noexcept {
    singleflight_role_.store(value, std::memory_order_release);
  }

  RequestSingleflightRole singleflightRole() const noexcept {
    return singleflight_role_.load(std::memory_order_acquire);
  }

  bool addConsumer() noexcept {
    uint32_t current = consumers_.load(std::memory_order_acquire);
    while (current != 0) {
      if (consumers_.compare_exchange_weak(current, current + 1,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire))
        return true;
    }
    return false;
  }

  uint32_t releaseConsumer() noexcept {
    uint32_t current = consumers_.load(std::memory_order_acquire);
    while (current != 0) {
      if (consumers_.compare_exchange_weak(current, current - 1,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire))
        return current - 1;
    }
    return 0;
  }

  void setConsumerCount(uint32_t value) noexcept {
    consumers_.store(value, std::memory_order_release);
  }

  uint32_t consumerCount() const noexcept {
    return consumers_.load(std::memory_order_acquire);
  }

  void suggestFailure(RequestFailureAttribution value) noexcept {
    if (value == RequestFailureAttribution::None ||
        value == RequestFailureAttribution::Count)
      return;
    RequestFailureAttribution expected = RequestFailureAttribution::None;
    suggested_failure_.compare_exchange_strong(
        expected, value, std::memory_order_acq_rel, std::memory_order_acquire);
  }

  RequestFailureAttribution suggestedFailure() const noexcept {
    return suggested_failure_.load(std::memory_order_acquire);
  }

  void setCurrentStage(RequestStage stage) noexcept {
    if (stage != RequestStage::Count)
      current_stage_.store(stage, std::memory_order_release);
  }

  RequestStage currentStage() const noexcept {
    return current_stage_.load(std::memory_order_acquire);
  }

  void addStageDuration(RequestStage stage,
                        Clock::duration duration) noexcept {
    const std::size_t index = static_cast<std::size_t>(stage);
    if (index >= stage_nanoseconds_.size() || duration <= Clock::duration::zero())
      return;
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
    if (nanoseconds <= 0)
      return;
    stage_nanoseconds_[index].fetch_add(static_cast<uint64_t>(nanoseconds),
                                        std::memory_order_relaxed);
  }

  bool recordAdmissionOnce(Clock::time_point finished_at) noexcept {
    bool expected = false;
    if (!admission_recorded_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel,
            std::memory_order_acquire))
      return false;
    addStageDuration(RequestStage::Admission, finished_at - received_at_);
    return true;
  }

  uint64_t stageNanoseconds(RequestStage stage) const noexcept {
    const std::size_t index = static_cast<std::size_t>(stage);
    return index < stage_nanoseconds_.size()
               ? stage_nanoseconds_[index].load(std::memory_order_relaxed)
               : 0;
  }

  bool tryFinish(RequestTerminalState terminal,
                 RequestFailureAttribution failure) noexcept {
    if (terminal == RequestTerminalState::None ||
        terminal == RequestTerminalState::Count ||
        failure == RequestFailureAttribution::Count)
      return false;
    const uint16_t encoded =
        static_cast<uint16_t>(static_cast<uint8_t>(terminal)) |
        static_cast<uint16_t>(static_cast<uint8_t>(failure) << 8);
    uint16_t expected = 0;
    if (!terminal_outcome_.compare_exchange_strong(
            expected, encoded, std::memory_order_acq_rel,
            std::memory_order_acquire))
      return false;

    request_lifecycle_metrics::terminal_counts[static_cast<std::size_t>(
        terminal)]
        .fetch_add(1, std::memory_order_relaxed);
    request_lifecycle_metrics::failure_counts[static_cast<std::size_t>(failure)]
        .fetch_add(1, std::memory_order_relaxed);
    for (std::size_t index = 0; index < stage_nanoseconds_.size(); ++index) {
      const uint64_t duration =
          stage_nanoseconds_[index].load(std::memory_order_relaxed);
      if (duration == 0)
        continue;
      request_lifecycle_metrics::stage_nanoseconds[index].fetch_add(
          duration, std::memory_order_relaxed);
      request_lifecycle_metrics::stage_samples[index].fetch_add(
          1, std::memory_order_relaxed);
    }
    return true;
  }

  bool finalizeResponse(int status_code, bool response_sent) noexcept {
    RequestTerminalState terminal = RequestTerminalState::Completed;
    RequestFailureAttribution failure = suggestedFailure();
    const RequestCancellationReason cancellation =
        cancellationToken().reason();
    if (!response_sent) {
      requestCancellation(RequestCancellationReason::ClientDisconnected);
      terminal = RequestTerminalState::Cancelled;
      failure = RequestFailureAttribution::Client;
    } else if (cancellation == RequestCancellationReason::Deadline ||
               deadlineExceeded()) {
      requestCancellation(RequestCancellationReason::Deadline);
      terminal = RequestTerminalState::DeadlineExceeded;
      if (failure == RequestFailureAttribution::None)
        failure = RequestFailureAttribution::Client;
    } else if (cancellation != RequestCancellationReason::None) {
      terminal = RequestTerminalState::Cancelled;
      if (failure == RequestFailureAttribution::None)
        failure = cancellation == RequestCancellationReason::Shutdown
                      ? RequestFailureAttribution::Server
                      : RequestFailureAttribution::Client;
    } else if (failure == RequestFailureAttribution::Capacity) {
      terminal = RequestTerminalState::Rejected;
    } else if (failure == RequestFailureAttribution::Client) {
      terminal = RequestTerminalState::Cancelled;
    } else if (status_code >= 500) {
      terminal = RequestTerminalState::Failed;
      if (failure == RequestFailureAttribution::None)
        failure = RequestFailureAttribution::Server;
    } else if (status_code >= 400 &&
               failure == RequestFailureAttribution::None) {
      failure = RequestFailureAttribution::User;
    }
    return tryFinish(terminal, failure);
  }

  RequestTerminalState terminalState() const noexcept {
    return static_cast<RequestTerminalState>(
        terminal_outcome_.load(std::memory_order_acquire) & 0xff);
  }

  RequestFailureAttribution failureAttribution() const noexcept {
    return static_cast<RequestFailureAttribution>(
        (terminal_outcome_.load(std::memory_order_acquire) >> 8) & 0xff);
  }

private:
  const std::string request_id_;
  const Clock::time_point received_at_;
  const Clock::time_point deadline_;
  RequestCancellationSource cancellation_source_;
  std::atomic<RequestCostClass> cost_class_{RequestCostClass::Unclassified};
  std::atomic<uint64_t> estimated_bytes_{0};
  std::atomic<RequestSingleflightRole> singleflight_role_{
      RequestSingleflightRole::None};
  std::atomic<uint32_t> consumers_{1};
  std::atomic<RequestFailureAttribution> suggested_failure_{
      RequestFailureAttribution::None};
  std::atomic<RequestStage> current_stage_{RequestStage::Admission};
  std::array<std::atomic<uint64_t>, kRequestStageCount> stage_nanoseconds_{};
  std::atomic<bool> admission_recorded_{false};
  std::atomic<uint16_t> terminal_outcome_{0};
};

inline thread_local std::shared_ptr<RequestContext> active_request_context;

inline std::shared_ptr<RequestContext> captureCurrentRequestContext() {
  return active_request_context;
}

class ScopedRequestContext {
public:
  explicit ScopedRequestContext(std::shared_ptr<RequestContext> context)
      : previous_(std::move(active_request_context)) {
    active_request_context = std::move(context);
  }

  ~ScopedRequestContext() { active_request_context = std::move(previous_); }

  ScopedRequestContext(const ScopedRequestContext &) = delete;
  ScopedRequestContext &operator=(const ScopedRequestContext &) = delete;

private:
  std::shared_ptr<RequestContext> previous_;
};

class RequestStageTimer {
public:
  explicit RequestStageTimer(RequestStage stage)
      : RequestStageTimer(captureCurrentRequestContext(), stage) {}

  RequestStageTimer(std::shared_ptr<RequestContext> context, RequestStage stage)
      : context_(std::move(context)), stage_(stage), started_at_(Clock::now()) {
    if (context_)
      context_->setCurrentStage(stage_);
  }

  ~RequestStageTimer() { stop(); }

  RequestStageTimer(RequestStageTimer &&other) noexcept
      : context_(std::move(other.context_)), stage_(other.stage_),
        started_at_(other.started_at_), stopped_(other.stopped_) {
    other.stopped_ = true;
  }

  RequestStageTimer(const RequestStageTimer &) = delete;
  RequestStageTimer &operator=(const RequestStageTimer &) = delete;

  void stop() noexcept {
    if (stopped_)
      return;
    stopped_ = true;
    if (context_)
      context_->addStageDuration(stage_, Clock::now() - started_at_);
  }

private:
  using Clock = RequestContext::Clock;
  std::shared_ptr<RequestContext> context_;
  RequestStage stage_;
  Clock::time_point started_at_;
  bool stopped_ = false;
};

#endif // REQUEST_CONTEXT_H_INCLUDED
