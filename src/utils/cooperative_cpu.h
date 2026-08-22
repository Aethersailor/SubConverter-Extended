#ifndef COOPERATIVE_CPU_H_INCLUDED
#define COOPERATIVE_CPU_H_INCLUDED

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <type_traits>
#include <utility>

#include "utils/workload_scheduler.h"

struct CpuPermitSnapshot {
  uint64_t limit = 1;
  uint64_t active = 0;
  uint64_t waiting = 0;
};

inline std::size_t cooperativeFlowWorkerCap(
    std::size_t cpu_permits) noexcept {
  if (cpu_permits >= 64)
    return 256;
  return std::min<std::size_t>(
      256, std::max<std::size_t>(
               16, std::max<std::size_t>(1, cpu_permits) * 4));
}

class CpuPermitGate {
public:
  explicit CpuPermitGate(std::size_t limit) : limit_(std::max<size_t>(1, limit)) {}

  CpuPermitGate(const CpuPermitGate &) = delete;
  CpuPermitGate &operator=(const CpuPermitGate &) = delete;

  SchedulerSubmitStatus acquire(
      std::chrono::steady_clock::time_point deadline,
      const RequestCancellationToken &cancellation) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);
    ++waiting_;
    const auto finish = [this](SchedulerSubmitStatus status) {
      --waiting_;
      return status;
    };
    for (;;) {
      if (stopping_)
        return finish(SchedulerSubmitStatus::Stopping);
      if (cancellation.isCancellationRequested())
        return finish(SchedulerSubmitStatus::Cancelled);
      const auto now = std::chrono::steady_clock::now();
      if (deadline != std::chrono::steady_clock::time_point::max() &&
          now >= deadline)
        return finish(SchedulerSubmitStatus::Deadline);
      if (active_ < limit_) {
        ++active_;
        return finish(SchedulerSubmitStatus::Accepted);
      }
      const auto wake_at =
          deadline == std::chrono::steady_clock::time_point::max()
              ? now + std::chrono::milliseconds(25)
              : std::min(deadline, now + std::chrono::milliseconds(25));
      condition_.wait_until(lock, wake_at);
    }
  }

  void release() noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (active_ != 0)
        --active_;
    }
    condition_.notify_one();
  }

  void setLimit(std::size_t limit) noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      limit_ = std::max<std::size_t>(1, limit);
    }
    condition_.notify_all();
  }

  void requestShutdown() noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    condition_.notify_all();
  }

  CpuPermitSnapshot snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return {static_cast<uint64_t>(limit_), active_, waiting_};
  }

private:
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::size_t limit_ = 1;
  uint64_t active_ = 0;
  uint64_t waiting_ = 0;
  bool stopping_ = false;
};

class CpuPermitLease {
public:
  CpuPermitLease(CpuPermitGate &gate,
                 std::chrono::steady_clock::time_point deadline,
                 RequestCancellationToken cancellation)
      : gate_(&gate), deadline_(deadline),
        cancellation_(std::move(cancellation)) {}

  ~CpuPermitLease() { release(); }

  CpuPermitLease(const CpuPermitLease &) = delete;
  CpuPermitLease &operator=(const CpuPermitLease &) = delete;

  SchedulerSubmitStatus acquire() noexcept {
    if (held_)
      return SchedulerSubmitStatus::Accepted;
    auto deadline = deadline_;
    RequestCancellationToken cancellation = cancellation_;
    if (const std::shared_ptr<RequestContext> context =
            captureCurrentRequestContext()) {
      deadline = context->deadline();
      cancellation = context->cancellationToken();
    }
    const SchedulerSubmitStatus status =
        gate_->acquire(deadline, cancellation);
    held_ = status == SchedulerSubmitStatus::Accepted;
    return status;
  }

  void release() noexcept {
    if (!held_)
      return;
    held_ = false;
    gate_->release();
  }

  bool held() const noexcept { return held_; }

private:
  CpuPermitGate *gate_;
  std::chrono::steady_clock::time_point deadline_;
  RequestCancellationToken cancellation_;
  bool held_ = false;
};

inline thread_local CpuPermitLease *current_cpu_permit = nullptr;

class ScopedCpuPermit {
public:
  explicit ScopedCpuPermit(CpuPermitLease &permit) noexcept
      : previous_(current_cpu_permit) {
    current_cpu_permit = &permit;
  }

  ~ScopedCpuPermit() { current_cpu_permit = previous_; }

  ScopedCpuPermit(const ScopedCpuPermit &) = delete;
  ScopedCpuPermit &operator=(const ScopedCpuPermit &) = delete;

private:
  CpuPermitLease *previous_;
};

inline bool cooperativeCpuPermitActive() noexcept {
  return current_cpu_permit != nullptr;
}

class ScopedCpuWait {
public:
  ScopedCpuWait() noexcept : permit_(current_cpu_permit) {
    if (permit_ && permit_->held())
      permit_->release();
    else
      permit_ = nullptr;
  }

  void resumeOrThrow() {
    if (!permit_ || resumed_)
      return;
    resumed_ = true;
    const SchedulerSubmitStatus status = permit_->acquire();
    if (status != SchedulerSubmitStatus::Accepted)
      throw SchedulerSubmitError(status);
  }

  bool resumed() const noexcept { return resumed_; }

private:
  CpuPermitLease *permit_ = nullptr;
  bool resumed_ = false;
};

template <class Function>
auto waitWithoutCpuPermit(Function &&function)
    -> std::invoke_result_t<Function> {
  using Result = std::invoke_result_t<Function>;
  ScopedCpuWait wait;
  if constexpr (std::is_void_v<Result>) {
    try {
      std::invoke(std::forward<Function>(function));
    } catch (...) {
      wait.resumeOrThrow();
      throw;
    }
    wait.resumeOrThrow();
  } else {
    try {
      Result result = std::invoke(std::forward<Function>(function));
      wait.resumeOrThrow();
      return result;
    } catch (...) {
      if (!wait.resumed())
        wait.resumeOrThrow();
      throw;
    }
  }
}

#endif // COOPERATIVE_CPU_H_INCLUDED
