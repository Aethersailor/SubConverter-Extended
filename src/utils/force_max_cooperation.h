#ifndef FORCE_MAX_COOPERATION_H_INCLUDED
#define FORCE_MAX_COOPERATION_H_INCLUDED

#include <chrono>
#include <cstddef>
#include <thread>

#ifdef NO_WEBGET

class ForceMaxCooperativeBatch {
public:
  explicit ForceMaxCooperativeBatch(bool,
                                    std::size_t = 64) noexcept {}
  void complete(std::size_t = 1) noexcept {}
};

#else

#include "runtime/compute_executor.h"
#include "runtime/owner_admission.h"
#include "server/request_context.h"
#include "utils/cooperative_cpu.h"

// Long, synchronous conversion loops use this force_max-only checkpoint to
// keep admitted owners responsive. A checkpoint may execute one already
// queued continuation inline, but it never submits or waits for child work;
// that keeps a saturated pool making progress without introducing a join
// dependency from one compute task to another.
class ForceMaxCooperativeBatch {
public:
  explicit ForceMaxCooperativeBatch(bool enabled,
                                    std::size_t batch_size = 64) noexcept
      : enabled_(enabled), batch_size_(batch_size ? batch_size : 1) {}

  void complete(std::size_t units = 1) {
    if (!enabled_)
      return;
    completed_ += units;
    if (completed_ < next_checkpoint_)
      return;
    next_checkpoint_ = completed_ + batch_size_;

    const std::shared_ptr<RequestContext> context =
        captureCurrentRequestContext();
    if (context) {
      const RequestCancellationReason reason =
          context->cancellationToken().reason();
      if (reason != RequestCancellationReason::None) {
        throw SchedulerSubmitError(
            reason == RequestCancellationReason::Deadline
                ? SchedulerSubmitStatus::Deadline
                : reason == RequestCancellationReason::Shutdown
                      ? SchedulerSubmitStatus::Stopping
                      : SchedulerSubmitStatus::Cancelled);
      }
      const auto deadline = context->deadline();
      if (deadline != RequestContext::Clock::time_point::max() &&
          RequestContext::Clock::now() >= deadline) {
        context->requestCancellation(RequestCancellationReason::Deadline);
        throw SchedulerSubmitError(SchedulerSubmitStatus::Deadline);
      }
    }

    const OwnerAdmissionSnapshot owners = globalOwnerAdmissionSnapshot();
    const ComputeExecutorSnapshot compute = globalComputeExecutorSnapshot();
    if (owners.waiting_entries == 0 && compute.queued_entries == 0)
      return;

    // A fallback conversion owner may hold a cooperative CPU permit. Release
    // it while yielding so a queued owner can make progress, then reacquire it
    // under the current request deadline/cancellation contract.
    ScopedCpuWait wait;
    if (!runOneGlobalComputeTaskCooperatively())
      std::this_thread::yield();
    wait.resumeOrThrow();
  }

private:
  bool enabled_ = false;
  std::size_t batch_size_ = 64;
  std::size_t completed_ = 0;
  std::size_t next_checkpoint_ = batch_size_;
};

#endif // NO_WEBGET

#endif // FORCE_MAX_COOPERATION_H_INCLUDED
