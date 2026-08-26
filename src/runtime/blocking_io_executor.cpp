#include "runtime/blocking_io_executor.h"

#include <memory>
#include <mutex>
#include <utility>

namespace {

struct BlockingIoRuntime {
  std::mutex mutex;
  std::unique_ptr<ComputeExecutor> executor;
  BlockingIoExecutorBudget budget;
  bool stopping = false;
};

BlockingIoRuntime blocking_io;

} // namespace

BlockingIoExecutorInitStatus initializeBlockingIoExecutor(
    BlockingIoExecutorBudget budget) noexcept {
  if (budget.workers == 0 || budget.max_queue_entries == 0 ||
      budget.max_queue_bytes == 0)
    return BlockingIoExecutorInitStatus::InvalidBudget;
  std::lock_guard<std::mutex> lock(blocking_io.mutex);
  if (blocking_io.stopping)
    return BlockingIoExecutorInitStatus::Stopping;
  if (blocking_io.executor)
    return blocking_io.budget == budget
               ? BlockingIoExecutorInitStatus::AlreadyInitialized
               : BlockingIoExecutorInitStatus::BudgetMismatch;
  try {
    blocking_io.executor = std::make_unique<ComputeExecutor>(
        ComputeExecutorBudget{budget.workers, budget.max_queue_entries,
                              budget.max_queue_bytes,
                              budget.max_queue_entries});
    blocking_io.budget = budget;
    return BlockingIoExecutorInitStatus::Initialized;
  } catch (...) {
    blocking_io.executor.reset();
    return BlockingIoExecutorInitStatus::InvalidBudget;
  }
}

SchedulerSubmitStatus submitBlockingIo(
    ComputeTaskOptions options, std::function<void()> work,
    std::function<void(SchedulerSubmitStatus, std::exception_ptr)>
        completion) {
  ComputeExecutor *executor = nullptr;
  {
    std::lock_guard<std::mutex> lock(blocking_io.mutex);
    executor = blocking_io.executor.get();
  }
  if (!executor) {
    if (completion) {
      try {
        completion(SchedulerSubmitStatus::Stopping, {});
      } catch (...) {
      }
    }
    return SchedulerSubmitStatus::Stopping;
  }
  return executor->submitContinuation(
      std::move(options), std::move(work), std::move(completion));
}

ComputeExecutorSnapshot blockingIoExecutorSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(blocking_io.mutex);
  return blocking_io.executor ? blocking_io.executor->snapshot()
                              : ComputeExecutorSnapshot{};
}

void requestBlockingIoExecutorShutdown() noexcept {
  ComputeExecutor *executor = nullptr;
  {
    std::lock_guard<std::mutex> lock(blocking_io.mutex);
    blocking_io.stopping = true;
    executor = blocking_io.executor.get();
  }
  if (executor)
    executor->requestShutdown(true);
}

bool joinBlockingIoExecutor() noexcept {
  ComputeExecutor *executor = nullptr;
  {
    std::lock_guard<std::mutex> lock(blocking_io.mutex);
    executor = blocking_io.executor.get();
  }
  return !executor || executor->join();
}
