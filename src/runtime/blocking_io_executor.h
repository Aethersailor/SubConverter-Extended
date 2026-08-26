#ifndef BLOCKING_IO_EXECUTOR_H_INCLUDED
#define BLOCKING_IO_EXECUTOR_H_INCLUDED

#include <functional>

#include "runtime/compute_executor.h"

struct BlockingIoExecutorBudget {
  uint64_t workers = 0;
  uint64_t max_queue_entries = 0;
  uint64_t max_queue_bytes = 0;

  bool operator==(const BlockingIoExecutorBudget &) const = default;
};

enum class BlockingIoExecutorInitStatus : uint8_t {
  Initialized,
  AlreadyInitialized,
  BudgetMismatch,
  InvalidBudget,
  Stopping,
};

BlockingIoExecutorInitStatus initializeBlockingIoExecutor(
    BlockingIoExecutorBudget budget) noexcept;
SchedulerSubmitStatus submitBlockingIo(
    ComputeTaskOptions options, std::function<void()> work,
    std::function<void(SchedulerSubmitStatus, std::exception_ptr)>
        completion = {});
ComputeExecutorSnapshot blockingIoExecutorSnapshot() noexcept;
void requestBlockingIoExecutorShutdown() noexcept;
bool joinBlockingIoExecutor() noexcept;

#endif // BLOCKING_IO_EXECUTOR_H_INCLUDED
