#ifndef COMPUTE_EXECUTOR_H_INCLUDED
#define COMPUTE_EXECUTOR_H_INCLUDED

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "server/request_context.h"
#include "utils/workload_scheduler.h"

struct ComputeExecutorBudget {
  uint64_t workers = 1;
  uint64_t max_queue_entries = 1;
  uint64_t max_queue_bytes = 1;
  uint64_t max_control_entries = 0;

  bool operator==(const ComputeExecutorBudget &) const = default;
};

struct ComputeTaskOptions {
  RequestCostClass cost = RequestCostClass::Medium;
  uint64_t bytes = 0;
  std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::time_point::max();
  RequestCancellationToken cancellation;
  std::optional<std::size_t> preferred_worker;
  bool control = false;
};

struct ComputeWorkerSnapshot {
  uint64_t executed = 0;
  uint64_t cancelled = 0;
  uint64_t busy_nanoseconds = 0;
  uint64_t affinity_hits = 0;
};

struct ComputeExecutorSnapshot {
  bool initialized = false;
  bool ready = false;
  bool stopping = false;
  uint64_t workers = 0;
  uint64_t ready_workers = 0;
  uint64_t active_workers = 0;
  uint64_t idle_workers = 0;
  uint64_t queued_entries = 0;
  uint64_t queued_bytes = 0;
  uint64_t max_queue_entries = 0;
  uint64_t max_queue_bytes = 0;
  uint64_t control_queued_entries = 0;
  uint64_t max_control_entries = 0;
  uint64_t accepted_total = 0;
  uint64_t rejected_total = 0;
  uint64_t cancelled_total = 0;
  uint64_t deadline_total = 0;
  uint64_t shutdown_total = 0;
  uint64_t oldest_queue_age_ms = 0;
  std::vector<ComputeWorkerSnapshot> worker_metrics;
};

template <class Result> struct ComputeSubmission {
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Stopping;
  std::future<Result> future;
};

class ComputeExecutor {
  using Clock = std::chrono::steady_clock;

  struct TaskBase {
    virtual ~TaskBase() = default;
    virtual void run() noexcept = 0;
    virtual void cancel(SchedulerSubmitStatus status) noexcept = 0;

    RequestCostClass cost = RequestCostClass::Medium;
    uint64_t bytes = 0;
    Clock::time_point enqueued_at;
    Clock::time_point deadline = Clock::time_point::max();
    RequestCancellationToken cancellation;
    std::optional<std::size_t> preferred_worker;
    bool control = false;
  };

  template <class Function, class Result> struct FutureTask final : TaskBase {
    explicit FutureTask(Function &&function) : function(std::move(function)) {}

    std::future<Result> getFuture() { return promise.get_future(); }

    void run() noexcept override {
      if (completed.exchange(true, std::memory_order_acq_rel))
        return;
      try {
        if constexpr (std::is_void_v<Result>) {
          function();
          promise.set_value();
        } else {
          promise.set_value(function());
        }
      } catch (...) {
        try {
          promise.set_exception(std::current_exception());
        } catch (...) {
        }
      }
    }

    void cancel(SchedulerSubmitStatus status) noexcept override {
      if (completed.exchange(true, std::memory_order_acq_rel))
        return;
      try {
        promise.set_exception(
            std::make_exception_ptr(SchedulerSubmitError(status)));
      } catch (...) {
      }
    }

    Function function;
    std::promise<Result> promise;
    std::atomic<bool> completed{false};
  };

  struct ContinuationTask final : TaskBase {
    ContinuationTask(std::function<void()> function,
                     std::function<void(SchedulerSubmitStatus,
                                        std::exception_ptr)> completion)
        : function(std::move(function)), completion(std::move(completion)) {}

    void run() noexcept override;
    void cancel(SchedulerSubmitStatus status) noexcept override;

    std::function<void()> function;
    std::function<void(SchedulerSubmitStatus, std::exception_ptr)> completion;
    std::atomic<bool> completed{false};
  };

  struct alignas(64) WorkerMetrics {
    std::atomic<uint64_t> executed{0};
    std::atomic<uint64_t> cancelled{0};
    std::atomic<uint64_t> busy_nanoseconds{0};
    std::atomic<uint64_t> affinity_hits{0};
  };

public:
  explicit ComputeExecutor(ComputeExecutorBudget budget);
  ~ComputeExecutor();

  ComputeExecutor(const ComputeExecutor &) = delete;
  ComputeExecutor &operator=(const ComputeExecutor &) = delete;

  template <class Function>
  auto submit(ComputeTaskOptions options, Function &&function)
      -> ComputeSubmission<std::invoke_result_t<std::decay_t<Function>>> {
    using StoredFunction = std::decay_t<Function>;
    using Result = std::invoke_result_t<StoredFunction>;
    auto task = std::make_shared<FutureTask<StoredFunction, Result>>(
        StoredFunction(std::forward<Function>(function)));
    std::future<Result> future = task->getFuture();
    prepareTask(*task, std::move(options));
    const SchedulerSubmitStatus status = enqueue(task);
    if (status != SchedulerSubmitStatus::Accepted)
      task->cancel(status);
    return {status, std::move(future)};
  }

  SchedulerSubmitStatus submitContinuation(
      ComputeTaskOptions options, std::function<void()> continuation,
      std::function<void(SchedulerSubmitStatus, std::exception_ptr)>
          completion = {});

  void requestShutdown(bool cancel_pending) noexcept;
  bool join() noexcept;
  void shutdown(bool cancel_pending) noexcept;
  bool isCurrentWorkerThread() const noexcept;
  bool runOnePendingCooperatively() noexcept;
  bool ready() const noexcept;
  ComputeExecutorSnapshot snapshot() const;

  static std::optional<std::size_t> currentWorkerIndex() noexcept;

private:
  void prepareTask(TaskBase &task, ComputeTaskOptions options) noexcept;
  SchedulerSubmitStatus enqueue(const std::shared_ptr<TaskBase> &task);
  std::shared_ptr<TaskBase> takeTaskLocked(std::size_t worker_index,
                                           bool &affinity_hit);
  std::shared_ptr<TaskBase> popLocked(std::size_t queue_index,
                                      std::size_t element_index);
  std::shared_ptr<TaskBase> popControlLocked(std::size_t element_index = 0);
  void executeTask(const std::shared_ptr<TaskBase> &task,
                   std::size_t worker_index, bool affinity_hit,
                   bool cooperative_child) noexcept;
  void workerLoop(std::size_t worker_index) noexcept;
  static RequestCostClass normalizedCost(RequestCostClass cost) noexcept;
  static std::size_t queueIndex(RequestCostClass cost) noexcept;

  inline static constexpr std::array<uint8_t, 3> kWeights{8, 4, 1};
  inline static thread_local const ComputeExecutor *current_executor_ =
      nullptr;
  inline static thread_local std::size_t current_worker_index_ =
      std::numeric_limits<std::size_t>::max();
  inline static thread_local bool cooperative_dispatch_active_ = false;
  inline static thread_local uint64_t cooperative_child_nanoseconds_ = 0;

  const ComputeExecutorBudget budget_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::condition_variable ready_condition_;
  std::array<std::deque<std::shared_ptr<TaskBase>>, 3> queues_;
  std::deque<std::shared_ptr<TaskBase>> control_queue_;
  std::vector<std::thread> workers_;
  std::vector<std::unique_ptr<WorkerMetrics>> worker_metrics_;
  std::array<uint8_t, 3> credits_ = kWeights;
  std::size_t next_queue_ = 0;
  uint64_t ready_workers_ = 0;
  uint64_t queued_entries_ = 0;
  uint64_t queued_bytes_ = 0;
  uint64_t control_queued_entries_ = 0;
  uint64_t active_workers_ = 0;
  uint64_t accepted_total_ = 0;
  uint64_t rejected_total_ = 0;
  uint64_t cancelled_total_ = 0;
  uint64_t deadline_total_ = 0;
  uint64_t shutdown_total_ = 0;
  bool stopping_ = false;
};

enum class GlobalComputeExecutorInitStatus {
  Initialized,
  AlreadyInitialized,
  BudgetMismatch,
  InvalidBudget,
  InitializationFailed,
  Stopping,
};

GlobalComputeExecutorInitStatus initializeGlobalComputeExecutor(
    ComputeExecutorBudget budget) noexcept;
bool publishGlobalComputeExecutor(
    std::unique_ptr<ComputeExecutor> executor,
    ComputeExecutorBudget budget) noexcept;
bool resetGlobalComputeExecutor() noexcept;
ComputeExecutor *globalComputeExecutor() noexcept;
ComputeExecutorSnapshot globalComputeExecutorSnapshot();
void requestGlobalComputeExecutorShutdown(
    bool cancel_pending = true) noexcept;
bool joinGlobalComputeExecutor() noexcept;
bool runOneGlobalComputeTaskCooperatively() noexcept;

#endif // COMPUTE_EXECUTOR_H_INCLUDED
