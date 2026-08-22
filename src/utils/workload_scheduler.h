#ifndef WORKLOAD_SCHEDULER_H_INCLUDED
#define WORKLOAD_SCHEDULER_H_INCLUDED

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "server/request_context.h"

enum class SchedulerSubmitStatus {
  Accepted,
  EntryLimit,
  ByteLimit,
  Deadline,
  Cancelled,
  Stopping,
};

class SchedulerSubmitError : public std::runtime_error {
public:
  explicit SchedulerSubmitError(SchedulerSubmitStatus status)
      : std::runtime_error(message(status)), status_(status) {}

  SchedulerSubmitStatus status() const noexcept { return status_; }

private:
  static const char *message(SchedulerSubmitStatus status) noexcept {
    switch (status) {
    case SchedulerSubmitStatus::EntryLimit:
      return "workload scheduler entry limit reached";
    case SchedulerSubmitStatus::ByteLimit:
      return "workload scheduler byte limit reached";
    case SchedulerSubmitStatus::Deadline:
      return "workload scheduler deadline exceeded";
    case SchedulerSubmitStatus::Cancelled:
      return "workload scheduler request cancelled";
    case SchedulerSubmitStatus::Stopping:
      return "workload scheduler is stopping";
    case SchedulerSubmitStatus::Accepted:
      break;
    }
    return "workload scheduler submission error";
  }

  SchedulerSubmitStatus status_;
};

template <class Result> struct SchedulerSubmission {
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Stopping;
  std::future<Result> future;
};

template <class Result> struct SchedulerAsyncResult {
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Stopping;
  std::exception_ptr error;
  std::optional<Result> value;
};

struct WorkloadSchedulerSnapshot {
  uint64_t queued_entries = 0;
  uint64_t queued_bytes = 0;
  uint64_t active = 0;
  uint64_t accepted = 0;
  uint64_t rejected = 0;
  uint64_t cancelled = 0;
  uint64_t oldest_queued_age_ms = 0;
};

class WorkloadScheduler {
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
  };

  template <class Function, class Result> struct Task final : TaskBase {
    explicit Task(Function &&function) : function(std::move(function)) {}

    std::future<Result> getFuture() { return promise.get_future(); }

    void run() noexcept override {
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
      try {
        promise.set_exception(
            std::make_exception_ptr(SchedulerSubmitError(status)));
      } catch (...) {
      }
    }

    Function function;
    std::promise<Result> promise;
  };

  template <class Function, class Completion, class Result>
  struct CallbackTask final : TaskBase {
    CallbackTask(Function &&function, Completion &&completion)
        : function(std::move(function)), completion(std::move(completion)) {}

    void run() noexcept override {
      SchedulerAsyncResult<Result> result;
      result.status = SchedulerSubmitStatus::Accepted;
      try {
        result.value.emplace(function());
      } catch (...) {
        result.error = std::current_exception();
      }
      complete(std::move(result));
    }

    void cancel(SchedulerSubmitStatus status) noexcept override {
      SchedulerAsyncResult<Result> result;
      result.status = status;
      try {
        result.error =
            std::make_exception_ptr(SchedulerSubmitError(status));
      } catch (...) {
        result.error = std::current_exception();
      }
      complete(std::move(result));
    }

    void complete(SchedulerAsyncResult<Result> result) noexcept {
      if (completed.exchange(true, std::memory_order_acq_rel))
        return;
      try {
        completion(std::move(result));
      } catch (...) {
      }
    }

    Function function;
    Completion completion;
    std::atomic<bool> completed{false};
  };

public:
  WorkloadScheduler(std::size_t worker_count, std::size_t max_entries,
                    uint64_t max_bytes)
      : max_entries_(max_entries ? max_entries : 1),
        max_bytes_(max_bytes ? max_bytes : 1) {
    if (worker_count == 0)
      throw std::invalid_argument(
          "WorkloadScheduler requires at least one worker");
    workers_.reserve(worker_count);
    for (std::size_t index = 0; index < worker_count; ++index) {
      try {
        workers_.emplace_back([this] { workerLoop(); });
      } catch (...) {
        if (workers_.empty())
          throw;
        break;
      }
    }
  }

  ~WorkloadScheduler() { shutdown(true); }

  WorkloadScheduler(const WorkloadScheduler &) = delete;
  WorkloadScheduler &operator=(const WorkloadScheduler &) = delete;

  template <class Function>
  auto submit(RequestCostClass cost, uint64_t bytes,
              Clock::time_point deadline,
              RequestCancellationToken cancellation, Function &&function)
      -> SchedulerSubmission<std::invoke_result_t<std::decay_t<Function>>> {
    using StoredFunction = std::decay_t<Function>;
    using Result = std::invoke_result_t<StoredFunction>;
    using StoredTask = Task<StoredFunction, Result>;

    auto task = std::make_shared<StoredTask>(
        StoredFunction(std::forward<Function>(function)));
    std::future<Result> future = task->getFuture();
    task->cost = normalizedCost(cost);
    task->bytes = bytes;
    task->enqueued_at = Clock::now();
    task->deadline = deadline;
    task->cancellation = std::move(cancellation);

    SchedulerSubmitStatus status = SchedulerSubmitStatus::Accepted;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_) {
        status = SchedulerSubmitStatus::Stopping;
      } else if (task->cancellation.isCancellationRequested()) {
        status = SchedulerSubmitStatus::Cancelled;
      } else if (deadline != Clock::time_point::max() &&
                 task->enqueued_at >= deadline) {
        status = SchedulerSubmitStatus::Deadline;
      } else if (queued_entries_ >= max_entries_) {
        status = SchedulerSubmitStatus::EntryLimit;
      } else if (bytes > max_bytes_ || queued_bytes_ > max_bytes_ - bytes) {
        status = SchedulerSubmitStatus::ByteLimit;
      } else {
        queues_[queueIndex(task->cost)].emplace_back(task);
        ++queued_entries_;
        queued_bytes_ += bytes;
        ++accepted_;
      }
      if (status != SchedulerSubmitStatus::Accepted)
        ++rejected_;
    }

    if (status == SchedulerSubmitStatus::Accepted) {
      condition_.notify_one();
      return {status, std::move(future)};
    }
    task->cancel(status);
    return {status, std::move(future)};
  }

  template <class Function, class Completion>
  auto submitAsync(RequestCostClass cost, uint64_t bytes,
                   Clock::time_point deadline,
                   RequestCancellationToken cancellation, Function &&function,
                   Completion &&completion) -> SchedulerSubmitStatus {
    using StoredFunction = std::decay_t<Function>;
    using StoredCompletion = std::decay_t<Completion>;
    using Result = std::invoke_result_t<StoredFunction>;
    static_assert(!std::is_void_v<Result>,
                  "WorkloadScheduler async tasks require a result");
    using StoredTask =
        CallbackTask<StoredFunction, StoredCompletion, Result>;

    auto task = std::make_shared<StoredTask>(
        StoredFunction(std::forward<Function>(function)),
        StoredCompletion(std::forward<Completion>(completion)));
    task->cost = normalizedCost(cost);
    task->bytes = bytes;
    task->enqueued_at = Clock::now();
    task->deadline = deadline;
    task->cancellation = std::move(cancellation);

    SchedulerSubmitStatus status = SchedulerSubmitStatus::Accepted;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_) {
        status = SchedulerSubmitStatus::Stopping;
      } else if (task->cancellation.isCancellationRequested()) {
        status = SchedulerSubmitStatus::Cancelled;
      } else if (deadline != Clock::time_point::max() &&
                 task->enqueued_at >= deadline) {
        status = SchedulerSubmitStatus::Deadline;
      } else if (queued_entries_ >= max_entries_) {
        status = SchedulerSubmitStatus::EntryLimit;
      } else if (bytes > max_bytes_ || queued_bytes_ > max_bytes_ - bytes) {
        status = SchedulerSubmitStatus::ByteLimit;
      } else {
        queues_[queueIndex(task->cost)].emplace_back(task);
        ++queued_entries_;
        queued_bytes_ += bytes;
        ++accepted_;
      }
      if (status != SchedulerSubmitStatus::Accepted)
        ++rejected_;
    }

    if (status == SchedulerSubmitStatus::Accepted) {
      condition_.notify_one();
    } else {
      task->cancel(status);
    }
    return status;
  }

  void shutdown(bool cancel_pending) noexcept {
    requestShutdown(cancel_pending);
    (void)join();
  }

  void requestShutdown(bool cancel_pending) noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return;
      stopping_ = true;
      if (cancel_pending) {
        cancelled_ += queued_entries_;
        queued_entries_ = 0;
        queued_bytes_ = 0;
      }
    }
    if (cancel_pending) {
      for (;;) {
        std::shared_ptr<TaskBase> task;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          for (auto &queue : queues_) {
            if (queue.empty())
              continue;
            task = std::move(queue.front());
            queue.pop_front();
            break;
          }
        }
        if (!task)
          break;
        task->cancel(SchedulerSubmitStatus::Stopping);
      }
    }
    condition_.notify_all();
  }

  bool join() noexcept {
    if (isCurrentWorkerThread())
      return false;
    for (std::thread &worker : workers_) {
      if (!worker.joinable())
        continue;
      try {
        worker.join();
      } catch (...) {
        return false;
      }
    }
    return true;
  }

  bool isCurrentWorkerThread() const noexcept {
    return current_worker_scheduler_ == this;
  }

  WorkloadSchedulerSnapshot snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Clock::time_point oldest = Clock::time_point::max();
    for (const auto &queue : queues_) {
      if (!queue.empty())
        oldest = std::min(oldest, queue.front()->enqueued_at);
    }
    const uint64_t oldest_age_ms =
        oldest == Clock::time_point::max()
            ? 0
            : static_cast<uint64_t>(std::max<int64_t>(
                  0, std::chrono::duration_cast<std::chrono::milliseconds>(
                         Clock::now() - oldest)
                         .count()));
    return {queued_entries_, queued_bytes_, active_, accepted_, rejected_,
            cancelled_, oldest_age_ms};
  }

  std::size_t workerCount() const noexcept { return workers_.size(); }
  std::size_t maxEntries() const noexcept { return max_entries_; }
  uint64_t maxBytes() const noexcept { return max_bytes_; }

private:
  static RequestCostClass normalizedCost(RequestCostClass cost) noexcept {
    switch (cost) {
    case RequestCostClass::Low:
    case RequestCostClass::Medium:
    case RequestCostClass::High:
      return cost;
    case RequestCostClass::Unclassified:
    case RequestCostClass::Count:
      return RequestCostClass::Medium;
    }
    return RequestCostClass::Medium;
  }

  static std::size_t queueIndex(RequestCostClass cost) noexcept {
    switch (cost) {
    case RequestCostClass::Low:
      return 0;
    case RequestCostClass::Medium:
      return 1;
    case RequestCostClass::High:
      return 2;
    case RequestCostClass::Unclassified:
    case RequestCostClass::Count:
      return 1;
    }
    return 1;
  }

  std::shared_ptr<TaskBase> takeTaskLocked() {
    const auto now = Clock::now();
    std::size_t oldest_index = queues_.size();
    Clock::time_point oldest = Clock::time_point::max();
    for (std::size_t index = 0; index < queues_.size(); ++index) {
      if (!queues_[index].empty() &&
          queues_[index].front()->enqueued_at < oldest) {
        oldest = queues_[index].front()->enqueued_at;
        oldest_index = index;
      }
    }
    if (oldest_index < queues_.size() &&
        now - oldest >= std::chrono::milliseconds(500))
      return popLocked(oldest_index);

    auto activeHasCredit = [this] {
      for (std::size_t index = 0; index < queues_.size(); ++index) {
        if (!queues_[index].empty() && credits_[index] != 0)
          return true;
      }
      return false;
    };
    if (!activeHasCredit()) {
      for (std::size_t index = 0; index < queues_.size(); ++index)
        credits_[index] = queues_[index].empty() ? 0 : kWeights[index];
    }
    for (std::size_t attempts = 0; attempts < queues_.size() * 2;
         ++attempts) {
      const std::size_t index = next_queue_++ % queues_.size();
      if (credits_[index] == 0 || queues_[index].empty())
        continue;
      --credits_[index];
      return popLocked(index);
    }
    if (oldest_index < queues_.size())
      return popLocked(oldest_index);
    return nullptr;
  }

  std::shared_ptr<TaskBase> popLocked(std::size_t index) {
    std::shared_ptr<TaskBase> task = std::move(queues_[index].front());
    queues_[index].pop_front();
    --queued_entries_;
    queued_bytes_ -= task->bytes;
    ++active_;
    return task;
  }

  void workerLoop() {
    struct WorkerScope {
      explicit WorkerScope(WorkloadScheduler *scheduler) noexcept
          : previous(current_worker_scheduler_) {
        current_worker_scheduler_ = scheduler;
      }
      ~WorkerScope() { current_worker_scheduler_ = previous; }
      WorkloadScheduler *previous;
    } worker_scope(this);
    for (;;) {
      std::shared_ptr<TaskBase> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] {
          return stopping_ || queued_entries_ != 0;
        });
        if (stopping_ && queued_entries_ == 0)
          return;
        task = takeTaskLocked();
      }
      if (!task)
        continue;

      SchedulerSubmitStatus cancelled = SchedulerSubmitStatus::Accepted;
      if (task->cancellation.isCancellationRequested())
        cancelled = SchedulerSubmitStatus::Cancelled;
      else if (task->deadline != Clock::time_point::max() &&
               Clock::now() >= task->deadline)
        cancelled = SchedulerSubmitStatus::Deadline;
      if (cancelled == SchedulerSubmitStatus::Accepted) {
        task->run();
      } else {
        task->cancel(cancelled);
        std::lock_guard<std::mutex> lock(mutex_);
        ++cancelled_;
      }
      {
        std::lock_guard<std::mutex> lock(mutex_);
        --active_;
      }
    }
  }

  inline static constexpr std::array<uint8_t, 3> kWeights{8, 4, 1};
  inline static thread_local WorkloadScheduler *current_worker_scheduler_ =
      nullptr;
  const std::size_t max_entries_;
  const uint64_t max_bytes_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::array<std::deque<std::shared_ptr<TaskBase>>, 3> queues_;
  std::vector<std::thread> workers_;
  std::array<uint8_t, 3> credits_ = kWeights;
  std::size_t next_queue_ = 0;
  uint64_t queued_entries_ = 0;
  uint64_t queued_bytes_ = 0;
  uint64_t active_ = 0;
  uint64_t accepted_ = 0;
  uint64_t rejected_ = 0;
  uint64_t cancelled_ = 0;
  bool stopping_ = false;
};

#endif // WORKLOAD_SCHEDULER_H_INCLUDED
