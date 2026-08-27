#include "runtime/compute_executor.h"

#include <algorithm>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace {

void setComputeThreadName(std::size_t index) noexcept {
  try {
    const std::string name = "sc-compute-" + std::to_string(index);
#ifdef _WIN32
    using SetThreadDescriptionFunction = HRESULT(WINAPI *)(HANDLE, PCWSTR);
    HMODULE kernel = GetModuleHandleW(L"Kernel32.dll");
    if (!kernel)
      return;
    auto set_description = reinterpret_cast<SetThreadDescriptionFunction>(
        GetProcAddress(kernel, "SetThreadDescription"));
    if (!set_description)
      return;
    const std::wstring wide(name.begin(), name.end());
    (void)set_description(GetCurrentThread(), wide.c_str());
#elif defined(__APPLE__)
    (void)pthread_setname_np(name.c_str());
#else
    (void)pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
#endif
  } catch (...) {
  }
}

struct GlobalComputeRuntime {
  std::mutex mutex;
  std::unique_ptr<ComputeExecutor> executor;
  ComputeExecutorBudget budget;
  bool stopping = false;
};

GlobalComputeRuntime global_compute;

} // namespace

void ComputeExecutor::ContinuationTask::run() noexcept {
  if (completed.exchange(true, std::memory_order_acq_rel))
    return;
  std::exception_ptr error;
  try {
    function();
  } catch (...) {
    error = std::current_exception();
  }
  if (!completion)
    return;
  try {
    completion(SchedulerSubmitStatus::Accepted, std::move(error));
  } catch (...) {
  }
}

void ComputeExecutor::ContinuationTask::cancel(
    SchedulerSubmitStatus status) noexcept {
  if (completed.exchange(true, std::memory_order_acq_rel))
    return;
  if (!completion)
    return;
  std::exception_ptr error;
  try {
    error = std::make_exception_ptr(SchedulerSubmitError(status));
  } catch (...) {
    error = std::current_exception();
  }
  try {
    completion(status, std::move(error));
  } catch (...) {
  }
}

ComputeExecutor::ComputeExecutor(ComputeExecutorBudget budget)
    : budget_(budget) {
  if (budget.workers == 0 || budget.max_queue_entries == 0 ||
      budget.max_queue_bytes == 0 ||
      budget.workers > std::numeric_limits<std::size_t>::max())
    throw std::invalid_argument("invalid ComputeExecutor budget");
  const std::size_t worker_count = static_cast<std::size_t>(budget.workers);
  workers_.reserve(worker_count);
  worker_metrics_.reserve(worker_count);
  for (std::size_t index = 0; index < worker_count; ++index)
    worker_metrics_.emplace_back(std::make_unique<WorkerMetrics>());
  try {
    for (std::size_t index = 0; index < worker_count; ++index)
      workers_.emplace_back([this, index] { workerLoop(index); });
  } catch (...) {
    requestShutdown(true);
    (void)join();
    throw;
  }
  std::unique_lock<std::mutex> lock(mutex_);
  ready_condition_.wait(lock, [this, worker_count] {
    return ready_workers_ == worker_count || stopping_;
  });
  if (ready_workers_ != worker_count) {
    lock.unlock();
    requestShutdown(true);
    (void)join();
    throw std::runtime_error("ComputeExecutor workers failed to become ready");
  }
}

ComputeExecutor::~ComputeExecutor() { shutdown(true); }

void ComputeExecutor::prepareTask(TaskBase &task,
                                  ComputeTaskOptions options) noexcept {
  task.cost = normalizedCost(options.cost);
  task.bytes = options.bytes;
  task.enqueued_at = Clock::now();
  task.deadline = options.deadline;
  task.cancellation = std::move(options.cancellation);
  task.control = options.control;
  if (options.preferred_worker &&
      *options.preferred_worker < workers_.size())
    task.preferred_worker = options.preferred_worker;
}

SchedulerSubmitStatus
ComputeExecutor::enqueue(const std::shared_ptr<TaskBase> &task) {
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Accepted;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_) {
      status = SchedulerSubmitStatus::Stopping;
    } else if (task->cancellation.isCancellationRequested()) {
      status = SchedulerSubmitStatus::Cancelled;
    } else if (task->deadline != Clock::time_point::max() &&
               task->enqueued_at >= task->deadline) {
      status = SchedulerSubmitStatus::Deadline;
    } else if (task->control &&
               control_queued_entries_ >=
                   (budget_.max_control_entries != 0
                        ? budget_.max_control_entries
                        : budget_.max_queue_entries)) {
      status = SchedulerSubmitStatus::EntryLimit;
    } else if (!task->control &&
               queued_entries_ - control_queued_entries_ >=
                   budget_.max_queue_entries) {
      status = SchedulerSubmitStatus::EntryLimit;
    } else if (!task->control &&
               (task->bytes > budget_.max_queue_bytes ||
                queued_bytes_ > budget_.max_queue_bytes - task->bytes)) {
      status = SchedulerSubmitStatus::ByteLimit;
    } else {
      if (task->control) {
        control_queue_.emplace_back(task);
        ++control_queued_entries_;
      } else {
        queues_[queueIndex(task->cost)].emplace_back(task);
        queued_bytes_ += task->bytes;
      }
      ++queued_entries_;
      ++accepted_total_;
    }
    if (status != SchedulerSubmitStatus::Accepted)
      ++rejected_total_;
  }
  if (status == SchedulerSubmitStatus::Accepted)
    condition_.notify_one();
  return status;
}

SchedulerSubmitStatus ComputeExecutor::submitContinuation(
    ComputeTaskOptions options, std::function<void()> continuation,
    std::function<void(SchedulerSubmitStatus, std::exception_ptr)>
        completion) {
  auto task = std::make_shared<ContinuationTask>(
      std::move(continuation), std::move(completion));
  prepareTask(*task, std::move(options));
  const SchedulerSubmitStatus status = enqueue(task);
  if (status != SchedulerSubmitStatus::Accepted)
    task->cancel(status);
  return status;
}

void ComputeExecutor::requestShutdown(bool cancel_pending) noexcept {
  std::vector<std::shared_ptr<TaskBase>> cancelled;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_)
      return;
    stopping_ = true;
    if (cancel_pending) {
      cancelled.reserve(static_cast<std::size_t>(queued_entries_));
      for (auto &queue : queues_) {
        while (!queue.empty()) {
          cancelled.emplace_back(std::move(queue.front()));
          queue.pop_front();
        }
      }
      while (!control_queue_.empty()) {
        cancelled.emplace_back(std::move(control_queue_.front()));
        control_queue_.pop_front();
      }
      cancelled_total_ += queued_entries_;
      queued_entries_ = 0;
      queued_bytes_ = 0;
      control_queued_entries_ = 0;
    }
  }
  for (const auto &task : cancelled)
    task->cancel(SchedulerSubmitStatus::Stopping);
  condition_.notify_all();
  ready_condition_.notify_all();
}

bool ComputeExecutor::join() noexcept {
  if (isCurrentWorkerThread())
    return false;
  for (auto worker = workers_.rbegin(); worker != workers_.rend(); ++worker) {
    if (!worker->joinable())
      continue;
    try {
      worker->join();
    } catch (...) {
      return false;
    }
  }
  return true;
}

void ComputeExecutor::shutdown(bool cancel_pending) noexcept {
  requestShutdown(cancel_pending);
  (void)join();
}

bool ComputeExecutor::isCurrentWorkerThread() const noexcept {
  return current_executor_ == this;
}

bool ComputeExecutor::ready() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return !stopping_ && ready_workers_ == workers_.size();
}

ComputeExecutorSnapshot ComputeExecutor::snapshot() const {
  ComputeExecutorSnapshot result;
  std::lock_guard<std::mutex> lock(mutex_);
  result.initialized = true;
  result.ready = !stopping_ && ready_workers_ == workers_.size();
  result.stopping = stopping_;
  result.workers = workers_.size();
  result.ready_workers = ready_workers_;
  result.active_workers = active_workers_;
  result.idle_workers = workers_.size() > active_workers_
                            ? workers_.size() - active_workers_
                            : 0;
  result.queued_entries = queued_entries_;
  result.queued_bytes = queued_bytes_;
  result.max_queue_entries = budget_.max_queue_entries;
  result.max_queue_bytes = budget_.max_queue_bytes;
  result.control_queued_entries = control_queued_entries_;
  result.max_control_entries =
      budget_.max_control_entries != 0
          ? budget_.max_control_entries
          : budget_.max_queue_entries;
  result.accepted_total = accepted_total_;
  result.rejected_total = rejected_total_;
  result.cancelled_total = cancelled_total_;
  Clock::time_point oldest = Clock::time_point::max();
  for (const auto &queue : queues_) {
    if (!queue.empty())
      oldest = std::min(oldest, queue.front()->enqueued_at);
  }
  if (!control_queue_.empty())
    oldest = std::min(oldest, control_queue_.front()->enqueued_at);
  if (oldest != Clock::time_point::max())
    result.oldest_queue_age_ms = static_cast<uint64_t>(
        std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(
                                 Clock::now() - oldest)
                                 .count()));
  result.worker_metrics.reserve(worker_metrics_.size());
  for (const auto &metrics : worker_metrics_) {
    result.worker_metrics.push_back(
        {metrics->executed.load(std::memory_order_relaxed),
         metrics->cancelled.load(std::memory_order_relaxed),
         metrics->busy_nanoseconds.load(std::memory_order_relaxed),
         metrics->affinity_hits.load(std::memory_order_relaxed)});
  }
  return result;
}

std::optional<std::size_t> ComputeExecutor::currentWorkerIndex() noexcept {
  if (!current_executor_ ||
      current_worker_index_ == std::numeric_limits<std::size_t>::max())
    return std::nullopt;
  return current_worker_index_;
}

RequestCostClass
ComputeExecutor::normalizedCost(RequestCostClass cost) noexcept {
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

std::size_t ComputeExecutor::queueIndex(RequestCostClass cost) noexcept {
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

std::shared_ptr<ComputeExecutor::TaskBase>
ComputeExecutor::popLocked(std::size_t queue_index,
                           std::size_t element_index) {
  auto &queue = queues_[queue_index];
  auto iterator = queue.begin() + static_cast<std::ptrdiff_t>(element_index);
  std::shared_ptr<TaskBase> task = std::move(*iterator);
  queue.erase(iterator);
  --queued_entries_;
  queued_bytes_ -= task->bytes;
  ++active_workers_;
  return task;
}

std::shared_ptr<ComputeExecutor::TaskBase>
ComputeExecutor::popControlLocked(std::size_t element_index) {
  auto iterator = control_queue_.begin() +
      static_cast<std::ptrdiff_t>(element_index);
  std::shared_ptr<TaskBase> task = std::move(*iterator);
  control_queue_.erase(iterator);
  --control_queued_entries_;
  --queued_entries_;
  ++active_workers_;
  return task;
}

std::shared_ptr<ComputeExecutor::TaskBase>
ComputeExecutor::takeTaskLocked(std::size_t worker_index,
                                bool &affinity_hit) {
  affinity_hit = false;
  if (!control_queue_.empty()) {
    const std::size_t scan =
        std::min<std::size_t>(8, control_queue_.size());
    for (std::size_t element = 0; element < scan; ++element) {
      if (control_queue_[element]->preferred_worker == worker_index) {
        affinity_hit = true;
        return popControlLocked(element);
      }
    }
    return popControlLocked();
  }
  const Clock::time_point now = Clock::now();
  std::size_t oldest_queue = queues_.size();
  Clock::time_point oldest = Clock::time_point::max();
  for (std::size_t index = 0; index < queues_.size(); ++index) {
    if (!queues_[index].empty() &&
        queues_[index].front()->enqueued_at < oldest) {
      oldest = queues_[index].front()->enqueued_at;
      oldest_queue = index;
    }
  }
  if (oldest_queue < queues_.size() &&
      now - oldest >= std::chrono::milliseconds(500))
    return popLocked(oldest_queue, 0);

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
    const std::size_t queue_index = next_queue_++ % queues_.size();
    auto &queue = queues_[queue_index];
    if (credits_[queue_index] == 0 || queue.empty())
      continue;
    --credits_[queue_index];
    const std::size_t scan = std::min<std::size_t>(8, queue.size());
    for (std::size_t element = 0; element < scan; ++element) {
      if (queue[element]->preferred_worker == worker_index) {
        affinity_hit = true;
        return popLocked(queue_index, element);
      }
    }
    return popLocked(queue_index, 0);
  }
  return oldest_queue < queues_.size() ? popLocked(oldest_queue, 0)
                                        : nullptr;
}

void ComputeExecutor::workerLoop(std::size_t worker_index) noexcept {
  const ComputeExecutor *previous_executor = current_executor_;
  const std::size_t previous_index = current_worker_index_;
  current_executor_ = this;
  current_worker_index_ = worker_index;
  setComputeThreadName(worker_index);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    ++ready_workers_;
  }
  ready_condition_.notify_all();

  for (;;) {
    std::shared_ptr<TaskBase> task;
    bool affinity_hit = false;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      condition_.wait(lock,
                      [this] { return stopping_ || queued_entries_ != 0; });
      if (stopping_ && queued_entries_ == 0)
        break;
      task = takeTaskLocked(worker_index, affinity_hit);
    }
    if (!task)
      continue;

    executeTask(task, worker_index, affinity_hit, false);
  }

  current_worker_index_ = previous_index;
  current_executor_ = previous_executor;
}

GlobalComputeExecutorInitStatus initializeGlobalComputeExecutor(
    ComputeExecutorBudget budget) noexcept {
  if (budget.workers == 0 || budget.max_queue_entries == 0 ||
      budget.max_queue_bytes == 0)
    return GlobalComputeExecutorInitStatus::InvalidBudget;
  std::lock_guard<std::mutex> lock(global_compute.mutex);
  if (global_compute.stopping)
    return GlobalComputeExecutorInitStatus::Stopping;
  if (global_compute.executor)
    return global_compute.budget == budget
               ? GlobalComputeExecutorInitStatus::AlreadyInitialized
               : GlobalComputeExecutorInitStatus::BudgetMismatch;
  try {
    global_compute.executor = std::make_unique<ComputeExecutor>(budget);
    global_compute.budget = budget;
    return GlobalComputeExecutorInitStatus::Initialized;
  } catch (...) {
    return GlobalComputeExecutorInitStatus::InitializationFailed;
  }
}

void ComputeExecutor::executeTask(const std::shared_ptr<TaskBase> &task,
                                  std::size_t worker_index,
                                  bool affinity_hit,
                                  bool cooperative_child) noexcept {
  if (!task)
    return;
  const Clock::time_point started = Clock::now();
  const uint64_t children_before = cooperative_child_nanoseconds_;
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Accepted;
  if (task->cancellation.isCancellationRequested())
    status = SchedulerSubmitStatus::Cancelled;
  else if (task->deadline != Clock::time_point::max() &&
           started >= task->deadline)
    status = SchedulerSubmitStatus::Deadline;
  if (status == SchedulerSubmitStatus::Accepted) {
    task->run();
    worker_metrics_[worker_index]->executed.fetch_add(
        1, std::memory_order_relaxed);
  } else {
    task->cancel(status);
    worker_metrics_[worker_index]->cancelled.fetch_add(
        1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(mutex_);
    ++cancelled_total_;
  }
  if (affinity_hit)
    worker_metrics_[worker_index]->affinity_hits.fetch_add(
        1, std::memory_order_relaxed);
  const uint64_t elapsed = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - started)
          .count());
  const uint64_t child_time = cooperative_child_nanoseconds_ - children_before;
  worker_metrics_[worker_index]->busy_nanoseconds.fetch_add(
      elapsed >= child_time ? elapsed - child_time : 0,
      std::memory_order_relaxed);
  if (cooperative_child)
    cooperative_child_nanoseconds_ += elapsed;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    --active_workers_;
  }
}

bool ComputeExecutor::runOnePendingCooperatively() noexcept {
  if (current_executor_ != this || cooperative_dispatch_active_ ||
      current_worker_index_ >= workers_.size())
    return false;
  std::shared_ptr<TaskBase> task;
  bool affinity_hit = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queued_entries_ == 0)
      return false;
    task = takeTaskLocked(current_worker_index_, affinity_hit);
  }
  if (!task)
    return false;
  cooperative_dispatch_active_ = true;
  executeTask(task, current_worker_index_, affinity_hit, true);
  cooperative_dispatch_active_ = false;
  return true;
}

bool publishGlobalComputeExecutor(
    std::unique_ptr<ComputeExecutor> executor,
    ComputeExecutorBudget budget) noexcept {
  if (!executor || !executor->ready())
    return false;
  std::lock_guard<std::mutex> lock(global_compute.mutex);
  if (global_compute.stopping || global_compute.executor)
    return false;
  global_compute.budget = budget;
  global_compute.executor = std::move(executor);
  return true;
}

bool resetGlobalComputeExecutor() noexcept {
  std::unique_ptr<ComputeExecutor> retired;
  {
    std::lock_guard<std::mutex> lock(global_compute.mutex);
    if (global_compute.executor &&
        !global_compute.executor->snapshot().stopping)
      return false;
    retired = std::move(global_compute.executor);
    global_compute.budget = {};
    global_compute.stopping = false;
  }
  if (retired && !retired->join())
    return false;
  return true;
}

ComputeExecutor *globalComputeExecutor() noexcept {
  std::lock_guard<std::mutex> lock(global_compute.mutex);
  return global_compute.executor.get();
}

ComputeExecutorSnapshot globalComputeExecutorSnapshot() {
  std::lock_guard<std::mutex> lock(global_compute.mutex);
  return global_compute.executor ? global_compute.executor->snapshot()
                                 : ComputeExecutorSnapshot{};
}

void requestGlobalComputeExecutorShutdown(bool cancel_pending) noexcept {
  ComputeExecutor *executor = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_compute.mutex);
    global_compute.stopping = true;
    executor = global_compute.executor.get();
  }
  if (executor)
    executor->requestShutdown(cancel_pending);
}

bool joinGlobalComputeExecutor() noexcept {
  ComputeExecutor *executor = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_compute.mutex);
    executor = global_compute.executor.get();
  }
  return !executor || executor->join();
}

bool runOneGlobalComputeTaskCooperatively() noexcept {
  ComputeExecutor *executor = globalComputeExecutor();
  return executor && executor->runOnePendingCooperatively();
}
