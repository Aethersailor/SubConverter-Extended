#include "runtime/quickjs_lane.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifndef NO_JS_RUNTIME
#include <quickjs/quickjs.h>
#include <quickjspp.hpp>

#include "script/script_quickjs.h"
#endif

#include "utils/force_max_budget.h"

namespace {

struct GlobalQuickJsLaneRuntime {
  std::mutex mutex;
  std::unique_ptr<QuickJsLane> lane;
  QuickJsLaneBudget budget;
  bool stopping = false;
};

GlobalQuickJsLaneRuntime global_quickjs_lane;

void setQuickJsThreadName(std::size_t index) noexcept {
  try {
    const std::string name = "sc-quickjs-" + std::to_string(index);
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

#ifndef NO_JS_RUNTIME
struct QuickJsInterruptState {
  std::chrono::steady_clock::time_point deadline;
  RequestCancellationToken cancellation;
  const std::atomic<bool> *shutdown = nullptr;
};

std::mutex quickjs_bootstrap_mutex;

int quickJsInterrupt(JSRuntime *, void *opaque) noexcept {
  const auto *state = static_cast<const QuickJsInterruptState *>(opaque);
  if (!state)
    return 1;
  if (state->shutdown &&
      state->shutdown->load(std::memory_order_acquire))
    return 1;
  if (state->cancellation.isCancellationRequested())
    return 1;
  return state->deadline !=
                 std::chrono::steady_clock::time_point::max() &&
             std::chrono::steady_clock::now() >= state->deadline
         ? 1
         : 0;
}
#endif

} // namespace

struct QuickJsLane::Task {
  Task(QuickJsTaskOptions options, QuickJsWork work,
       QuickJsCompletion completion)
      : options(std::move(options)), work(std::move(work)),
        completion(std::move(completion)) {
    if (this->options.request_context)
      cancellation =
          this->options.request_context->cancellationToken();
  }

  QuickJsTaskOptions options;
  RequestCancellationToken cancellation;
  QuickJsWork work;
  QuickJsCompletion completion;
  std::atomic<bool> completed{false};
};

QuickJsLaneBudget quickJsLaneBudgetFromForceMax(
    const ForceMaxBudget &budget) noexcept {
  return {budget.quickjs_workers, budget.quickjs_queue_entries,
          budget.quickjs_queue_bytes,
          budget.quickjs_heap_bytes_per_worker,
          budget.quickjs_stack_bytes_per_worker};
}

QuickJsLane::QuickJsLane(QuickJsLaneBudget budget) : budget_(budget) {
  if (budget_.workers == 0 || budget_.max_queue_entries == 0 ||
      budget_.max_queue_bytes == 0 ||
      budget_.heap_bytes_per_worker == 0 ||
      budget_.stack_bytes_per_worker == 0 ||
      budget_.workers > std::numeric_limits<std::size_t>::max() ||
      budget_.heap_bytes_per_worker >
          std::numeric_limits<std::size_t>::max() ||
      budget_.stack_bytes_per_worker >
          std::numeric_limits<std::size_t>::max())
    throw std::invalid_argument("invalid QuickJsLane budget");
#ifdef NO_JS_RUNTIME
  throw std::runtime_error("QuickJS runtime unavailable");
#else
  {
    // quickjspp assigns process-global class IDs lazily. Bootstrap them before
    // any lane worker starts so separate runtimes never race that assignment.
    std::lock_guard<std::mutex> bootstrap_lock(quickjs_bootstrap_mutex);
    qjs::Runtime runtime;
    JS_SetMemoryLimit(runtime.rt,
                      static_cast<size_t>(budget_.heap_bytes_per_worker));
    JS_SetMaxStackSize(runtime.rt,
                       static_cast<size_t>(budget_.stack_bytes_per_worker));
    script_runtime_init(runtime);
    qjs::Context context(runtime);
    if (script_context_init(context) != 0) {
      (void)script_cleanup(context);
      throw std::runtime_error("QuickJS bootstrap failed");
    }
    (void)script_cleanup(context);
  }
  const std::size_t worker_count =
      static_cast<std::size_t>(budget_.workers);
  workers_.reserve(worker_count);
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
    throw std::runtime_error("QuickJsLane workers failed to become ready");
  }
#endif
}

QuickJsLane::~QuickJsLane() { shutdown(true); }

QuickJsTaskStatus QuickJsLane::rejectionResult(
    QuickJsSubmitStatus status) noexcept {
  switch (status) {
  case QuickJsSubmitStatus::Cancelled:
    return QuickJsTaskStatus::Cancelled;
  case QuickJsSubmitStatus::Deadline:
    return QuickJsTaskStatus::Deadline;
  case QuickJsSubmitStatus::Stopping:
    return QuickJsTaskStatus::Shutdown;
  case QuickJsSubmitStatus::Unavailable:
    return QuickJsTaskStatus::Unavailable;
  case QuickJsSubmitStatus::EntryLimit:
  case QuickJsSubmitStatus::ByteLimit:
    return QuickJsTaskStatus::Capacity;
  case QuickJsSubmitStatus::Accepted:
    break;
  }
  return QuickJsTaskStatus::RuntimeError;
}

QuickJsSubmitStatus QuickJsLane::submit(
    QuickJsTaskOptions options, QuickJsWork work,
    QuickJsCompletion completion) {
  if (!work || !completion || !options.settings ||
      !options.request_context) {
    if (completion) {
      try {
        completion({QuickJsTaskStatus::RuntimeError});
      } catch (...) {
      }
    }
    return QuickJsSubmitStatus::Unavailable;
  }
  options.deadline = std::min(options.deadline,
                              options.request_context->deadline());
  std::shared_ptr<Task> task;
  try {
    task = std::make_shared<Task>(std::move(options), std::move(work),
                                  completion);
  } catch (...) {
    try {
      completion({QuickJsTaskStatus::Capacity});
    } catch (...) {
    }
    return QuickJsSubmitStatus::ByteLimit;
  }

  QuickJsSubmitStatus status = QuickJsSubmitStatus::Accepted;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (stopping_)
      status = QuickJsSubmitStatus::Stopping;
    else if (task->cancellation.isCancellationRequested())
      status = QuickJsSubmitStatus::Cancelled;
    else if (task->options.deadline !=
                 std::chrono::steady_clock::time_point::max() &&
             now >= task->options.deadline)
      status = QuickJsSubmitStatus::Deadline;
    else if (queue_.size() >= budget_.max_queue_entries)
      status = QuickJsSubmitStatus::EntryLimit;
    else if (task->options.bytes > budget_.max_queue_bytes ||
             queued_bytes_ >
                 budget_.max_queue_bytes - task->options.bytes)
      status = QuickJsSubmitStatus::ByteLimit;
    else {
      queued_bytes_ += task->options.bytes;
      queue_.emplace_back(task);
      accepted_total_.fetch_add(1, std::memory_order_relaxed);
    }
    if (status != QuickJsSubmitStatus::Accepted)
      rejected_total_.fetch_add(1, std::memory_order_relaxed);
  }
  if (status == QuickJsSubmitStatus::Accepted) {
    condition_.notify_one();
  } else {
    finishTask(task, rejectionResult(status));
  }
  return status;
}

void QuickJsLane::workerLoop(std::size_t index) noexcept {
  setQuickJsThreadName(index);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    ++ready_workers_;
  }
  ready_condition_.notify_all();

  for (;;) {
    std::shared_ptr<Task> task;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      condition_.wait(lock,
                      [this] { return stopping_ || !queue_.empty(); });
      if (queue_.empty()) {
        if (stopping_)
          break;
        continue;
      }
      task = std::move(queue_.front());
      queue_.pop_front();
      queued_bytes_ -= task->options.bytes;
      ++active_;
    }
    const QuickJsTaskStatus status = runTask(task);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      --active_;
    }
    finishTask(task, status);
  }
}

QuickJsTaskStatus
QuickJsLane::runTask(const std::shared_ptr<Task> &task) noexcept {
  if (!task)
    return QuickJsTaskStatus::RuntimeError;
  if (interrupt_shutdown_.load(std::memory_order_acquire))
    return QuickJsTaskStatus::Shutdown;
  if (task->cancellation.isCancellationRequested())
    return QuickJsTaskStatus::Cancelled;
  if (task->options.deadline !=
          std::chrono::steady_clock::time_point::max() &&
      std::chrono::steady_clock::now() >= task->options.deadline)
    return QuickJsTaskStatus::Deadline;
#ifdef NO_JS_RUNTIME
  return QuickJsTaskStatus::Unavailable;
#else
  try {
    ScopedSettingsView settings_scope(task->options.settings);
    ScopedRequestContext request_scope(task->options.request_context);
    qjs::Runtime runtime;
    JS_SetMemoryLimit(runtime.rt,
                      static_cast<size_t>(budget_.heap_bytes_per_worker));
    JS_SetMaxStackSize(runtime.rt,
                       static_cast<size_t>(budget_.stack_bytes_per_worker));
    QuickJsInterruptState interrupt{
        task->options.deadline, task->cancellation,
        &interrupt_shutdown_};
    JS_SetInterruptHandler(runtime.rt, quickJsInterrupt, &interrupt);
    script_runtime_init(runtime);
    qjs::Context context(runtime);
    bool context_initialized = false;
    try {
      if (script_context_init(context) != 0) {
        (void)script_cleanup(context);
        return QuickJsTaskStatus::RuntimeError;
      }
      context_initialized = true;
      task->work(context);
      (void)script_cleanup(context);
      context_initialized = false;
    } catch (qjs::exception &) {
      if (context_initialized)
        (void)script_cleanup(context);
      if (interrupt_shutdown_.load(std::memory_order_acquire))
        return QuickJsTaskStatus::Shutdown;
      if (task->cancellation.isCancellationRequested())
        return QuickJsTaskStatus::Cancelled;
      if (task->options.deadline !=
              std::chrono::steady_clock::time_point::max() &&
          std::chrono::steady_clock::now() >= task->options.deadline)
        return QuickJsTaskStatus::Deadline;
      script_print_stack(context);
      return QuickJsTaskStatus::ScriptError;
    } catch (...) {
      if (context_initialized)
        (void)script_cleanup(context);
      throw;
    }
    if (interrupt_shutdown_.load(std::memory_order_acquire))
      return QuickJsTaskStatus::Shutdown;
    if (task->cancellation.isCancellationRequested())
      return QuickJsTaskStatus::Cancelled;
    if (task->options.deadline !=
            std::chrono::steady_clock::time_point::max() &&
        std::chrono::steady_clock::now() >= task->options.deadline)
      return QuickJsTaskStatus::Deadline;
    return QuickJsTaskStatus::Success;
  } catch (...) {
    return QuickJsTaskStatus::RuntimeError;
  }
#endif
}

void QuickJsLane::finishTask(const std::shared_ptr<Task> &task,
                             QuickJsTaskStatus status) noexcept {
  if (!task || task->completed.exchange(true, std::memory_order_acq_rel))
    return;
  completed_total_.fetch_add(1, std::memory_order_relaxed);
  if (status == QuickJsTaskStatus::Cancelled)
    cancelled_total_.fetch_add(1, std::memory_order_relaxed);
  else if (status == QuickJsTaskStatus::Deadline)
    deadline_total_.fetch_add(1, std::memory_order_relaxed);
  else if (status == QuickJsTaskStatus::ScriptError)
    script_error_total_.fetch_add(1, std::memory_order_relaxed);
  QuickJsCompletion completion = std::move(task->completion);
  if (!completion)
    return;
  try {
    completion({status});
  } catch (...) {
  }
}

void QuickJsLane::requestShutdown(bool cancel_pending) noexcept {
  std::deque<std::shared_ptr<Task>> cancelled;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!stopping_)
      stopping_ = true;
    cancel_pending_ = cancel_pending_ || cancel_pending;
    if (cancel_pending_) {
      interrupt_shutdown_.store(true, std::memory_order_release);
      cancelled.swap(queue_);
      queued_bytes_ = 0;
    }
  }
  for (const auto &task : cancelled)
    finishTask(task, QuickJsTaskStatus::Shutdown);
  condition_.notify_all();
  ready_condition_.notify_all();
}

bool QuickJsLane::join() noexcept {
  const std::thread::id current = std::this_thread::get_id();
  {
    std::unique_lock<std::mutex> lock(mutex_);
    if (joined_)
      return true;
    for (const auto &worker : workers_)
      if (worker.get_id() == current)
        return false;
    if (joining_) {
      ready_condition_.wait(lock, [this] { return joined_; });
      return true;
    }
    joining_ = true;
  }
  for (auto iter = workers_.rbegin(); iter != workers_.rend(); ++iter)
    if (iter->joinable())
      iter->join();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    joined_ = true;
    joining_ = false;
  }
  ready_condition_.notify_all();
  return true;
}

void QuickJsLane::shutdown(bool cancel_pending) noexcept {
  requestShutdown(cancel_pending);
  (void)join();
}

QuickJsLaneSnapshot QuickJsLane::snapshot() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return {
      ready_workers_ == budget_.workers,
      stopping_,
      joined_,
      budget_.workers,
      ready_workers_,
      budget_.max_queue_entries,
      budget_.max_queue_bytes,
      budget_.heap_bytes_per_worker,
      budget_.stack_bytes_per_worker,
      static_cast<uint64_t>(queue_.size()),
      queued_bytes_,
      active_,
      accepted_total_.load(std::memory_order_relaxed),
      rejected_total_.load(std::memory_order_relaxed),
      completed_total_.load(std::memory_order_relaxed),
      cancelled_total_.load(std::memory_order_relaxed),
      deadline_total_.load(std::memory_order_relaxed),
      script_error_total_.load(std::memory_order_relaxed),
  };
}

GlobalQuickJsLaneInitStatus initializeGlobalQuickJsLane(
    QuickJsLaneBudget budget) noexcept {
  if (budget.workers == 0 || budget.max_queue_entries == 0 ||
      budget.max_queue_bytes == 0 ||
      budget.heap_bytes_per_worker == 0 ||
      budget.stack_bytes_per_worker == 0)
    return GlobalQuickJsLaneInitStatus::InvalidBudget;
  std::lock_guard<std::mutex> lock(global_quickjs_lane.mutex);
  if (global_quickjs_lane.stopping)
    return GlobalQuickJsLaneInitStatus::Stopping;
  if (global_quickjs_lane.lane)
    return global_quickjs_lane.budget == budget
               ? GlobalQuickJsLaneInitStatus::AlreadyInitialized
               : GlobalQuickJsLaneInitStatus::BudgetMismatch;
  try {
    global_quickjs_lane.lane =
        std::make_unique<QuickJsLane>(budget);
    global_quickjs_lane.budget = budget;
    return GlobalQuickJsLaneInitStatus::Initialized;
  } catch (...) {
    global_quickjs_lane.lane.reset();
    return GlobalQuickJsLaneInitStatus::InvalidBudget;
  }
}

QuickJsLane *globalQuickJsLane() noexcept {
  std::lock_guard<std::mutex> lock(global_quickjs_lane.mutex);
  return global_quickjs_lane.lane.get();
}

QuickJsLaneSnapshot globalQuickJsLaneSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(global_quickjs_lane.mutex);
  return global_quickjs_lane.lane
             ? global_quickjs_lane.lane->snapshot()
             : QuickJsLaneSnapshot{};
}

void requestGlobalQuickJsLaneShutdown() noexcept {
  QuickJsLane *lane = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_quickjs_lane.mutex);
    global_quickjs_lane.stopping = true;
    lane = global_quickjs_lane.lane.get();
  }
  if (lane)
    lane->requestShutdown(true);
}

bool joinGlobalQuickJsLane() noexcept {
  QuickJsLane *lane = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_quickjs_lane.mutex);
    lane = global_quickjs_lane.lane.get();
  }
  return !lane || lane->join();
}
