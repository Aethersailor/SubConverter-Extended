#ifndef QUICKJS_LANE_H_INCLUDED
#define QUICKJS_LANE_H_INCLUDED

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "handler/settings_view.h"
#include "server/request_context.h"

#ifndef NO_JS_RUNTIME
namespace qjs {
class Context;
}
#endif

struct ForceMaxBudget;

struct QuickJsLaneBudget {
  uint64_t workers = 0;
  uint64_t max_queue_entries = 0;
  uint64_t max_queue_bytes = 0;
  uint64_t heap_bytes_per_worker = 0;
  uint64_t stack_bytes_per_worker = 0;

  bool operator==(const QuickJsLaneBudget &) const = default;
};

QuickJsLaneBudget quickJsLaneBudgetFromForceMax(
    const ForceMaxBudget &budget) noexcept;

enum class QuickJsSubmitStatus : uint8_t {
  Accepted,
  EntryLimit,
  ByteLimit,
  Cancelled,
  Deadline,
  Stopping,
  Unavailable,
};

enum class QuickJsTaskStatus : uint8_t {
  Success,
  Cancelled,
  Deadline,
  ScriptError,
  RuntimeError,
  Capacity,
  Shutdown,
  Unavailable,
};

struct QuickJsTaskResult {
  QuickJsTaskStatus status = QuickJsTaskStatus::RuntimeError;
};

struct QuickJsTaskOptions {
  uint64_t bytes = 0;
  std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::time_point::max();
  SettingsSnapshot settings;
  std::shared_ptr<RequestContext> request_context;
};

#ifndef NO_JS_RUNTIME
using QuickJsWork = std::function<void(qjs::Context &)>;
#else
using QuickJsWork = std::function<void()>;
#endif
using QuickJsCompletion = std::function<void(QuickJsTaskResult)>;

struct QuickJsLaneSnapshot {
  bool ready = false;
  bool stopping = false;
  bool joined = false;
  uint64_t workers = 0;
  uint64_t ready_workers = 0;
  uint64_t max_queue_entries = 0;
  uint64_t max_queue_bytes = 0;
  uint64_t heap_bytes_per_worker = 0;
  uint64_t stack_bytes_per_worker = 0;
  uint64_t queued_entries = 0;
  uint64_t queued_bytes = 0;
  uint64_t active = 0;
  uint64_t accepted_total = 0;
  uint64_t rejected_total = 0;
  uint64_t completed_total = 0;
  uint64_t cancelled_total = 0;
  uint64_t deadline_total = 0;
  uint64_t script_error_total = 0;
};

class QuickJsLane {
public:
  explicit QuickJsLane(QuickJsLaneBudget budget);
  ~QuickJsLane();

  QuickJsLane(const QuickJsLane &) = delete;
  QuickJsLane &operator=(const QuickJsLane &) = delete;

  QuickJsSubmitStatus submit(QuickJsTaskOptions options,
                             QuickJsWork work,
                             QuickJsCompletion completion);
  void requestShutdown(bool cancel_pending = true) noexcept;
  bool join() noexcept;
  void shutdown(bool cancel_pending = true) noexcept;
  QuickJsLaneSnapshot snapshot() const noexcept;
  const QuickJsLaneBudget &budget() const noexcept { return budget_; }

private:
  struct Task;

  void workerLoop(std::size_t index) noexcept;
  QuickJsTaskStatus runTask(const std::shared_ptr<Task> &task) noexcept;
  void finishTask(const std::shared_ptr<Task> &task,
                  QuickJsTaskStatus status) noexcept;
  static QuickJsTaskStatus rejectionResult(
      QuickJsSubmitStatus status) noexcept;

  const QuickJsLaneBudget budget_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::condition_variable ready_condition_;
  std::deque<std::shared_ptr<Task>> queue_;
  std::vector<std::thread> workers_;
  uint64_t ready_workers_ = 0;
  uint64_t queued_bytes_ = 0;
  uint64_t active_ = 0;
  bool stopping_ = false;
  bool cancel_pending_ = false;
  bool joining_ = false;
  bool joined_ = false;
  std::atomic<bool> interrupt_shutdown_{false};
  std::atomic<uint64_t> accepted_total_{0};
  std::atomic<uint64_t> rejected_total_{0};
  std::atomic<uint64_t> completed_total_{0};
  std::atomic<uint64_t> cancelled_total_{0};
  std::atomic<uint64_t> deadline_total_{0};
  std::atomic<uint64_t> script_error_total_{0};
};

enum class GlobalQuickJsLaneInitStatus : uint8_t {
  Initialized,
  AlreadyInitialized,
  BudgetMismatch,
  InvalidBudget,
  Stopping,
};

GlobalQuickJsLaneInitStatus initializeGlobalQuickJsLane(
    QuickJsLaneBudget budget) noexcept;
QuickJsLane *globalQuickJsLane() noexcept;
QuickJsLaneSnapshot globalQuickJsLaneSnapshot() noexcept;
void requestGlobalQuickJsLaneShutdown() noexcept;
bool joinGlobalQuickJsLane() noexcept;

#endif // QUICKJS_LANE_H_INCLUDED
