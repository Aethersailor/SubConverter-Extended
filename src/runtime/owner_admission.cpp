#include "runtime/owner_admission.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <iterator>
#include <list>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "utils/force_max_budget.h"

namespace {

using Clock = std::chrono::steady_clock;

RequestCostClass normalizedCost(RequestCostClass cost) noexcept {
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

std::size_t queueIndex(RequestCostClass cost) noexcept {
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

struct GlobalOwnerAdmissionRuntime {
  std::mutex mutex;
  std::unique_ptr<OwnerAdmission> admission;
  OwnerAdmissionBudget budget;
  bool stopping = false;
};

GlobalOwnerAdmissionRuntime global_owner_admission;

} // namespace

struct OwnerAdmission::Core
    : public std::enable_shared_from_this<OwnerAdmission::Core> {
  struct Waiter {
    explicit Waiter(OwnerAdmissionOptions options,
                    OwnerAdmissionCompletion completion)
        : options(std::move(options)),
          completion(std::move(completion)),
          enqueued_at(Clock::now()) {}

    OwnerAdmissionOptions options;
    OwnerAdmissionCompletion completion;
    RequestCancellationRegistration cancellation_registration;
    Clock::time_point enqueued_at;
    std::list<std::shared_ptr<Waiter>>::iterator position;
    std::size_t queue_index = 0;
    bool queued = false;
    bool claimed = false;
  };

  struct Action {
    std::shared_ptr<Waiter> waiter;
    OwnerAdmissionStatus status = OwnerAdmissionStatus::Shutdown;
  };

  explicit Core(OwnerAdmissionBudget budget)
      : budget(std::move(budget)),
        active_entry_limit(this->budget.max_active_entries),
        active_byte_limit(this->budget.max_active_bytes) {}

  ~Core() {
    requestShutdown();
    (void)join();
  }

  void start() {
    timer = std::thread([this] { timerLoop(); });
    std::unique_lock<std::mutex> lock(mutex);
    ready_condition.wait(lock, [this] { return ready || stopping; });
    if (!ready)
      throw std::runtime_error("owner admission timer failed to become ready");
  }

  bool canGrant(uint64_t bytes) const noexcept {
    return active_entries < active_entry_limit &&
           bytes <= active_byte_limit &&
           active_bytes <= active_byte_limit - bytes;
  }

  bool hasWaiting() const noexcept { return waiting_entries != 0; }

  bool hasLegalWaiting() const noexcept {
    for (const auto &queue : queues)
      if (!queue.empty() && canGrant(queue.front()->options.bytes))
        return true;
    return false;
  }

  std::size_t selectQueueLocked() {
    const auto now = Clock::now();
    std::size_t oldest_index = queues.size();
    Clock::time_point oldest = Clock::time_point::max();
    for (std::size_t index = 0; index < queues.size(); ++index) {
      if (!queues[index].empty() &&
          canGrant(queues[index].front()->options.bytes) &&
          queues[index].front()->enqueued_at < oldest) {
        oldest = queues[index].front()->enqueued_at;
        oldest_index = index;
      }
    }
    if (oldest_index == queues.size())
      return oldest_index;
    if (now - oldest >= std::chrono::milliseconds(500))
      return oldest_index;

    auto has_credit = [this] {
      for (std::size_t index = 0; index < queues.size(); ++index)
        if (!queues[index].empty() && credits[index] != 0 &&
            canGrant(queues[index].front()->options.bytes))
          return true;
      return false;
    };
    if (!has_credit()) {
      for (std::size_t index = 0; index < queues.size(); ++index)
        credits[index] = queues[index].empty() ? 0 : weights[index];
    }
    for (std::size_t attempts = 0; attempts < queues.size() * 2;
         ++attempts) {
      const std::size_t index = next_queue++ % queues.size();
      if (credits[index] == 0 || queues[index].empty() ||
          !canGrant(queues[index].front()->options.bytes))
        continue;
      --credits[index];
      return index;
    }
    return oldest_index;
  }

  void eraseWaiterLocked(const std::shared_ptr<Waiter> &waiter) {
    if (!waiter || !waiter->queued)
      return;
    queues[waiter->queue_index].erase(waiter->position);
    waiter->queued = false;
    --waiting_entries;
    waiting_bytes -= waiter->options.bytes;
  }

  void addActionLocked(std::vector<Action> &actions,
                       const std::shared_ptr<Waiter> &waiter,
                       OwnerAdmissionStatus status) {
    if (!waiter || waiter->claimed)
      return;
    eraseWaiterLocked(waiter);
    waiter->claimed = true;
    actions.push_back({waiter, status});
  }

  void pruneExpiredLocked(std::vector<Action> &actions) {
    const auto now = Clock::now();
    for (auto &queue : queues) {
      for (auto iter = queue.begin(); iter != queue.end();) {
        const std::shared_ptr<Waiter> waiter = *iter++;
        if (waiter->options.request_context &&
            waiter->options.request_context->cancellationToken()
                .isCancellationRequested()) {
          ++cancelled_total;
          addActionLocked(actions, waiter,
                          OwnerAdmissionStatus::Cancelled);
        } else if (waiter->options.deadline !=
                       Clock::time_point::max() &&
                   now >= waiter->options.deadline) {
          ++deadline_total;
          addActionLocked(actions, waiter,
                          OwnerAdmissionStatus::Deadline);
        }
      }
    }
  }

  void collectGrantsLocked(std::vector<Action> &actions) {
    pruneExpiredLocked(actions);
    while (active_entries < active_entry_limit) {
      const std::size_t index = selectQueueLocked();
      if (index >= queues.size())
        break;
      const std::shared_ptr<Waiter> waiter = queues[index].front();
      if (!canGrant(waiter->options.bytes))
        break;
      addActionLocked(actions, waiter, OwnerAdmissionStatus::Granted);
      ++active_entries;
      active_bytes += waiter->options.bytes;
      ++accepted_total;
    }
  }

  Clock::time_point nextDeadlineLocked() const noexcept {
    Clock::time_point result = Clock::time_point::max();
    for (const auto &queue : queues)
      for (const auto &waiter : queue)
        result = std::min(result, waiter->options.deadline);
    return result;
  }

  void finishActions(std::vector<Action> actions) noexcept {
    const std::weak_ptr<Core> weak = weak_from_this();
    for (Action &action : actions) {
      if (!action.waiter)
        continue;
      action.waiter->cancellation_registration.reset();
      OwnerAdmissionCompletion completion =
          std::move(action.waiter->completion);
      if (!completion)
        continue;
      OwnerAdmissionResult result;
      result.status = action.status;
      if (action.status == OwnerAdmissionStatus::Granted) {
        const uint64_t bytes = action.waiter->options.bytes;
        result.lease = OwnerAdmissionLease([weak, bytes] {
          if (const std::shared_ptr<Core> core = weak.lock())
            core->release(bytes);
        });
      }
      try {
        completion(std::move(result));
      } catch (...) {
      }
    }
  }

  OwnerAdmissionStatus admit(OwnerAdmissionOptions options,
                             OwnerAdmissionCompletion completion) {
    if (!completion || !options.request_context) {
      if (completion) {
        try {
          completion({OwnerAdmissionStatus::Shutdown, {}});
        } catch (...) {
        }
      }
      return OwnerAdmissionStatus::Shutdown;
    }
    options.cost = normalizedCost(options.cost);
    options.deadline = std::min(options.deadline,
                                options.request_context->deadline());
    auto waiter = std::make_shared<Waiter>(std::move(options),
                                           std::move(completion));
    const std::weak_ptr<Core> weak = weak_from_this();
    waiter->cancellation_registration =
        waiter->options.request_context->registerCancellationCallback(
            [weak, weak_waiter = std::weak_ptr<Waiter>(waiter)] {
              if (const std::shared_ptr<Core> core = weak.lock())
                if (const std::shared_ptr<Waiter> locked =
                        weak_waiter.lock())
                  core->cancelWaiter(locked);
            });

    std::vector<Action> actions;
    OwnerAdmissionStatus result = OwnerAdmissionStatus::Granted;
    {
      std::lock_guard<std::mutex> lock(mutex);
      collectGrantsLocked(actions);
      const auto now = Clock::now();
      if (stopping) {
        waiter->claimed = true;
        ++shutdown_total;
        actions.push_back({waiter, OwnerAdmissionStatus::Shutdown});
        result = OwnerAdmissionStatus::Shutdown;
      } else if (waiter->options.request_context->cancellationToken()
                     .isCancellationRequested()) {
        waiter->claimed = true;
        ++cancelled_total;
        actions.push_back({waiter, OwnerAdmissionStatus::Cancelled});
        result = OwnerAdmissionStatus::Cancelled;
      } else if (waiter->options.deadline !=
                     Clock::time_point::max() &&
                 now >= waiter->options.deadline) {
        waiter->claimed = true;
        ++deadline_total;
        actions.push_back({waiter, OwnerAdmissionStatus::Deadline});
        result = OwnerAdmissionStatus::Deadline;
      } else if (waiter->options.bytes > budget.max_active_bytes) {
        waiter->claimed = true;
        ++rejected_total;
        actions.push_back({waiter, OwnerAdmissionStatus::ByteLimit});
        result = OwnerAdmissionStatus::ByteLimit;
      } else if (canGrant(waiter->options.bytes) &&
                 !hasLegalWaiting()) {
        waiter->claimed = true;
        ++active_entries;
        active_bytes += waiter->options.bytes;
        ++accepted_total;
        actions.push_back({waiter, OwnerAdmissionStatus::Granted});
      } else if (!waiter->options.wait) {
        waiter->claimed = true;
        ++rejected_total;
        actions.push_back({waiter, OwnerAdmissionStatus::EntryLimit});
        result = OwnerAdmissionStatus::EntryLimit;
      } else if (waiter->options.bytes > budget.max_wait_bytes) {
        waiter->claimed = true;
        ++rejected_total;
        actions.push_back({waiter, OwnerAdmissionStatus::ByteLimit});
        result = OwnerAdmissionStatus::ByteLimit;
      } else if (waiting_entries >= budget.max_wait_entries) {
        waiter->claimed = true;
        ++rejected_total;
        actions.push_back({waiter, OwnerAdmissionStatus::EntryLimit});
        result = OwnerAdmissionStatus::EntryLimit;
      } else if (waiting_bytes >
                 budget.max_wait_bytes - waiter->options.bytes) {
        waiter->claimed = true;
        ++rejected_total;
        actions.push_back({waiter, OwnerAdmissionStatus::ByteLimit});
        result = OwnerAdmissionStatus::ByteLimit;
      } else {
        waiter->queue_index = queueIndex(waiter->options.cost);
        queues[waiter->queue_index].push_back(waiter);
        waiter->position = std::prev(
            queues[waiter->queue_index].end());
        waiter->queued = true;
        ++waiting_entries;
        waiting_bytes += waiter->options.bytes;
        collectGrantsLocked(actions);
      }
    }
    finishActions(std::move(actions));
    timer_condition.notify_all();
    return result;
  }

  void cancelWaiter(const std::shared_ptr<Waiter> &waiter) noexcept {
    std::vector<Action> actions;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (!waiter || waiter->claimed || !waiter->queued)
        return;
      ++cancelled_total;
      addActionLocked(actions, waiter,
                      OwnerAdmissionStatus::Cancelled);
      collectGrantsLocked(actions);
    }
    finishActions(std::move(actions));
    timer_condition.notify_all();
  }

  void release(uint64_t bytes) noexcept {
    std::vector<Action> actions;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (active_entries != 0)
        --active_entries;
      active_bytes -= std::min(active_bytes, bytes);
      if (!stopping)
        collectGrantsLocked(actions);
    }
    finishActions(std::move(actions));
    timer_condition.notify_all();
  }

  void timerLoop() noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex);
      ready = true;
    }
    ready_condition.notify_all();
    for (;;) {
      std::vector<Action> actions;
      {
        std::unique_lock<std::mutex> lock(mutex);
        if (stopping)
          break;
        const Clock::time_point deadline = nextDeadlineLocked();
        if (deadline == Clock::time_point::max()) {
          timer_condition.wait(lock);
        } else {
          timer_condition.wait_until(lock, deadline);
        }
        if (stopping)
          break;
        collectGrantsLocked(actions);
      }
      finishActions(std::move(actions));
    }
  }

  void requestShutdown() noexcept {
    std::vector<Action> actions;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (stopping)
        return;
      stopping = true;
      for (auto &queue : queues) {
        while (!queue.empty()) {
          const std::shared_ptr<Waiter> waiter = queue.front();
          ++shutdown_total;
          addActionLocked(actions, waiter,
                          OwnerAdmissionStatus::Shutdown);
        }
      }
    }
    finishActions(std::move(actions));
    timer_condition.notify_all();
    ready_condition.notify_all();
  }

  bool join() noexcept {
    const std::thread::id current = std::this_thread::get_id();
    {
      std::unique_lock<std::mutex> lock(mutex);
      if (joined)
        return true;
      if (timer.get_id() == current)
        return false;
      if (joining) {
        ready_condition.wait(lock, [this] { return joined; });
        return true;
      }
      joining = true;
    }
    if (timer.joinable()) {
      try {
        timer.join();
      } catch (...) {
        std::lock_guard<std::mutex> lock(mutex);
        joining = false;
        ready_condition.notify_all();
        return false;
      }
    }
    {
      std::lock_guard<std::mutex> lock(mutex);
      joined = true;
      joining = false;
    }
    ready_condition.notify_all();
    return true;
  }

  OwnerAdmissionSnapshot snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex);
    Clock::time_point oldest = Clock::time_point::max();
    for (const auto &queue : queues)
      if (!queue.empty())
        oldest = std::min(oldest, queue.front()->enqueued_at);
    const uint64_t oldest_ms =
        oldest == Clock::time_point::max()
            ? 0
            : static_cast<uint64_t>(std::max<int64_t>(
                  0, std::chrono::duration_cast<std::chrono::milliseconds>(
                         Clock::now() - oldest)
                         .count()));
    return {ready,
            stopping,
            joined,
            active_entries,
            active_bytes,
            waiting_entries,
            waiting_bytes,
            accepted_total,
            rejected_total,
            cancelled_total,
            deadline_total,
            shutdown_total,
            oldest_ms,
            active_entry_limit,
            active_byte_limit,
            budget.max_wait_entries,
            budget.max_wait_bytes};
  }

  bool setActiveLimits(uint64_t max_active_entries,
                       uint64_t max_active_bytes) noexcept {
    std::vector<Action> actions;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (stopping)
        return false;
      active_entry_limit = std::clamp<uint64_t>(
          max_active_entries, 1, budget.max_active_entries);
      active_byte_limit = std::clamp<uint64_t>(
          max_active_bytes, 1, budget.max_active_bytes);
      collectGrantsLocked(actions);
    }
    timer_condition.notify_all();
    finishActions(std::move(actions));
    return true;
  }

  const OwnerAdmissionBudget budget;
  uint64_t active_entry_limit;
  uint64_t active_byte_limit;
  mutable std::mutex mutex;
  std::condition_variable timer_condition;
  std::condition_variable ready_condition;
  std::array<std::list<std::shared_ptr<Waiter>>, 3> queues;
  std::thread timer;
  std::array<uint8_t, 3> credits{8, 4, 1};
  inline static constexpr std::array<uint8_t, 3> weights{8, 4, 1};
  std::size_t next_queue = 0;
  uint64_t active_entries = 0;
  uint64_t active_bytes = 0;
  uint64_t waiting_entries = 0;
  uint64_t waiting_bytes = 0;
  uint64_t accepted_total = 0;
  uint64_t rejected_total = 0;
  uint64_t cancelled_total = 0;
  uint64_t deadline_total = 0;
  uint64_t shutdown_total = 0;
  bool ready = false;
  bool stopping = false;
  bool joining = false;
  bool joined = false;
};

OwnerAdmissionBudget ownerAdmissionBudgetFromForceMax(
    const ForceMaxBudget &budget) noexcept {
  return {budget.active_owners, budget.owner_active_bytes,
          budget.owner_queue_entries, budget.owner_queue_bytes};
}

void OwnerAdmissionLease::reset() noexcept {
  std::function<void()> release = std::move(release_);
  if (!release)
    return;
  try {
    release();
  } catch (...) {
  }
}

OwnerAdmission::OwnerAdmission(OwnerAdmissionBudget budget)
    : core_(std::make_shared<Core>(std::move(budget))) {
  const OwnerAdmissionBudget &applied = core_->budget;
  if (applied.max_active_entries == 0 || applied.max_active_bytes == 0 ||
      applied.max_wait_entries == 0 || applied.max_wait_bytes == 0)
    throw std::invalid_argument("invalid owner admission budget");
  core_->start();
}

OwnerAdmission::~OwnerAdmission() {
  if (!core_)
    return;
  core_->requestShutdown();
  (void)core_->join();
}

OwnerAdmissionStatus OwnerAdmission::admit(
    OwnerAdmissionOptions options, OwnerAdmissionCompletion completion) {
  return core_->admit(std::move(options), std::move(completion));
}

bool OwnerAdmission::setActiveLimits(uint64_t max_active_entries,
                                     uint64_t max_active_bytes) noexcept {
  return core_ && core_->setActiveLimits(max_active_entries,
                                         max_active_bytes);
}

void OwnerAdmission::requestShutdown() noexcept {
  if (core_)
    core_->requestShutdown();
}

bool OwnerAdmission::join() noexcept {
  return !core_ || core_->join();
}

OwnerAdmissionSnapshot OwnerAdmission::snapshot() const noexcept {
  return core_ ? core_->snapshot() : OwnerAdmissionSnapshot{};
}

const OwnerAdmissionBudget &OwnerAdmission::budget() const noexcept {
  return core_->budget;
}

GlobalOwnerAdmissionInitStatus initializeGlobalOwnerAdmission(
    OwnerAdmissionBudget budget) noexcept {
  if (budget.max_active_entries == 0 || budget.max_active_bytes == 0 ||
      budget.max_wait_entries == 0 || budget.max_wait_bytes == 0)
    return GlobalOwnerAdmissionInitStatus::InvalidBudget;
  std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
  if (global_owner_admission.stopping)
    return GlobalOwnerAdmissionInitStatus::Stopping;
  if (global_owner_admission.admission)
    return global_owner_admission.budget == budget
               ? GlobalOwnerAdmissionInitStatus::AlreadyInitialized
               : GlobalOwnerAdmissionInitStatus::BudgetMismatch;
  try {
    global_owner_admission.admission =
        std::make_unique<OwnerAdmission>(budget);
    global_owner_admission.budget = budget;
    return GlobalOwnerAdmissionInitStatus::Initialized;
  } catch (...) {
    global_owner_admission.admission.reset();
    return GlobalOwnerAdmissionInitStatus::InvalidBudget;
  }
}

bool publishGlobalOwnerAdmission(std::unique_ptr<OwnerAdmission> admission,
                                 OwnerAdmissionBudget budget) noexcept {
  if (!admission || !admission->snapshot().ready)
    return false;
  std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
  if (global_owner_admission.stopping || global_owner_admission.admission)
    return false;
  global_owner_admission.budget = budget;
  global_owner_admission.admission = std::move(admission);
  return true;
}

bool resetGlobalOwnerAdmission() noexcept {
  std::unique_ptr<OwnerAdmission> retired;
  {
    std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
    if (global_owner_admission.admission &&
        !global_owner_admission.admission->snapshot().stopping)
      return false;
    retired = std::move(global_owner_admission.admission);
    global_owner_admission.budget = {};
    global_owner_admission.stopping = false;
  }
  if (retired && !retired->join())
    return false;
  return true;
}

OwnerAdmission *globalOwnerAdmission() noexcept {
  std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
  return global_owner_admission.admission.get();
}

OwnerAdmissionSnapshot globalOwnerAdmissionSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
  return global_owner_admission.admission
             ? global_owner_admission.admission->snapshot()
             : OwnerAdmissionSnapshot{};
}

bool setGlobalOwnerAdmissionActiveLimits(
    uint64_t max_active_entries, uint64_t max_active_bytes) noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
    admission = global_owner_admission.admission.get();
  }
  return admission && admission->setActiveLimits(
                          max_active_entries, max_active_bytes);
}

void requestGlobalOwnerAdmissionShutdown() noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
    global_owner_admission.stopping = true;
    admission = global_owner_admission.admission.get();
  }
  if (admission)
    admission->requestShutdown();
}

bool joinGlobalOwnerAdmission() noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_owner_admission.mutex);
    admission = global_owner_admission.admission.get();
  }
  return !admission || admission->join();
}
