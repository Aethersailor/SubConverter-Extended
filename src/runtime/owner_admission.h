#ifndef OWNER_ADMISSION_H_INCLUDED
#define OWNER_ADMISSION_H_INCLUDED

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>

#include "server/request_context.h"

struct ForceMaxBudget;

struct OwnerAdmissionBudget {
  uint64_t max_active_entries = 0;
  uint64_t max_active_bytes = 0;
  uint64_t max_wait_entries = 0;
  uint64_t max_wait_bytes = 0;

  bool operator==(const OwnerAdmissionBudget &) const = default;
};

OwnerAdmissionBudget ownerAdmissionBudgetFromForceMax(
    const ForceMaxBudget &budget) noexcept;

enum class OwnerAdmissionStatus : uint8_t {
  Granted,
  EntryLimit,
  ByteLimit,
  Cancelled,
  Deadline,
  Shutdown,
};

class OwnerAdmission;

class OwnerAdmissionLease {
public:
  OwnerAdmissionLease() = default;
  ~OwnerAdmissionLease() { reset(); }

  OwnerAdmissionLease(OwnerAdmissionLease &&other) noexcept
      : state_(std::move(other.state_)) {}
  OwnerAdmissionLease &operator=(OwnerAdmissionLease &&other) noexcept {
    if (this != &other) {
      reset();
      state_ = std::move(other.state_);
    }
    return *this;
  }

  OwnerAdmissionLease(const OwnerAdmissionLease &) = delete;
  OwnerAdmissionLease &operator=(const OwnerAdmissionLease &) = delete;

  explicit operator bool() const noexcept {
    return static_cast<bool>(state_);
  }
  void reset() noexcept;
  // Growth never waits while holding a working set. Capacity failure lets the
  // flow unwind, releasing memory for queued owners instead of deadlocking.
  bool resize(uint64_t bytes) noexcept;
  bool transferRetainedBytes(uint64_t bytes,
                            RetainedResponseByteLease &retained) noexcept;
  OwnerAdmissionLease share() const noexcept;

private:
  friend class OwnerAdmission;
  struct State;
  OwnerAdmissionLease(uint64_t bytes,
                      std::function<void(uint64_t)> release,
                      std::function<bool(uint64_t, uint64_t)> resize,
                      std::function<void(uint64_t)> transfer);
  std::shared_ptr<State> state_;
};

struct OwnerAdmissionResult {
  OwnerAdmissionStatus status = OwnerAdmissionStatus::Shutdown;
  OwnerAdmissionLease lease;
};

struct OwnerAdmissionOptions {
  RequestCostClass cost = RequestCostClass::Medium;
  // Active bytes reserve the owner's current conversion working set. Waiting
  // bytes charge only the metadata retained while this request is queued.
  uint64_t bytes = 0;
  uint64_t wait_bytes = std::numeric_limits<uint64_t>::max();
  std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::time_point::max();
  std::shared_ptr<RequestContext> request_context;
  bool wait = true;
};

using OwnerAdmissionCompletion =
    std::function<void(OwnerAdmissionResult)>;

struct OwnerAdmissionSnapshot {
  bool ready = false;
  bool stopping = false;
  bool joined = false;
  uint64_t active_entries = 0;
  uint64_t active_bytes = 0;
  uint64_t waiting_entries = 0;
  uint64_t waiting_bytes = 0;
  uint64_t accepted_total = 0;
  uint64_t rejected_total = 0;
  uint64_t cancelled_total = 0;
  uint64_t deadline_total = 0;
  uint64_t shutdown_total = 0;
  uint64_t oldest_wait_ms = 0;
  uint64_t max_active_entries = 0;
  uint64_t max_active_bytes = 0;
  uint64_t max_wait_entries = 0;
  uint64_t max_wait_bytes = 0;
};

class OwnerAdmission {
public:
  explicit OwnerAdmission(OwnerAdmissionBudget budget);
  ~OwnerAdmission();

  OwnerAdmission(const OwnerAdmission &) = delete;
  OwnerAdmission &operator=(const OwnerAdmission &) = delete;

  std::optional<OwnerAdmissionResult>
  tryAdmitImmediate(const OwnerAdmissionOptions &options);
  OwnerAdmissionStatus admit(OwnerAdmissionOptions options,
                             OwnerAdmissionCompletion completion);
  bool setActiveLimits(uint64_t max_active_entries,
                       uint64_t max_active_bytes) noexcept;
  void requestShutdown() noexcept;
  bool join() noexcept;
  OwnerAdmissionSnapshot snapshot() const noexcept;
  const OwnerAdmissionBudget &budget() const noexcept;

private:
  struct Core;
  std::shared_ptr<Core> core_;
};

enum class GlobalOwnerAdmissionInitStatus : uint8_t {
  Initialized,
  AlreadyInitialized,
  BudgetMismatch,
  InvalidBudget,
  Stopping,
};

GlobalOwnerAdmissionInitStatus initializeGlobalOwnerAdmission(
    OwnerAdmissionBudget budget) noexcept;
bool publishGlobalOwnerAdmission(std::unique_ptr<OwnerAdmission> admission,
                                 OwnerAdmissionBudget budget) noexcept;
bool resetGlobalOwnerAdmission() noexcept;
OwnerAdmission *globalOwnerAdmission() noexcept;
OwnerAdmissionSnapshot globalOwnerAdmissionSnapshot() noexcept;
bool setGlobalOwnerAdmissionActiveLimits(
    uint64_t max_active_entries, uint64_t max_active_bytes) noexcept;
void requestGlobalOwnerAdmissionShutdown() noexcept;
bool joinGlobalOwnerAdmission() noexcept;

#endif // OWNER_ADMISSION_H_INCLUDED
