#ifndef OWNER_ADMISSION_H_INCLUDED
#define OWNER_ADMISSION_H_INCLUDED

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

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
      : release_(std::move(other.release_)) {}
  OwnerAdmissionLease &operator=(OwnerAdmissionLease &&other) noexcept {
    if (this != &other) {
      reset();
      release_ = std::move(other.release_);
    }
    return *this;
  }

  OwnerAdmissionLease(const OwnerAdmissionLease &) = delete;
  OwnerAdmissionLease &operator=(const OwnerAdmissionLease &) = delete;

  explicit operator bool() const noexcept {
    return static_cast<bool>(release_);
  }
  void reset() noexcept;

private:
  friend class OwnerAdmission;
  explicit OwnerAdmissionLease(std::function<void()> release)
      : release_(std::move(release)) {}

  std::function<void()> release_;
};

struct OwnerAdmissionResult {
  OwnerAdmissionStatus status = OwnerAdmissionStatus::Shutdown;
  OwnerAdmissionLease lease;
};

struct OwnerAdmissionOptions {
  RequestCostClass cost = RequestCostClass::Medium;
  uint64_t bytes = 0;
  std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::time_point::max();
  std::shared_ptr<RequestContext> request_context;
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
OwnerAdmission *globalOwnerAdmission() noexcept;
OwnerAdmissionSnapshot globalOwnerAdmissionSnapshot() noexcept;
bool setGlobalOwnerAdmissionActiveLimits(
    uint64_t max_active_entries, uint64_t max_active_bytes) noexcept;
void requestGlobalOwnerAdmissionShutdown() noexcept;
bool joinGlobalOwnerAdmission() noexcept;

#endif // OWNER_ADMISSION_H_INCLUDED
