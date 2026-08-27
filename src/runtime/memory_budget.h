#ifndef RUNTIME_MEMORY_BUDGET_H_INCLUDED
#define RUNTIME_MEMORY_BUDGET_H_INCLUDED

#include <cstdint>
#include <utility>

struct FetchMemoryBudgetSnapshot {
  bool enabled = false;
  uint64_t limit = 0;
  uint64_t used = 0;
  uint64_t peak = 0;
  uint64_t waiters = 0;
  uint64_t wait_total = 0;
  uint64_t resumed_total = 0;
  uint64_t capacity_generation = 0;
};

// This budget is enabled only by the force_max Curl runtime. In other modes
// leases remain inert so compat/adaptive retain their historical behavior.
void configureGlobalFetchMemoryBudget(uint64_t limit) noexcept;
FetchMemoryBudgetSnapshot globalFetchMemoryBudgetSnapshot() noexcept;
uint64_t globalFetchMemoryCapacityGeneration() noexcept;
void noteGlobalFetchMemoryWaiterAdded() noexcept;
void noteGlobalFetchMemoryWaiterRemoved(bool resumed) noexcept;

class FetchMemoryLease {
public:
  FetchMemoryLease() = default;
  ~FetchMemoryLease() { reset(); }

  FetchMemoryLease(FetchMemoryLease &&other) noexcept
      : bytes_(std::exchange(other.bytes_, 0)),
        charged_(std::exchange(other.charged_, false)) {}
  FetchMemoryLease &operator=(FetchMemoryLease &&other) noexcept {
    if (this != &other) {
      reset();
      bytes_ = std::exchange(other.bytes_, 0);
      charged_ = std::exchange(other.charged_, false);
    }
    return *this;
  }

  FetchMemoryLease(const FetchMemoryLease &) = delete;
  FetchMemoryLease &operator=(const FetchMemoryLease &) = delete;

  bool acquire(uint64_t bytes) noexcept;
  void reset() noexcept;
  uint64_t bytes() const noexcept { return bytes_; }
  bool charged() const noexcept { return charged_; }

private:
  uint64_t bytes_ = 0;
  bool charged_ = false;
};

#endif // RUNTIME_MEMORY_BUDGET_H_INCLUDED
