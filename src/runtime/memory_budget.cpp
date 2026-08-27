#include "runtime/memory_budget.h"

#include <atomic>
#include <limits>

namespace {

struct FetchMemoryBudgetState {
  std::atomic<bool> enabled{false};
  std::atomic<uint64_t> limit{0};
  std::atomic<uint64_t> used{0};
  std::atomic<uint64_t> peak{0};
  std::atomic<uint64_t> waiters{0};
  std::atomic<uint64_t> wait_total{0};
  std::atomic<uint64_t> resumed_total{0};
  std::atomic<uint64_t> capacity_generation{0};
};

FetchMemoryBudgetState fetch_memory;

void updatePeak(uint64_t candidate) noexcept {
  uint64_t peak = fetch_memory.peak.load(std::memory_order_relaxed);
  while (candidate > peak &&
         !fetch_memory.peak.compare_exchange_weak(
             peak, candidate, std::memory_order_relaxed,
             std::memory_order_relaxed)) {
  }
}

} // namespace

void configureGlobalFetchMemoryBudget(uint64_t limit) noexcept {
  if (limit == 0)
    return;
  fetch_memory.limit.store(limit, std::memory_order_release);
  fetch_memory.enabled.store(true, std::memory_order_release);
  fetch_memory.capacity_generation.fetch_add(1, std::memory_order_acq_rel);
}

bool resetGlobalFetchMemoryBudget() noexcept {
  if (fetch_memory.used.load(std::memory_order_acquire) != 0 ||
      fetch_memory.waiters.load(std::memory_order_acquire) != 0)
    return false;
  fetch_memory.enabled.store(false, std::memory_order_release);
  fetch_memory.limit.store(0, std::memory_order_release);
  fetch_memory.peak.store(0, std::memory_order_relaxed);
  fetch_memory.wait_total.store(0, std::memory_order_relaxed);
  fetch_memory.resumed_total.store(0, std::memory_order_relaxed);
  fetch_memory.capacity_generation.fetch_add(1,
                                              std::memory_order_acq_rel);
  return true;
}

FetchMemoryBudgetSnapshot globalFetchMemoryBudgetSnapshot() noexcept {
  return {
      fetch_memory.enabled.load(std::memory_order_acquire),
      fetch_memory.limit.load(std::memory_order_acquire),
      fetch_memory.used.load(std::memory_order_relaxed),
      fetch_memory.peak.load(std::memory_order_relaxed),
      fetch_memory.waiters.load(std::memory_order_relaxed),
      fetch_memory.wait_total.load(std::memory_order_relaxed),
      fetch_memory.resumed_total.load(std::memory_order_relaxed),
      fetch_memory.capacity_generation.load(std::memory_order_acquire),
  };
}

uint64_t globalFetchMemoryCapacityGeneration() noexcept {
  return fetch_memory.capacity_generation.load(std::memory_order_acquire);
}

void noteGlobalFetchMemoryWaiterAdded() noexcept {
  fetch_memory.waiters.fetch_add(1, std::memory_order_relaxed);
  fetch_memory.wait_total.fetch_add(1, std::memory_order_relaxed);
}

void noteGlobalFetchMemoryWaiterRemoved(bool resumed) noexcept {
  uint64_t current = fetch_memory.waiters.load(std::memory_order_acquire);
  while (current != 0 &&
         !fetch_memory.waiters.compare_exchange_weak(
             current, current - 1, std::memory_order_acq_rel,
             std::memory_order_acquire)) {
  }
  if (resumed)
    fetch_memory.resumed_total.fetch_add(1, std::memory_order_relaxed);
}

bool FetchMemoryLease::acquire(uint64_t bytes) noexcept {
  if (bytes == 0)
    return true;
  if (!fetch_memory.enabled.load(std::memory_order_acquire))
    return true;

  const uint64_t limit = fetch_memory.limit.load(std::memory_order_acquire);
  uint64_t current = fetch_memory.used.load(std::memory_order_acquire);
  for (;;) {
    if (bytes > limit || current > limit - bytes ||
        current > std::numeric_limits<uint64_t>::max() - bytes)
      return false;
    if (fetch_memory.used.compare_exchange_weak(
            current, current + bytes, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      bytes_ += bytes;
      charged_ = true;
      updatePeak(current + bytes);
      return true;
    }
  }
}

void FetchMemoryLease::reset() noexcept {
  if (charged_ && bytes_ != 0) {
    fetch_memory.used.fetch_sub(bytes_, std::memory_order_acq_rel);
    fetch_memory.capacity_generation.fetch_add(1,
                                                std::memory_order_acq_rel);
  }
  bytes_ = 0;
  charged_ = false;
}
