#ifndef FORCE_MAX_MEMORY_H_INCLUDED
#define FORCE_MAX_MEMORY_H_INCLUDED

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <utility>

// The force_max pools are ceilings over one ledger, not disjoint shares of
// RAM. This ledger is enabled before accepting work and stays enabled until
// its last lease is released. Other resource-control modes remain inert.
namespace force_max_memory {
inline std::atomic<uint64_t> limit{0};
inline std::atomic<uint64_t> used{0};
inline std::atomic<uint64_t> peak{0};
inline std::atomic<uint64_t> active_limit{0};
inline std::atomic<uint64_t> released_total{0};
inline std::atomic<bool> physical_guard{false};
inline void lowerActiveLimit(uint64_t bytes) noexcept {
  uint64_t current = active_limit.load();
  while (!active_limit.compare_exchange_weak(
      current, current - std::min(current, bytes))) {}
}
struct PhysicalSample {
  uint64_t released;
  uint64_t used;
};
inline PhysicalSample beginPhysicalSample() noexcept {
  // Read release generation first: an overlapping release can only make the
  // captured usage conservative, never create extra allocation credit.
  return {released_total.load(std::memory_order_acquire),
          used.load(std::memory_order_acquire)};
}
inline void refreshPhysicalHeadroom(PhysicalSample sample, uint64_t headroom,
                                    uint64_t reserve) noexcept {
  const uint64_t observed_releases = released_total.load();
  const uint64_t released = observed_releases - sample.released;
  const uint64_t existing = sample.used - std::min(sample.used, released);
  const uint64_t free = headroom > reserve ? headroom - reserve : 0;
  const uint64_t maximum = limit.load();
  if (maximum == 0) return;
  active_limit.store(free > maximum - std::min(maximum, existing)
                         ? maximum : existing + free,
                     std::memory_order_release);
  // A release racing the publication must not be overwritten and turn an
  // unused estimate into new physical credit. A duplicate subtraction is
  // conservative and corrected by the next sample.
  lowerActiveLimit(released_total.load() - observed_releases);
}
inline uint64_t availableLimit() noexcept {
  return physical_guard.load() ? std::min(limit.load(), active_limit.load())
                               : limit.load();
}
using Reclaimer = void (*)() noexcept;
inline std::atomic<Reclaimer> reclaimer{nullptr};
inline void reclaimCaches() noexcept {
  if (auto reclaim = reclaimer.load(std::memory_order_acquire)) reclaim();
}

inline bool acquire(uint64_t bytes) noexcept {
  if (limit.load(std::memory_order_acquire) == 0 || bytes == 0)
    return true;
  uint64_t current = used.load(std::memory_order_acquire);
  for (;;) {
    const uint64_t maximum = availableLimit();
    if (bytes > maximum || current > maximum - bytes)
      return false;
    if (used.compare_exchange_weak(current, current + bytes,
                                   std::memory_order_acq_rel)) {
      if (current + bytes > availableLimit()) {
        used.fetch_sub(bytes);
        released_total.fetch_add(bytes);
        if (physical_guard.load()) lowerActiveLimit(bytes);
        return false;
      }
      uint64_t previous = peak.load(std::memory_order_relaxed);
      while (previous < current + bytes &&
             !peak.compare_exchange_weak(previous, current + bytes,
                                        std::memory_order_relaxed)) {}
      return true;
    }
  }
}

inline void release(uint64_t bytes) noexcept {
  if (limit.load(std::memory_order_acquire) != 0 && bytes != 0) {
    used.fetch_sub(bytes, std::memory_order_acq_rel);
    released_total.fetch_add(bytes, std::memory_order_acq_rel);
    // Lease shrink can release an estimate rather than physical pages. Only
    // a fresh kernel sample may replenish physical allocation credit.
    if (physical_guard.load()) {
      lowerActiveLimit(bytes);
    }
  }
}

// Only the startup/rollback transaction may configure the shared ledger.
inline bool configure(uint64_t maximum, uint64_t retained = 0) noexcept {
  if (used.load(std::memory_order_acquire) != 0 || retained > maximum)
    return false;
  used.store(retained, std::memory_order_release);
  peak.store(retained, std::memory_order_relaxed);
  released_total.store(0);
  active_limit.store(maximum);
  physical_guard.store(false);
  limit.store(maximum, std::memory_order_release);
  return true;
}

class Lease {
public:
  Lease() = default;
  ~Lease() { reset(); }
  Lease(Lease &&other) noexcept : bytes_(std::exchange(other.bytes_, 0)) {}
  Lease &operator=(Lease &&other) noexcept {
    if (this != &other) { reset(); bytes_ = std::exchange(other.bytes_, 0); }
    return *this;
  }
  Lease(const Lease &) = delete;
  Lease &operator=(const Lease &) = delete;
  bool acquire(uint64_t bytes) noexcept {
    if (limit.load(std::memory_order_acquire) == 0)
      return true;
    if (!force_max_memory::acquire(bytes))
      return false;
    bytes_ += bytes;
    return true;
  }
  void reset() noexcept { force_max_memory::release(std::exchange(bytes_, 0)); }
  uint64_t bytes() const noexcept { return bytes_; }
  uint64_t relinquish() noexcept { return std::exchange(bytes_, 0); }
private:
  uint64_t bytes_ = 0;
};
} // namespace force_max_memory

#endif
