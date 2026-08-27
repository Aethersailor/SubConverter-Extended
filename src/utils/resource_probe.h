#ifndef RESOURCE_PROBE_H_INCLUDED
#define RESOURCE_PROBE_H_INCLUDED

#include <cstdint>

struct ResourceControlSnapshot;

struct ResourceEnvelope {
  uint64_t affinity_cpu_millis = 0;
  uint64_t cpuset_cpu_millis = 0;
  uint64_t quota_cpu_millis = 0;
  uint64_t schedulable_cpu_millis = 1000;

  uint64_t memory_current_bytes = 0;
  uint64_t memory_high_bytes = 0;
  uint64_t memory_max_bytes = 0;
  uint64_t host_total_memory_bytes = 0;
  uint64_t host_available_memory_bytes = 0;

  uint64_t nofile_soft = 0;
  uint64_t nofile_hard = 0;
  uint64_t open_fds = 0;
  uint64_t pids_current = 0;
  uint64_t pids_max = 0;
  uint64_t self_threads = 0;
  uint64_t resolver_threads_per_transfer = 1;
  uint64_t http_handler_threads_per_compute = 4;

  bool affinity_available = false;
  bool cpuset_available = false;
  bool quota_available = false;
  bool memory_limit_available = false;
  bool nofile_available = false;
  bool pids_available = false;
  bool cgroup_scope_known = true;
  bool psi_available = false;
  bool memory_events_available = false;
  bool complete = false;

  bool operator==(const ResourceEnvelope &) const = default;
};

struct ResourceMemoryLedger {
  bool valid = false;
  uint64_t capacity_bytes = 0;
  uint64_t startup_bytes = 0;
  uint64_t headroom_bytes = 0;

  bool operator==(const ResourceMemoryLedger &) const = default;
};

uint64_t resourceEnvelopeMemoryBoundary(
    const ResourceEnvelope &envelope) noexcept;
ResourceMemoryLedger resourceEnvelopeMemoryLedger(
    const ResourceEnvelope &envelope) noexcept;
ResourceEnvelope resourceEnvelopeFromSnapshot(
    const ResourceControlSnapshot &snapshot) noexcept;

#endif // RESOURCE_PROBE_H_INCLUDED
