#include "utils/resource_probe.h"

#include <algorithm>
#include <limits>

#include "utils/resource_control.h"

uint64_t resourceEnvelopeMemoryBoundary(
    const ResourceEnvelope &envelope) noexcept {
  uint64_t boundary = envelope.memory_max_bytes;
  if (envelope.memory_high_bytes != 0)
    boundary = boundary == 0
                   ? envelope.memory_high_bytes
                   : std::min(boundary, envelope.memory_high_bytes);
  if (boundary == 0)
    boundary = envelope.host_total_memory_bytes;
  return boundary;
}

ResourceMemoryLedger resourceEnvelopeMemoryLedger(
    const ResourceEnvelope &envelope) noexcept {
  ResourceMemoryLedger ledger;
  ledger.startup_bytes = envelope.memory_current_bytes;
  if (ledger.startup_bytes == 0)
    return ledger;

  const uint64_t configured_boundary =
      resourceEnvelopeMemoryBoundary(envelope);
  uint64_t headroom = 0;
  if (configured_boundary != 0) {
    if (ledger.startup_bytes >= configured_boundary)
      return ledger;
    headroom = configured_boundary - ledger.startup_bytes;
  } else {
    headroom = envelope.host_available_memory_bytes;
  }

  if (envelope.host_available_memory_bytes != 0)
    headroom = std::min(headroom, envelope.host_available_memory_bytes);
  headroom = std::min(
      headroom,
      std::numeric_limits<uint64_t>::max() - ledger.startup_bytes);
  if (headroom == 0)
    return ledger;

  ledger.headroom_bytes = headroom;
  ledger.capacity_bytes = ledger.startup_bytes + ledger.headroom_bytes;
  ledger.valid = true;
  return ledger;
}

ResourceEnvelope resourceEnvelopeFromSnapshot(
    const ResourceControlSnapshot &snapshot) noexcept {
  ResourceEnvelope envelope;
  envelope.affinity_cpu_millis = snapshot.affinity_cpus * 1000;
  envelope.cpuset_cpu_millis = snapshot.cpuset_cpus * 1000;
  envelope.quota_cpu_millis = snapshot.cpu_quota_millis;
  envelope.schedulable_cpu_millis =
      std::max<uint64_t>(1, snapshot.effective_cpu_millis);
  envelope.memory_current_bytes = snapshot.memory_current_bytes;
  envelope.memory_high_bytes = snapshot.memory_high_bytes;
  envelope.memory_max_bytes = snapshot.memory_max_bytes;
  envelope.host_total_memory_bytes = snapshot.host_total_memory_bytes;
  envelope.host_available_memory_bytes =
      snapshot.host_available_memory_bytes;
  envelope.nofile_soft = snapshot.nofile_soft;
  envelope.nofile_hard = snapshot.nofile_hard;
  envelope.open_fds = snapshot.open_fds;
  envelope.pids_current = snapshot.pids_current;
  envelope.pids_max = snapshot.pids_max;
  envelope.self_threads = snapshot.self_threads;
  envelope.resolver_threads_per_transfer =
      snapshot.resolver_may_use_threads ? 1 : 0;
  envelope.http_handler_threads_per_compute =
      std::max<uint64_t>(1,
                         snapshot.http_handler_threads_per_compute);
  envelope.affinity_available = snapshot.affinity_cpus != 0;
  envelope.cpuset_available = snapshot.cpuset_cpus != 0;
  envelope.quota_available = snapshot.cpu_quota_millis != 0;
  envelope.memory_limit_available =
      snapshot.memory_max_bytes != 0 || snapshot.memory_high_bytes != 0;
  envelope.nofile_available = snapshot.nofile_soft != 0;
  envelope.pids_available = snapshot.pids_max != 0;
  envelope.cgroup_scope_known = snapshot.cgroup_scope_known;
  envelope.psi_available = snapshot.cpu_pressure_available ||
                           snapshot.memory_pressure_available ||
                           snapshot.io_pressure_available;
  envelope.memory_events_available = snapshot.memory_events_supported;
  envelope.complete = snapshot.hardware_detected;
  return envelope;
}
