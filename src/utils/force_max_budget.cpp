#include "utils/force_max_budget.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace {

bool checkedAdd(uint64_t left, uint64_t right, uint64_t &result) noexcept {
  if (right > std::numeric_limits<uint64_t>::max() - left)
    return false;
  result = left + right;
  return true;
}

bool checkedMultiply(uint64_t left, uint64_t right,
                     uint64_t &result) noexcept {
  if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left)
    return false;
  result = left * right;
  return true;
}

uint64_t ceilDivide(uint64_t value, uint64_t divisor) noexcept {
  return value / divisor + (value % divisor != 0 ? 1 : 0);
}

uint64_t fraction(uint64_t value, uint64_t numerator,
                  uint64_t denominator) noexcept {
  return value / denominator * numerator +
         value % denominator * numerator / denominator;
}

bool fail(ForceMaxBudget &budget, const char *error) noexcept {
  budget.valid = false;
  budget.validation_error = error;
  return false;
}

bool assignScaled(uint64_t value, uint64_t scale, uint64_t &target,
                  ForceMaxBudget &budget) noexcept {
  if (!checkedMultiply(value, scale, target))
    return fail(budget, "integer_overflow");
  return true;
}

} // namespace

bool validateForceMaxBudget(const ForceMaxBudget &budget,
                            std::string *error) noexcept {
  auto invalid = [&](const char *message) {
    if (error)
      *error = message;
    return false;
  };
  if (budget.formula_revision.empty())
    return invalid("missing_formula_revision");
  if (budget.compute_workers == 0 || budget.compute_permits == 0 ||
      budget.io_runners == 0 || budget.handler_permits == 0 ||
      budget.active_owners == 0 || budget.active_flows == 0)
    return invalid("zero_runtime_capacity");
  if (budget.active_owners > budget.active_flows)
    return invalid("owners_exceed_flows");
  uint64_t minimum_inbound_connections = 0;
  if (!checkedMultiply(budget.active_flows, 2,
                       minimum_inbound_connections) ||
      budget.inbound_connections < minimum_inbound_connections)
    return invalid("insufficient_inbound_connection_headroom");
  if (budget.outbound_active == 0 ||
      budget.outbound_per_host > budget.outbound_active ||
      budget.outbound_active > budget.outbound_open ||
      budget.outbound_idle_cache !=
          budget.outbound_open - budget.outbound_active)
    return invalid("invalid_outbound_capacity");
  if (budget.transport_queue_entries == 0 ||
      budget.owner_queue_entries == 0 || budget.flow_queue_entries == 0 ||
      budget.blocking_io_queue_entries == 0 ||
      budget.transport_queue_bytes == 0 || budget.owner_queue_bytes == 0 ||
      budget.flow_queue_bytes == 0 || budget.blocking_io_queue_bytes == 0)
    return invalid("zero_queue_capacity");
  uint64_t queue_total = 0;
  if (!checkedAdd(budget.transport_queue_bytes,
                  budget.owner_queue_bytes, queue_total) ||
      !checkedAdd(queue_total, budget.flow_queue_bytes, queue_total) ||
      !checkedAdd(queue_total, budget.blocking_io_queue_bytes,
                  queue_total))
    return invalid("queue_budget_overflow");
  uint64_t memory_total = 0;
  for (uint64_t component :
       {budget.reserved_memory_bytes, budget.retained_response_bytes,
        budget.fetch_bytes, budget.cache_bytes,
        budget.working_memory_bytes, queue_total}) {
    if (!checkedAdd(memory_total, component, memory_total))
      return invalid("memory_budget_overflow");
  }
  if (memory_total != budget.memory_budget_total)
    return invalid("memory_budget_partition_mismatch");
  if (budget.quickjs_workers == 0 || budget.quickjs_queue_entries == 0 ||
      budget.quickjs_queue_bytes == 0 ||
      budget.quickjs_heap_bytes_per_worker == 0 ||
      budget.quickjs_stack_bytes_per_worker == 0)
    return invalid("invalid_quickjs_budget");
  uint64_t quickjs_worker_bytes = 0;
  uint64_t quickjs_total_bytes = 0;
  if (!checkedAdd(budget.quickjs_heap_bytes_per_worker,
                  budget.quickjs_stack_bytes_per_worker,
                  quickjs_worker_bytes) ||
      !checkedMultiply(quickjs_worker_bytes, budget.quickjs_workers,
                       quickjs_total_bytes) ||
      !checkedAdd(quickjs_total_bytes, budget.quickjs_queue_bytes,
                  quickjs_total_bytes) ||
      quickjs_total_bytes > budget.working_memory_bytes)
    return invalid("quickjs_budget_exceeds_working_memory");
  if (budget.transport_active_bytes == 0 ||
      budget.owner_active_bytes == 0)
    return invalid("invalid_active_byte_budget");
  if (budget.fetch_bytes < UINT64_C(64) * 1024)
    return invalid("fetch_budget_too_small");
  uint64_t active_memory_total = 0;
  if (!checkedAdd(quickjs_total_bytes, budget.transport_active_bytes,
                  active_memory_total) ||
      !checkedAdd(active_memory_total, budget.owner_active_bytes,
                  active_memory_total) ||
      active_memory_total > budget.working_memory_bytes)
    return invalid("active_bytes_exceed_working_memory");
  if (error)
    error->clear();
  return true;
}

ForceMaxBudget calculateForceMaxBudget(
    const ResourceEnvelope &envelope) noexcept {
  ForceMaxBudget budget;
  budget.envelope_complete = envelope.complete;

  const uint64_t cpu_millis =
      std::max<uint64_t>(1, envelope.schedulable_cpu_millis);
  const uint64_t cpu_units = std::max<uint64_t>(1, ceilDivide(cpu_millis, 1000));
  budget.compute_workers = cpu_units;
  budget.compute_permits = cpu_units;
  budget.io_runners = std::max<uint64_t>(1, ceilDivide(cpu_units, 4));
  if (!assignScaled(cpu_units, 4, budget.handler_permits, budget) ||
      !assignScaled(cpu_units, 8, budget.active_owners, budget) ||
      !assignScaled(cpu_units, 16, budget.active_flows, budget))
    return budget;

  if (envelope.pids_max != 0) {
    const uint64_t remaining =
        envelope.pids_max > envelope.pids_current
            ? envelope.pids_max - envelope.pids_current
            : 0;
    const uint64_t available = remaining > 8 ? remaining - 8 : 0;
    if (available == 0) {
      fail(budget, "pids_exhausted");
      return budget;
    }
    budget.compute_workers = std::min(budget.compute_workers, available);
    budget.compute_permits =
        std::min(budget.compute_permits, budget.compute_workers);
    budget.io_runners = std::min(budget.io_runners, available);
  }

  uint64_t fallback_fds = 0;
  if (!assignScaled(cpu_units, 64, fallback_fds, budget))
    return budget;
  fallback_fds = std::max<uint64_t>(1024, fallback_fds);
  const uint64_t fd_boundary =
      envelope.nofile_soft != 0 ? envelope.nofile_soft : fallback_fds;
  budget.reserved_fds =
      std::min<uint64_t>(fd_boundary / 2,
                         std::max<uint64_t>(64, ceilDivide(fd_boundary, 32)));
  const uint64_t committed_fds =
      std::min(envelope.open_fds, fd_boundary);
  const uint64_t usable_fds =
      fd_boundary > committed_fds + budget.reserved_fds
          ? fd_boundary - committed_fds - budget.reserved_fds
          : 0;
  if (usable_fds < 2) {
    fail(budget, "nofile_exhausted");
    return budget;
  }
  uint64_t desired_outbound = 0;
  uint64_t desired_open = 0;
  uint64_t desired_inbound = 0;
  if (!assignScaled(cpu_units, 16, desired_outbound, budget) ||
      !assignScaled(desired_outbound, 4, desired_open, budget) ||
      !assignScaled(cpu_units, 64, desired_inbound, budget))
    return budget;
  const uint64_t outbound_fd_budget = usable_fds / 2;
  budget.outbound_open = std::min(desired_open, outbound_fd_budget);
  budget.inbound_connections =
      std::min(desired_inbound, usable_fds - budget.outbound_open);
  if (budget.outbound_open < 2 || budget.inbound_connections < 2) {
    fail(budget, "insufficient_connection_fds");
    return budget;
  }
  budget.outbound_active =
      std::min(desired_outbound,
               std::max<uint64_t>(1, budget.outbound_open / 2));
  budget.outbound_per_host = std::min(
      budget.outbound_active,
      std::max<uint64_t>(1, ceilDivide(budget.outbound_active, 4)));
  budget.outbound_idle_cache =
      budget.outbound_open - budget.outbound_active;

  uint64_t memory_boundary = resourceEnvelopeMemoryBoundary(envelope);
  if (memory_boundary == 0)
    memory_boundary = UINT64_C(256) * 1024 * 1024;
  if (memory_boundary < UINT64_C(8) * 1024 * 1024) {
    fail(budget, "memory_boundary_too_small");
    return budget;
  }
  budget.memory_budget_total = memory_boundary;
  budget.reserved_memory_bytes = fraction(memory_boundary, 1, 8);
  const uint64_t allocatable =
      memory_boundary - budget.reserved_memory_bytes;
  budget.retained_response_bytes = fraction(allocatable, 2, 10);
  budget.fetch_bytes = fraction(allocatable, 2, 10);
  budget.cache_bytes = fraction(allocatable, 2, 10);
  budget.working_memory_bytes = fraction(allocatable, 3, 10);
  const uint64_t queue_bytes =
      memory_boundary - budget.reserved_memory_bytes -
      budget.retained_response_bytes - budget.fetch_bytes -
      budget.cache_bytes - budget.working_memory_bytes;
  budget.transport_queue_bytes = queue_bytes / 2;
  budget.owner_queue_bytes = queue_bytes / 4;
  budget.flow_queue_bytes = queue_bytes / 8;
  budget.blocking_io_queue_bytes =
      queue_bytes - budget.transport_queue_bytes -
      budget.owner_queue_bytes - budget.flow_queue_bytes;
  budget.transport_queue_entries = std::max<uint64_t>(
      1, std::min<uint64_t>(usable_fds,
                            budget.transport_queue_bytes / 4096));
  budget.owner_queue_entries = std::max<uint64_t>(
      1, budget.owner_queue_bytes / (UINT64_C(64) * 1024));
  budget.flow_queue_entries = std::max<uint64_t>(
      1, budget.flow_queue_bytes / (UINT64_C(16) * 1024));
  budget.blocking_io_queue_entries = std::max<uint64_t>(
      1, budget.blocking_io_queue_bytes / (UINT64_C(64) * 1024));

  budget.active_owners = std::min(
      budget.active_owners,
      std::max<uint64_t>(1, budget.working_memory_bytes /
                                (UINT64_C(1) * 1024 * 1024)));
  budget.active_flows = std::max(
      budget.active_owners,
      std::min(budget.active_flows,
               std::max<uint64_t>(1, budget.working_memory_bytes /
                                          (UINT64_C(512) * 1024))));
  budget.active_flows = std::min(
      budget.active_flows,
      std::max<uint64_t>(1, budget.inbound_connections / 2));
  budget.active_owners =
      std::min(budget.active_owners, budget.active_flows);
  budget.quickjs_workers =
      std::max<uint64_t>(1, budget.compute_workers / 2);
  budget.quickjs_queue_bytes =
      std::max<uint64_t>(1, budget.working_memory_bytes / 8);
  budget.quickjs_queue_entries = std::max<uint64_t>(
      1, budget.quickjs_queue_bytes / (UINT64_C(256) * 1024));
  const uint64_t quickjs_worker_pool =
      std::max<uint64_t>(1, budget.working_memory_bytes / 8);
  const uint64_t quickjs_worker_bytes =
      std::max<uint64_t>(2,
          quickjs_worker_pool / budget.quickjs_workers);
  budget.quickjs_stack_bytes_per_worker = std::min<uint64_t>(
      UINT64_C(1) * 1024 * 1024,
      std::max<uint64_t>(UINT64_C(64) * 1024,
                         quickjs_worker_bytes / 16));
  if (budget.quickjs_stack_bytes_per_worker >= quickjs_worker_bytes)
    budget.quickjs_stack_bytes_per_worker =
        std::max<uint64_t>(1, quickjs_worker_bytes / 4);
  budget.quickjs_heap_bytes_per_worker =
      quickjs_worker_bytes - budget.quickjs_stack_bytes_per_worker;
  uint64_t quickjs_total = budget.quickjs_queue_bytes;
  const uint64_t quickjs_per_worker =
      budget.quickjs_heap_bytes_per_worker +
      budget.quickjs_stack_bytes_per_worker;
  quickjs_total += quickjs_per_worker * budget.quickjs_workers;
  budget.transport_active_bytes =
      std::max<uint64_t>(1, budget.working_memory_bytes / 4);
  budget.owner_active_bytes =
      std::max<uint64_t>(
          1, budget.working_memory_bytes - quickjs_total -
                 budget.transport_active_bytes);

  std::string error;
  budget.valid = validateForceMaxBudget(budget, &error);
  budget.validation_error = std::move(error);
  return budget;
}
