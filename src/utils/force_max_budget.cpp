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
  if (budget.formula_revision != kForceMaxFormulaRevision)
    return invalid("unsupported_formula_revision");
  if (budget.compute_workers == 0 || budget.compute_permits == 0 ||
      budget.io_runners == 0 || budget.handler_permits == 0 ||
      budget.active_owners == 0 || budget.active_flows == 0)
    return invalid("zero_runtime_capacity");
  if (budget.active_owners > budget.active_flows)
    return invalid("owners_exceed_flows");
  uint64_t minimum_inbound_connections = 0;
  if (!checkedMultiply(budget.active_flows, 2,
                        minimum_inbound_connections) ||
      !checkedAdd(minimum_inbound_connections, 2,
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
  uint64_t accounted_capacity = 0;
  if (budget.startup_memory_bytes == 0 ||
      budget.memory_headroom_bytes == 0 ||
      budget.memory_budget_total != budget.memory_headroom_bytes ||
      !checkedAdd(budget.startup_memory_bytes,
                  budget.memory_headroom_bytes, accounted_capacity) ||
      accounted_capacity != budget.memory_capacity_bytes)
    return invalid("invalid_memory_ledger");
  if (budget.quickjs_workers == 0 || budget.quickjs_queue_entries == 0 ||
      budget.quickjs_queue_bytes == 0 ||
      budget.quickjs_heap_bytes_per_worker == 0 ||
      budget.quickjs_stack_bytes_per_worker == 0)
    return invalid("invalid_quickjs_budget");
  if (budget.reserved_pids == 0 || budget.fixed_threads == 0 ||
      budget.thread_budget_total == 0)
    return invalid("invalid_thread_budget");
  uint64_t expected_threads = 0;
  for (uint64_t component :
       {budget.compute_workers, budget.handler_permits,
        budget.io_runners, budget.quickjs_workers,
        budget.io_runners, budget.fixed_threads,
        budget.resolver_thread_budget, budget.reserved_pids}) {
    if (!checkedAdd(expected_threads, component, expected_threads))
      return invalid("thread_budget_overflow");
  }
  if (expected_threads != budget.thread_budget_total)
    return invalid("thread_budget_mismatch");
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

bool validateForceMaxFetchContract(const ForceMaxBudget &budget,
                                   uint64_t maximum_download_bytes,
                                   std::string *error) noexcept {
  auto invalid = [&](const char *message) {
    if (error)
      *error = message;
    return false;
  };
  std::string budget_error;
  if (!validateForceMaxBudget(budget, &budget_error)) {
    if (error)
      *error = std::move(budget_error);
    return false;
  }
  if (maximum_download_bytes == 0)
    return invalid("invalid_maximum_download_size");
  if (budget.fetch_bytes < maximum_download_bytes)
    return invalid("fetch_budget_below_download_contract");
  uint64_t expanded_working_contract = 0;
  if (!checkedMultiply(maximum_download_bytes, 4,
                       expanded_working_contract))
    return invalid("working_download_contract_overflow");
  if (budget.owner_active_bytes < expanded_working_contract)
    return invalid("working_budget_below_download_contract");
  if (error)
    error->clear();
  return true;
}

uint64_t forceMaxOwnerWorkingReservation(
    const ForceMaxBudget &budget, uint64_t request_bytes,
    uint64_t maximum_download_bytes) noexcept {
  if (!budget.valid || budget.active_owners == 0 ||
      budget.owner_active_bytes == 0)
    return request_bytes;
  const uint64_t owner_slice =
      ceilDivide(budget.owner_active_bytes, budget.active_owners);
  uint64_t expanded_download = maximum_download_bytes;
  if (!checkedMultiply(maximum_download_bytes, 4, expanded_download))
    expanded_download = budget.owner_active_bytes;
  const uint64_t reservation = std::max(
      request_bytes, std::max(owner_slice, expanded_download));
  // A single oversized owner is still allowed to make progress, but it owns
  // the entire working partition and therefore serializes against peers.
  return std::min(reservation, budget.owner_active_bytes);
}

ForceMaxBudget calculateForceMaxBudget(
    const ResourceEnvelope &envelope) noexcept {
  ForceMaxBudget budget;
  budget.envelope_complete = envelope.complete;
  if (!envelope.cgroup_scope_known) {
    fail(budget, "unknown_cgroup_scope");
    return budget;
  }

  const uint64_t cpu_millis =
      std::max<uint64_t>(1, envelope.schedulable_cpu_millis);
  const uint64_t cpu_units = std::max<uint64_t>(1, ceilDivide(cpu_millis, 1000));
  budget.compute_workers = cpu_units;
  budget.compute_permits = cpu_units;
  budget.io_runners = std::max<uint64_t>(1, ceilDivide(cpu_units, 4));
  const uint64_t handler_threads_per_compute =
      std::max<uint64_t>(1,
                         envelope.http_handler_threads_per_compute);
  if (!assignScaled(cpu_units, handler_threads_per_compute,
                    budget.handler_permits, budget) ||
      !assignScaled(cpu_units, 8, budget.active_owners, budget) ||
      !assignScaled(cpu_units, 16, budget.active_flows, budget))
    return budget;

  budget.fixed_threads = 7;
  auto threadRequirement = [&](uint64_t compute, uint64_t &io,
                                uint64_t &handlers, uint64_t &quickjs,
                                uint64_t &resolver_threads,
                                uint64_t &transient_reserve,
                                uint64_t &total) {
    io = std::max<uint64_t>(1, ceilDivide(compute, 4));
    if (!checkedMultiply(compute, handler_threads_per_compute,
                         handlers))
      return false;
    handlers = std::max<uint64_t>(1, handlers);
    quickjs = std::max<uint64_t>(1, compute / 2);
    const uint64_t ruleset_workers = io;
    transient_reserve = std::max<uint64_t>(4, compute);
    uint64_t resolver_transfers = 0;
    if (!checkedMultiply(compute, 16, resolver_transfers) ||
        !checkedMultiply(resolver_transfers,
                         envelope.resolver_threads_per_transfer,
                         resolver_threads))
      return false;
    uint64_t variable = 0;
    return checkedAdd(compute, handlers, variable) &&
           checkedAdd(variable, io, variable) &&
           checkedAdd(variable, quickjs, variable) &&
           checkedAdd(variable, ruleset_workers, variable) &&
           checkedAdd(variable, resolver_threads, variable) &&
           checkedAdd(variable, budget.fixed_threads, variable) &&
           checkedAdd(variable, transient_reserve, total);
  };

  uint64_t pids_io = 0;
  uint64_t pids_handlers = 0;
  uint64_t pids_quickjs = 0;
  uint64_t pids_resolver = 0;
  uint64_t pids_transient = 0;
  uint64_t pids_total = 0;

  if (envelope.pids_max != 0) {
    const uint64_t remaining =
        envelope.pids_max > envelope.pids_current
            ? envelope.pids_max - envelope.pids_current
            : 0;
    uint64_t selected_compute = budget.compute_workers;
    while (selected_compute != 0 &&
            (!threadRequirement(selected_compute, pids_io,
                                pids_handlers, pids_quickjs,
                                pids_resolver, pids_transient,
                                pids_total) ||
            pids_total > remaining))
      --selected_compute;
    if (selected_compute == 0) {
      fail(budget, "pids_exhausted");
      return budget;
    }
    budget.compute_workers = selected_compute;
    budget.compute_permits = selected_compute;
    budget.io_runners = pids_io;
    budget.handler_permits = pids_handlers;
    budget.resolver_thread_budget = pids_resolver;
    budget.reserved_pids = pids_transient;
    budget.thread_budget_total = pids_total;
  } else {
    if (!threadRequirement(budget.compute_workers, pids_io,
                            pids_handlers, pids_quickjs,
                            pids_resolver, pids_transient,
                            pids_total)) {
      fail(budget, "integer_overflow");
      return budget;
    }
    budget.resolver_thread_budget = pids_resolver;
    budget.reserved_pids = pids_transient;
    budget.thread_budget_total = pids_total;
  }
  if (!assignScaled(budget.compute_workers, 8, budget.active_owners,
                    budget) ||
      !assignScaled(budget.compute_workers, 16, budget.active_flows,
                    budget))
    return budget;

  uint64_t fallback_fds = 0;
  if (!assignScaled(budget.compute_workers, 64, fallback_fds, budget))
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
  if (!assignScaled(budget.compute_workers, 16, desired_outbound, budget) ||
      !assignScaled(desired_outbound, 4, desired_open, budget) ||
      !assignScaled(budget.compute_workers, 64, desired_inbound, budget))
    return budget;
  const uint64_t outbound_fd_budget = usable_fds / 2;
  budget.outbound_open = std::min(desired_open, outbound_fd_budget);
  budget.inbound_connections =
      std::min(desired_inbound, usable_fds - budget.outbound_open);
  if (budget.outbound_open < 2 || budget.inbound_connections < 4) {
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

  const ResourceMemoryLedger memory_ledger =
      resourceEnvelopeMemoryLedger(envelope);
  if (!memory_ledger.valid) {
    fail(budget, envelope.memory_current_bytes == 0
                     ? "memory_current_unavailable"
                     : "memory_headroom_exhausted");
    return budget;
  }
  if (memory_ledger.headroom_bytes < UINT64_C(8) * 1024 * 1024) {
    fail(budget, "memory_headroom_too_small");
    return budget;
  }
  budget.memory_capacity_bytes = memory_ledger.capacity_bytes;
  budget.startup_memory_bytes = memory_ledger.startup_bytes;
  budget.memory_headroom_bytes = memory_ledger.headroom_bytes;
  budget.memory_budget_total = memory_ledger.headroom_bytes;
  budget.reserved_memory_bytes =
      fraction(budget.memory_headroom_bytes, 1, 8);
  const uint64_t allocatable =
      budget.memory_headroom_bytes - budget.reserved_memory_bytes;
  budget.retained_response_bytes = fraction(allocatable, 2, 10);
  budget.fetch_bytes = fraction(allocatable, 2, 10);
  budget.cache_bytes = fraction(allocatable, 2, 10);
  budget.working_memory_bytes = fraction(allocatable, 3, 10);
  const uint64_t queue_bytes =
      budget.memory_headroom_bytes - budget.reserved_memory_bytes -
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
      std::max<uint64_t>(1, (budget.inbound_connections - 2) / 2));
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
  uint64_t quickjs_per_worker = 0;
  uint64_t quickjs_worker_total = 0;
  uint64_t quickjs_total = 0;
  if (!checkedAdd(budget.quickjs_heap_bytes_per_worker,
                  budget.quickjs_stack_bytes_per_worker,
                  quickjs_per_worker) ||
      !checkedMultiply(quickjs_per_worker, budget.quickjs_workers,
                       quickjs_worker_total) ||
      !checkedAdd(budget.quickjs_queue_bytes, quickjs_worker_total,
                  quickjs_total)) {
    fail(budget, "integer_overflow");
    return budget;
  }
  budget.transport_active_bytes =
      std::max<uint64_t>(1, budget.working_memory_bytes / 4);
  uint64_t committed_working_memory = 0;
  if (!checkedAdd(quickjs_total, budget.transport_active_bytes,
                  committed_working_memory) ||
      committed_working_memory >= budget.working_memory_bytes) {
    fail(budget, "working_memory_too_small");
    return budget;
  }
  budget.owner_active_bytes =
      budget.working_memory_bytes - committed_working_memory;

  std::string error;
  budget.valid = validateForceMaxBudget(budget, &error);
  budget.validation_error = std::move(error);
  return budget;
}
