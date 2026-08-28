#ifndef FORCE_MAX_BUDGET_H_INCLUDED
#define FORCE_MAX_BUDGET_H_INCLUDED

#include <cstdint>
#include <string>

#include "utils/resource_probe.h"

inline constexpr const char *kForceMaxFormulaRevision = "force-max-v5";
inline constexpr uint64_t kForceMaxOwnerWaitMetadataBytes =
    UINT64_C(64) * 1024;

struct ForceMaxOwnerReservationBudget {
  bool valid = false;
  uint64_t active_owners = 0;
  uint64_t owner_active_bytes = 0;
};

struct ForceMaxBudget {
  std::string formula_revision = kForceMaxFormulaRevision;
  bool valid = false;
  bool envelope_complete = false;
  std::string validation_error;

  uint64_t compute_workers = 0;
  uint64_t compute_permits = 0;
  uint64_t io_runners = 0;
  uint64_t handler_permits = 0;
  uint64_t active_owners = 0;
  uint64_t active_flows = 0;
  uint64_t inbound_connections = 0;

  uint64_t outbound_active = 0;
  uint64_t outbound_per_host = 0;
  uint64_t outbound_open = 0;
  uint64_t outbound_idle_cache = 0;

  uint64_t transport_queue_entries = 0;
  uint64_t transport_queue_bytes = 0;
  uint64_t owner_queue_entries = 0;
  uint64_t owner_queue_bytes = 0;
  uint64_t flow_queue_entries = 0;
  uint64_t flow_queue_bytes = 0;
  uint64_t blocking_io_queue_entries = 0;
  uint64_t blocking_io_queue_bytes = 0;

  uint64_t retained_response_bytes = 0;
  uint64_t fetch_bytes = 0;
  uint64_t cache_bytes = 0;
  uint64_t working_memory_bytes = 0;
  uint64_t memory_capacity_bytes = 0;
  uint64_t startup_memory_bytes = 0;
  uint64_t memory_headroom_bytes = 0;
  uint64_t memory_budget_total = 0;
  uint64_t transport_active_bytes = 0;
  uint64_t owner_active_bytes = 0;

  uint64_t quickjs_workers = 0;
  uint64_t quickjs_queue_entries = 0;
  uint64_t quickjs_queue_bytes = 0;
  uint64_t quickjs_heap_bytes_per_worker = 0;
  uint64_t quickjs_stack_bytes_per_worker = 0;

  uint64_t reserved_fds = 0;
  uint64_t reserved_pids = 0;
  uint64_t fixed_threads = 0;
  uint64_t resolver_thread_budget = 0;
  uint64_t thread_budget_total = 0;
  uint64_t handler_stack_bytes = 0;
  uint64_t reserved_memory_bytes = 0;

  bool operator==(const ForceMaxBudget &) const = default;
};

ForceMaxBudget calculateForceMaxBudget(
    const ResourceEnvelope &envelope) noexcept;
bool validateForceMaxBudget(const ForceMaxBudget &budget,
                            std::string *error = nullptr) noexcept;
bool validateForceMaxFetchContract(const ForceMaxBudget &budget,
                                   uint64_t maximum_download_bytes,
                                   std::string *error = nullptr) noexcept;
uint64_t forceMaxOwnerWorkingReservation(
    const ForceMaxBudget &budget, uint64_t request_bytes,
    uint64_t maximum_download_bytes) noexcept;
uint64_t forceMaxOwnerWorkingReservation(
    const ForceMaxOwnerReservationBudget &budget, uint64_t request_bytes,
    uint64_t maximum_download_bytes) noexcept;
uint64_t forceMaxOwnerWaitReservation(uint64_t request_bytes) noexcept;

#endif // FORCE_MAX_BUDGET_H_INCLUDED
