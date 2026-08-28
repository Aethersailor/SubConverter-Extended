#ifndef RUNTIME_COORDINATOR_H_INCLUDED
#define RUNTIME_COORDINATOR_H_INCLUDED

#include <cstdint>
#include <string>

#include "utils/force_max_budget.h"

struct RuntimeCoordinatorSnapshot {
  bool force_max = false;
  bool prepared = false;
  bool ready = false;
  bool stopping = false;
  bool joined = false;
  bool shutdown_deadline_exceeded = false;
  uint64_t generation = 0;
  uint64_t rollback_total = 0;
  uint64_t shutdown_deadline_ms = 0;
  uint64_t shutdown_elapsed_ms = 0;
  std::string reason = "not_prepared";
  std::string last_failed_stage;
  std::string shutdown_stage = "not_started";
};

struct RuntimeCoordinatorLivenessSnapshot {
  bool force_max = false;
  bool prepared = false;
  bool ready = false;
  bool stopping = false;
  uint64_t generation = 0;
};

struct ForceMaxRuntimeBudgetSlice {
  bool force_max = false;
  bool valid = false;
  uint64_t generation = 0;
  ForceMaxOwnerReservationBudget owner;
  uint64_t active_flows = 0;
  uint64_t flow_queue_entries = 0;
  uint64_t flow_queue_bytes = 0;
  uint64_t quickjs_heap_bytes_per_worker = 0;
};

inline bool forceMaxRuntimeBudgetUsable(
    const ForceMaxRuntimeBudgetSlice &budget,
    const RuntimeCoordinatorLivenessSnapshot &runtime) noexcept {
  return budget.force_max && budget.valid && runtime.force_max &&
         runtime.prepared && runtime.ready && !runtime.stopping &&
         runtime.generation != 0 && runtime.generation == budget.generation;
}

bool prepareRuntimeCoordinator() noexcept;
bool commitRuntimeCoordinator() noexcept;
RuntimeCoordinatorSnapshot runtimeCoordinatorSnapshot() noexcept;
RuntimeCoordinatorLivenessSnapshot
runtimeCoordinatorLivenessSnapshot() noexcept;
ForceMaxRuntimeBudgetSlice forceMaxRuntimeBudgetSlice() noexcept;
void requestRuntimeCoordinatorShutdown() noexcept;
bool joinRuntimeCoordinator() noexcept;
void completeRuntimeCoordinatorShutdown() noexcept;

#endif // RUNTIME_COORDINATOR_H_INCLUDED
