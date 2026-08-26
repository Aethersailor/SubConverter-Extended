#include "runtime/runtime_coordinator.h"

#include <algorithm>
#include <cstdint>
#include <mutex>

#include "generator/config/ruleconvert.h"
#include "handler/conversion_service.h"
#include "handler/interfaces.h"
#include "handler/multithread.h"
#include "handler/settings.h"
#include "handler/webget.h"
#include "runtime/blocking_io_executor.h"
#include "runtime/conversion_flow.h"
#include "runtime/owner_admission.h"
#include "runtime/quickjs_lane.h"
#include "runtime/transport_admission.h"
#include "server/request_context.h"
#include "utils/logger.h"
#include "utils/resource_control.h"

namespace {

struct RuntimeCoordinatorState {
  std::mutex mutex;
  RuntimeCoordinatorSnapshot snapshot;
  ResourceEnvelope startup_envelope;
  ForceMaxBudget budget;
};

RuntimeCoordinatorState coordinator;

bool hardEnvelopeMatches(const ResourceEnvelope &expected,
                         const ResourceEnvelope &current) noexcept {
  return expected.schedulable_cpu_millis ==
             current.schedulable_cpu_millis &&
         resourceEnvelopeMemoryBoundary(expected) ==
             resourceEnvelopeMemoryBoundary(current) &&
         expected.nofile_soft == current.nofile_soft &&
         expected.pids_max == current.pids_max;
}

void configureForceMaxCaches(const ForceMaxBudget &budget) {
  const uint64_t response_bytes = budget.cache_bytes / 2;
  const uint64_t ruleset_bytes = budget.cache_bytes / 4;
  const uint64_t external_bytes =
      budget.cache_bytes - response_bytes - ruleset_bytes;
  configureResponseMicroCacheLimit(response_bytes);
  configureRulesetConversionCache(
      static_cast<size_t>(std::min<uint64_t>(
          std::max<uint64_t>(1, ruleset_bytes / (UINT64_C(64) * 1024)),
          SIZE_MAX)),
      static_cast<size_t>(std::min<uint64_t>(ruleset_bytes, SIZE_MAX)));
  configureExternalConfigCache(
      static_cast<size_t>(std::min<uint64_t>(
          std::max<uint64_t>(1, external_bytes / (UINT64_C(128) * 1024)),
          SIZE_MAX)),
      static_cast<size_t>(std::min<uint64_t>(external_bytes, SIZE_MAX)));
}

void requestComponentsShutdown() noexcept {
  requestGlobalTransportAdmissionShutdown();
  requestGlobalOwnerAdmissionShutdown();
  cancelAllActiveRequests(RequestCancellationReason::Shutdown);
  shutdownResourceControlRuntime();
  requestConversionSchedulerShutdown();
  requestAllConversionFlowsShutdown();
  requestGlobalQuickJsLaneShutdown();
  requestBlockingIoExecutorShutdown();
  requestOwnedWebGetContinuationShutdown();
  requestRulesetExecutorShutdown();
}

bool joinComponents() noexcept {
  bool joined = true;
  joined = joinGlobalTransportAdmission() && joined;
  joined = joinGlobalOwnerAdmission() && joined;
  joined = joinGlobalQuickJsLane() && joined;
  joined = joinBlockingIoExecutor() && joined;
  joined = joinOwnedWebGetContinuationRuntime() && joined;
  shutdownRulesetExecutor();
  shutdownConversionScheduler();
  return joined;
}

bool validateAppliedRuntime(const ForceMaxBudget &budget) noexcept {
  const ComputeExecutorSnapshot compute = globalComputeExecutorSnapshot();
  const ComputeExecutorSnapshot io = blockingIoExecutorSnapshot();
  const QuickJsLaneSnapshot quickjs = globalQuickJsLaneSnapshot();
  const OwnerAdmissionSnapshot owner = globalOwnerAdmissionSnapshot();
  const OwnerAdmissionSnapshot transport =
      globalTransportAdmissionSnapshot();
  const AsyncFetchEngineSnapshot fetch = asyncFetchEngineSnapshot();
  return compute.ready && compute.workers == budget.compute_workers &&
      compute.max_queue_entries == budget.flow_queue_entries &&
      compute.max_queue_bytes == budget.flow_queue_bytes && io.ready &&
      io.workers == budget.io_runners &&
      io.max_queue_entries == budget.blocking_io_queue_entries &&
      io.max_queue_bytes == budget.blocking_io_queue_bytes &&
      quickjs.ready && quickjs.workers == budget.quickjs_workers &&
      quickjs.max_queue_entries == budget.quickjs_queue_entries &&
      quickjs.max_queue_bytes == budget.quickjs_queue_bytes &&
      owner.ready && owner.max_active_entries == budget.active_owners &&
      owner.max_active_bytes == budget.owner_active_bytes &&
      transport.ready &&
      transport.max_active_entries == budget.active_flows &&
      transport.max_active_bytes == budget.transport_active_bytes &&
      fetch.available &&
      fetch.active_connection_limit == budget.outbound_active &&
      fetch.open_connection_limit == budget.outbound_open &&
      fetch.connection_cache_limit == budget.outbound_idle_cache;
}

bool prepareForceMax(const ResourceControlSnapshot &resources) {
  const ForceMaxBudget &budget = resources.calculated_force_max_budget;
  if (!budget.valid || budget.compute_workers > SIZE_MAX ||
      budget.flow_queue_entries > SIZE_MAX || budget.io_runners > SIZE_MAX ||
      budget.blocking_io_queue_entries > SIZE_MAX)
    return false;
  const ResourceEnvelope preflight = probeCurrentResourceEnvelope();
  if (!hardEnvelopeMatches(resources.envelope, preflight))
    return false;

  configureForceMaxCaches(budget);
  configureRetainedResponseByteLimit(budget.retained_response_bytes);
  const OwnedWebGetContinuationInitStatus compute_status =
      initializeOwnedWebGetContinuationRuntime(
          {static_cast<size_t>(budget.compute_workers),
           static_cast<size_t>(budget.flow_queue_entries),
           budget.flow_queue_bytes});
  if (compute_status != OwnedWebGetContinuationInitStatus::Initialized &&
      compute_status !=
          OwnedWebGetContinuationInitStatus::AlreadyInitialized)
    return false;

  const BlockingIoExecutorInitStatus io_status =
      initializeBlockingIoExecutor(
          {budget.io_runners, budget.blocking_io_queue_entries,
           budget.blocking_io_queue_bytes});
  if (io_status != BlockingIoExecutorInitStatus::Initialized &&
      io_status != BlockingIoExecutorInitStatus::AlreadyInitialized)
    return false;
  const GlobalQuickJsLaneInitStatus quickjs_status =
      initializeGlobalQuickJsLane(quickJsLaneBudgetFromForceMax(budget));
  if (quickjs_status != GlobalQuickJsLaneInitStatus::Initialized &&
      quickjs_status != GlobalQuickJsLaneInitStatus::AlreadyInitialized)
    return false;
  if (!initializeAsyncFetchEngine())
    return false;

  const GlobalOwnerAdmissionInitStatus owner_status =
      initializeGlobalOwnerAdmission(ownerAdmissionBudgetFromForceMax(budget));
  if (owner_status != GlobalOwnerAdmissionInitStatus::Initialized &&
      owner_status != GlobalOwnerAdmissionInitStatus::AlreadyInitialized)
    return false;
  const GlobalTransportAdmissionInitStatus transport_status =
      initializeGlobalTransportAdmission(
          {budget.active_flows, budget.transport_active_bytes,
           budget.transport_queue_entries, budget.transport_queue_bytes});
  if (transport_status != GlobalTransportAdmissionInitStatus::Initialized &&
      transport_status !=
          GlobalTransportAdmissionInitStatus::AlreadyInitialized)
    return false;
  return validateAppliedRuntime(budget);
}

} // namespace

bool prepareRuntimeCoordinator() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  if (coordinator.snapshot.prepared)
    return true;
  const ResourceControlSnapshot resources = resourceControlSnapshot();
  coordinator.snapshot.force_max =
      resources.effective_mode == "force_max";
  coordinator.startup_envelope = resources.envelope;
  coordinator.budget = resources.calculated_force_max_budget;
  if (!coordinator.snapshot.force_max) {
    coordinator.snapshot.prepared = true;
    coordinator.snapshot.reason = "non_force_max";
    return true;
  }
  try {
    if (!prepareForceMax(resources)) {
      coordinator.snapshot.reason = "force_max_prepare_failed";
      requestComponentsShutdown();
      (void)joinComponents();
      return false;
    }
    coordinator.snapshot.prepared = true;
    coordinator.snapshot.reason = "prepared_not_published";
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_RUNTIME_PREPARED formula_revision=" +
                 coordinator.budget.formula_revision);
    return true;
  } catch (...) {
    coordinator.snapshot.reason = "force_max_prepare_exception";
    requestComponentsShutdown();
    (void)joinComponents();
    return false;
  }
}

bool commitRuntimeCoordinator() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  if (!coordinator.snapshot.prepared || coordinator.snapshot.stopping)
    return false;
  if (coordinator.snapshot.ready)
    return true;
  if (coordinator.snapshot.force_max) {
    const ResourceEnvelope current = probeCurrentResourceEnvelope();
    if (!hardEnvelopeMatches(coordinator.startup_envelope, current) ||
        !validateAppliedRuntime(coordinator.budget)) {
      coordinator.snapshot.reason = "force_max_commit_validation_failed";
      requestComponentsShutdown();
      (void)joinComponents();
      return false;
    }
  }
  coordinator.snapshot.ready = true;
  ++coordinator.snapshot.generation;
  coordinator.snapshot.reason = "ready";
  writeLog(LOG_LEVEL_INFO,
           coordinator.snapshot.force_max
               ? "FORCE_MAX_RUNTIME_READY generation=" +
                     std::to_string(coordinator.snapshot.generation)
               : "RUNTIME_COORDINATOR_READY mode=compatibility");
  return true;
}

RuntimeCoordinatorSnapshot runtimeCoordinatorSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  return coordinator.snapshot;
}

void requestRuntimeCoordinatorShutdown() noexcept {
  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    coordinator.snapshot.stopping = true;
    coordinator.snapshot.ready = false;
    coordinator.snapshot.reason = "shutdown_requested";
  }
  requestComponentsShutdown();
}

bool joinRuntimeCoordinator() noexcept {
  const bool joined = joinComponents();
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  coordinator.snapshot.joined = joined;
  coordinator.snapshot.reason = joined ? "joined" : "join_failed";
  return joined;
}
