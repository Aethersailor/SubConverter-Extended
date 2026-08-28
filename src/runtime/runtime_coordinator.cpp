#include "runtime/runtime_coordinator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>

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
  struct CandidateRuntime {
    std::unique_ptr<ComputeExecutor> compute;
    std::unique_ptr<ComputeExecutor> blocking_io;
    std::unique_ptr<QuickJsLane> quickjs;
    std::unique_ptr<OwnerAdmission> owner;
    std::unique_ptr<OwnerAdmission> transport;
  };
  std::unique_ptr<CandidateRuntime> candidate;
  struct PublishedLimits {
    uint64_t response_cache_bytes = 0;
    size_t ruleset_cache_entries = 0;
    size_t ruleset_cache_bytes = 0;
    size_t external_cache_entries = 0;
    size_t external_cache_bytes = 0;
    uint64_t retained_response_bytes = 0;
  } original_limits;
  std::chrono::steady_clock::time_point shutdown_started{};
  std::shared_ptr<std::atomic<bool>> shutdown_watchdog_done;
};

RuntimeCoordinatorState coordinator;

static_assert(
    std::is_trivially_copyable_v<ForceMaxOwnerReservationBudget>);
static_assert(std::is_trivially_copyable_v<ForceMaxRuntimeBudgetSlice>);

bool hardEnvelopeMatches(const ResourceEnvelope &expected,
                         const ResourceEnvelope &current) noexcept {
  return expected.schedulable_cpu_millis ==
             current.schedulable_cpu_millis &&
         resourceEnvelopeMemoryBoundary(expected) ==
             resourceEnvelopeMemoryBoundary(current) &&
         expected.nofile_soft == current.nofile_soft &&
         expected.pids_max == current.pids_max &&
         expected.resolver_threads_per_transfer ==
             current.resolver_threads_per_transfer;
}

bool currentMemoryFitsStartupReserve(
    const ResourceEnvelope &current,
    const ForceMaxBudget &budget) noexcept {
  const ResourceMemoryLedger ledger =
      resourceEnvelopeMemoryLedger(current);
  if (!ledger.valid ||
      budget.memory_headroom_bytes < budget.reserved_memory_bytes)
    return false;
  const uint64_t required_remaining =
      budget.memory_headroom_bytes - budget.reserved_memory_bytes;
  return ledger.headroom_bytes >= required_remaining;
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

void capturePublishedLimitsLocked() {
  coordinator.original_limits = {
      responseMicroCacheSnapshot().max_bytes,
      rulesetConversionCacheMaxEntries(),
      rulesetConversionCacheMaxBytes(),
      externalConfigCacheMaxEntries(),
      externalConfigCacheMaxBytes(),
      retainedResponseByteSnapshot().limit};
}

void restorePublishedLimitsLocked() {
  configureResponseMicroCacheLimit(
      coordinator.original_limits.response_cache_bytes);
  configureRulesetConversionCache(
      coordinator.original_limits.ruleset_cache_entries,
      coordinator.original_limits.ruleset_cache_bytes);
  configureExternalConfigCache(
      coordinator.original_limits.external_cache_entries,
      coordinator.original_limits.external_cache_bytes);
  configureRetainedResponseByteLimit(
      coordinator.original_limits.retained_response_bytes);
}

bool failureInjected(const char *stage) noexcept {
  const char *configured =
      std::getenv("SUBCONVERTER_FORCE_MAX_FAIL_STAGE");
  return configured && std::string(configured) == stage;
}

uint64_t configuredShutdownDeadlineMs() noexcept {
  uint64_t deadline_ms = 4500;
  if (const char *configured =
          std::getenv("SUBCONVERTER_SHUTDOWN_DEADLINE_MS")) {
    try {
      deadline_ms = std::clamp<uint64_t>(std::stoull(configured),
                                         1000, 60000);
    } catch (...) {
    }
  }
  return deadline_ms;
}

void noteFailureLocked(const char *stage, const char *reason) {
  coordinator.snapshot.prepared = false;
  coordinator.snapshot.ready = false;
  coordinator.snapshot.generation = 0;
  coordinator.snapshot.reason = reason;
  coordinator.snapshot.last_failed_stage = stage;
  ++coordinator.snapshot.rollback_total;
  writeLog(LOG_LEVEL_ERROR,
           "FORCE_MAX_RUNTIME_ROLLBACK stage=" + std::string(stage) +
               " reason=" + reason);
}

void rollbackCandidateLocked(const char *stage, const char *reason) {
  rollbackAsyncFetchEngineCandidate();
  coordinator.candidate.reset();
  noteFailureLocked(stage, reason);
}

void requestFlowCancellation() noexcept {
  requestGlobalTransportAdmissionShutdown();
  requestGlobalOwnerAdmissionShutdown();
  cancelAllActiveRequests(RequestCancellationReason::Shutdown);
  requestAllConversionFlowsShutdown();
}

void requestExecutionShutdown(bool stop_resource_control = true) noexcept {
  requestConversionSchedulerShutdown();
  requestGlobalQuickJsLaneShutdown();
  requestBlockingIoExecutorShutdown();
  requestOutboundFetchShutdown();
  requestOwnedWebGetContinuationShutdown();
  requestRulesetExecutorShutdown();
  if (stop_resource_control)
    shutdownResourceControlRuntime();
}

bool joinComponents() noexcept {
  bool joined = true;
  joined = joinGlobalTransportAdmission() && joined;
  joined = joinGlobalOwnerAdmission() && joined;
  joined = joinGlobalQuickJsLane() && joined;
  joined = joinBlockingIoExecutor() && joined;
  joined = joinOutboundFetchShutdown() && joined;
  shutdownRulesetExecutor();
  shutdownConversionScheduler();
  joined = joinOwnedWebGetContinuationRuntime(false) && joined;
  // Every downstream lane is now joined, so no further terminal completion
  // can be posted. Drain already-enqueued control continuations instead of
  // cancelling them, then join the compute workers last.
  requestGlobalComputeExecutorShutdown(false);
  joined = joinGlobalComputeExecutor() && joined;
  return joined;
}

bool resetPublishedRuntime() noexcept {
  bool reset = true;
  reset = resetOwnedWebGetContinuationRuntime() && reset;
  reset = resetGlobalComputeExecutor() && reset;
  reset = resetBlockingIoExecutor() && reset;
  reset = resetGlobalQuickJsLane() && reset;
  reset = resetGlobalOwnerAdmission() && reset;
  reset = resetGlobalTransportAdmission() && reset;
  reset = resetAsyncFetchEngine() && reset;
  return reset;
}

void requestPublishedRuntimeRollback() noexcept {
  // Commit validation runs before the listener, the controller, cron and
  // background refresh start. Only stop objects published by this
  // transaction; touching lazy flow/ruleset/controller shutdown flags here
  // would poison an otherwise valid same-process rebuild.
  requestGlobalTransportAdmissionShutdown();
  requestGlobalOwnerAdmissionShutdown();
  requestGlobalQuickJsLaneShutdown();
  requestBlockingIoExecutorShutdown();
  requestOutboundFetchShutdown();
  requestOwnedWebGetContinuationShutdown();
}

bool joinPublishedRuntimeRollback() noexcept {
  bool joined = true;
  joined = joinGlobalTransportAdmission() && joined;
  joined = joinGlobalOwnerAdmission() && joined;
  joined = joinGlobalQuickJsLane() && joined;
  joined = joinBlockingIoExecutor() && joined;
  joined = joinOutboundFetchShutdown() && joined;
  joined = joinOwnedWebGetContinuationRuntime(false) && joined;
  requestGlobalComputeExecutorShutdown(false);
  joined = joinGlobalComputeExecutor() && joined;
  return joined;
}

bool rollbackPublishedRuntimeLocked(bool restore_limits) noexcept {
  rollbackAsyncFetchEngineCandidate();
  coordinator.candidate.reset();
  requestPublishedRuntimeRollback();
  const bool joined = joinPublishedRuntimeRollback();
  const bool reset = resetPublishedRuntime();
  if (restore_limits) {
    try {
      restorePublishedLimitsLocked();
    } catch (...) {
      return false;
    }
  }
  return joined && reset;
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

bool prepareForceMax(const ResourceControlSnapshot &resources,
                     RuntimeCoordinatorState::CandidateRuntime &candidate,
                     std::string &failed_stage) {
  const ForceMaxBudget &budget = resources.calculated_force_max_budget;
  if (!budget.valid || budget.compute_workers > SIZE_MAX ||
      budget.flow_queue_entries > SIZE_MAX || budget.io_runners > SIZE_MAX ||
      budget.blocking_io_queue_entries > SIZE_MAX)
    return false;
  const ResourceEnvelope preflight = probeCurrentResourceEnvelope();
  if (!hardEnvelopeMatches(resources.envelope, preflight))
    return false;

  failed_stage = "compute";
  if (failureInjected(failed_stage.c_str()))
    return false;
  candidate.compute = std::make_unique<ComputeExecutor>(
      ComputeExecutorBudget{budget.compute_workers,
                            budget.flow_queue_entries,
                            budget.flow_queue_bytes,
                            budget.flow_queue_entries});
  if (!candidate.compute->ready())
    return false;

  failed_stage = "blocking_io";
  if (failureInjected(failed_stage.c_str()))
    return false;
  candidate.blocking_io = std::make_unique<ComputeExecutor>(
      ComputeExecutorBudget{budget.io_runners,
                            budget.blocking_io_queue_entries,
                            budget.blocking_io_queue_bytes,
                            budget.blocking_io_queue_entries});
  if (!candidate.blocking_io->ready())
    return false;

  failed_stage = "quickjs";
  if (failureInjected(failed_stage.c_str()))
    return false;
  candidate.quickjs = std::make_unique<QuickJsLane>(
      quickJsLaneBudgetFromForceMax(budget));
  if (!candidate.quickjs->snapshot().ready)
    return false;

  failed_stage = "outbound_fetch";
  if (failureInjected(failed_stage.c_str()) ||
      !prepareAsyncFetchEngineCandidate())
    return false;

  failed_stage = "owner_admission";
  if (failureInjected(failed_stage.c_str()))
    return false;
  candidate.owner = std::make_unique<OwnerAdmission>(
      ownerAdmissionBudgetFromForceMax(budget));
  if (!candidate.owner->snapshot().ready)
    return false;

  failed_stage = "transport_admission";
  if (failureInjected(failed_stage.c_str()))
    return false;
  candidate.transport = std::make_unique<OwnerAdmission>(
      OwnerAdmissionBudget{budget.active_flows,
                           budget.transport_active_bytes,
                           budget.transport_queue_entries,
                           budget.transport_queue_bytes});
  return candidate.transport->snapshot().ready;
}

} // namespace

bool prepareRuntimeCoordinator() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  if (coordinator.snapshot.prepared)
    return true;
  const ResourceControlSnapshot resources = resourceControlSnapshot();
  coordinator.snapshot.force_max =
      resources.effective_mode == "force_max";
  if (!coordinator.snapshot.force_max)
    return true;
  coordinator.startup_envelope = resources.envelope;
  coordinator.budget = resources.calculated_force_max_budget;
  capturePublishedLimitsLocked();
  std::string fetch_contract_error;
  const SettingsSnapshot settings = captureEffectiveSettingsSnapshot();
  if (!settings || settings->maxAllowedDownloadSize <= 0 ||
      !validateForceMaxFetchContract(
          coordinator.budget,
          static_cast<uint64_t>(settings->maxAllowedDownloadSize),
          &fetch_contract_error)) {
    noteFailureLocked("fetch_contract",
                      fetch_contract_error.empty()
                          ? "invalid_maximum_download_size"
                          : fetch_contract_error.c_str());
    return false;
  }
  try {
    coordinator.candidate =
        std::make_unique<RuntimeCoordinatorState::CandidateRuntime>();
    std::string failed_stage = "preflight";
    if (!prepareForceMax(resources, *coordinator.candidate, failed_stage)) {
      rollbackCandidateLocked(failed_stage.c_str(),
                              "force_max_prepare_failed");
      return false;
    }
    coordinator.snapshot.prepared = true;
    coordinator.snapshot.reason = "prepared_not_published";
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_RUNTIME_PREPARED formula_revision=" +
                 coordinator.budget.formula_revision);
    return true;
  } catch (...) {
    rollbackCandidateLocked("exception", "force_max_prepare_exception");
    return false;
  }
}

bool commitRuntimeCoordinator() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  const ResourceControlSnapshot resources = resourceControlSnapshot();
  if (resources.effective_mode != "force_max")
    return true;
  if (!coordinator.snapshot.prepared || coordinator.snapshot.stopping)
    return false;
  if (coordinator.snapshot.ready)
    return true;
  if (coordinator.snapshot.force_max) {
    const ResourceEnvelope current = probeCurrentResourceEnvelope();
    if (!hardEnvelopeMatches(coordinator.startup_envelope, current) ||
        !currentMemoryFitsStartupReserve(current, coordinator.budget) ||
        failureInjected("precommit")) {
      rollbackCandidateLocked("precommit",
                              "force_max_commit_validation_failed");
      return false;
    }
  }
  if (!coordinator.candidate) {
    noteFailureLocked("publish", "force_max_candidate_missing");
    return false;
  }

  try {

  const OwnedWebGetContinuationBudget continuation_budget{
      static_cast<size_t>(coordinator.budget.compute_workers),
      static_cast<size_t>(coordinator.budget.flow_queue_entries),
      coordinator.budget.flow_queue_bytes};
  const BlockingIoExecutorBudget io_budget{
      coordinator.budget.io_runners,
      coordinator.budget.blocking_io_queue_entries,
      coordinator.budget.blocking_io_queue_bytes};
  const QuickJsLaneBudget quickjs_budget =
      quickJsLaneBudgetFromForceMax(coordinator.budget);
  const OwnerAdmissionBudget owner_budget =
      ownerAdmissionBudgetFromForceMax(coordinator.budget);
  const OwnerAdmissionBudget transport_budget{
      coordinator.budget.active_flows,
      coordinator.budget.transport_active_bytes,
      coordinator.budget.transport_queue_entries,
      coordinator.budget.transport_queue_bytes};

  bool published = publishGlobalComputeExecutor(
      std::move(coordinator.candidate->compute),
      {coordinator.budget.compute_workers,
       coordinator.budget.flow_queue_entries,
       coordinator.budget.flow_queue_bytes,
       coordinator.budget.flow_queue_entries});
  published = published &&
      publishOwnedWebGetContinuationRuntime(continuation_budget);
  if (failureInjected("publish_compute"))
    published = false;
  published = published && publishBlockingIoExecutor(
      std::move(coordinator.candidate->blocking_io), io_budget);
  published = published && publishGlobalQuickJsLane(
      std::move(coordinator.candidate->quickjs), quickjs_budget);
  published = published && commitAsyncFetchEngineCandidate();
  published = published && publishGlobalOwnerAdmission(
      std::move(coordinator.candidate->owner), owner_budget);
  published = published && publishGlobalTransportAdmission(
      std::move(coordinator.candidate->transport), transport_budget);

  if (!published || failureInjected("publish")) {
    const bool reset = rollbackPublishedRuntimeLocked(false);
    noteFailureLocked("publish",
                      reset ? "force_max_publish_failed"
                            : "force_max_publish_rollback_failed");
    return false;
  }
  coordinator.candidate.reset();

  configureForceMaxCaches(coordinator.budget);
  configureRetainedResponseByteLimit(
      coordinator.budget.retained_response_bytes);
  if (failureInjected("validation") ||
      !validateAppliedRuntime(coordinator.budget)) {
    const bool reset = rollbackPublishedRuntimeLocked(true);
    noteFailureLocked("validation",
                      reset ? "force_max_commit_validation_failed"
                            : "force_max_validation_rollback_failed");
    return false;
  }
  coordinator.snapshot.ready = true;
  ++coordinator.snapshot.generation;
  coordinator.snapshot.reason = "ready";
  writeLog(LOG_LEVEL_INFO,
           "FORCE_MAX_RUNTIME_READY generation=" +
               std::to_string(coordinator.snapshot.generation));
  return true;
  } catch (...) {
    const bool reset = rollbackPublishedRuntimeLocked(true);
    noteFailureLocked("exception",
                      reset ? "force_max_commit_exception"
                            : "force_max_exception_rollback_failed");
    return false;
  }
}

RuntimeCoordinatorSnapshot runtimeCoordinatorSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  return coordinator.snapshot;
}

RuntimeCoordinatorLivenessSnapshot
runtimeCoordinatorLivenessSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  return {coordinator.snapshot.force_max,
          coordinator.snapshot.prepared,
          coordinator.snapshot.ready,
          coordinator.snapshot.stopping,
          coordinator.snapshot.generation};
}

ForceMaxRuntimeBudgetSlice forceMaxRuntimeBudgetSlice() noexcept {
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  const RuntimeCoordinatorSnapshot &state = coordinator.snapshot;
  const ForceMaxBudget &budget = coordinator.budget;
  const bool valid = state.force_max && state.prepared && state.ready &&
                     !state.stopping && state.generation != 0 &&
                     budget.valid && budget.active_owners != 0 &&
                     budget.owner_active_bytes != 0 &&
                     budget.active_flows != 0 &&
                     budget.flow_queue_entries != 0 &&
                     budget.flow_queue_bytes != 0 &&
                     budget.quickjs_heap_bytes_per_worker != 0;
  return {state.force_max,
          valid,
          state.generation,
          {valid, budget.active_owners, budget.owner_active_bytes},
          budget.active_flows,
          budget.flow_queue_entries,
          budget.flow_queue_bytes,
          budget.quickjs_heap_bytes_per_worker};
}

void requestRuntimeCoordinatorShutdown() noexcept {
  std::shared_ptr<std::atomic<bool>> watchdog_done;
  uint64_t deadline_ms = 0;
  bool start_watchdog = false;
  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    if (!coordinator.snapshot.stopping) {
      coordinator.shutdown_started =
          std::chrono::steady_clock::now();
      deadline_ms = coordinator.snapshot.force_max
                        ? configuredShutdownDeadlineMs()
                        : 0;
      coordinator.snapshot.shutdown_deadline_ms = deadline_ms;
      if (coordinator.snapshot.force_max) {
        coordinator.shutdown_watchdog_done =
            std::make_shared<std::atomic<bool>>(false);
        watchdog_done = coordinator.shutdown_watchdog_done;
      }
      start_watchdog = true;
    }
    coordinator.snapshot.stopping = true;
    coordinator.snapshot.ready = false;
    coordinator.snapshot.reason = "shutdown_requested";
    coordinator.snapshot.shutdown_stage = "cancel_flows";
  }
  if (!start_watchdog)
    return;
  if (watchdog_done) {
    std::thread([watchdog_done, deadline_ms] {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(deadline_ms));
      if (!watchdog_done->load(std::memory_order_acquire))
        std::_Exit(EXIT_FAILURE);
    }).detach();
  }
  requestFlowCancellation();
  if (watchdog_done)
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_SHUTDOWN_STAGE stage=cancel_flows "
             "status=complete");
}

bool joinRuntimeCoordinator() noexcept {
  using Clock = std::chrono::steady_clock;
  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    if (coordinator.snapshot.joined)
      return true;
  }
  requestRuntimeCoordinatorShutdown();
  Clock::time_point started;
  uint64_t deadline_ms = 0;
  std::shared_ptr<std::atomic<bool>> watchdog_done;

  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    started = coordinator.shutdown_started;
    deadline_ms = coordinator.snapshot.shutdown_deadline_ms;
    watchdog_done = coordinator.shutdown_watchdog_done;
    coordinator.snapshot.shutdown_stage = "stop_continuations";
  }
  if (watchdog_done)
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_SHUTDOWN_STAGE stage=stop_continuations "
             "status=start");
  requestExecutionShutdown();

  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    coordinator.snapshot.shutdown_stage = "join_components";
  }
  if (watchdog_done)
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_SHUTDOWN_STAGE stage=join_components "
             "status=start");
  const bool joined = joinComponents();
  const uint64_t elapsed_ms = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          Clock::now() - started).count());
  std::lock_guard<std::mutex> lock(coordinator.mutex);
  coordinator.snapshot.joined = joined;
  coordinator.snapshot.shutdown_elapsed_ms = elapsed_ms;
  coordinator.snapshot.shutdown_deadline_exceeded =
      deadline_ms != 0 && elapsed_ms > deadline_ms;
  coordinator.snapshot.shutdown_stage =
      joined ? "joined" : "join_failed";
  coordinator.snapshot.reason = joined ? "joined" : "join_failed";
  if (coordinator.snapshot.force_max)
    writeLog(joined ? LOG_LEVEL_INFO : LOG_LEVEL_ERROR,
             "FORCE_MAX_SHUTDOWN_STAGE stage=" +
                 coordinator.snapshot.shutdown_stage +
                 " status=complete elapsed_ms=" +
                 std::to_string(elapsed_ms) + " deadline_ms=" +
                 std::to_string(deadline_ms));
  return joined;
}

void completeRuntimeCoordinatorShutdown() noexcept {
  std::shared_ptr<std::atomic<bool>> watchdog_done;
  uint64_t elapsed_ms = 0;
  uint64_t deadline_ms = 0;
  bool force_max = false;
  {
    std::lock_guard<std::mutex> lock(coordinator.mutex);
    watchdog_done = coordinator.shutdown_watchdog_done;
    force_max = coordinator.snapshot.force_max;
    deadline_ms = coordinator.snapshot.shutdown_deadline_ms;
    if (coordinator.shutdown_started !=
        std::chrono::steady_clock::time_point{}) {
      elapsed_ms = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() -
              coordinator.shutdown_started)
              .count());
    }
    coordinator.snapshot.shutdown_elapsed_ms = elapsed_ms;
    coordinator.snapshot.shutdown_deadline_exceeded =
        deadline_ms != 0 && elapsed_ms > deadline_ms;
    coordinator.snapshot.shutdown_stage = "process_complete";
    coordinator.snapshot.reason = "process_complete";
  }
  if (force_max)
    writeLog(LOG_LEVEL_INFO,
             "FORCE_MAX_SHUTDOWN_STAGE stage=process_complete "
             "status=complete elapsed_ms=" +
                 std::to_string(elapsed_ms) + " deadline_ms=" +
                 std::to_string(deadline_ms));
  if (watchdog_done)
    watchdog_done->store(true, std::memory_order_release);
}
