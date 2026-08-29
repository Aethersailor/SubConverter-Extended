#ifndef RUNTIME_COORDINATOR_H_INCLUDED
#define RUNTIME_COORDINATOR_H_INCLUDED

#include <cstdint>
#include <string>

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

bool prepareRuntimeCoordinator() noexcept;
bool commitRuntimeCoordinator() noexcept;
RuntimeCoordinatorSnapshot runtimeCoordinatorSnapshot() noexcept;
void requestRuntimeCoordinatorShutdown() noexcept;
bool joinRuntimeCoordinator() noexcept;
void completeRuntimeCoordinatorShutdown() noexcept;

#endif // RUNTIME_COORDINATOR_H_INCLUDED
