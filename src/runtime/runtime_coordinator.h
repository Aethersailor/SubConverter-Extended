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
  uint64_t generation = 0;
  std::string reason = "not_prepared";
};

bool prepareRuntimeCoordinator() noexcept;
bool commitRuntimeCoordinator() noexcept;
RuntimeCoordinatorSnapshot runtimeCoordinatorSnapshot() noexcept;
void requestRuntimeCoordinatorShutdown() noexcept;
bool joinRuntimeCoordinator() noexcept;

#endif // RUNTIME_COORDINATOR_H_INCLUDED
