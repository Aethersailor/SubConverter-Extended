#include "runtime/transport_admission.h"

#include <memory>
#include <mutex>

namespace {

struct GlobalTransportAdmissionRuntime {
  std::mutex mutex;
  std::unique_ptr<OwnerAdmission> admission;
  OwnerAdmissionBudget budget;
  bool stopping = false;
};

GlobalTransportAdmissionRuntime global_transport_admission;

} // namespace

GlobalTransportAdmissionInitStatus initializeGlobalTransportAdmission(
    OwnerAdmissionBudget budget) noexcept {
  if (budget.max_active_entries == 0 || budget.max_active_bytes == 0 ||
      budget.max_wait_entries == 0 || budget.max_wait_bytes == 0)
    return GlobalTransportAdmissionInitStatus::InvalidBudget;
  std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
  if (global_transport_admission.stopping)
    return GlobalTransportAdmissionInitStatus::Stopping;
  if (global_transport_admission.admission)
    return global_transport_admission.budget == budget
               ? GlobalTransportAdmissionInitStatus::AlreadyInitialized
               : GlobalTransportAdmissionInitStatus::BudgetMismatch;
  try {
    global_transport_admission.admission =
        std::make_unique<OwnerAdmission>(budget);
    global_transport_admission.budget = budget;
    return GlobalTransportAdmissionInitStatus::Initialized;
  } catch (...) {
    global_transport_admission.admission.reset();
    return GlobalTransportAdmissionInitStatus::InvalidBudget;
  }
}

OwnerAdmission *globalTransportAdmission() noexcept {
  std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
  return global_transport_admission.admission.get();
}

OwnerAdmissionSnapshot globalTransportAdmissionSnapshot() noexcept {
  std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
  return global_transport_admission.admission
             ? global_transport_admission.admission->snapshot()
             : OwnerAdmissionSnapshot{};
}

bool setGlobalTransportAdmissionActiveLimits(
    uint64_t max_active_entries, uint64_t max_active_bytes) noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
    admission = global_transport_admission.admission.get();
  }
  return admission && admission->setActiveLimits(
                          max_active_entries, max_active_bytes);
}

void requestGlobalTransportAdmissionShutdown() noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
    global_transport_admission.stopping = true;
    admission = global_transport_admission.admission.get();
  }
  if (admission)
    admission->requestShutdown();
}

bool joinGlobalTransportAdmission() noexcept {
  OwnerAdmission *admission = nullptr;
  {
    std::lock_guard<std::mutex> lock(global_transport_admission.mutex);
    admission = global_transport_admission.admission.get();
  }
  return !admission || admission->join();
}
