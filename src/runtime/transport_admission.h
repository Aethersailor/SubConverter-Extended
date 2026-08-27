#ifndef TRANSPORT_ADMISSION_H_INCLUDED
#define TRANSPORT_ADMISSION_H_INCLUDED

#include "runtime/owner_admission.h"

enum class GlobalTransportAdmissionInitStatus : uint8_t {
  Initialized,
  AlreadyInitialized,
  BudgetMismatch,
  InvalidBudget,
  Stopping,
};

GlobalTransportAdmissionInitStatus initializeGlobalTransportAdmission(
    OwnerAdmissionBudget budget) noexcept;
bool publishGlobalTransportAdmission(
    std::unique_ptr<OwnerAdmission> admission,
    OwnerAdmissionBudget budget) noexcept;
bool resetGlobalTransportAdmission() noexcept;
OwnerAdmission *globalTransportAdmission() noexcept;
OwnerAdmissionSnapshot globalTransportAdmissionSnapshot() noexcept;
bool setGlobalTransportAdmissionActiveLimits(
    uint64_t max_active_entries, uint64_t max_active_bytes) noexcept;
void requestGlobalTransportAdmissionShutdown() noexcept;
bool joinGlobalTransportAdmission() noexcept;

#endif // TRANSPORT_ADMISSION_H_INCLUDED
