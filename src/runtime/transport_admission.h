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
OwnerAdmission *globalTransportAdmission() noexcept;
OwnerAdmissionSnapshot globalTransportAdmissionSnapshot() noexcept;
void requestGlobalTransportAdmissionShutdown() noexcept;
bool joinGlobalTransportAdmission() noexcept;

#endif // TRANSPORT_ADMISSION_H_INCLUDED
