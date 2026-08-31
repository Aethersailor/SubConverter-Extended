#ifndef CONVERSION_FLOW_H_INCLUDED
#define CONVERSION_FLOW_H_INCLUDED

#include <atomic>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "handler/settings_view.h"
#include "runtime/compute_executor.h"
#include "server/request_context.h"

enum class ConversionFlowPhase {
  Preparing,
  FetchingExternalConfig,
  FetchingRulesets,
  FetchingSubscriptions,
  Parsing,
  Generating,
  Uploading,
  Publishing,
  Completed,
};

const char *conversionFlowPhaseName(ConversionFlowPhase phase) noexcept;

enum class ConversionFlowTerminalState {
  Completed,
  Cancelled,
  Deadline,
  Shutdown,
  Capacity,
  Failed,
};

struct ConversionFlowTerminal {
  ConversionFlowTerminalState state = ConversionFlowTerminalState::Failed;
  RequestCancellationReason cancellation =
      RequestCancellationReason::None;
  std::exception_ptr error;
};

// Flow events retain a callable and small ownership handles. Large payloads
// handed back by the conversion pipeline are already bounded by retained-byte
// and owner-working-memory leases, so callers charge only bytes not covered by
// those budgets. Every ordinary event still pays this metadata floor.
inline constexpr uint64_t kConversionFlowMailboxEventMetadataBytes = 256;

struct ConversionFlowBudget {
  uint64_t max_mailbox_entries = 1;
  uint64_t max_mailbox_bytes = kConversionFlowMailboxEventMetadataBytes;
};

struct ConversionFlowSnapshot {
  uint64_t id = 0;
  ConversionFlowPhase phase = ConversionFlowPhase::Preparing;
  uint64_t generation = 0;
  uint64_t mailbox_entries = 0;
  uint64_t mailbox_bytes = 0;
  uint64_t outstanding_operations = 0;
  uint64_t events_processed = 0;
  uint64_t duplicate_callbacks = 0;
  bool drain_scheduled = false;
  bool terminal = false;
};

struct ConversionFlowRegistrySnapshot {
  uint64_t active = 0;
  uint64_t created_total = 0;
  uint64_t completed_total = 0;
  uint64_t rejected_total = 0;
  bool stopping = false;
};

class ConversionFlow;

class ConversionFlowOperation {
public:
  using Event = std::function<void(ConversionFlow &)>;

  bool post(Event event, uint64_t unaccounted_bytes = 0) const;
  bool valid() const noexcept { return id_ != 0; }
  uint64_t id() const noexcept { return id_; }
  uint64_t generation() const noexcept { return generation_; }

private:
  friend class ConversionFlow;
  ConversionFlowOperation(std::weak_ptr<ConversionFlow> flow, uint64_t id,
                          uint64_t generation)
      : flow_(std::move(flow)), id_(id), generation_(generation) {}

  std::weak_ptr<ConversionFlow> flow_;
  uint64_t id_ = 0;
  uint64_t generation_ = 0;
};

class ConversionFlow : public std::enable_shared_from_this<ConversionFlow> {
  friend class ConversionFlowOperation;

public:
  using Event = std::function<void(ConversionFlow &)>;
  using Completion = std::function<void(ConversionFlowTerminal)>;

  static std::shared_ptr<ConversionFlow> create(
      ComputeExecutor &executor, ConversionFlowBudget budget,
      SettingsSnapshot settings, std::shared_ptr<RequestContext> context,
      Completion completion);

  ~ConversionFlow();

  ConversionFlow(const ConversionFlow &) = delete;
  ConversionFlow &operator=(const ConversionFlow &) = delete;

  bool start(Event event, uint64_t unaccounted_bytes = 0);
  ConversionFlowOperation beginOperation();
  bool setPhase(ConversionFlowPhase phase) noexcept;
  bool complete() noexcept;
  bool fail(std::exception_ptr error) noexcept;
  void requestCancellation(RequestCancellationReason reason) noexcept;
  void requestShutdown() noexcept;

  uint64_t id() const noexcept { return id_; }
  ConversionFlowSnapshot snapshot() const;
  bool isCurrentDrain() const noexcept;

private:
  struct MailboxEvent {
    Event event;
    uint64_t bytes = 0;
  };

  ConversionFlow(ComputeExecutor &executor, ConversionFlowBudget budget,
                 SettingsSnapshot settings,
                 std::shared_ptr<RequestContext> context,
                 Completion completion, uint64_t id);

  bool activate(const std::shared_ptr<ConversionFlow> &self);
  bool postOperation(uint64_t operation_id, uint64_t generation,
                     Event event, uint64_t unaccounted_bytes);
  bool enqueue(Event event, uint64_t unaccounted_bytes, bool control);
  bool scheduleDrain();
  void drain() noexcept;
  void finishTerminal(ConversionFlowTerminal terminal) noexcept;
  void finishSchedulingFailure(SchedulerSubmitStatus status,
                               std::exception_ptr error) noexcept;

  inline static thread_local ConversionFlow *current_drain_ = nullptr;

  ComputeExecutor *executor_;
  const ConversionFlowBudget budget_;
  const SettingsSnapshot settings_;
  const std::shared_ptr<RequestContext> context_;
  const uint64_t id_;
  mutable std::mutex mutex_;
  std::deque<MailboxEvent> control_mailbox_;
  std::deque<MailboxEvent> mailbox_;
  std::unordered_map<uint64_t, uint64_t> outstanding_operations_;
  Completion completion_;
  std::shared_ptr<ConversionFlow> self_keepalive_;
  RequestCancellationRegistration cancellation_registration_;
  ConversionFlowPhase phase_ = ConversionFlowPhase::Preparing;
  uint64_t generation_ = 1;
  uint64_t next_operation_id_ = 1;
  uint64_t mailbox_bytes_ = 0;
  uint64_t events_processed_ = 0;
  uint64_t duplicate_callbacks_ = 0;
  std::optional<std::size_t> preferred_worker_;
  bool drain_scheduled_ = false;
  bool termination_queued_ = false;
  std::atomic<bool> terminal_claimed_{false};
};

ConversionFlowRegistrySnapshot conversionFlowRegistrySnapshot();
void requestAllConversionFlowsShutdown() noexcept;

#endif // CONVERSION_FLOW_H_INCLUDED
