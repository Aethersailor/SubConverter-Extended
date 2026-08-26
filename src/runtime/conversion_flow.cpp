#include "runtime/conversion_flow.h"

#include <algorithm>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

struct ConversionFlowRegistry {
  std::mutex mutex;
  std::unordered_map<uint64_t, std::weak_ptr<ConversionFlow>> flows;
  uint64_t next_id = 1;
  uint64_t created_total = 0;
  uint64_t completed_total = 0;
  uint64_t rejected_total = 0;
  bool stopping = false;
};

ConversionFlowRegistry registry;

uint64_t reserveFlowId() noexcept {
  std::lock_guard<std::mutex> lock(registry.mutex);
  if (registry.stopping) {
    ++registry.rejected_total;
    return 0;
  }
  return registry.next_id++;
}

bool registerFlow(const std::shared_ptr<ConversionFlow> &flow) noexcept {
  std::lock_guard<std::mutex> lock(registry.mutex);
  if (registry.stopping) {
    ++registry.rejected_total;
    return false;
  }
  try {
    registry.flows.emplace(flow->id(), flow);
    ++registry.created_total;
    return true;
  } catch (...) {
    ++registry.rejected_total;
    return false;
  }
}

void unregisterFlow(uint64_t id) noexcept {
  std::lock_guard<std::mutex> lock(registry.mutex);
  registry.flows.erase(id);
  ++registry.completed_total;
}

ConversionFlowTerminal cancellationTerminal(
    RequestCancellationReason reason) noexcept {
  ConversionFlowTerminal terminal;
  terminal.cancellation = reason;
  switch (reason) {
  case RequestCancellationReason::Deadline:
    terminal.state = ConversionFlowTerminalState::Deadline;
    break;
  case RequestCancellationReason::Shutdown:
    terminal.state = ConversionFlowTerminalState::Shutdown;
    break;
  case RequestCancellationReason::ClientDisconnected:
  case RequestCancellationReason::NoConsumers:
    terminal.state = ConversionFlowTerminalState::Cancelled;
    break;
  case RequestCancellationReason::None:
    terminal.state = ConversionFlowTerminalState::Cancelled;
    break;
  }
  return terminal;
}

} // namespace

const char *conversionFlowPhaseName(ConversionFlowPhase phase) noexcept {
  switch (phase) {
  case ConversionFlowPhase::Preparing:
    return "preparing";
  case ConversionFlowPhase::FetchingExternalConfig:
    return "fetching_external_config";
  case ConversionFlowPhase::FetchingSubscriptions:
    return "fetching_subscriptions";
  case ConversionFlowPhase::FetchingRulesets:
    return "fetching_rulesets";
  case ConversionFlowPhase::Parsing:
    return "parsing";
  case ConversionFlowPhase::Generating:
    return "generating";
  case ConversionFlowPhase::Uploading:
    return "uploading";
  case ConversionFlowPhase::Publishing:
    return "publishing";
  case ConversionFlowPhase::Completed:
    return "completed";
  }
  return "invalid";
}

bool ConversionFlowOperation::post(Event event, uint64_t bytes) const {
  const std::shared_ptr<ConversionFlow> flow = flow_.lock();
  return flow && flow->postOperation(id_, generation_, std::move(event),
                                     bytes);
}

std::shared_ptr<ConversionFlow> ConversionFlow::create(
    ComputeExecutor &executor, ConversionFlowBudget budget,
    SettingsSnapshot settings, std::shared_ptr<RequestContext> context,
    Completion completion) {
  if (budget.max_mailbox_entries == 0 ||
      budget.max_mailbox_bytes == 0 || !settings || !context)
    return nullptr;
  const uint64_t id = reserveFlowId();
  if (id == 0)
    return nullptr;
  std::shared_ptr<ConversionFlow> flow;
  try {
    flow = std::shared_ptr<ConversionFlow>(new ConversionFlow(
        executor, budget, std::move(settings), std::move(context),
        std::move(completion), id));
  } catch (...) {
    return nullptr;
  }
  if (!registerFlow(flow) || !flow->activate(flow))
    return nullptr;
  return flow;
}

ConversionFlow::ConversionFlow(ComputeExecutor &executor,
                               ConversionFlowBudget budget,
                               SettingsSnapshot settings,
                               std::shared_ptr<RequestContext> context,
                               Completion completion, uint64_t id)
    : executor_(&executor), budget_(budget), settings_(std::move(settings)),
      context_(std::move(context)), id_(id),
      completion_(std::move(completion)) {}

ConversionFlow::~ConversionFlow() = default;

bool ConversionFlow::activate(
    const std::shared_ptr<ConversionFlow> &self) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    self_keepalive_ = self;
  }
  const std::weak_ptr<ConversionFlow> weak = self;
  try {
    cancellation_registration_ = context_->registerCancellationCallback(
        [weak] {
          if (const std::shared_ptr<ConversionFlow> flow = weak.lock())
            flow->requestCancellation(
                flow->context_->cancellationToken().reason());
        });
  } catch (...) {
    finishTerminal({ConversionFlowTerminalState::Capacity,
                    RequestCancellationReason::None,
                    std::current_exception()});
    return false;
  }
  return !terminal_claimed_.load(std::memory_order_acquire);
}

bool ConversionFlow::start(Event event, uint64_t bytes) {
  return enqueue(std::move(event), bytes, false);
}

ConversionFlowOperation ConversionFlow::beginOperation() {
  if (!isCurrentDrain() ||
      terminal_claimed_.load(std::memory_order_acquire))
    return {{}, 0, 0};
  std::lock_guard<std::mutex> lock(mutex_);
  const uint64_t id = next_operation_id_++;
  try {
    outstanding_operations_.emplace(id, generation_);
  } catch (...) {
    return {{}, 0, 0};
  }
  return {weak_from_this(), id, generation_};
}

bool ConversionFlow::setPhase(ConversionFlowPhase phase) noexcept {
  if (!isCurrentDrain() || phase == ConversionFlowPhase::Completed ||
      terminal_claimed_.load(std::memory_order_acquire))
    return false;
  std::lock_guard<std::mutex> lock(mutex_);
  if (static_cast<unsigned>(phase) < static_cast<unsigned>(phase_))
    return false;
  if (phase != phase_) {
    phase_ = phase;
    ++generation_;
    outstanding_operations_.clear();
  }
  return true;
}

bool ConversionFlow::complete() noexcept {
  if (!isCurrentDrain())
    return false;
  finishTerminal({ConversionFlowTerminalState::Completed,
                  RequestCancellationReason::None, {}});
  return true;
}

bool ConversionFlow::fail(std::exception_ptr error) noexcept {
  if (!isCurrentDrain())
    return false;
  finishTerminal({ConversionFlowTerminalState::Failed,
                  RequestCancellationReason::None, std::move(error)});
  return true;
}

void ConversionFlow::requestCancellation(
    RequestCancellationReason reason) noexcept {
  if (reason == RequestCancellationReason::None)
    reason = RequestCancellationReason::ClientDisconnected;
  (void)enqueue(
      [reason](ConversionFlow &flow) {
        flow.finishTerminal(cancellationTerminal(reason));
      },
      0, true);
}

void ConversionFlow::requestShutdown() noexcept {
  requestCancellation(RequestCancellationReason::Shutdown);
}

bool ConversionFlow::postOperation(uint64_t operation_id,
                                   uint64_t generation, Event event,
                                   uint64_t bytes) {
  bool overflow = false;
  bool schedule = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (terminal_claimed_.load(std::memory_order_acquire))
      return false;
    const auto operation = outstanding_operations_.find(operation_id);
    if (operation == outstanding_operations_.end() ||
        operation->second != generation) {
      ++duplicate_callbacks_;
      return false;
    }
    outstanding_operations_.erase(operation);
    if (!event || mailbox_.size() >= budget_.max_mailbox_entries ||
        bytes > budget_.max_mailbox_bytes ||
        mailbox_bytes_ > budget_.max_mailbox_bytes - bytes) {
      overflow = true;
    } else {
      mailbox_.push_back({std::move(event), bytes});
      mailbox_bytes_ += bytes;
      if (!drain_scheduled_) {
        drain_scheduled_ = true;
        schedule = true;
      }
    }
  }
  if (overflow) {
    finishTerminal({ConversionFlowTerminalState::Capacity,
                    RequestCancellationReason::None,
                    std::make_exception_ptr(
                        std::runtime_error("conversion flow mailbox full"))});
    return false;
  }
  return !schedule || scheduleDrain();
}

bool ConversionFlow::enqueue(Event event, uint64_t bytes, bool control) {
  bool overflow = false;
  bool schedule = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (terminal_claimed_.load(std::memory_order_acquire))
      return false;
    if (control) {
      if (termination_queued_)
        return false;
      termination_queued_ = true;
      control_mailbox_.push_back({std::move(event), 0});
    } else if (!event || mailbox_.size() >= budget_.max_mailbox_entries ||
               bytes > budget_.max_mailbox_bytes ||
               mailbox_bytes_ > budget_.max_mailbox_bytes - bytes) {
      overflow = true;
    } else {
      mailbox_.push_back({std::move(event), bytes});
      mailbox_bytes_ += bytes;
    }
    if (!overflow && !drain_scheduled_) {
      drain_scheduled_ = true;
      schedule = true;
    }
  }
  if (overflow) {
    finishTerminal({ConversionFlowTerminalState::Capacity,
                    RequestCancellationReason::None,
                    std::make_exception_ptr(
                        std::runtime_error("conversion flow mailbox full"))});
    return false;
  }
  return !schedule || scheduleDrain();
}

bool ConversionFlow::scheduleDrain() {
  ComputeTaskOptions options;
  options.cost = context_->costClass();
  options.control = true;
  const std::shared_ptr<ConversionFlow> self = shared_from_this();
  SchedulerSubmitStatus status = SchedulerSubmitStatus::Stopping;
  try {
    status = executor_->submitContinuation(
        std::move(options), [self] { self->drain(); },
        [weak = std::weak_ptr<ConversionFlow>(self)](
            SchedulerSubmitStatus completion_status,
            std::exception_ptr error) {
          if (completion_status == SchedulerSubmitStatus::Accepted && !error)
            return;
          if (const std::shared_ptr<ConversionFlow> flow = weak.lock())
            flow->finishSchedulingFailure(completion_status,
                                          std::move(error));
        });
  } catch (...) {
    finishSchedulingFailure(SchedulerSubmitStatus::Stopping,
                            std::current_exception());
    return false;
  }
  return status == SchedulerSubmitStatus::Accepted;
}

void ConversionFlow::drain() noexcept {
  ConversionFlow *previous = current_drain_;
  current_drain_ = this;
  for (;;) {
    MailboxEvent next;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (terminal_claimed_.load(std::memory_order_acquire)) {
        drain_scheduled_ = false;
        break;
      }
      if (!control_mailbox_.empty()) {
        next = std::move(control_mailbox_.front());
        control_mailbox_.pop_front();
      } else if (!mailbox_.empty()) {
        next = std::move(mailbox_.front());
        mailbox_.pop_front();
        mailbox_bytes_ -= next.bytes;
      } else {
        drain_scheduled_ = false;
        break;
      }
      ++events_processed_;
    }
    try {
      ScopedSettingsView settings_view(settings_);
      ScopedRequestContext request_context(context_);
      next.event(*this);
    } catch (...) {
      finishTerminal({ConversionFlowTerminalState::Failed,
                      RequestCancellationReason::None,
                      std::current_exception()});
    }
  }
  current_drain_ = previous;
}

void ConversionFlow::finishTerminal(
    ConversionFlowTerminal terminal) noexcept {
  if (terminal_claimed_.exchange(true, std::memory_order_acq_rel))
    return;
  Completion completion;
  std::deque<MailboxEvent> discarded;
  std::deque<MailboxEvent> discarded_control;
  std::shared_ptr<ConversionFlow> keepalive;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    phase_ = ConversionFlowPhase::Completed;
    ++generation_;
    outstanding_operations_.clear();
    discarded.swap(mailbox_);
    discarded_control.swap(control_mailbox_);
    mailbox_bytes_ = 0;
    drain_scheduled_ = false;
    completion = std::move(completion_);
    keepalive = self_keepalive_;
  }
  cancellation_registration_.reset();
  unregisterFlow(id_);
  if (completion) {
    try {
      completion(std::move(terminal));
    } catch (...) {
    }
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    self_keepalive_.reset();
  }
}

void ConversionFlow::finishSchedulingFailure(
    SchedulerSubmitStatus status, std::exception_ptr error) noexcept {
  const ConversionFlowTerminalState terminal_state =
      status == SchedulerSubmitStatus::Stopping
          ? ConversionFlowTerminalState::Shutdown
          : ConversionFlowTerminalState::Capacity;
  finishTerminal({terminal_state,
                  status == SchedulerSubmitStatus::Stopping
                      ? RequestCancellationReason::Shutdown
                      : RequestCancellationReason::None,
                  std::move(error)});
}

ConversionFlowSnapshot ConversionFlow::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return {id_,
          phase_,
          generation_,
          mailbox_.size() + control_mailbox_.size(),
          mailbox_bytes_,
          outstanding_operations_.size(),
          events_processed_,
          duplicate_callbacks_,
          drain_scheduled_,
          terminal_claimed_.load(std::memory_order_acquire)};
}

bool ConversionFlow::isCurrentDrain() const noexcept {
  return current_drain_ == this;
}

ConversionFlowRegistrySnapshot conversionFlowRegistrySnapshot() {
  std::lock_guard<std::mutex> lock(registry.mutex);
  return {registry.flows.size(), registry.created_total,
          registry.completed_total, registry.rejected_total,
          registry.stopping};
}

void requestAllConversionFlowsShutdown() noexcept {
  std::vector<std::shared_ptr<ConversionFlow>> active;
  {
    std::lock_guard<std::mutex> lock(registry.mutex);
    registry.stopping = true;
    active.reserve(registry.flows.size());
    for (auto iterator = registry.flows.begin();
         iterator != registry.flows.end();) {
      if (std::shared_ptr<ConversionFlow> flow = iterator->second.lock()) {
        active.emplace_back(std::move(flow));
        ++iterator;
      } else {
        iterator = registry.flows.erase(iterator);
      }
    }
  }
  for (const auto &flow : active)
    flow->requestShutdown();
}
