#include "handler/conversion_resource_async.h"

#include <atomic>
#include <mutex>
#include <utility>

#include "runtime/blocking_io_executor.h"
#include "handler/settings.h"
#include "utils/file_extra.h"
#include "utils/network.h"

namespace {

AsyncFetchFailure localFailure(SchedulerSubmitStatus status) noexcept {
  switch (status) {
  case SchedulerSubmitStatus::Cancelled:
    return AsyncFetchFailure::Cancelled;
  case SchedulerSubmitStatus::Deadline:
    return AsyncFetchFailure::Deadline;
  case SchedulerSubmitStatus::Stopping:
    return AsyncFetchFailure::Shutdown;
  case SchedulerSubmitStatus::EntryLimit:
  case SchedulerSubmitStatus::ByteLimit:
    return AsyncFetchFailure::Capacity;
  case SchedulerSubmitStatus::Accepted:
    break;
  }
  return AsyncFetchFailure::Transport;
}

class AsyncConversionResourceState
    : public std::enable_shared_from_this<AsyncConversionResourceState> {
public:
  AsyncConversionResourceState(
      std::vector<AsyncConversionResourceRequest> requests,
      SettingsSnapshot settings,
      std::shared_ptr<RequestContext> request_context,
      AsyncConversionResourceCompletion completion)
      : requests_(std::move(requests)), settings_(std::move(settings)),
        request_context_(std::move(request_context)),
        completion_(std::move(completion)) {
    result_.resources.resize(requests_.size());
    remaining_ = requests_.size();
  }

  void start() {
    if (requests_.empty()) {
      finish();
      return;
    }
    for (size_t index = 0; index < requests_.size(); ++index) {
      AsyncConversionResourceRequest &source = requests_[index];
      ResolvedConversionResource &slot = result_.resources[index];
      slot.kind = source.kind;
      slot.source_index = source.source_index;
      slot.url = source.url;
      if (source.preloaded_content.valid()) {
        startPreloaded(index, source.preloaded_content);
        continue;
      }
      if (!isLink(source.url) && !startsWith(source.url, "data:")) {
        startLocal(index, source);
        continue;
      }
      startRemote(index, source);
    }
  }

private:
  void startRemote(size_t index,
                   const AsyncConversionResourceRequest &source) {
    OwnedWebGetRequest request;
    request.url = source.url;
    request.proxy = source.proxy;
    request.has_request_headers = !source.request_headers.empty();
    request.request_headers = source.request_headers;
    request.cache_ttl = source.cache_ttl;
    request.capture_response_headers = true;
    request.context = source.context;
    request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
    ScopedSettingsView settings_view(settings_);
    webGetOwnedAsync(
        std::move(request), request_context_,
        [self = shared_from_this(), index](
            OwnedWebGetAsyncOutcome outcome) mutable {
          self->complete(index, std::move(outcome));
        });
  }

  void startPreloaded(size_t index,
                      std::shared_future<std::string> content) {
    auto self = shared_from_this();
    (void)submitBlockingIo(
        {.cost = RequestCostClass::Low,
         .bytes = 0,
         .deadline = request_context_->deadline(),
         .cancellation = request_context_->cancellationToken(),
         .preferred_worker = std::nullopt},
        [self, index, content = std::move(content)]() mutable {
          OwnedWebGetAsyncOutcome outcome;
          try {
            auto payload = std::make_shared<OwnedWebGetAsyncPayload>();
            payload->status_code = 200;
            payload->content = content.get();
            if (!payload->retained_bytes.retain(payload->content.size()))
              outcome.failure = AsyncFetchFailure::Capacity;
            else
              outcome.payload = std::move(payload);
          } catch (...) {
            outcome.failure = AsyncFetchFailure::Transport;
          }
          self->complete(index, std::move(outcome));
        },
        [self, index](SchedulerSubmitStatus completion_status,
                      std::exception_ptr error) mutable {
          if (completion_status == SchedulerSubmitStatus::Accepted && !error)
            return;
          OwnedWebGetAsyncOutcome outcome;
          outcome.failure = error ? AsyncFetchFailure::Transport
                                  : localFailure(completion_status);
          self->complete(index, std::move(outcome));
        });
  }

  void startLocal(size_t index,
                  const AsyncConversionResourceRequest &source) {
    const AsyncConversionResourceRequest request = source;
    const std::string path = request.url;
    auto self = shared_from_this();
    const SchedulerSubmitStatus status = submitBlockingIo(
        {.cost = RequestCostClass::Low,
         .bytes = static_cast<uint64_t>(path.size()),
         .deadline = request_context_->deadline(),
         .cancellation = request_context_->cancellationToken(),
         .preferred_worker = std::nullopt},
        [self, index, path, request]() mutable {
          ScopedSettingsView settings_view(self->settings_);
          ScopedRequestContext request_scope(self->request_context_);
          OwnedWebGetAsyncOutcome outcome;
          try {
            const bool trusted = isTrustedLocalResourcePath(path);
            const bool scope_limit = !trusted;
            if (!fileExist(path, scope_limit) ||
                (isPublicFetchRestricted(request.context) && !trusted)) {
              self->startRemote(index, request);
              return;
            } else {
              auto payload = std::make_shared<OwnedWebGetAsyncPayload>();
              payload->status_code = 200;
              payload->content = fileGet(path, scope_limit);
              if (!payload->retained_bytes.retain(payload->content.size())) {
                outcome.failure = AsyncFetchFailure::Capacity;
              } else {
                outcome.payload = std::move(payload);
              }
            }
          } catch (...) {
            outcome.failure = AsyncFetchFailure::Transport;
          }
          self->complete(index, std::move(outcome));
        },
        [self, index](SchedulerSubmitStatus completion_status,
                      std::exception_ptr error) mutable {
          if (completion_status == SchedulerSubmitStatus::Accepted && !error)
            return;
          OwnedWebGetAsyncOutcome outcome;
          outcome.failure = error ? AsyncFetchFailure::Transport
                                  : localFailure(completion_status);
          if (completion_status == SchedulerSubmitStatus::Cancelled)
            outcome.cancellation = RequestCancellationReason::ClientDisconnected;
          else if (completion_status == SchedulerSubmitStatus::Deadline)
            outcome.cancellation = RequestCancellationReason::Deadline;
          else if (completion_status == SchedulerSubmitStatus::Stopping)
            outcome.cancellation = RequestCancellationReason::Shutdown;
          self->complete(index, std::move(outcome));
        });
    (void)status;
  }

  void complete(size_t index,
                OwnedWebGetAsyncOutcome outcome) noexcept {
    bool ready = false;
    try {
      std::lock_guard<std::mutex> lock(mutex_);
      if (completed_.load(std::memory_order_acquire) ||
          index >= result_.resources.size())
        return;
      ResolvedConversionResource &slot = result_.resources[index];
      slot.payload = std::move(outcome.payload);
      slot.failure = outcome.failure;
      slot.cancellation = outcome.cancellation;
      if (remaining_ != 0)
        --remaining_;
      ready = remaining_ == 0;
    } catch (...) {
      finish();
      return;
    }
    if (ready)
      finish();
  }

  void finish() noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncConversionResourceCompletion completion =
        std::move(completion_);
    if (!completion)
      return;
    try {
      completion(std::move(result_));
    } catch (...) {
    }
  }

  std::vector<AsyncConversionResourceRequest> requests_;
  const SettingsSnapshot settings_;
  const std::shared_ptr<RequestContext> request_context_;
  AsyncConversionResourceCompletion completion_;
  AsyncConversionResourceBatchResult result_;
  std::mutex mutex_;
  size_t remaining_ = 0;
  std::atomic<bool> completed_{false};
};

} // namespace

void resolveConversionResourcesAsync(
    std::vector<AsyncConversionResourceRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncConversionResourceCompletion completion) {
  if (!settings || !request_context || !completion) {
    if (completion)
      completion({});
    return;
  }
  try {
    auto state = std::make_shared<AsyncConversionResourceState>(
        std::move(requests), settings, request_context, completion);
    state->start();
  } catch (...) {
    completion({});
  }
}
