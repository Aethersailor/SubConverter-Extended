#include "handler/conversion_resource_async.h"

#include <atomic>
#include <mutex>
#include <utility>

namespace {

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
      OwnedWebGetRequest request;
      request.url = source.url;
      request.proxy = source.proxy;
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
  }

private:
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
