#include "generator/template/template_async.h"

#include <atomic>
#include <limits>
#include <mutex>
#include <utility>

#include "handler/proxy_policy.h"
#include "handler/settings.h"
#include "handler/webget.h"

namespace {

class AsyncTemplateState
    : public std::enable_shared_from_this<AsyncTemplateState> {
public:
  AsyncTemplateState(
      std::string content, template_args arguments,
      std::string include_scope, FetchContext context,
      SettingsSnapshot settings,
      std::shared_ptr<RequestContext> request_context,
      AsyncTemplateCompletion completion)
      : content_(std::move(content)), arguments_(std::move(arguments)),
        include_scope_(std::move(include_scope)), context_(context),
        settings_(std::move(settings)),
        request_context_(std::move(request_context)),
        completion_(std::move(completion)) {}

  void start() {
    if (!retain(content_.size())) {
      finish(AsyncTemplateStatus::ResourceLimitExceeded);
      return;
    }
    scheduleRender();
  }

private:
  bool retain(uint64_t bytes) noexcept {
    if (bytes > std::numeric_limits<uint64_t>::max() - retained_.bytes())
      return false;
    return retained_.retain(bytes);
  }

  void scheduleRender() {
    auto self = shared_from_this();
    const SchedulerSubmitStatus status = submitOwnedWebGetContinuation(
        RequestCostClass::Medium, retained_.bytes(),
        request_context_->deadline(),
        request_context_->cancellationToken(),
        [self] { self->renderAttempt(); },
        [self](SchedulerSubmitStatus completion_status,
               std::exception_ptr error) {
          if (completion_status != SchedulerSubmitStatus::Accepted || error)
            self->finish(AsyncTemplateStatus::RenderFailed);
        });
    if (status != SchedulerSubmitStatus::Accepted)
      return;
  }

  void renderAttempt() {
    if (completed_.load(std::memory_order_acquire))
      return;
    ScopedSettingsView settings_view(settings_);
    ScopedRequestContext request_scope(request_context_);
    string_array missing;
    std::string output;
    bool fetch_failed = false;
    const int status = render_template_resolved(
        content_, arguments_, output, include_scope_, context_,
        resolved_fetches_, missing, &fetch_failed);
    if (!missing.empty()) {
      const uint64_t total = static_cast<uint64_t>(resolved_fetches_.size()) +
                             static_cast<uint64_t>(missing.size());
      if (settings_->maxAllowedRulesets != 0 &&
          total > settings_->maxAllowedRulesets) {
        finish(AsyncTemplateStatus::ResourceLimitExceeded);
        return;
      }
      fetchMissing(std::move(missing));
      return;
    }
    if (status != 0 || fetch_failed) {
      finish(fetch_failed ? AsyncTemplateStatus::FetchFailed
                          : AsyncTemplateStatus::RenderFailed);
      return;
    }
    finishSuccess(std::move(output));
  }

  void fetchMissing(string_array missing) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_ = missing.size();
      fetch_failed_ = false;
    }
    for (std::string &url : missing) {
      const std::string key = url;
      OwnedWebGetRequest request;
      request.url = std::move(url);
      request.proxy = parseProxy(settings_->proxyConfig,
                                 settings_->proxyBypass);
      request.cache_ttl = static_cast<unsigned int>(
          std::max(0, settings_->cacheConfig));
      request.context = context_;
      request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
      ScopedSettingsView settings_view(settings_);
      webGetOwnedAsync(
          std::move(request), request_context_,
          [self = shared_from_this(), key](
              OwnedWebGetAsyncOutcome outcome) mutable {
            self->completeFetch(key, std::move(outcome));
          });
    }
  }

  void completeFetch(const std::string &key,
                     OwnedWebGetAsyncOutcome outcome) noexcept {
    if (completed_.load(std::memory_order_acquire))
      return;
    bool ready = false;
    bool failed = false;
    try {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!outcome.payload ||
          outcome.failure != AsyncFetchFailure::None ||
          outcome.payload->status_code != 200 ||
          !retain(outcome.payload->content.size())) {
        fetch_failed_ = true;
      } else {
        resolved_fetches_[key] = outcome.payload->content;
      }
      if (pending_ != 0)
        --pending_;
      ready = pending_ == 0;
      failed = fetch_failed_;
    } catch (...) {
      finish(AsyncTemplateStatus::ResourceLimitExceeded);
      return;
    }
    if (!ready)
      return;
    if (failed)
      finish(AsyncTemplateStatus::FetchFailed);
    else
      scheduleRender();
  }

  void finishSuccess(std::string output) noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncTemplateCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion({AsyncTemplateStatus::Success, std::move(output),
                  resolved_fetches_.size()});
    } catch (...) {
    }
  }

  void finish(AsyncTemplateStatus status) noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncTemplateCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion({status, {}, resolved_fetches_.size()});
    } catch (...) {
    }
  }

  const std::string content_;
  const template_args arguments_;
  const std::string include_scope_;
  const FetchContext context_;
  const SettingsSnapshot settings_;
  const std::shared_ptr<RequestContext> request_context_;
  AsyncTemplateCompletion completion_;
  string_map resolved_fetches_;
  RetainedResponseByteLease retained_;
  std::mutex mutex_;
  size_t pending_ = 0;
  bool fetch_failed_ = false;
  std::atomic<bool> completed_{false};
};

} // namespace

void renderTemplateAsync(
    std::string content, template_args arguments,
    std::string include_scope, FetchContext context,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncTemplateCompletion completion) {
  if (!settings || !request_context || !completion) {
    if (completion)
      completion({AsyncTemplateStatus::RenderFailed, {}, 0});
    return;
  }
  try {
    auto state = std::make_shared<AsyncTemplateState>(
        std::move(content), std::move(arguments),
        std::move(include_scope), context, settings,
        request_context, completion);
    state->start();
  } catch (...) {
    completion({AsyncTemplateStatus::ResourceLimitExceeded, {}, 0});
  }
}
