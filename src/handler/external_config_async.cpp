#include "handler/external_config_async.h"

#include <atomic>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

#include "handler/proxy_policy.h"
#include "handler/webget.h"
#include "generator/template/template_async.h"
#include "runtime/blocking_io_executor.h"
#include "utils/file_extra.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/redact.h"

namespace {

struct SourceCompletionState {
  explicit SourceCompletionState(
      std::function<void(ExternalConfigLoadStatus, std::string)> callback)
      : callback(std::move(callback)) {}

  void complete(ExternalConfigLoadStatus status,
                std::string content = {}) noexcept {
    if (completed.exchange(true, std::memory_order_acq_rel) || !callback)
      return;
    try {
      callback(status, std::move(content));
    } catch (...) {
    }
  }

  std::function<void(ExternalConfigLoadStatus, std::string)> callback;
  std::atomic<bool> completed{false};
};

class AsyncExternalConfigState
    : public std::enable_shared_from_this<AsyncExternalConfigState> {
public:
  AsyncExternalConfigState(
      std::string path, FetchContext context, SettingsSnapshot settings,
      std::shared_ptr<RequestContext> request_context,
      template_args template_arguments,
      AsyncExternalConfigCompletion completion)
      : path_(std::move(path)), context_(context),
        settings_(std::move(settings)),
        request_context_(std::move(request_context)),
        template_arguments_(std::move(template_arguments)),
        completion_(std::move(completion)) {}

  void start() {
    fetchSource(path_, context_,
                [self = shared_from_this()](
                    ExternalConfigLoadStatus status,
                    std::string content) mutable {
                  try {
                    if (status != ExternalConfigLoadStatus::Success) {
                      self->finish(status, "base_fetch");
                      return;
                    }
                    if (!self->retain(content.size())) {
                      self->finish(
                          ExternalConfigLoadStatus::ResourceLimitExceeded,
                          "base_retention");
                      return;
                    }
                    self->base_content_ = std::move(content);
                    self->renderBase();
                  } catch (...) {
                    self->finish(
                        ExternalConfigLoadStatus::ResourceLimitExceeded,
                        "base_completion");
                  }
                });
  }

  void renderBase() {
    auto self = shared_from_this();
    renderTemplateAsync(
        base_content_, template_arguments_, settings_->templatePath,
        context_, settings_, request_context_,
        [self](AsyncTemplateResult result) mutable {
          if (result.status != AsyncTemplateStatus::Success) {
            const char *failure_stage = "base_render";
            if (result.status == AsyncTemplateStatus::FetchFailed)
              failure_stage = "base_render_fetch";
            else if (result.status == AsyncTemplateStatus::RenderFailed)
              failure_stage = "base_render_syntax";
            else if (result.status ==
                     AsyncTemplateStatus::ResourceLimitExceeded)
              failure_stage = "base_render_capacity";
            self->finish(
                result.status == AsyncTemplateStatus::ResourceLimitExceeded
                    ? ExternalConfigLoadStatus::ResourceLimitExceeded
                    : ExternalConfigLoadStatus::RenderFailed,
                failure_stage);
            return;
          }
          if (!self->retain(result.output.size())) {
            self->finish(
                ExternalConfigLoadStatus::ResourceLimitExceeded,
                "rendered_retention");
            return;
          }
          self->rendered_content_ = std::move(result.output);
          self->scheduleParse();
        });
  }

private:
  using SourceCompletion =
      std::function<void(ExternalConfigLoadStatus, std::string)>;

  bool retain(uint64_t bytes) noexcept {
    if (bytes > std::numeric_limits<uint64_t>::max() - retained_.bytes())
      return false;
    return retained_.retain(bytes);
  }

  void fetchSource(std::string source, FetchContext context,
                   SourceCompletion completion) {
    if (request_context_->cancellationToken().isCancellationRequested()) {
      completion(ExternalConfigLoadStatus::FetchFailed, {});
      return;
    }
    if (isLink(source) || startsWith(source, "data:")) {
      OwnedWebGetRequest request;
      request.url = source;
      request.proxy = parseProxy(settings_->proxyConfig,
                                 settings_->proxyBypass);
      request.cache_ttl = static_cast<unsigned int>(
          std::max(0, settings_->cacheConfig));
      request.context = context;
      request.retention =
          OwnedWebGetRequest::RetentionPolicy::Result;
      ScopedSettingsView settings_view(settings_);
      webGetOwnedAsync(
          std::move(request), request_context_,
          [completion = std::move(completion)](
              OwnedWebGetAsyncOutcome outcome) mutable {
            if (!outcome.payload ||
                outcome.failure != AsyncFetchFailure::None ||
                outcome.payload->status_code != 200 ||
                outcome.payload->content.empty()) {
              completion(ExternalConfigLoadStatus::FetchFailed, {});
              return;
            }
            completion(ExternalConfigLoadStatus::Success,
                       outcome.payload->content);
          });
      return;
    }

    auto self = shared_from_this();
    auto completion_state =
        std::make_shared<SourceCompletionState>(std::move(completion));
    const SchedulerSubmitStatus status = submitBlockingIo(
        {.cost = RequestCostClass::Low,
         .bytes = 0,
         .deadline = request_context_->deadline(),
         .cancellation = request_context_->cancellationToken(),
         .preferred_worker = std::nullopt},
        [self, source = std::move(source), context,
         completion_state]() mutable {
          ScopedSettingsView settings_view(self->settings_);
          ScopedRequestContext request_scope(self->request_context_);
          const bool trusted = isTrustedLocalResourcePath(source);
          const bool scope_limit = !trusted;
          std::string content;
          if (fileExist(source, scope_limit) &&
              (!isPublicFetchRestricted(context) || trusted))
            content = fileGet(source, scope_limit);
          completion_state->complete(
              content.empty() ? ExternalConfigLoadStatus::FetchFailed
                              : ExternalConfigLoadStatus::Success,
              std::move(content));
        },
        [completion_state](SchedulerSubmitStatus completion_status,
                           std::exception_ptr error) mutable {
          if (completion_status != SchedulerSubmitStatus::Accepted || error)
            completion_state->complete(
                ExternalConfigLoadStatus::FetchFailed);
        });
    if (status != SchedulerSubmitStatus::Accepted)
      return;
  }

  void scheduleParse() {
    auto self = shared_from_this();
    const uint64_t bytes = retained_.bytes();
    const SchedulerSubmitStatus status = submitOwnedWebGetContinuation(
        RequestCostClass::Medium, bytes, request_context_->deadline(),
        request_context_->cancellationToken(),
        [self] { self->parseAttempt(); },
        [self](SchedulerSubmitStatus completion_status,
               std::exception_ptr error) {
          if (completion_status != SchedulerSubmitStatus::Accepted || error) {
            if (error) {
              try {
                std::rethrow_exception(error);
              } catch (const std::exception &exception) {
                writeLog(LOG_LEVEL_ERROR,
                         "ASYNC_EXTERNAL_CONFIG_PARSE_EXCEPTION detail=" +
                             summarizeSensitiveTextForLog(
                                 exception.what()));
                self->finish(ExternalConfigLoadStatus::FetchFailed,
                             "parse_exception");
                return;
              } catch (...) {
                writeLog(LOG_LEVEL_ERROR,
                         "ASYNC_EXTERNAL_CONFIG_PARSE_EXCEPTION "
                         "detail=unknown");
                self->finish(ExternalConfigLoadStatus::FetchFailed,
                             "parse_exception");
                return;
              }
            }
            self->finish(ExternalConfigLoadStatus::FetchFailed,
                         "parse_continuation");
          }
        });
    if (status != SchedulerSubmitStatus::Accepted)
      return;
  }

  void parseAttempt() {
    if (completed_.load(std::memory_order_acquire))
      return;
    ScopedSettingsView settings_view(settings_);
    ScopedRequestContext request_scope(request_context_);
    template_args attempt_arguments = template_arguments_;
    ExternalConfig attempt;
    attempt.tpl_args = &attempt_arguments;
    string_array missing;
    const ExternalConfigLoadResult loaded =
        loadExternalConfigFromRenderedContent(
            path_, rendered_content_, attempt, context_,
            &resolved_imports_, &missing,
            isExternalConfigCacheableContent(base_content_));
    if (!missing.empty()) {
      const uint64_t total = static_cast<uint64_t>(resolved_imports_.size()) +
                             static_cast<uint64_t>(missing.size());
      if (settings_->maxAllowedRulesets != 0 &&
          total > settings_->maxAllowedRulesets) {
        finish(ExternalConfigLoadStatus::ResourceLimitExceeded,
               "import_limit");
        return;
      }
      fetchMissing(std::move(missing));
      return;
    }
    if (!loaded.ok()) {
      finish(loaded.status, "parse");
      return;
    }
    attempt.tpl_args = nullptr;
    finishSuccess(std::move(attempt), std::move(attempt_arguments));
  }

  void fetchMissing(string_array missing) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_ = missing.size();
      fetch_failed_ = false;
    }
    for (std::string &source : missing) {
      const std::string key = source;
      fetchSource(
          std::move(source), context_,
          [self = shared_from_this(), key](
              ExternalConfigLoadStatus status,
              std::string content) mutable {
            if (self->completed_.load(std::memory_order_acquire))
              return;
            bool ready = false;
            bool failed = false;
            try {
              {
                std::lock_guard<std::mutex> lock(self->mutex_);
                if (status != ExternalConfigLoadStatus::Success ||
                    content.empty() || !self->retain(content.size())) {
                  self->fetch_failed_ = true;
                } else {
                  self->resolved_imports_[key] = std::move(content);
                }
                if (self->pending_ != 0)
                  --self->pending_;
                ready = self->pending_ == 0;
                failed = self->fetch_failed_;
              }
            } catch (...) {
              self->finish(
                  ExternalConfigLoadStatus::ResourceLimitExceeded,
                  "import_completion");
              return;
            }
            if (!ready)
              return;
            if (failed)
              self->finish(ExternalConfigLoadStatus::FetchFailed,
                           "import_fetch");
            else
              self->scheduleParse();
          });
    }
  }

  void finishSuccess(ExternalConfig config,
                     template_args arguments) noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncExternalConfigCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion({ExternalConfigLoadStatus::Success, {},
                  std::move(config), std::move(arguments)});
    } catch (...) {
    }
  }

  void finish(ExternalConfigLoadStatus status,
              std::string failure_stage = {}) noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncExternalConfigCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion({status, std::move(failure_stage), {},
                  std::move(template_arguments_)});
    } catch (...) {
    }
  }

  const std::string path_;
  const FetchContext context_;
  const SettingsSnapshot settings_;
  const std::shared_ptr<RequestContext> request_context_;
  template_args template_arguments_;
  AsyncExternalConfigCompletion completion_;
  std::string base_content_;
  std::string rendered_content_;
  string_map resolved_imports_;
  RetainedResponseByteLease retained_;
  std::mutex mutex_;
  size_t pending_ = 0;
  bool fetch_failed_ = false;
  std::atomic<bool> completed_{false};
};

} // namespace

void loadExternalConfigAsync(
    std::string path, FetchContext context, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    template_args template_arguments,
    AsyncExternalConfigCompletion completion) {
  if (!settings || !request_context || !completion) {
    if (completion)
      completion({ExternalConfigLoadStatus::FetchFailed, {}, {},
                  std::move(template_arguments)});
    return;
  }
  try {
    auto state = std::make_shared<AsyncExternalConfigState>(
        std::move(path), context, settings,
        request_context, template_arguments, completion);
    state->start();
  } catch (...) {
    completion({ExternalConfigLoadStatus::ResourceLimitExceeded,
                "state_allocation", {},
                std::move(template_arguments)});
  }
}
