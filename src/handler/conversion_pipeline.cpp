#include "handler/conversion_pipeline.h"

#include <utility>

namespace {

std::optional<std::string>
cancelled(const ConversionPipelineHooks &hooks) {
  return hooks.cancellation ? hooks.cancellation() : std::nullopt;
}

} // namespace

// Async stage results retain their payloads through stage-specific retained
// byte or owner-working-memory budgets. Flow posts therefore use the default
// metadata-only mailbox charge instead of counting the payload a second time.

std::string runConversionPipeline(ConversionPipelineHooks hooks) {
  if (auto body = cancelled(hooks))
    return std::move(*body);

  for (const auto *stage : {&hooks.parse_and_policy,
                            &hooks.dependency_plan,
                            &hooks.subscription,
                            &hooks.generation}) {
    if (!*stage)
      continue;
    ConversionPipelineStepResult result = (*stage)();
    if (result.complete)
      return std::move(result.body);
    if (auto body = cancelled(hooks))
      return std::move(*body);
  }

  return hooks.assembly ? hooks.assembly() : std::string();
}

bool resolveExternalConfigOnFlow(
    ConversionFlow &flow, std::string path, FetchContext context,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    template_args template_arguments,
    ConversionFlowExternalConfigCompletion completion,
    uint64_t max_output_bytes) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  loadExternalConfigAsync(
      std::move(path), context, std::move(settings),
      std::move(request_context), std::move(template_arguments),
      [operation, completion = std::move(completion)](
          AsyncExternalConfigResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            });
      }, max_output_bytes);
  return true;
}

bool resolveSubscriptionsOnFlow(
    ConversionFlow &flow,
    std::vector<AsyncSubscriptionRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowSubscriptionCompletion completion) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  resolveSubscriptionSourcesAsync(
      std::move(requests), std::move(settings),
      std::move(request_context),
      [operation, completion = std::move(completion)](
          AsyncSubscriptionBatchResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            });
      });
  return true;
}

bool resolveConversionResourcesOnFlow(
    ConversionFlow &flow,
    std::vector<AsyncConversionResourceRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowResourceCompletion completion) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  resolveConversionResourcesAsync(
      std::move(requests), std::move(settings),
      std::move(request_context),
      [operation, completion = std::move(completion)](
          AsyncConversionResourceBatchResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            });
      });
  return true;
}

bool renderTemplateOnFlow(
    ConversionFlow &flow, std::string content,
    template_args arguments, std::string include_scope,
    FetchContext context, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowTemplateCompletion completion,
    uint64_t max_output_bytes) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  renderTemplateAsync(
      std::move(content), std::move(arguments),
      std::move(include_scope), context, std::move(settings),
      std::move(request_context),
      [operation, completion = std::move(completion)](
          AsyncTemplateResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            });
      }, max_output_bytes);
  return true;
}

bool uploadGistOnFlow(
    ConversionFlow &flow, std::string name, std::string path,
    std::string content, bool write_manage_url,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowUploadCompletion completion) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  uploadGistAsync(
      std::move(name), std::move(path), std::move(content),
      write_manage_url, std::move(settings),
      std::move(request_context),
      [operation, completion = std::move(completion)](
          AsyncUploadResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion), result](
                ConversionFlow &resumed) mutable {
              completion(resumed, result);
            });
      });
  return true;
}

bool runQuickJsOnFlow(
    ConversionFlow &flow, QuickJsLane &lane,
    QuickJsTaskOptions options, QuickJsWork work,
    ConversionFlowQuickJsCompletion completion) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !work || !completion)
    return false;
  (void)lane.submit(
      std::move(options), std::move(work),
      [operation, completion = std::move(completion)](
          QuickJsTaskResult result) mutable {
        (void)operation.post(
            [completion = std::move(completion), result](
                ConversionFlow &resumed) mutable {
              completion(resumed, result);
            });
      });
  return true;
}
