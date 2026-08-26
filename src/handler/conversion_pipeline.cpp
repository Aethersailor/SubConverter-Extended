#include "handler/conversion_pipeline.h"

#include <cstdint>
#include <utility>

namespace {

std::optional<std::string>
cancelled(const ConversionPipelineHooks &hooks) {
  return hooks.cancellation ? hooks.cancellation() : std::nullopt;
}

} // namespace

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
    ConversionFlowExternalConfigCompletion completion) {
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
      });
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
        uint64_t bytes = 0;
        for (const AsyncSubscriptionSlot &slot : result.slots) {
          if (!slot.payload)
            continue;
          const uint64_t slot_bytes =
              static_cast<uint64_t>(slot.payload->content.size()) +
              static_cast<uint64_t>(slot.payload->response_headers.size());
          if (slot_bytes > UINT64_MAX - bytes) {
            bytes = UINT64_MAX;
            break;
          }
          bytes += slot_bytes;
        }
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            },
            bytes);
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
        uint64_t bytes = 0;
        for (const ResolvedConversionResource &resource : result.resources) {
          if (!resource.payload)
            continue;
          const uint64_t resource_bytes =
              static_cast<uint64_t>(resource.payload->content.size()) +
              static_cast<uint64_t>(
                  resource.payload->response_headers.size());
          if (resource_bytes > UINT64_MAX - bytes) {
            bytes = UINT64_MAX;
            break;
          }
          bytes += resource_bytes;
        }
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            },
            bytes);
      });
  return true;
}

bool renderTemplateOnFlow(
    ConversionFlow &flow, std::string content,
    template_args arguments, std::string include_scope,
    FetchContext context, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowTemplateCompletion completion) {
  const ConversionFlowOperation operation = flow.beginOperation();
  if (!operation.valid() || !completion)
    return false;
  renderTemplateAsync(
      std::move(content), std::move(arguments),
      std::move(include_scope), context, std::move(settings),
      std::move(request_context),
      [operation, completion = std::move(completion)](
          AsyncTemplateResult result) mutable {
        const uint64_t bytes = result.output.size();
        (void)operation.post(
            [completion = std::move(completion),
             result = std::move(result)](ConversionFlow &resumed) mutable {
              completion(resumed, std::move(result));
            },
            bytes);
      });
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
