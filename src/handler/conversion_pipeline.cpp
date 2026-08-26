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
