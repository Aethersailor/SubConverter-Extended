#include "handler/conversion_pipeline.h"

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
