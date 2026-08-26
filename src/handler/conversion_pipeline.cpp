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
