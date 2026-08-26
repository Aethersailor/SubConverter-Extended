#ifndef CONVERSION_PIPELINE_H_INCLUDED
#define CONVERSION_PIPELINE_H_INCLUDED

#include <functional>
#include <optional>
#include <string>

struct ConversionPipelineStepResult {
  bool complete = false;
  std::string body;
};

struct ConversionPipelineHooks {
  std::function<std::optional<std::string>()> cancellation;
  std::function<ConversionPipelineStepResult()> parse_and_policy;
  std::function<ConversionPipelineStepResult()> dependency_plan;
  std::function<ConversionPipelineStepResult()> subscription;
  std::function<ConversionPipelineStepResult()> generation;
  std::function<std::string()> assembly;
};

std::string runConversionPipeline(ConversionPipelineHooks hooks);

#endif // CONVERSION_PIPELINE_H_INCLUDED
