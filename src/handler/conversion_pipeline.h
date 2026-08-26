#ifndef CONVERSION_PIPELINE_H_INCLUDED
#define CONVERSION_PIPELINE_H_INCLUDED

#include <functional>
#include <optional>
#include <string>

#include "handler/external_config_async.h"
#include "handler/conversion_resource_async.h"
#include "generator/template/template_async.h"
#include "handler/subscription_async.h"
#include "runtime/conversion_flow.h"

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

using ConversionFlowExternalConfigCompletion =
    std::function<void(ConversionFlow &, AsyncExternalConfigResult)>;

bool resolveExternalConfigOnFlow(
    ConversionFlow &flow, std::string path, FetchContext context,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    template_args template_arguments,
    ConversionFlowExternalConfigCompletion completion);

using ConversionFlowSubscriptionCompletion =
    std::function<void(ConversionFlow &, AsyncSubscriptionBatchResult)>;

bool resolveSubscriptionsOnFlow(
    ConversionFlow &flow,
    std::vector<AsyncSubscriptionRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowSubscriptionCompletion completion);

using ConversionFlowResourceCompletion =
    std::function<void(ConversionFlow &,
                       AsyncConversionResourceBatchResult)>;

bool resolveConversionResourcesOnFlow(
    ConversionFlow &flow,
    std::vector<AsyncConversionResourceRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowResourceCompletion completion);

using ConversionFlowTemplateCompletion =
    std::function<void(ConversionFlow &, AsyncTemplateResult)>;

bool renderTemplateOnFlow(
    ConversionFlow &flow, std::string content,
    template_args arguments, std::string include_scope,
    FetchContext context, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    ConversionFlowTemplateCompletion completion);

#endif // CONVERSION_PIPELINE_H_INCLUDED
