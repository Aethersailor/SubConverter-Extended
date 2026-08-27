#ifndef TEMPLATE_ASYNC_H_INCLUDED
#define TEMPLATE_ASYNC_H_INCLUDED

#include <functional>
#include <memory>
#include <string>

#include "generator/template/templates.h"
#include "handler/settings_view.h"
#include "server/request_context.h"

enum class AsyncTemplateStatus {
  Success,
  FetchFailed,
  RenderFailed,
  ResourceLimitExceeded,
  Cancelled,
  Deadline,
  Shutdown,
};

struct AsyncTemplateResult {
  AsyncTemplateStatus status = AsyncTemplateStatus::RenderFailed;
  std::string output;
  uint64_t dependency_count = 0;
};

using AsyncTemplateCompletion =
    std::function<void(AsyncTemplateResult)>;

void renderTemplateAsync(
    std::string content, template_args arguments,
    std::string include_scope, FetchContext context,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncTemplateCompletion completion,
    uint64_t max_output_bytes = 0);

#endif // TEMPLATE_ASYNC_H_INCLUDED
