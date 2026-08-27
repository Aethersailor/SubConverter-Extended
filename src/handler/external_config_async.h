#ifndef EXTERNAL_CONFIG_ASYNC_H_INCLUDED
#define EXTERNAL_CONFIG_ASYNC_H_INCLUDED

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "server/request_context.h"

struct AsyncExternalConfigResult {
  ExternalConfigLoadStatus status = ExternalConfigLoadStatus::ParseFailed;
  std::string failure_stage;
  ExternalConfig config;
  template_args template_arguments;
  uint64_t working_source_bytes = 0;
};

using AsyncExternalConfigCompletion =
    std::function<void(AsyncExternalConfigResult)>;

void loadExternalConfigAsync(
    std::string path, FetchContext context, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    template_args template_arguments,
    AsyncExternalConfigCompletion completion,
    uint64_t max_output_bytes = 0);

#endif // EXTERNAL_CONFIG_ASYNC_H_INCLUDED
