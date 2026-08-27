#ifndef CONVERSION_RESOURCE_ASYNC_H_INCLUDED
#define CONVERSION_RESOURCE_ASYNC_H_INCLUDED

#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include "handler/proxy_policy.h"
#include "handler/settings_view.h"
#include "handler/webget.h"

enum class ConversionResourceKind {
  Ruleset,
  Base,
  RulePrepend,
  RuleAppend,
  SubscriptionImport,
};

struct AsyncConversionResourceRequest {
  ConversionResourceKind kind = ConversionResourceKind::Ruleset;
  uint64_t source_index = 0;
  std::string url;
  ProxyPolicy proxy;
  string_icase_map request_headers;
  std::shared_future<std::string> preloaded_content;
  unsigned int cache_ttl = 0;
  FetchContext context = FetchContext::TrustedConfig;
};

struct ResolvedConversionResource {
  ConversionResourceKind kind = ConversionResourceKind::Ruleset;
  uint64_t source_index = 0;
  std::string url;
  SharedOwnedWebGetAsyncPayload payload;
  AsyncFetchFailure failure = AsyncFetchFailure::None;
  RequestCancellationReason cancellation =
      RequestCancellationReason::None;
};

struct AsyncConversionResourceBatchResult {
  std::vector<ResolvedConversionResource> resources;
  AsyncFetchFailure terminal_failure = AsyncFetchFailure::None;
};

using AsyncConversionResourceCompletion =
    std::function<void(AsyncConversionResourceBatchResult)>;

void resolveConversionResourcesAsync(
    std::vector<AsyncConversionResourceRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncConversionResourceCompletion completion);

#endif // CONVERSION_RESOURCE_ASYNC_H_INCLUDED
