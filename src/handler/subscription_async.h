#ifndef SUBSCRIPTION_ASYNC_H_INCLUDED
#define SUBSCRIPTION_ASYNC_H_INCLUDED

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "handler/proxy_policy.h"
#include "handler/settings_view.h"
#include "handler/webget.h"

struct AsyncSubscriptionRequest {
  uint64_t source_index = 0;
  std::string url;
  ProxyPolicy proxy;
  string_icase_map request_headers;
  unsigned int cache_ttl = 0;
  FetchContext context = FetchContext::TrustedConfig;
};

struct AsyncSubscriptionSlot {
  uint64_t source_index = 0;
  std::string url;
  SharedOwnedWebGetAsyncPayload payload;
  AsyncFetchFailure failure = AsyncFetchFailure::None;
  RequestCancellationReason cancellation =
      RequestCancellationReason::None;
};

struct AsyncSubscriptionBatchResult {
  std::vector<AsyncSubscriptionSlot> slots;
  AsyncFetchFailure terminal_failure = AsyncFetchFailure::None;
};

using AsyncSubscriptionBatchCompletion =
    std::function<void(AsyncSubscriptionBatchResult)>;

void resolveSubscriptionSourcesAsync(
    std::vector<AsyncSubscriptionRequest> requests,
    SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncSubscriptionBatchCompletion completion);

#endif // SUBSCRIPTION_ASYNC_H_INCLUDED
