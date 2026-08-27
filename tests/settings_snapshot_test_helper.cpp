#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "handler/interfaces.h"
#include "handler/external_config_async.h"
#include "handler/conversion_pipeline.h"
#include "handler/settings.h"
#include "handler/settings_snapshot.h"
#include "handler/webget.h"
#include "generator/config/nodemanip.h"
#include "parser/mihomo_bridge.h"
#include "runtime/conversion_flow.h"
#include "runtime/blocking_io_executor.h"
#include "runtime/memory_budget.h"
#include "runtime/quickjs_lane.h"
#include "script/script_quickjs.h"
#include "server/webserver.h"
#include "utils/logger.h"
#include "utils/resource_control.h"

WebServer webServer;

namespace mihomo {

std::vector<ProxyNode> parseSubscription(const std::string &) {
  throw std::runtime_error(
      "Mihomo parsing is unavailable in the settings snapshot helper");
}

bool isMihomoParserAvailable() { return false; }

AgeRecipient resolveAgeRecipient(const std::string &) {
  throw std::runtime_error(
      "Age recipient resolution is unavailable in the settings snapshot helper");
}

std::string encryptAgeArmored(const std::string &, const std::string &) {
  throw std::runtime_error(
      "Age encryption is unavailable in the settings snapshot helper");
}

} // namespace mihomo

int main(int argc, char *argv[]) {
  const bool webget_probe =
      argc == 6 && std::string(argv[1]) == "--webget-probe";
  const bool fetch_shutdown_race =
      argc == 3 && std::string(argv[1]) == "--fetch-shutdown-race";
  const bool expect_reload_failure =
      argc == 4 && std::string(argv[3]) == "--expect-reload-failure";
  if ((!webget_probe && !fetch_shutdown_race && argc != 2 && argc != 3 &&
       argc != 4) ||
      (argc == 4 && !expect_reload_failure)) {
    std::cerr << "usage: settings_snapshot_test_helper <config> "
                 "[reload-config [--expect-reload-failure]]\n"
                 "       settings_snapshot_test_helper --webget-probe "
                 "<config> <url> <cache-ttl> <delay-ms>\n"
                 "       settings_snapshot_test_helper "
                 "--fetch-shutdown-race <config>\n";
    return 2;
  }

  const std::filesystem::path config =
      std::filesystem::absolute(
          argv[webget_probe || fetch_shutdown_race ? 2 : 1])
          .lexically_normal();
  if (!config.has_filename()) {
    std::cerr << "configuration path has no filename\n";
    return 2;
  }

  std::filesystem::current_path(config.parent_path());
  global.prefPath = config.filename().string();
  if (!readConf())
    return 1;

  if (fetch_shutdown_race) {
    std::atomic<int> ready{0};
    std::atomic<bool> start{false};
    auto rendezvous = [&] {
      ready.fetch_add(1, std::memory_order_release);
      while (!start.load(std::memory_order_acquire))
        std::this_thread::yield();
    };
    std::thread initialize([&] {
      rendezvous();
      (void)asyncFetchEngineAvailable();
    });
    std::thread shutdown([&] {
      rendezvous();
      requestOutboundFetchShutdown();
    });
    while (ready.load(std::memory_order_acquire) != 2)
      std::this_thread::yield();
    start.store(true, std::memory_order_release);
    initialize.join();
    shutdown.join();
    requestOutboundFetchShutdown();
    const AsyncFetchEngineSnapshot snapshot = asyncFetchEngineSnapshot();
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("available");
    writer.Bool(snapshot.available);
    writer.Key("pending");
    writer.Uint64(snapshot.pending);
    writer.Key("active");
    writer.Uint64(snapshot.active);
    writer.Key("running");
    writer.Uint64(snapshot.running);
    writer.EndObject();
    std::cout << buffer.GetString() << '\n';
    return snapshot.available || snapshot.pending != 0 ||
                   snapshot.active != 0 || snapshot.running != 0
               ? 1
               : 0;
  }

  if (webget_probe) {
    int cache_ttl = 0;
    int delay_ms = 0;
    try {
      cache_ttl = std::max(0, std::stoi(argv[4]));
      delay_ms = std::max(0, std::stoi(argv[5]));
    } catch (...) {
      std::cerr << "webget probe cache-ttl and delay-ms must be integers\n";
      return 2;
    }
    auto fetch = [&]() {
      OwnedWebGetRequest request;
      request.url = argv[3];
      request.proxy = ProxyPolicy::direct();
      request.cache_ttl = static_cast<unsigned int>(cache_ttl);
      request.capture_response_headers = true;
      request.context = FetchContext::TrustedConfig;
      request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
      return webGetOwned(std::move(request));
    };
    const OwnedWebGetResult first = fetch();
    if (delay_ms > 0)
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    const OwnedWebGetResult second = fetch();
    const std::string payload_url =
        std::string(argv[3]) + "?payload-singleflight=1";
    auto fetch_payload = [&]() {
      OwnedWebGetRequest request;
      request.url = payload_url;
      request.proxy = ProxyPolicy::direct();
      request.cache_ttl = static_cast<unsigned int>(cache_ttl);
      request.capture_response_headers = true;
      request.context = FetchContext::TrustedConfig;
      request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
      return webGetOwned(std::move(request));
    };
    std::future<OwnedWebGetResult> payload_owner =
        std::async(std::launch::async, fetch_payload);
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    std::future<OwnedWebGetResult> payload_follower =
        std::async(std::launch::async, fetch_payload);
    const OwnedWebGetResult payload_owner_result = payload_owner.get();
    const OwnedWebGetResult payload_follower_result = payload_follower.get();
    const CacheFetchPayloadSnapshot payload_snapshot =
        cacheFetchPayloadSnapshot();
    const CacheFetchOperationProbeSnapshot operation_probe =
        cacheFetchOperationProbe();
    const OwnedWebGetAsyncConsumerProbeSnapshot async_consumer_probe =
        ownedWebGetAsyncConsumerProbe();
    std::promise<OwnedWebGetAsyncOutcome> async_data_completion;
    OwnedWebGetRequest async_data_request;
    async_data_request.url = "data:,owned-async-data";
    async_data_request.proxy = ProxyPolicy::direct();
    webGetOwnedAsync(
        std::move(async_data_request),
        std::make_shared<RequestContext>("owned-async-data",
                                         RequestContext::Clock::now()),
        [&](OwnedWebGetAsyncOutcome outcome) {
          async_data_completion.set_value(std::move(outcome));
        });
    OwnedWebGetAsyncOutcome async_data_outcome =
        async_data_completion.get_future().get();
    const bool async_data_ok =
        async_data_outcome.payload &&
        async_data_outcome.failure == AsyncFetchFailure::None &&
        async_data_outcome.payload->status_code == 200 &&
        async_data_outcome.payload->content == "owned-async-data" &&
        async_data_outcome.payload->retained_bytes.bytes() >=
            async_data_outcome.payload->content.size();
    std::promise<OwnedWebGetAsyncOutcome> async_no_cache_completion;
    OwnedWebGetRequest async_no_cache_request;
    async_no_cache_request.url =
        std::string(argv[3]) + "?owned-async-no-cache=1";
    async_no_cache_request.proxy = ProxyPolicy::direct();
    async_no_cache_request.cache_ttl = 0;
    async_no_cache_request.capture_response_headers = true;
    async_no_cache_request.context = FetchContext::TrustedConfig;
    webGetOwnedAsync(
        std::move(async_no_cache_request),
        std::make_shared<RequestContext>(
            "owned-async-no-cache", RequestContext::Clock::now(),
            RequestContext::Clock::now() + std::chrono::seconds(10)),
        [&](OwnedWebGetAsyncOutcome outcome) {
          async_no_cache_completion.set_value(std::move(outcome));
        });
    const OwnedWebGetAsyncOutcome async_no_cache_outcome =
        async_no_cache_completion.get_future().get();
    const bool async_no_cache_ok =
        async_no_cache_outcome.payload &&
        async_no_cache_outcome.failure == AsyncFetchFailure::None &&
        async_no_cache_outcome.payload->status_code == 200 &&
        async_no_cache_outcome.payload->content ==
            "owned-webget:/webget-probe-hit" &&
        async_no_cache_outcome.payload->response_headers_touched &&
            async_no_cache_outcome.payload->retained_bytes.bytes() >=
                async_no_cache_outcome.payload->content.size();
    bool async_fetch_memory_lifetime_ok = true;
    if (globalFetchMemoryBudgetSnapshot().enabled) {
      std::promise<SharedAsyncFetchResult> held_fetch_completion;
      AsyncFetchRequest held_fetch_request;
      held_fetch_request.url =
          std::string(argv[3]) + "?fetch-memory-lifetime=1";
      held_fetch_request.proxy = ProxyPolicy::direct();
      held_fetch_request.capture_content = true;
      held_fetch_request.retain_result_bytes = true;
      held_fetch_request.context = FetchContext::TrustedConfig;
      held_fetch_request.deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(10);
      webGetAsync(
          std::move(held_fetch_request),
          [&](SharedAsyncFetchResult result) {
            held_fetch_completion.set_value(std::move(result));
          });
      SharedAsyncFetchResult held_fetch =
          held_fetch_completion.get_future().get();
      const FetchMemoryBudgetSnapshot held_fetch_snapshot =
          globalFetchMemoryBudgetSnapshot();
      async_fetch_memory_lifetime_ok =
          held_fetch && held_fetch->failure == AsyncFetchFailure::None &&
          !held_fetch->content.empty() &&
          held_fetch->fetch_memory.bytes() != 0 &&
          held_fetch_snapshot.used >= held_fetch->fetch_memory.bytes();
      held_fetch.reset();
      const auto fetch_release_deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(2);
      while (globalFetchMemoryBudgetSnapshot().used != 0 &&
             std::chrono::steady_clock::now() < fetch_release_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      async_fetch_memory_lifetime_ok =
          async_fetch_memory_lifetime_ok &&
          globalFetchMemoryBudgetSnapshot().used == 0;
    }
    std::promise<OwnedWebGetAsyncOutcome> expired_completion;
    OwnedWebGetRequest expired_request;
    expired_request.url =
        std::string(argv[3]) + "?owned-async-expired=1";
    expired_request.proxy = ProxyPolicy::direct();
    expired_request.cache_ttl = 0;
    expired_request.context = FetchContext::TrustedConfig;
    webGetOwnedAsync(
        std::move(expired_request),
        std::make_shared<RequestContext>(
            "owned-async-expired", RequestContext::Clock::now(),
            RequestContext::Clock::now() - std::chrono::milliseconds(1)),
        [&](OwnedWebGetAsyncOutcome outcome) {
          expired_completion.set_value(std::move(outcome));
        });
    const OwnedWebGetAsyncOutcome expired_outcome =
        expired_completion.get_future().get();
    const bool async_absolute_deadline_ok =
        !expired_outcome.payload &&
        expired_outcome.failure == AsyncFetchFailure::Deadline &&
        expired_outcome.cancellation ==
            RequestCancellationReason::Deadline;
    const bool continuation_was_uninitialized =
        !ownedWebGetContinuationRuntimeSnapshot().initialized;
    std::promise<SchedulerSubmitStatus> preinit_completion;
    const SchedulerSubmitStatus preinit_submit =
        submitOwnedWebGetContinuation(
            RequestCostClass::Low, 0,
            std::chrono::steady_clock::time_point::max(), {}, [] {},
            [&](SchedulerSubmitStatus status, std::exception_ptr) {
              preinit_completion.set_value(status);
            });
    const SchedulerSubmitStatus preinit_status =
        preinit_completion.get_future().get();
    std::promise<OwnedWebGetAsyncOutcome> rejected_cache_completion;
    std::atomic<uint64_t> rejected_cache_completion_count{0};
    OwnedWebGetRequest rejected_cache_request;
    rejected_cache_request.url =
        std::string(argv[3]) + "?owned-async-rejected=1";
    rejected_cache_request.proxy = ProxyPolicy::direct();
    rejected_cache_request.cache_ttl =
        static_cast<unsigned int>(cache_ttl);
    rejected_cache_request.context = FetchContext::TrustedConfig;
    webGetOwnedAsync(
        std::move(rejected_cache_request),
        std::make_shared<RequestContext>(
            "owned-async-cache-rejected",
            RequestContext::Clock::now(),
            RequestContext::Clock::now() + std::chrono::seconds(10)),
        [&](OwnedWebGetAsyncOutcome outcome) {
          rejected_cache_completion_count.fetch_add(
              1, std::memory_order_relaxed);
          rejected_cache_completion.set_value(std::move(outcome));
        });
    const OwnedWebGetAsyncOutcome rejected_cache_outcome =
        rejected_cache_completion.get_future().get();
    const auto rejected_cache_cleanup_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (cacheFetchPayloadSnapshot().registry_entries != 0 &&
           std::chrono::steady_clock::now() <
               rejected_cache_cleanup_deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const bool async_cache_rejection_ok =
        rejected_cache_completion_count.load(std::memory_order_relaxed) == 1 &&
        rejected_cache_outcome.payload &&
        rejected_cache_outcome.failure == AsyncFetchFailure::Shutdown &&
        rejected_cache_outcome.payload->failure ==
            AsyncFetchFailure::Shutdown &&
        cacheFetchPayloadSnapshot().registry_entries == 0;
    const OwnedWebGetContinuationBudget continuation_budget{
        2, 8, 1024 * 1024};
    const OwnedWebGetContinuationInitStatus invalid_init =
        initializeOwnedWebGetContinuationRuntime({0, 8, 1024 * 1024});
    const OwnedWebGetContinuationInitStatus continuation_init =
        initializeOwnedWebGetContinuationRuntime(continuation_budget);
    const OwnedWebGetContinuationInitStatus same_budget_init =
        initializeOwnedWebGetContinuationRuntime(continuation_budget);
    const OwnedWebGetContinuationInitStatus different_budget_init =
        initializeOwnedWebGetContinuationRuntime({2, 9, 1024 * 1024});
    const BlockingIoExecutorInitStatus blocking_io_init =
        initializeBlockingIoExecutor({2, 8, 1024 * 1024});
    const std::string fixture_root =
        std::string(argv[3]).substr(0, std::string(argv[3]).rfind('/'));
    std::promise<AsyncExternalConfigResult> async_external_completion;
    template_args async_external_arguments;
    loadExternalConfigAsync(
        fixture_root + "/async-external-config.toml",
        FetchContext::TrustedConfig, captureEffectiveSettingsSnapshot(),
        std::make_shared<RequestContext>(
            "async-external-config", RequestContext::Clock::now(),
            RequestContext::Clock::now() + std::chrono::seconds(10)),
        std::move(async_external_arguments),
        [&](AsyncExternalConfigResult result) {
          async_external_completion.set_value(std::move(result));
        });
    AsyncExternalConfigResult async_external_result =
        async_external_completion.get_future().get();
    const bool async_external_config_ok =
        async_external_result.status ==
            ExternalConfigLoadStatus::Success &&
        async_external_result.config.custom_proxy_group.size() == 1 &&
        async_external_result.config.custom_proxy_group.front().Name ==
            "AsyncImported" &&
        async_external_result.template_arguments.local_vars["marker"].find(
            "template-ok") != std::string::npos;
    auto make_subscription_requests = [&] {
      std::vector<AsyncSubscriptionRequest> requests;
      for (uint64_t index = 0; index < 2; ++index) {
        AsyncSubscriptionRequest request;
        request.source_index = index;
        request.url = fixture_root + "/subscription.txt?async-batch=" +
                      std::to_string(index);
        request.proxy = ProxyPolicy::direct();
        request.cache_ttl = 0;
        request.context = FetchContext::TrustedConfig;
        requests.emplace_back(std::move(request));
      }
      return requests;
    };
    std::promise<AsyncSubscriptionBatchResult> async_subscription_completion;
    auto async_subscription_context = std::make_shared<RequestContext>(
        "async-subscription-batch", RequestContext::Clock::now(),
        RequestContext::Clock::now() + std::chrono::seconds(10));
    resolveSubscriptionSourcesAsync(
        make_subscription_requests(), captureEffectiveSettingsSnapshot(),
        async_subscription_context,
        [&](AsyncSubscriptionBatchResult result) {
          async_subscription_completion.set_value(std::move(result));
        });
    AsyncSubscriptionBatchResult async_subscription_result =
        async_subscription_completion.get_future().get();
    ProxyPolicy async_subscription_proxy = ProxyPolicy::direct();
    string_array async_exclude, async_include;
    RegexMatchConfigs async_stream, async_time;
    std::string async_sub_info;
    std::vector<Proxy> async_nodes;
    bool async_subscription_ok =
        async_subscription_result.slots.size() == 2;
    for (size_t index = 0;
         index < async_subscription_result.slots.size(); ++index) {
      const AsyncSubscriptionSlot &slot =
          async_subscription_result.slots[index];
      async_subscription_ok =
          async_subscription_ok && slot.source_index == index &&
          slot.failure == AsyncFetchFailure::None && slot.payload &&
          slot.payload->status_code == 200;
      if (!slot.payload)
        continue;
      parse_settings parse;
      parse.proxy = &async_subscription_proxy;
      parse.exclude_remarks = &async_exclude;
      parse.include_remarks = &async_include;
      parse.stream_rules = &async_stream;
      parse.time_rules = &async_time;
      parse.sub_info = &async_sub_info;
      parse.parser_mode = NodeParserMode::LegacyOnly;
      parse.fetch_context = FetchContext::TrustedConfig;
      parse.resolved_subscription_content = &slot.payload->content;
      parse.resolved_subscription_headers =
          &slot.payload->response_headers;
      parse.require_resolved_subscription = true;
      async_subscription_ok =
          async_subscription_ok &&
          addNodes(slot.url, async_nodes, static_cast<int>(index), parse) == 0;
    }
    async_subscription_ok =
        async_subscription_ok && async_nodes.size() == 2 &&
        async_nodes[0].GroupId == 0 && async_nodes[1].GroupId == 1;
    auto make_conversion_resource_requests = [&] {
      std::vector<AsyncConversionResourceRequest> requests;
      for (uint64_t index = 0; index < 2; ++index) {
        AsyncConversionResourceRequest request;
        request.kind = ConversionResourceKind::Ruleset;
        request.source_index = index;
        request.url = fixture_root + "/generation-rules.list?async=" +
                      std::to_string(index);
        request.proxy = ProxyPolicy::direct();
        request.cache_ttl = 0;
        requests.emplace_back(std::move(request));
      }
      AsyncConversionResourceRequest base;
      base.kind = ConversionResourceKind::Base;
      base.source_index = 2;
      base.url = fixture_root + "/async-base.yaml";
      base.proxy = ProxyPolicy::direct();
      base.cache_ttl = 0;
      requests.emplace_back(std::move(base));
      AsyncConversionResourceRequest local_base;
      local_base.kind = ConversionResourceKind::Base;
      local_base.source_index = 3;
      local_base.url = config.filename().string();
      local_base.proxy = ProxyPolicy::direct();
      local_base.cache_ttl = 0;
      local_base.context = FetchContext::TrustedConfig;
      requests.emplace_back(std::move(local_base));
      return requests;
    };
    std::promise<AsyncConversionResourceBatchResult>
        async_resource_completion;
    auto async_resource_context = std::make_shared<RequestContext>(
        "async-conversion-resources", RequestContext::Clock::now(),
        RequestContext::Clock::now() + std::chrono::seconds(10));
    resolveConversionResourcesAsync(
        make_conversion_resource_requests(),
        captureEffectiveSettingsSnapshot(), async_resource_context,
        [&](AsyncConversionResourceBatchResult result) {
          async_resource_completion.set_value(std::move(result));
        });
    AsyncConversionResourceBatchResult async_resource_result =
        async_resource_completion.get_future().get();
    bool async_conversion_resources_ok =
        async_resource_result.resources.size() == 4;
    for (size_t index = 0;
         index < async_resource_result.resources.size(); ++index) {
      const ResolvedConversionResource &resource =
          async_resource_result.resources[index];
      async_conversion_resources_ok =
          async_conversion_resources_ok &&
          resource.source_index == index && resource.payload &&
          resource.failure == AsyncFetchFailure::None &&
          resource.payload->status_code == 200 &&
          !resource.payload->content.empty() &&
          resource.kind == (index < 2 ? ConversionResourceKind::Ruleset
                                      : ConversionResourceKind::Base);
    }
    const std::string async_template_content =
        "marker={{ fetch(\"" + fixture_root +
        "/template-marker\") }}";
    std::promise<AsyncTemplateResult> async_template_completion;
    auto async_template_context = std::make_shared<RequestContext>(
        "async-template", RequestContext::Clock::now(),
        RequestContext::Clock::now() + std::chrono::seconds(10));
    renderTemplateAsync(
        async_template_content, {}, "", FetchContext::TrustedConfig,
        captureEffectiveSettingsSnapshot(), async_template_context,
        [&](AsyncTemplateResult result) {
          async_template_completion.set_value(std::move(result));
        });
    const AsyncTemplateResult async_template_result =
        async_template_completion.get_future().get();
    const bool async_template_ok =
        async_template_result.status == AsyncTemplateStatus::Success &&
        async_template_result.output == "marker=template-ok" &&
        async_template_result.dependency_count == 1;
    {
      std::ofstream gist_config("gistconf.ini", std::ios::trunc);
      gist_config << "[common]\n"
                     "token=fixture-token\n";
    }
    std::promise<AsyncUploadResult> async_upload_completion;
    auto async_upload_context = std::make_shared<RequestContext>(
        "async-upload", RequestContext::Clock::now(),
        RequestContext::Clock::now() + std::chrono::seconds(10));
    uploadGistAsync(
        "async-direct", "async-direct", "async-upload-content", false,
        captureEffectiveSettingsSnapshot(), async_upload_context,
        [&](AsyncUploadResult result) {
          async_upload_completion.set_value(result);
        });
    const AsyncUploadResult async_upload_result =
        async_upload_completion.get_future().get();
    auto cancelled_upload_context = std::make_shared<RequestContext>(
        "async-upload-cancelled", RequestContext::Clock::now(),
        RequestContext::Clock::now() + std::chrono::seconds(10));
    cancelled_upload_context->requestCancellation(
        RequestCancellationReason::ClientDisconnected);
    std::promise<AsyncUploadResult> cancelled_upload_completion;
    uploadGistAsync(
        "async-cancelled", "async-cancelled", "must-not-upload", false,
        captureEffectiveSettingsSnapshot(), cancelled_upload_context,
        [&](AsyncUploadResult result) {
          cancelled_upload_completion.set_value(result);
        });
    const AsyncUploadResult cancelled_upload_result =
        cancelled_upload_completion.get_future().get();
    const bool async_upload_ok =
        async_upload_result.status == AsyncUploadStatus::Success &&
        async_upload_result.remote_status == 201 &&
        cancelled_upload_result.status == AsyncUploadStatus::Cancelled &&
        cancelled_upload_result.remote_status == 0;
    bool quickjs_lane_ok = true;
    bool quickjs_global_ok = true;
#ifndef NO_JS_RUNTIME
    {
      QuickJsLane lane({1, 1, 1024 * 1024,
                        64 * 1024 * 1024, 1024 * 1024});
      const SettingsSnapshot lane_settings =
          captureEffectiveSettingsSnapshot();
      auto first_context = std::make_shared<RequestContext>(
          "quickjs-lane-first", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<void> first_started;
      std::promise<QuickJsTaskResult> first_completion;
      std::future<QuickJsTaskResult> first_future =
          first_completion.get_future();
      std::atomic<uint64_t> side_effects{0};
      std::atomic<uint64_t> completion_count{0};
      std::atomic<bool> scope_ok{false};
      const QuickJsSubmitStatus first_submit = lane.submit(
          {.bytes = 128,
           .settings = lane_settings,
           .request_context = first_context},
          [&](qjs::Context &context) {
            scope_ok.store(
                captureCurrentRequestContext() == first_context &&
                    &effectiveSettings() == lane_settings.get(),
                std::memory_order_release);
            first_started.set_value();
            context.eval("sleep(500)");
            side_effects.fetch_add(1, std::memory_order_relaxed);
          },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            first_completion.set_value(result);
          });
      first_started.get_future().wait();

      std::promise<SchedulerSubmitStatus> ordinary_completion;
      std::future<SchedulerSubmitStatus> ordinary_future =
          ordinary_completion.get_future();
      const SchedulerSubmitStatus ordinary_submit =
          submitOwnedWebGetContinuation(
              RequestCostClass::Low, 1,
              RequestContext::Clock::time_point::max(), {}, [] {},
              [&](SchedulerSubmitStatus status,
                  std::exception_ptr error) {
                ordinary_completion.set_value(
                    error ? SchedulerSubmitStatus::Stopping : status);
              });
      const bool ordinary_completed_while_quickjs_busy =
          ordinary_future.wait_for(std::chrono::seconds(2)) ==
              std::future_status::ready &&
          ordinary_future.get() == SchedulerSubmitStatus::Accepted &&
          first_future.wait_for(std::chrono::milliseconds(0)) !=
              std::future_status::ready;

      std::promise<QuickJsTaskResult> queued_completion;
      std::future<QuickJsTaskResult> queued_future =
          queued_completion.get_future();
      const QuickJsSubmitStatus queued_submit = lane.submit(
          {.bytes = 256,
           .settings = lane_settings,
           .request_context = std::make_shared<RequestContext>(
               "quickjs-lane-queued", RequestContext::Clock::now(),
               RequestContext::Clock::now() +
                   std::chrono::seconds(10))},
          [&](qjs::Context &context) {
            context.eval("1 + 1");
            side_effects.fetch_add(1, std::memory_order_relaxed);
          },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            queued_completion.set_value(result);
          });
      std::promise<QuickJsTaskResult> capacity_completion;
      std::future<QuickJsTaskResult> capacity_future =
          capacity_completion.get_future();
      const QuickJsSubmitStatus capacity_submit = lane.submit(
          {.bytes = 256,
           .settings = lane_settings,
           .request_context = std::make_shared<RequestContext>(
               "quickjs-lane-capacity", RequestContext::Clock::now(),
               RequestContext::Clock::now() +
                   std::chrono::seconds(10))},
          [](qjs::Context &context) { context.eval("2 + 2"); },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            capacity_completion.set_value(result);
          });
      const QuickJsTaskResult capacity_result = capacity_future.get();
      const QuickJsTaskResult first_result = first_future.get();
      const QuickJsTaskResult queued_result = queued_future.get();

      auto cancelled_context = std::make_shared<RequestContext>(
          "quickjs-lane-cancelled", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<void> sleep_started;
      std::promise<QuickJsTaskResult> cancelled_completion;
      std::future<QuickJsTaskResult> cancelled_future =
          cancelled_completion.get_future();
      const QuickJsSubmitStatus cancelled_submit = lane.submit(
          {.bytes = 64,
           .settings = lane_settings,
           .request_context = cancelled_context},
          [&](qjs::Context &context) {
            sleep_started.set_value();
            context.eval("sleep(5000)");
          },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            cancelled_completion.set_value(result);
          });
      sleep_started.get_future().wait();
      const auto cancellation_started = RequestContext::Clock::now();
      (void)cancelled_context->requestCancellation(
          RequestCancellationReason::ClientDisconnected);
      const QuickJsTaskResult cancelled_result = cancelled_future.get();
      const auto cancellation_elapsed =
          RequestContext::Clock::now() - cancellation_started;

      auto deadline_context = std::make_shared<RequestContext>(
          "quickjs-lane-deadline", RequestContext::Clock::now(),
          RequestContext::Clock::now() +
              std::chrono::milliseconds(100));
      std::promise<QuickJsTaskResult> deadline_completion;
      std::future<QuickJsTaskResult> deadline_future =
          deadline_completion.get_future();
      const QuickJsSubmitStatus deadline_submit = lane.submit(
          {.bytes = 64,
           .settings = lane_settings,
           .request_context = deadline_context},
          [](qjs::Context &context) { context.eval("for (;;) {}"); },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            deadline_completion.set_value(result);
          });
      const QuickJsTaskResult deadline_result = deadline_future.get();

      lane.requestShutdown(false);
      const bool lane_joined = lane.join();
      std::promise<QuickJsTaskResult> stopped_completion;
      std::future<QuickJsTaskResult> stopped_future =
          stopped_completion.get_future();
      const QuickJsSubmitStatus stopped_submit = lane.submit(
          {.bytes = 1,
           .settings = lane_settings,
           .request_context = std::make_shared<RequestContext>(
               "quickjs-lane-stopped", RequestContext::Clock::now())},
          [](qjs::Context &context) { context.eval("3 + 3"); },
          [&](QuickJsTaskResult result) {
            completion_count.fetch_add(1, std::memory_order_relaxed);
            stopped_completion.set_value(result);
          });
      const QuickJsTaskResult stopped_result = stopped_future.get();
      const QuickJsLaneSnapshot lane_snapshot = lane.snapshot();
      quickjs_lane_ok =
          first_submit == QuickJsSubmitStatus::Accepted &&
          ordinary_submit == SchedulerSubmitStatus::Accepted &&
          ordinary_completed_while_quickjs_busy &&
          queued_submit == QuickJsSubmitStatus::Accepted &&
          capacity_submit == QuickJsSubmitStatus::EntryLimit &&
          capacity_result.status == QuickJsTaskStatus::Capacity &&
          first_result.status == QuickJsTaskStatus::Success &&
          queued_result.status == QuickJsTaskStatus::Success &&
          cancelled_submit == QuickJsSubmitStatus::Accepted &&
          cancelled_result.status == QuickJsTaskStatus::Cancelled &&
          cancellation_elapsed < std::chrono::seconds(1) &&
          deadline_submit == QuickJsSubmitStatus::Accepted &&
          deadline_result.status == QuickJsTaskStatus::Deadline &&
          lane_joined && stopped_submit == QuickJsSubmitStatus::Stopping &&
          stopped_result.status == QuickJsTaskStatus::Shutdown &&
          scope_ok.load(std::memory_order_acquire) &&
          side_effects.load(std::memory_order_relaxed) == 2 &&
          completion_count.load(std::memory_order_relaxed) == 6 &&
          lane_snapshot.ready && lane_snapshot.stopping &&
          lane_snapshot.joined && lane_snapshot.queued_entries == 0 &&
          lane_snapshot.queued_bytes == 0 && lane_snapshot.active == 0 &&
          lane_snapshot.accepted_total == 4 &&
          lane_snapshot.rejected_total == 2 &&
          lane_snapshot.completed_total == 6 &&
          lane_snapshot.cancelled_total == 1 &&
          lane_snapshot.deadline_total == 1 &&
          lane_snapshot.script_error_total == 0;
    }
    {
      const GlobalQuickJsLaneInitStatus invalid =
          initializeGlobalQuickJsLane({0, 1, 1, 1, 1});
      const GlobalQuickJsLaneInitStatus initialized =
          initializeGlobalQuickJsLane(
              {1, 2, 1024 * 1024, 64 * 1024 * 1024,
               1024 * 1024});
      const GlobalQuickJsLaneInitStatus same =
          initializeGlobalQuickJsLane(
              {1, 2, 1024 * 1024, 64 * 1024 * 1024,
               1024 * 1024});
      const GlobalQuickJsLaneInitStatus mismatch =
          initializeGlobalQuickJsLane(
              {2, 2, 1024 * 1024, 64 * 1024 * 1024,
               1024 * 1024});
      std::promise<QuickJsTaskResult> completion;
      std::future<QuickJsTaskResult> completed = completion.get_future();
      auto context = std::make_shared<RequestContext>(
          "quickjs-global", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      QuickJsLane *global_lane = globalQuickJsLane();
      const QuickJsSubmitStatus submitted = global_lane
          ? global_lane->submit(
                {.bytes = 32,
                 .settings = captureEffectiveSettingsSnapshot(),
                 .request_context = context},
                [](qjs::Context &quickjs) { quickjs.eval("6 * 7"); },
                [&](QuickJsTaskResult result) {
                  completion.set_value(result);
                })
          : QuickJsSubmitStatus::Unavailable;
      QuickJsTaskResult result;
      if (submitted == QuickJsSubmitStatus::Accepted)
        result = completed.get();
      requestGlobalQuickJsLaneShutdown();
      const bool joined = joinGlobalQuickJsLane();
      const QuickJsLaneSnapshot snapshot = globalQuickJsLaneSnapshot();
      quickjs_global_ok =
          invalid == GlobalQuickJsLaneInitStatus::InvalidBudget &&
          initialized == GlobalQuickJsLaneInitStatus::Initialized &&
          same == GlobalQuickJsLaneInitStatus::AlreadyInitialized &&
          mismatch == GlobalQuickJsLaneInitStatus::BudgetMismatch &&
          submitted == QuickJsSubmitStatus::Accepted &&
          result.status == QuickJsTaskStatus::Success && joined &&
          snapshot.ready && snapshot.stopping && snapshot.joined &&
          snapshot.queued_entries == 0 && snapshot.active == 0;
    }
#endif
    constexpr size_t async_cache_consumers = 16;
    const uint64_t retained_before_async_cache =
        retainedResponseByteSnapshot().used;
    std::vector<std::shared_ptr<RequestContext>> async_cache_contexts;
    std::vector<std::shared_ptr<std::promise<OwnedWebGetAsyncOutcome>>>
        async_cache_promises;
    std::vector<std::future<OwnedWebGetAsyncOutcome>> async_cache_futures;
    std::vector<std::shared_ptr<std::atomic<uint64_t>>>
        async_cache_completion_counts;
    async_cache_contexts.reserve(async_cache_consumers);
    async_cache_promises.reserve(async_cache_consumers);
    async_cache_futures.reserve(async_cache_consumers);
    async_cache_completion_counts.reserve(async_cache_consumers);
    const std::string async_cache_url =
        std::string(argv[3]) + "?owned-async-cache=1";
    for (size_t index = 0; index < async_cache_consumers; ++index) {
      auto context = std::make_shared<RequestContext>(
          "owned-async-cache-" + std::to_string(index),
          RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      auto promise =
          std::make_shared<std::promise<OwnedWebGetAsyncOutcome>>();
      auto completion_count = std::make_shared<std::atomic<uint64_t>>(0);
      async_cache_futures.emplace_back(promise->get_future());
      async_cache_contexts.emplace_back(context);
      async_cache_promises.emplace_back(promise);
      async_cache_completion_counts.emplace_back(completion_count);
      OwnedWebGetRequest async_cache_request;
      async_cache_request.url = async_cache_url;
      async_cache_request.proxy = ProxyPolicy::direct();
      async_cache_request.cache_ttl = static_cast<unsigned int>(cache_ttl);
      async_cache_request.capture_response_headers = true;
      async_cache_request.context = FetchContext::TrustedConfig;
      webGetOwnedAsync(
          std::move(async_cache_request), std::move(context),
          [promise, completion_count](OwnedWebGetAsyncOutcome outcome) {
            completion_count->fetch_add(1, std::memory_order_relaxed);
            promise->set_value(std::move(outcome));
          });
    }
    const size_t cancelled_async_cache_consumers[] = {0, 3, 7, 11};
    for (const size_t index : cancelled_async_cache_consumers)
      async_cache_contexts[index]->requestCancellation(
          RequestCancellationReason::ClientDisconnected);

    bool async_cache_ok = true;
    const OwnedWebGetAsyncPayload *shared_async_cache_payload = nullptr;
    for (size_t index = 0; index < async_cache_consumers; ++index) {
      OwnedWebGetAsyncOutcome outcome = async_cache_futures[index].get();
      const bool was_cancelled =
          std::find(std::begin(cancelled_async_cache_consumers),
                    std::end(cancelled_async_cache_consumers), index) !=
          std::end(cancelled_async_cache_consumers);
      if (was_cancelled) {
        async_cache_ok =
            async_cache_ok && !outcome.payload &&
            outcome.failure == AsyncFetchFailure::Cancelled &&
            outcome.cancellation ==
                RequestCancellationReason::ClientDisconnected;
      } else {
        async_cache_ok =
            async_cache_ok && outcome.payload &&
            outcome.failure == AsyncFetchFailure::None &&
            outcome.cancellation == RequestCancellationReason::None &&
            outcome.payload->status_code == 200 &&
            outcome.payload->content ==
                "owned-webget:/webget-probe-hit" &&
            outcome.payload->response_headers_touched &&
            outcome.payload->retained_bytes.bytes() >=
                outcome.payload->content.size();
        if (outcome.payload) {
          if (shared_async_cache_payload == nullptr)
            shared_async_cache_payload = outcome.payload.get();
          else
            async_cache_ok =
                async_cache_ok &&
                shared_async_cache_payload == outcome.payload.get();
        }
      }
    }
    for (const auto &count : async_cache_completion_counts)
      async_cache_ok = async_cache_ok &&
                       count->load(std::memory_order_relaxed) == 1;
    const auto committed_cache_registry_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (cacheFetchPayloadSnapshot().registry_entries != 0 &&
           std::chrono::steady_clock::now() <
               committed_cache_registry_deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    async_cache_ok = async_cache_ok &&
                     cacheFetchPayloadSnapshot().registry_entries == 0;
    std::promise<OwnedWebGetAsyncOutcome> committed_cache_completion;
    OwnedWebGetRequest committed_cache_request;
    committed_cache_request.url = async_cache_url;
    committed_cache_request.proxy = ProxyPolicy::direct();
    committed_cache_request.cache_ttl =
        static_cast<unsigned int>(cache_ttl);
    committed_cache_request.capture_response_headers = true;
    committed_cache_request.context = FetchContext::TrustedConfig;
    webGetOwnedAsync(
        std::move(committed_cache_request),
        std::make_shared<RequestContext>(
            "owned-async-cache-committed",
            RequestContext::Clock::now(),
            RequestContext::Clock::now() + std::chrono::seconds(10)),
        [&](OwnedWebGetAsyncOutcome outcome) {
          committed_cache_completion.set_value(std::move(outcome));
        });
    {
      const OwnedWebGetAsyncOutcome committed_cache_outcome =
          committed_cache_completion.get_future().get();
      async_cache_ok =
          async_cache_ok && committed_cache_outcome.payload &&
          committed_cache_outcome.failure == AsyncFetchFailure::None &&
          committed_cache_outcome.payload->status_code == 200 &&
          committed_cache_outcome.payload->content ==
              "owned-webget:/webget-probe-hit";
    }
    async_cache_promises.clear();
    async_cache_futures.clear();
    async_cache_contexts.clear();
    async_cache_completion_counts.clear();

    const auto async_cache_cleanup_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    CacheFetchPayloadSnapshot async_cache_payload_snapshot;
    AsyncFetchEngineSnapshot async_cache_engine_snapshot;
    OwnedWebGetContinuationRuntimeSnapshot async_cache_runtime_snapshot;
    FetchMemoryBudgetSnapshot async_fetch_memory_snapshot;
    do {
      async_cache_payload_snapshot = cacheFetchPayloadSnapshot();
      async_cache_engine_snapshot = asyncFetchEngineSnapshot();
      async_cache_runtime_snapshot =
          ownedWebGetContinuationRuntimeSnapshot();
      async_fetch_memory_snapshot =
          globalFetchMemoryBudgetSnapshot();
      if (async_cache_payload_snapshot.retained_bytes == 0 &&
          async_cache_payload_snapshot.registry_entries == 0 &&
          async_cache_engine_snapshot.pending == 0 &&
          async_cache_engine_snapshot.active == 0 &&
          async_cache_runtime_snapshot.scheduler.queued_entries == 0 &&
          async_cache_runtime_snapshot.scheduler.queued_bytes == 0 &&
          async_cache_runtime_snapshot.scheduler.active == 0 &&
          (!async_fetch_memory_snapshot.enabled ||
           async_fetch_memory_snapshot.used == 0))
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() <
             async_cache_cleanup_deadline);
    bool async_cache_resources_ok =
        async_cache_payload_snapshot.retained_bytes == 0 &&
        async_cache_payload_snapshot.registry_entries == 0 &&
        async_cache_engine_snapshot.pending == 0 &&
        async_cache_engine_snapshot.active == 0 &&
        async_cache_runtime_snapshot.scheduler.queued_entries == 0 &&
        async_cache_runtime_snapshot.scheduler.queued_bytes == 0 &&
        async_cache_runtime_snapshot.scheduler.active == 0 &&
        (!async_fetch_memory_snapshot.enabled ||
         (async_fetch_memory_snapshot.used == 0 &&
          async_fetch_memory_snapshot.waiters == 0)) &&
        retainedResponseByteSnapshot().used ==
            retained_before_async_cache;

    bool async_runtime_limits_ok = true;
    const ResourceControlSnapshot runtime_resources =
        resourceControlSnapshot();
    if (runtime_resources.effective_mode == "force_max") {
      const ForceMaxBudget &budget =
          runtime_resources.calculated_force_max_budget;
      const AsyncFetchEngineSnapshot before_limits =
          asyncFetchEngineSnapshot();
      const uint64_t guarded_active =
          std::max<uint64_t>(1, budget.outbound_active / 2);
      const uint64_t guarded_open =
          std::max<uint64_t>(guarded_active, budget.outbound_open / 2);
      const uint64_t guarded_host =
          std::min<uint64_t>(guarded_active,
                             std::max<uint64_t>(1,
                                                budget.outbound_per_host / 2));
      const uint64_t guarded_generation =
          before_limits.runtime_limit_generation + 100;
      async_runtime_limits_ok = requestAsyncFetchRuntimeLimits(
          {guarded_active, guarded_host, guarded_open,
           guarded_open - guarded_active, guarded_generation});
      const auto guarded_deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(2);
      AsyncFetchEngineSnapshot guarded_snapshot;
      do {
        guarded_snapshot = asyncFetchEngineSnapshot();
        if (guarded_snapshot.runtime_limit_generation ==
            guarded_generation)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      } while (std::chrono::steady_clock::now() < guarded_deadline);
      async_runtime_limits_ok =
          async_runtime_limits_ok &&
          guarded_snapshot.runtime_limit_generation ==
              guarded_generation &&
          guarded_snapshot.active_connection_limit == guarded_active &&
          guarded_snapshot.per_host_connection_limit == guarded_host &&
          guarded_snapshot.open_connection_limit == guarded_open &&
          guarded_snapshot.connection_cache_limit ==
              guarded_open - guarded_active;

      const uint64_t restored_generation = guarded_generation + 1;
      async_runtime_limits_ok =
          requestAsyncFetchRuntimeLimits(
              {budget.outbound_active, budget.outbound_per_host,
               budget.outbound_open, budget.outbound_idle_cache,
               restored_generation}) &&
          async_runtime_limits_ok;
      const auto restored_deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(2);
      AsyncFetchEngineSnapshot restored_snapshot;
      do {
        restored_snapshot = asyncFetchEngineSnapshot();
        if (restored_snapshot.runtime_limit_generation ==
            restored_generation)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      } while (std::chrono::steady_clock::now() < restored_deadline);
      async_runtime_limits_ok =
          async_runtime_limits_ok &&
          restored_snapshot.runtime_limit_generation ==
              restored_generation &&
          restored_snapshot.active_connection_limit ==
              budget.outbound_active &&
          restored_snapshot.per_host_connection_limit ==
              budget.outbound_per_host &&
          restored_snapshot.open_connection_limit ==
              budget.outbound_open &&
          restored_snapshot.connection_cache_limit ==
              budget.outbound_idle_cache;
    }
    async_cache_resources_ok =
        async_cache_resources_ok && async_runtime_limits_ok &&
        async_fetch_memory_lifetime_ok;

    bool conversion_flow_ok = false;
    ComputeExecutor *compute_executor = globalComputeExecutor();
    const SettingsSnapshot flow_settings =
        captureEffectiveSettingsSnapshot();
    if (compute_executor && flow_settings) {
      auto flow_context = std::make_shared<RequestContext>(
          "conversion-flow-complete", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> flow_completion;
      std::atomic<uint64_t> flow_completion_count{0};
      std::atomic<bool> duplicate_rejected{false};
      std::atomic<bool> initial_scope_ok{false};
      std::atomic<bool> initial_phase_ok{false};
      std::atomic<bool> operation_valid{false};
      std::atomic<bool> operation_posted{false};
      std::atomic<bool> resumed_scope_ok{false};
      std::atomic<bool> resumed_phase_ok{false};
      std::atomic<bool> completed_claimed{false};
      std::shared_ptr<ConversionFlow> flow = ConversionFlow::create(
          *compute_executor, {8, 1024 * 1024}, flow_settings,
          flow_context,
          [&](ConversionFlowTerminal terminal) {
            flow_completion_count.fetch_add(1, std::memory_order_relaxed);
            flow_completion.set_value(std::move(terminal));
          });
      const bool started = flow && flow->start(
          [&](ConversionFlow &current) {
            initial_scope_ok.store(
                captureCurrentRequestContext() == flow_context &&
                    captureEffectiveSettingsSnapshot() == flow_settings,
                std::memory_order_release);
            initial_phase_ok.store(
                current.setPhase(
                    ConversionFlowPhase::FetchingSubscriptions),
                std::memory_order_release);
            const ConversionFlowOperation operation =
                current.beginOperation();
            operation_valid.store(operation.valid(),
                                  std::memory_order_release);
            operation_posted.store(operation.post(
                [&](ConversionFlow &resumed) {
                  resumed_scope_ok.store(
                      captureCurrentRequestContext() == flow_context &&
                          captureEffectiveSettingsSnapshot() ==
                              flow_settings,
                      std::memory_order_release);
                  resumed_phase_ok.store(
                      resumed.setPhase(ConversionFlowPhase::Parsing),
                      std::memory_order_release);
                  completed_claimed.store(
                      resumed.complete(), std::memory_order_release);
                },
                128),
                std::memory_order_release);
            duplicate_rejected.store(
                !operation.post([](ConversionFlow &) {}, 128),
                std::memory_order_release);
          },
          128);
      ConversionFlowTerminal completed_terminal;
      ConversionFlowSnapshot completed_snapshot;
      if (started) {
        completed_terminal = flow_completion.get_future().get();
        completed_snapshot = flow->snapshot();
      }

      auto async_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-external-config",
          RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> async_flow_completion;
      std::atomic<bool> async_flow_result_ok{false};
      std::atomic<bool> async_flow_started_dependency{false};
      std::shared_ptr<ConversionFlow> async_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              async_flow_context,
              [&](ConversionFlowTerminal terminal) {
                async_flow_completion.set_value(std::move(terminal));
              });
      const bool async_flow_started = async_flow && async_flow->start(
          [&](ConversionFlow &current) {
            if (!current.setPhase(
                    ConversionFlowPhase::FetchingExternalConfig))
              throw std::runtime_error("failed to enter external config phase");
            template_args arguments;
            const bool dependency_started = resolveExternalConfigOnFlow(
                    current,
                    fixture_root + "/async-external-config.toml",
                    FetchContext::TrustedConfig, flow_settings,
                    async_flow_context, std::move(arguments),
                    [&](ConversionFlow &resumed,
                        AsyncExternalConfigResult result) {
                      async_flow_result_ok.store(
                          result.status ==
                                  ExternalConfigLoadStatus::Success &&
                              result.config.custom_proxy_group.size() == 1 &&
                              result.config.custom_proxy_group.front().Name ==
                                  "AsyncImported" &&
                              resumed.setPhase(
                                  ConversionFlowPhase::Parsing),
                          std::memory_order_release);
                      (void)resumed.complete();
                    });
            async_flow_started_dependency.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error("failed to start external config");
          });
      ConversionFlowTerminal async_flow_terminal;
      if (async_flow_started)
        async_flow_terminal = async_flow_completion.get_future().get();

      auto subscription_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-subscriptions", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> subscription_flow_completion;
      std::atomic<bool> subscription_flow_result_ok{false};
      std::atomic<bool> subscription_flow_dependency_started{false};
      std::shared_ptr<ConversionFlow> subscription_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              subscription_flow_context,
              [&](ConversionFlowTerminal terminal) {
                subscription_flow_completion.set_value(
                    std::move(terminal));
              });
      const bool subscription_flow_started = subscription_flow &&
          subscription_flow->start([&](ConversionFlow &current) {
            if (!current.setPhase(
                    ConversionFlowPhase::FetchingSubscriptions))
              throw std::runtime_error(
                  "failed to enter subscription phase");
            const bool dependency_started = resolveSubscriptionsOnFlow(
                current, make_subscription_requests(), flow_settings,
                subscription_flow_context,
                [&](ConversionFlow &resumed,
                    AsyncSubscriptionBatchResult result) {
                  bool valid = result.slots.size() == 2;
                  for (size_t index = 0; index < result.slots.size(); ++index)
                    valid = valid && result.slots[index].source_index == index &&
                            result.slots[index].payload &&
                            result.slots[index].failure ==
                                AsyncFetchFailure::None;
                  subscription_flow_result_ok.store(
                      valid && resumed.setPhase(
                                   ConversionFlowPhase::Parsing),
                      std::memory_order_release);
                  (void)resumed.complete();
                });
            subscription_flow_dependency_started.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error(
                  "failed to start subscription batch");
          });
      ConversionFlowTerminal subscription_flow_terminal;
      if (subscription_flow_started)
        subscription_flow_terminal =
            subscription_flow_completion.get_future().get();

      auto resource_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-resources", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> resource_flow_completion;
      std::atomic<bool> resource_flow_result_ok{false};
      std::atomic<bool> resource_flow_dependency_started{false};
      std::shared_ptr<ConversionFlow> resource_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              resource_flow_context,
              [&](ConversionFlowTerminal terminal) {
                resource_flow_completion.set_value(std::move(terminal));
              });
      const bool resource_flow_started = resource_flow &&
          resource_flow->start([&](ConversionFlow &current) {
            if (!current.setPhase(ConversionFlowPhase::FetchingRulesets))
              throw std::runtime_error("failed to enter ruleset phase");
            const bool dependency_started =
                resolveConversionResourcesOnFlow(
                    current, make_conversion_resource_requests(),
                    flow_settings, resource_flow_context,
                    [&](ConversionFlow &resumed,
                        AsyncConversionResourceBatchResult result) {
                      bool valid = result.resources.size() == 4;
                      for (size_t index = 0;
                           index < result.resources.size(); ++index)
                        valid = valid && result.resources[index].payload &&
                                result.resources[index].source_index == index &&
                                result.resources[index].failure ==
                                    AsyncFetchFailure::None;
                      resource_flow_result_ok.store(
                          valid && resumed.setPhase(
                                       ConversionFlowPhase::Parsing),
                          std::memory_order_release);
                      (void)resumed.complete();
                    });
            resource_flow_dependency_started.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error(
                  "failed to start conversion resources");
          });
      ConversionFlowTerminal resource_flow_terminal;
      if (resource_flow_started)
        resource_flow_terminal =
            resource_flow_completion.get_future().get();

      auto template_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-template", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> template_flow_completion;
      std::atomic<bool> template_flow_result_ok{false};
      std::atomic<bool> template_flow_dependency_started{false};
      std::shared_ptr<ConversionFlow> template_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              template_flow_context,
              [&](ConversionFlowTerminal terminal) {
                template_flow_completion.set_value(std::move(terminal));
              });
      const bool template_flow_started = template_flow &&
          template_flow->start([&](ConversionFlow &current) {
            if (!current.setPhase(ConversionFlowPhase::Generating))
              throw std::runtime_error("failed to enter template phase");
            const bool dependency_started = renderTemplateOnFlow(
                current, async_template_content, {}, "",
                FetchContext::TrustedConfig, flow_settings,
                template_flow_context,
                [&](ConversionFlow &resumed, AsyncTemplateResult result) {
                  template_flow_result_ok.store(
                      result.status == AsyncTemplateStatus::Success &&
                          result.output == "marker=template-ok" &&
                          result.dependency_count == 1 &&
                          resumed.setPhase(
                              ConversionFlowPhase::Publishing),
                      std::memory_order_release);
                  (void)resumed.complete();
                });
            template_flow_dependency_started.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error("failed to start template render");
          });
      ConversionFlowTerminal template_flow_terminal;
      if (template_flow_started)
        template_flow_terminal =
            template_flow_completion.get_future().get();

      auto upload_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-upload", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> upload_flow_completion;
      std::atomic<bool> upload_flow_result_ok{false};
      std::atomic<bool> upload_flow_dependency_started{false};
      std::shared_ptr<ConversionFlow> upload_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              upload_flow_context,
              [&](ConversionFlowTerminal terminal) {
                upload_flow_completion.set_value(std::move(terminal));
              });
      const bool upload_flow_started = upload_flow &&
          upload_flow->start([&](ConversionFlow &current) {
            if (!current.setPhase(ConversionFlowPhase::Uploading))
              throw std::runtime_error("failed to enter upload phase");
            const bool dependency_started = uploadGistOnFlow(
                current, "async-flow", "async-flow",
                "async-flow-content", false, flow_settings,
                upload_flow_context,
                [&](ConversionFlow &resumed, AsyncUploadResult result) {
                  upload_flow_result_ok.store(
                      result.status == AsyncUploadStatus::Success &&
                          result.remote_status == 200 &&
                          resumed.setPhase(
                              ConversionFlowPhase::Publishing),
                      std::memory_order_release);
                  (void)resumed.complete();
                });
            upload_flow_dependency_started.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error("failed to start async upload");
          });
      ConversionFlowTerminal upload_flow_terminal;
      if (upload_flow_started)
        upload_flow_terminal =
            upload_flow_completion.get_future().get();

      bool quickjs_flow_started = true;
      bool quickjs_flow_joined = true;
      std::atomic<bool> quickjs_flow_dependency_started{true};
      std::atomic<bool> quickjs_flow_result_ok{true};
      ConversionFlowTerminal quickjs_flow_terminal;
      quickjs_flow_terminal.state =
          ConversionFlowTerminalState::Completed;
#ifndef NO_JS_RUNTIME
      QuickJsLane quickjs_flow_lane(
          {1, 2, 1024 * 1024, 64 * 1024 * 1024, 1024 * 1024});
      auto quickjs_flow_context = std::make_shared<RequestContext>(
          "conversion-flow-quickjs", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<ConversionFlowTerminal> quickjs_flow_completion;
      std::shared_ptr<ConversionFlow> quickjs_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              quickjs_flow_context,
              [&](ConversionFlowTerminal terminal) {
                quickjs_flow_completion.set_value(std::move(terminal));
              });
      quickjs_flow_started = quickjs_flow &&
          quickjs_flow->start([&](ConversionFlow &current) {
            if (!current.setPhase(ConversionFlowPhase::Parsing))
              throw std::runtime_error("failed to enter QuickJS phase");
            const bool dependency_started = runQuickJsOnFlow(
                current, quickjs_flow_lane,
                {.bytes = 64,
                 .settings = flow_settings,
                 .request_context = quickjs_flow_context},
                [](qjs::Context &context) { context.eval("21 * 2"); },
                [&](ConversionFlow &resumed, QuickJsTaskResult result) {
                  quickjs_flow_result_ok.store(
                      result.status == QuickJsTaskStatus::Success &&
                          resumed.setPhase(
                              ConversionFlowPhase::Generating),
                      std::memory_order_release);
                  (void)resumed.complete();
                });
            quickjs_flow_dependency_started.store(
                dependency_started, std::memory_order_release);
            if (!dependency_started)
              throw std::runtime_error("failed to start QuickJS task");
          });
      if (quickjs_flow_started)
        quickjs_flow_terminal =
            quickjs_flow_completion.get_future().get();
      quickjs_flow_lane.requestShutdown(false);
      quickjs_flow_joined = quickjs_flow_lane.join();
#endif

      auto cancelled_context = std::make_shared<RequestContext>(
          "conversion-flow-cancel", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<void> cancel_started;
      std::promise<ConversionFlowTerminal> cancel_completion;
      std::atomic<bool> cancel_phase_ok{false};
      std::atomic<bool> cancel_operation_valid{false};
      std::shared_ptr<ConversionFlow> cancelled_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              cancelled_context,
              [&](ConversionFlowTerminal terminal) {
                cancel_completion.set_value(std::move(terminal));
              });
      const bool cancelled_started = cancelled_flow && cancelled_flow->start(
          [&](ConversionFlow &current) {
            cancel_phase_ok.store(
                current.setPhase(
                    ConversionFlowPhase::FetchingExternalConfig),
                std::memory_order_release);
            cancel_operation_valid.store(
                current.beginOperation().valid(),
                std::memory_order_release);
            cancel_started.set_value();
          });
      ConversionFlowTerminal cancelled_terminal;
      if (cancelled_started) {
        cancel_started.get_future().wait();
        cancelled_context->requestCancellation(
            RequestCancellationReason::ClientDisconnected);
        cancelled_terminal = cancel_completion.get_future().get();
      }

      auto shutdown_context = std::make_shared<RequestContext>(
          "conversion-flow-shutdown", RequestContext::Clock::now(),
          RequestContext::Clock::now() + std::chrono::seconds(10));
      std::promise<void> shutdown_started;
      std::promise<ConversionFlowTerminal> shutdown_completion;
      std::atomic<bool> shutdown_operation_valid{false};
      std::shared_ptr<ConversionFlow> shutdown_flow =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              shutdown_context,
              [&](ConversionFlowTerminal terminal) {
                shutdown_completion.set_value(std::move(terminal));
              });
      const bool shutdown_flow_started = shutdown_flow &&
          shutdown_flow->start(
          [&](ConversionFlow &current) {
            shutdown_operation_valid.store(
                current.beginOperation().valid(),
                std::memory_order_release);
            shutdown_started.set_value();
          });
      ConversionFlowTerminal shutdown_terminal;
      if (shutdown_flow_started) {
        shutdown_started.get_future().wait();
        requestAllConversionFlowsShutdown();
        shutdown_terminal = shutdown_completion.get_future().get();
      } else {
        requestAllConversionFlowsShutdown();
      }
      const std::shared_ptr<ConversionFlow> rejected_after_shutdown =
          ConversionFlow::create(
              *compute_executor, {8, 1024 * 1024}, flow_settings,
              std::make_shared<RequestContext>(
                  "conversion-flow-rejected",
                  RequestContext::Clock::now()),
              [](ConversionFlowTerminal) {});
      const ConversionFlowRegistrySnapshot flow_registry =
          conversionFlowRegistrySnapshot();
#ifdef NO_JS_RUNTIME
      constexpr uint64_t expected_flow_total = 8;
#else
      constexpr uint64_t expected_flow_total = 9;
#endif
      conversion_flow_ok =
          started &&
          initial_scope_ok.load(std::memory_order_acquire) &&
          initial_phase_ok.load(std::memory_order_acquire) &&
          operation_valid.load(std::memory_order_acquire) &&
          operation_posted.load(std::memory_order_acquire) &&
          resumed_scope_ok.load(std::memory_order_acquire) &&
          resumed_phase_ok.load(std::memory_order_acquire) &&
          completed_claimed.load(std::memory_order_acquire) &&
          completed_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          flow_completion_count.load(std::memory_order_relaxed) == 1 &&
          duplicate_rejected.load(std::memory_order_acquire) &&
          completed_snapshot.terminal &&
          completed_snapshot.phase == ConversionFlowPhase::Completed &&
          completed_snapshot.mailbox_entries == 0 &&
          completed_snapshot.mailbox_bytes == 0 &&
          completed_snapshot.outstanding_operations == 0 &&
          completed_snapshot.duplicate_callbacks == 1 &&
          async_flow_started &&
          async_flow_started_dependency.load(std::memory_order_acquire) &&
          async_flow_result_ok.load(std::memory_order_acquire) &&
          async_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          subscription_flow_started &&
          subscription_flow_dependency_started.load(
              std::memory_order_acquire) &&
          subscription_flow_result_ok.load(std::memory_order_acquire) &&
          subscription_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          resource_flow_started &&
          resource_flow_dependency_started.load(
              std::memory_order_acquire) &&
          resource_flow_result_ok.load(std::memory_order_acquire) &&
          resource_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          template_flow_started &&
          template_flow_dependency_started.load(
              std::memory_order_acquire) &&
          template_flow_result_ok.load(std::memory_order_acquire) &&
          template_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          upload_flow_started &&
          upload_flow_dependency_started.load(
              std::memory_order_acquire) &&
          upload_flow_result_ok.load(std::memory_order_acquire) &&
          upload_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          quickjs_flow_started &&
          quickjs_flow_dependency_started.load(
              std::memory_order_acquire) &&
          quickjs_flow_result_ok.load(std::memory_order_acquire) &&
          quickjs_flow_terminal.state ==
              ConversionFlowTerminalState::Completed &&
          quickjs_flow_joined &&
          cancelled_started &&
          cancel_phase_ok.load(std::memory_order_acquire) &&
          cancel_operation_valid.load(std::memory_order_acquire) &&
          cancelled_terminal.state ==
              ConversionFlowTerminalState::Cancelled &&
          cancelled_terminal.cancellation ==
              RequestCancellationReason::ClientDisconnected &&
          shutdown_flow_started &&
          shutdown_operation_valid.load(std::memory_order_acquire) &&
          shutdown_terminal.state ==
              ConversionFlowTerminalState::Shutdown &&
          shutdown_terminal.cancellation ==
              RequestCancellationReason::Shutdown &&
          !rejected_after_shutdown && flow_registry.active == 0 &&
          flow_registry.created_total == expected_flow_total &&
          flow_registry.completed_total == expected_flow_total &&
          flow_registry.rejected_total >= 1 && flow_registry.stopping;
    }

    requestBlockingIoExecutorShutdown();
    const bool blocking_io_joined = joinBlockingIoExecutor();

    std::promise<void> throwing_completion_called;
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Low, 0,
        std::chrono::steady_clock::time_point::max(), {}, [] {},
        [&](SchedulerSubmitStatus, std::exception_ptr) {
          throwing_completion_called.set_value();
          throw std::runtime_error("injected continuation completion failure");
        });
    throwing_completion_called.get_future().wait();
    std::promise<void> continuation_started;
    std::promise<void> continuation_started_second;
    std::promise<void> continuation_release;
    std::shared_future<void> release_future =
        continuation_release.get_future().share();
    std::promise<SchedulerSubmitStatus> active_completion;
    std::promise<SchedulerSubmitStatus> active_completion_second;
    std::promise<SchedulerSubmitStatus> pending_completion;
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Medium, 1,
        std::chrono::steady_clock::time_point::max(), {},
        [&] {
          continuation_started.set_value();
          release_future.wait();
        },
        [&](SchedulerSubmitStatus status, std::exception_ptr error) {
          active_completion.set_value(
              error ? SchedulerSubmitStatus::Stopping : status);
        });
    continuation_started.get_future().wait();
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Medium, 1,
        std::chrono::steady_clock::time_point::max(), {},
        [&] {
          continuation_started_second.set_value();
          release_future.wait();
        },
        [&](SchedulerSubmitStatus status, std::exception_ptr error) {
          active_completion_second.set_value(
              error ? SchedulerSubmitStatus::Stopping : status);
        });
    continuation_started_second.get_future().wait();
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Medium, 1,
        std::chrono::steady_clock::time_point::max(), {}, [] {},
        [&](SchedulerSubmitStatus status, std::exception_ptr) {
          pending_completion.set_value(status);
        });
    std::future<bool> first_join = std::async(
        std::launch::async, [] { return joinOwnedWebGetContinuationRuntime(); });
    std::future<bool> second_join = std::async(
        std::launch::async, [] { return joinOwnedWebGetContinuationRuntime(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    continuation_release.set_value();
    const bool first_joined = first_join.get();
    const bool second_joined = second_join.get();
    const SchedulerSubmitStatus active_status = active_completion.get_future().get();
    const SchedulerSubmitStatus active_status_second =
        active_completion_second.get_future().get();
    const SchedulerSubmitStatus pending_status = pending_completion.get_future().get();
    const OwnedWebGetContinuationRuntimeSnapshot continuation_snapshot =
        ownedWebGetContinuationRuntimeSnapshot();
    std::promise<SchedulerSubmitStatus> stopped_completion;
    const SchedulerSubmitStatus stopped_submit =
        submitOwnedWebGetContinuation(
            RequestCostClass::Low, 0,
            std::chrono::steady_clock::time_point::max(), {}, [] {},
            [&](SchedulerSubmitStatus status, std::exception_ptr) {
              stopped_completion.set_value(status);
            });
    const SchedulerSubmitStatus stopped_status =
        stopped_completion.get_future().get();
    std::string early_headers = "sentinel-header-state";
    const std::string early_body = webGet(
        "data:,owned-webget-early", ProxyPolicy::direct(), 0,
        &early_headers, nullptr, FetchContext::TrustedConfig);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("first_status");
    writer.Int(first.status_code);
    writer.Key("first_body");
    writer.String(first.content.c_str(),
                  static_cast<rapidjson::SizeType>(first.content.size()));
    writer.Key("first_headers");
    writer.String(
        first.response_headers.c_str(),
        static_cast<rapidjson::SizeType>(first.response_headers.size()));
    writer.Key("first_retained_bytes");
    writer.Uint64(first.retained_bytes.bytes());
    writer.Key("second_status");
    writer.Int(second.status_code);
    writer.Key("second_body");
    writer.String(second.content.c_str(),
                  static_cast<rapidjson::SizeType>(second.content.size()));
    writer.Key("second_headers");
    writer.String(
        second.response_headers.c_str(),
        static_cast<rapidjson::SizeType>(second.response_headers.size()));
    writer.Key("second_retained_bytes");
    writer.Uint64(second.retained_bytes.bytes());
    writer.Key("payload_bodies_equal");
    writer.Bool(!payload_owner_result.content.empty() &&
                payload_owner_result.content == payload_follower_result.content);
    writer.Key("payload_retained_bytes");
    writer.Uint64(payload_snapshot.retained_bytes);
    writer.Key("payload_peak_retained_bytes");
    writer.Uint64(payload_snapshot.peak_retained_bytes);
    writer.Key("operation_success_callbacks");
    writer.Uint64(operation_probe.success_callbacks);
    writer.Key("operation_exception_callbacks");
    writer.Uint64(operation_probe.exception_callbacks);
    writer.Key("operation_unsubscribed_callbacks");
    writer.Uint64(operation_probe.unsubscribed_callbacks);
    writer.Key("operation_duplicate_publish_rejected");
    writer.Bool(operation_probe.duplicate_publish_rejected);
    writer.Key("operation_exception_rethrown_to_waiter");
    writer.Bool(operation_probe.exception_rethrown_to_waiter);
    writer.Key("operation_no_consumers_cancelled");
    writer.Bool(operation_probe.no_consumers_cancelled);
    writer.Key("operation_owner_kinds_isolated");
    writer.Bool(operation_probe.owner_kinds_isolated);
    writer.Key("async_consumer_probe_ok");
    writer.Bool(async_consumer_probe.raced_completions == 1 &&
                async_consumer_probe.precancelled_completions == 1 &&
                async_consumer_probe.payload_lease_released);
    writer.Key("async_data_ok");
    writer.Bool(async_data_ok);
    writer.Key("async_no_cache_ok");
    writer.Bool(async_no_cache_ok);
    writer.Key("async_absolute_deadline_ok");
    writer.Bool(async_absolute_deadline_ok);
    writer.Key("async_cache_ok");
    writer.Bool(async_cache_ok);
    writer.Key("async_cache_rejection_ok");
    writer.Bool(async_cache_rejection_ok);
    writer.Key("async_cache_resources_ok");
    writer.Bool(async_cache_resources_ok);
    writer.Key("async_runtime_limits_ok");
    writer.Bool(async_runtime_limits_ok);
    writer.Key("async_fetch_memory_lifetime_ok");
    writer.Bool(async_fetch_memory_lifetime_ok);
    writer.Key("conversion_flow_ok");
    writer.Bool(conversion_flow_ok);
    writer.Key("async_external_config_ok");
    writer.Bool(async_external_config_ok);
    writer.Key("async_external_config_status");
    writer.Int(static_cast<int>(async_external_result.status));
    writer.Key("async_external_config_group_count");
    writer.Uint64(async_external_result.config.custom_proxy_group.size());
    writer.Key("async_external_config_failure_stage");
    writer.String(async_external_result.failure_stage.c_str());
    writer.Key("async_subscription_ok");
    writer.Bool(async_subscription_ok);
    writer.Key("async_conversion_resources_ok");
    writer.Bool(async_conversion_resources_ok);
    writer.Key("async_conversion_resource_summary");
    writer.StartArray();
    for (const ResolvedConversionResource &resource :
         async_resource_result.resources) {
      writer.StartObject();
      writer.Key("source_index");
      writer.Uint64(resource.source_index);
      writer.Key("kind");
      writer.Uint(static_cast<unsigned int>(resource.kind));
      writer.Key("failure");
      writer.Uint(static_cast<unsigned int>(resource.failure));
      writer.Key("status");
      writer.Int(resource.payload ? resource.payload->status_code : 0);
      writer.Key("bytes");
      writer.Uint64(resource.payload ? resource.payload->content.size() : 0);
      writer.EndObject();
    }
    writer.EndArray();
    writer.Key("async_template_ok");
    writer.Bool(async_template_ok);
    writer.Key("async_upload_ok");
    writer.Bool(async_upload_ok);
    writer.Key("async_upload_status");
    writer.Int(static_cast<int>(async_upload_result.status));
    writer.Key("async_upload_remote_status");
    writer.Int(async_upload_result.remote_status);
    writer.Key("async_cancelled_upload_status");
    writer.Int(static_cast<int>(cancelled_upload_result.status));
    writer.Key("quickjs_lane_ok");
    writer.Bool(quickjs_lane_ok);
    writer.Key("quickjs_global_ok");
    writer.Bool(quickjs_global_ok);
    writer.Key("continuation_runtime_ok");
    writer.Bool(continuation_was_uninitialized &&
                preinit_submit == SchedulerSubmitStatus::Stopping &&
                preinit_status == SchedulerSubmitStatus::Stopping &&
                invalid_init ==
                    OwnedWebGetContinuationInitStatus::InvalidBudget &&
                continuation_init ==
                    OwnedWebGetContinuationInitStatus::Initialized &&
                same_budget_init ==
                    OwnedWebGetContinuationInitStatus::AlreadyInitialized &&
                different_budget_init ==
                    OwnedWebGetContinuationInitStatus::BudgetMismatch &&
                blocking_io_init ==
                    BlockingIoExecutorInitStatus::Initialized &&
                blocking_io_joined &&
                active_status == SchedulerSubmitStatus::Accepted &&
                active_status_second == SchedulerSubmitStatus::Accepted &&
                pending_status == SchedulerSubmitStatus::Stopping &&
                first_joined && second_joined &&
                stopped_submit == SchedulerSubmitStatus::Stopping &&
                stopped_status == SchedulerSubmitStatus::Stopping &&
                continuation_snapshot.initialized &&
                continuation_snapshot.stopping &&
                continuation_snapshot.joined &&
                !continuation_snapshot.joining &&
                continuation_snapshot.workers == continuation_budget.workers &&
                continuation_snapshot.max_entries ==
                    continuation_budget.max_entries &&
                continuation_snapshot.max_bytes ==
                    continuation_budget.max_bytes &&
                continuation_snapshot.completion_exception_total >= 1 &&
                // The pre-cancelled upload is deliberately rejected before
                // any network work can start.
                continuation_snapshot.scheduler.rejected == 1 &&
                continuation_snapshot.scheduler.queued_entries == 0 &&
                continuation_snapshot.scheduler.queued_bytes == 0 &&
                continuation_snapshot.scheduler.active == 0);
    writer.Key("early_header_preserved");
    writer.Bool(early_body == "owned-webget-early" &&
                early_headers == "sentinel-header-state");
    writer.EndObject();
    std::cout << buffer.GetString();
    return 0;
  }

  if (argc >= 3) {
    const std::filesystem::path reload_config =
        std::filesystem::absolute(argv[2]).lexically_normal();
    if (!reload_config.has_filename()) {
      std::cerr << "reload configuration path has no filename\n";
      return 2;
    }
    std::filesystem::current_path(reload_config.parent_path());
    global.prefPath = reload_config.filename().string();
    const bool reloaded = readConf();
    if (expect_reload_failure ? reloaded : !reloaded) {
      std::cerr << (expect_reload_failure
                        ? "reload unexpectedly succeeded\n"
                        : "reload failed\n");
      return 1;
    }
    if (expect_reload_failure)
      writeLog(LOG_LEVEL_VERBOSE, "SETTINGS_RELOAD_LEVEL_PROBE");
  }

  std::cout << sanitizedSettingsSnapshot(global);
  return 0;
}
