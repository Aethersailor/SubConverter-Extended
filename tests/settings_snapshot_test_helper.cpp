#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/settings_snapshot.h"
#include "handler/webget.h"
#include "parser/mihomo_bridge.h"
#include "server/webserver.h"
#include "utils/logger.h"

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
    do {
      async_cache_payload_snapshot = cacheFetchPayloadSnapshot();
      async_cache_engine_snapshot = asyncFetchEngineSnapshot();
      async_cache_runtime_snapshot =
          ownedWebGetContinuationRuntimeSnapshot();
      if (async_cache_payload_snapshot.retained_bytes == 0 &&
          async_cache_payload_snapshot.registry_entries == 0 &&
          async_cache_engine_snapshot.pending == 0 &&
          async_cache_engine_snapshot.active == 0 &&
          async_cache_runtime_snapshot.scheduler.queued_entries == 0 &&
          async_cache_runtime_snapshot.scheduler.queued_bytes == 0 &&
          async_cache_runtime_snapshot.scheduler.active == 0)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() <
             async_cache_cleanup_deadline);
    const bool async_cache_resources_ok =
        async_cache_payload_snapshot.retained_bytes == 0 &&
        async_cache_payload_snapshot.registry_entries == 0 &&
        async_cache_engine_snapshot.pending == 0 &&
        async_cache_engine_snapshot.active == 0 &&
        async_cache_runtime_snapshot.scheduler.queued_entries == 0 &&
        async_cache_runtime_snapshot.scheduler.queued_bytes == 0 &&
        async_cache_runtime_snapshot.scheduler.active == 0 &&
        retainedResponseByteSnapshot().used ==
            retained_before_async_cache;

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
    writer.Key("async_cache_ok");
    writer.Bool(async_cache_ok);
    writer.Key("async_cache_rejection_ok");
    writer.Bool(async_cache_rejection_ok);
    writer.Key("async_cache_resources_ok");
    writer.Bool(async_cache_resources_ok);
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
                continuation_snapshot.scheduler.rejected == 0 &&
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
