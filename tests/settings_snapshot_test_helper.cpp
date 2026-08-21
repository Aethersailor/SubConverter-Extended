#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

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
  const bool expect_reload_failure =
      argc == 4 && std::string(argv[3]) == "--expect-reload-failure";
  if ((!webget_probe && argc != 2 && argc != 3 && argc != 4) ||
      (argc == 4 && !expect_reload_failure)) {
    std::cerr << "usage: settings_snapshot_test_helper <config> "
                 "[reload-config [--expect-reload-failure]]\n"
                 "       settings_snapshot_test_helper --webget-probe "
                 "<config> <url> <cache-ttl> <delay-ms>\n";
    return 2;
  }

  const std::filesystem::path config =
      std::filesystem::absolute(argv[webget_probe ? 2 : 1]).lexically_normal();
  if (!config.has_filename()) {
    std::cerr << "configuration path has no filename\n";
    return 2;
  }

  std::filesystem::current_path(config.parent_path());
  global.prefPath = config.filename().string();
  if (!readConf())
    return 1;

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
