#include "handler/statistics.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "handler/statistics_v2.h"
#include "handler/conversion_service.h"
#include "handler/webget.h"
#include "server/request_context.h"
#include "utils/logger.h"
#include "utils/redact.h"
#include "utils/resource_control.h"

namespace {

using statistics_v2::Counters;
using statistics_v2::DashboardSnapshot;
using statistics_v2::GeoId;
using statistics_v2::WindowSnapshot;

constexpr auto kDashboardCacheLifetime = std::chrono::seconds(1);
constexpr auto kMaximumRetry = std::chrono::seconds(60);
constexpr auto kErrorLogInterval = std::chrono::seconds(60);

int64_t nowSeconds() { return static_cast<int64_t>(std::time(nullptr)); }

bool asciiEqualsIgnoreCase(const std::string &value, const char *expected) {
  std::size_t length = 0;
  while (expected[length] != '\0')
    ++length;
  if (value.size() != length)
    return false;
  for (std::size_t i = 0; i < length; ++i) {
    char left = value[i], right = expected[i];
    if (left >= 'A' && left <= 'Z')
      left = static_cast<char>(left - 'A' + 'a');
    if (right >= 'A' && right <= 'Z')
      right = static_cast<char>(right - 'A' + 'a');
    if (left != right)
      return false;
  }
  return true;
}

struct GeoConfig {
  bool enabled = true;
  std::vector<std::string> country_headers;
  std::vector<std::string> china_region_headers;
};

struct GeoLocation {
  GeoId country = statistics_v2::countryGeoId("ZZ");
  GeoId china_region = statistics_v2::kInvalidGeoId;
};

GeoId findCountry(const Request &request, const GeoConfig &config) {
  const GeoId unknown = statistics_v2::countryGeoId("ZZ");
  for (const std::string &header : config.country_headers) {
    const auto found = request.headers.find(header);
    if (found == request.headers.end())
      continue;
    const GeoId id = statistics_v2::countryGeoId(found->second);
    // Historical behavior treats explicit/invalid ZZ as "keep looking".
    if (id != unknown)
      return id;
  }
  return unknown;
}

GeoLocation geoLocation(const Request &request, const GeoConfig &config) {
  GeoLocation result;
  if (!config.enabled)
    return result;
  result.country = findCountry(request, config);
  const GeoId cn = statistics_v2::countryGeoId("CN");
  const GeoId hk = statistics_v2::countryGeoId("HK");
  const GeoId mo = statistics_v2::countryGeoId("MO");
  const GeoId tw = statistics_v2::countryGeoId("TW");
  if (result.country == hk)
    result.china_region = statistics_v2::chinaRegionGeoId("CN-HK");
  else if (result.country == mo)
    result.china_region = statistics_v2::chinaRegionGeoId("CN-MO");
  else if (result.country == tw)
    result.china_region = statistics_v2::chinaRegionGeoId("CN-TW");
  else if (result.country == cn) {
    for (const std::string &header : config.china_region_headers) {
      const auto found = request.headers.find(header);
      if (found == request.headers.end())
        continue;
      result.china_region =
          statistics_v2::chinaRegionGeoId(found->second);
      if (result.china_region != statistics_v2::kInvalidGeoId)
        break;
    }
    if (result.china_region == statistics_v2::kInvalidGeoId)
      result.china_region = statistics_v2::chinaRegionGeoId("CN-XX");
  }
  return result;
}

struct Engine {
  std::mutex mutex;
  std::condition_variable condition;
  statistics_v2::Core core;
  std::unique_ptr<statistics_v2::Store> store;
  std::thread persistence_thread;
  GeoConfig geo;
  bool initialized = false;
  bool stopping = false;
  int flush_interval_seconds = 5;
};

Engine g_engine;
std::mutex g_cache_mutex;
std::string g_cached_dashboard;
std::chrono::steady_clock::time_point g_cached_dashboard_at{};

void logPersistenceError(const std::string &message,
                         std::chrono::steady_clock::time_point &last_log) {
  const auto now = std::chrono::steady_clock::now();
  if (last_log.time_since_epoch().count() != 0 &&
      now - last_log < kErrorLogInterval)
    return;
  last_log = now;
  writeLog(LOG_LEVEL_WARNING, "Statistics v2 持久化已降级为纯内存模式：" + message);
}

void logPersistenceException(
    const char *category, const char *detail,
    std::chrono::steady_clock::time_point &last_log) noexcept {
  try {
    std::string message(category);
    if (detail && detail[0] != '\0') {
      message += " detail=";
      message += summarizeSensitiveTextForLog(detail);
    }
    logPersistenceError(message, last_log);
  } catch (...) {
    // Logging must never make the persistence worker terminate.
  }
}

void persistenceWorker() {
  const auto heartbeat_interval = std::chrono::seconds(
      statistics_v2::runtimeHeartbeatIntervalSeconds(
          g_engine.flush_interval_seconds));
  const auto started = std::chrono::steady_clock::now();
  auto next_flush = started;
  auto next_heartbeat = started + heartbeat_interval;
  auto retry_delay = std::chrono::seconds(1);
  auto next_retry = started;
  std::chrono::steady_clock::time_point last_error_log{};
  std::unique_ptr<statistics_v2::DirtyPatch> pending;

  for (;;) {
    bool stopping = false;
    bool cycle_failed = false;
    try {
      {
        std::unique_lock<std::mutex> lock(g_engine.mutex);
        const bool store_ready =
            g_engine.store && g_engine.store->ready();
        const auto wake_at =
            store_ready ? std::min(next_flush, next_heartbeat) : next_retry;
        g_engine.condition.wait_until(lock, wake_at, [] {
          return g_engine.stopping;
        });
        stopping = g_engine.stopping;
      }

      const auto steady_now = std::chrono::steady_clock::now();
      bool store_ready = g_engine.store && g_engine.store->ready();
      if (!store_ready && (stopping || steady_now >= next_retry)) {
        const statistics_v2::StoreStatus status = g_engine.store->open();
        if (status == statistics_v2::StoreStatus::Ready) {
          // A later recovery must not replace the authoritative in-memory
          // state. load() only validates/repairs the existing files.
          g_engine.store->load();
          store_ready = g_engine.store->ready();
          statistics_v2::PersistentImage image;
          uint64_t dirty_version = 0;
          if (store_ready) {
            std::lock_guard<std::mutex> lock(g_engine.mutex);
            image = g_engine.core.checkpointImage(
                nowSeconds(), stopping, dirty_version);
          }
          if (store_ready && g_engine.store->writeCheckpoint(image)) {
            {
              std::lock_guard<std::mutex> lock(g_engine.mutex);
              g_engine.core.acknowledgeCheckpoint(dirty_version);
            }
            pending.reset();
            g_engine.store->cleanupLegacyFile();
            retry_delay = std::chrono::seconds(1);
            store_ready = true;
            next_heartbeat = steady_now + heartbeat_interval;
            writeLog(LOG_LEVEL_INFO, "Statistics v2 持久化已恢复。");
          } else {
            logPersistenceError(g_engine.store->lastError(), last_error_log);
            g_engine.store->close();
            store_ready = false;
          }
        } else {
          logPersistenceError(g_engine.store->lastError(), last_error_log);
        }
        if (!store_ready) {
          next_retry = steady_now + retry_delay;
          retry_delay = std::min(retry_delay * 2, kMaximumRetry);
        }
      }

      store_ready = g_engine.store && g_engine.store->ready();
      if (store_ready && g_engine.store->generation() == 0) {
        statistics_v2::PersistentImage image;
        uint64_t dirty_version = 0;
        {
          std::lock_guard<std::mutex> lock(g_engine.mutex);
          image = g_engine.core.checkpointImage(
              nowSeconds(), stopping, dirty_version);
        }
        if (!g_engine.store->ensureInitialCheckpoint(image)) {
          logPersistenceError(g_engine.store->lastError(), last_error_log);
          g_engine.store->close();
          next_retry = steady_now + retry_delay;
          if (stopping)
            break;
          continue;
        }
        {
          std::lock_guard<std::mutex> lock(g_engine.mutex);
          g_engine.core.acknowledgeCheckpoint(dirty_version);
        }
        g_engine.store->cleanupLegacyFile();
        next_heartbeat = steady_now + heartbeat_interval;
      }

      const bool flush_due = steady_now >= next_flush;
      const bool heartbeat_due = steady_now >= next_heartbeat;
      if (g_engine.store && g_engine.store->ready() &&
          (stopping || flush_due || heartbeat_due)) {
        if (!pending) {
          std::lock_guard<std::mutex> lock(g_engine.mutex);
          if (stopping || g_engine.core.hasDirty()) {
            pending.reset(new statistics_v2::DirtyPatch(
                g_engine.core.takeDirtyPatch(nowSeconds(), stopping)));
          } else if (heartbeat_due) {
            pending.reset(new statistics_v2::DirtyPatch(
                g_engine.core.runtimePatch(nowSeconds(), false)));
          }
        }
        if (pending && !pending->empty()) {
          if (g_engine.store->appendPatch(*pending)) {
            pending.reset();
            next_heartbeat = steady_now + heartbeat_interval;
            if (g_engine.store->needsCompaction()) {
              statistics_v2::PersistentImage image;
              uint64_t dirty_version = 0;
              {
                std::lock_guard<std::mutex> lock(g_engine.mutex);
                image = g_engine.core.checkpointImage(
                    nowSeconds(), stopping, dirty_version);
              }
              if (!g_engine.store->writeCheckpoint(image)) {
                logPersistenceError(g_engine.store->lastError(),
                                    last_error_log);
                g_engine.store->close();
                next_retry = steady_now + retry_delay;
              } else {
                std::lock_guard<std::mutex> lock(g_engine.mutex);
                g_engine.core.acknowledgeCheckpoint(dirty_version);
              }
            }
          } else {
            logPersistenceError(g_engine.store->lastError(), last_error_log);
            g_engine.store->close();
            next_retry = steady_now + retry_delay;
          }
        }
        next_flush =
            steady_now + std::chrono::seconds(g_engine.flush_interval_seconds);
      }

      if (stopping)
        break;
    } catch (const std::bad_alloc &error) {
      cycle_failed = true;
      logPersistenceException("memory allocation failure", error.what(),
                              last_error_log);
    } catch (const std::filesystem::filesystem_error &error) {
      cycle_failed = true;
      logPersistenceException("filesystem exception", error.what(),
                              last_error_log);
    } catch (const std::exception &error) {
      cycle_failed = true;
      logPersistenceException("unexpected persistence exception", error.what(),
                              last_error_log);
    } catch (...) {
      cycle_failed = true;
      logPersistenceException("unknown persistence exception", nullptr,
                              last_error_log);
    }

    if (!cycle_failed)
      continue;
    try {
      if (g_engine.store)
        g_engine.store->close();
    } catch (...) {
    }
    const auto retry_from = std::chrono::steady_clock::now();
    next_retry = retry_from + retry_delay;
    retry_delay = std::min(retry_delay * 2, kMaximumRetry);
    {
      std::lock_guard<std::mutex> lock(g_engine.mutex);
      stopping = g_engine.stopping;
    }
    if (stopping)
      break;
  }
  try {
    if (g_engine.store)
      g_engine.store->close();
  } catch (...) {
  }
}

void cacheHeaders(Response &response) {
  response.headers["Cache-Control"] =
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, "
      "s-maxage=0";
  response.headers["Pragma"] = "no-cache";
  response.headers["Expires"] = "0";
  response.headers["Surrogate-Control"] = "no-store";
  response.headers["X-Accel-Expires"] = "0";
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  response.content_type = "application/json; charset=utf-8";
}

template <typename Writer>
void writeCounters(Writer &writer, const Counters &counters) {
  writer.StartObject();
  writer.Key("subscription_requests");
  writer.Uint64(counters.subscription_requests);
  writer.Key("rule_conversions");
  writer.Uint64(counters.rule_conversions);
  writer.EndObject();
}

struct RankedGeo {
  GeoId id;
  Counters counters;
  std::string code;
};

std::vector<RankedGeo>
rankedGeo(const std::array<Counters, statistics_v2::kGeoCount> &geo,
          bool china_regions) {
  std::vector<RankedGeo> result;
  for (std::size_t i = 0; i < geo.size(); ++i) {
    const GeoId id = static_cast<GeoId>(i);
    if (geo[i].empty() ||
        statistics_v2::isChinaRegionGeoId(id) != china_regions)
      continue;
    result.push_back({id, geo[i], statistics_v2::geoCode(id)});
  }
  std::sort(result.begin(), result.end(),
            [](const RankedGeo &left, const RankedGeo &right) {
              if (left.counters.subscription_requests !=
                  right.counters.subscription_requests)
                return left.counters.subscription_requests >
                       right.counters.subscription_requests;
              if (left.counters.rule_conversions !=
                  right.counters.rule_conversions)
                return left.counters.rule_conversions >
                       right.counters.rule_conversions;
              return left.code < right.code;
            });
  return result;
}

template <typename Writer>
void writeGeoArray(Writer &writer, const WindowSnapshot &window,
                   bool china_regions) {
  const std::vector<RankedGeo> entries =
      rankedGeo(window.geo, china_regions);
  writer.StartArray();
  for (const RankedGeo &entry : entries) {
    writer.StartObject();
    writer.Key("code");
    writer.String(entry.code.c_str(),
                  static_cast<rapidjson::SizeType>(entry.code.size()));
    writer.Key("subscription_requests");
    writer.Uint64(entry.counters.subscription_requests);
    writer.Key("rule_conversions");
    writer.Uint64(entry.counters.rule_conversions);
    writer.EndObject();
  }
  writer.EndArray();
}

const std::array<const char *, 8> kWindowNames = {
    "startup", "hour",      "day",      "seven_days",
    "thirty_days", "half_year", "year", "lifetime"};

const WindowSnapshot &windowAt(const DashboardSnapshot &snapshot,
                               std::size_t index) {
  if (index == 0)
    return snapshot.startup;
  if (index >= 1 && index <= 4)
    return snapshot.minute_windows[index - 1];
  if (index >= 5 && index <= 6)
    return snapshot.daily_windows[index - 5];
  return snapshot.lifetime;
}

template <typename Writer>
void writeGeoWindows(Writer &writer, const DashboardSnapshot &snapshot,
                     bool china_regions) {
  writer.StartObject();
  for (std::size_t i = 0; i < kWindowNames.size(); ++i) {
    writer.Key(kWindowNames[i]);
    writeGeoArray(writer, windowAt(snapshot, i), china_regions);
  }
  writer.EndObject();
}

template <typename Writer> void writeRequestLifecycle(Writer &writer) {
  const RequestLifecycleMetricsSnapshot snapshot =
      requestLifecycleMetricsSnapshot();
  writer.StartObject();

  writer.Key("terminal");
  writer.StartObject();
  for (std::size_t index = 1; index < snapshot.terminal.size(); ++index) {
    const auto state = static_cast<RequestTerminalState>(index);
    writer.Key(requestTerminalStateName(state));
    writer.Uint64(snapshot.terminal[index]);
  }
  writer.EndObject();

  writer.Key("failure_attribution");
  writer.StartObject();
  for (std::size_t index = 0; index < snapshot.failure.size(); ++index) {
    const auto failure = static_cast<RequestFailureAttribution>(index);
    writer.Key(requestFailureAttributionName(failure));
    writer.Uint64(snapshot.failure[index]);
  }
  writer.EndObject();

  writer.Key("successful_owners");
  writer.Uint64(snapshot.successful_owners);
  writer.Key("successful_responses");
  writer.Uint64(snapshot.successful_responses);
  writer.Key("work_admitted");
  writer.Uint64(snapshot.work_admitted);
  writer.Key("server_capacity_failure_after_admission");
  writer.Uint64(snapshot.server_capacity_failure_after_admission);

  writer.Key("stages");
  writer.StartObject();
  for (std::size_t index = 0; index < snapshot.stage_nanoseconds.size();
       ++index) {
    const auto stage = static_cast<RequestStage>(index);
    writer.Key(requestStageName(stage));
    writer.StartObject();
    writer.Key("total_microseconds");
    writer.Uint64(snapshot.stage_nanoseconds[index] / 1000);
    writer.Key("samples");
    writer.Uint64(snapshot.stage_samples[index]);
    writer.Key("p50_microseconds");
    writer.Uint64(requestStageLatencyQuantileMicroseconds(
        snapshot, stage, 50, 100));
    writer.Key("p95_microseconds");
    writer.Uint64(requestStageLatencyQuantileMicroseconds(
        snapshot, stage, 95, 100));
    writer.Key("p99_microseconds");
    writer.Uint64(requestStageLatencyQuantileMicroseconds(
        snapshot, stage, 99, 100));
    writer.EndObject();
  }
  writer.EndObject();
  writer.EndObject();
}

std::string serializeDashboard(const DashboardSnapshot &snapshot) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  writer.Key("enabled");
  writer.Bool(global.statisticsEnabled);
  writer.Key("generated_at");
  writer.Int64(snapshot.generated_at);
  writer.Key("started_at");
  writer.Int64(snapshot.started_at);
  writer.Key("revision");
  writer.Uint64(snapshot.revision);

  writer.Key("runtime");
  writer.StartObject();
  writer.Key("first_started_at");
  writer.Int64(snapshot.runtime.first_started_at);
  writer.Key("started_at");
  writer.Int64(snapshot.started_at);
  writer.Key("uptime_seconds");
  writer.Int64(snapshot.uptime_seconds);
  writer.Key("total_runtime_seconds");
  writer.Int64(snapshot.total_runtime_seconds);
  writer.Key("launch_count");
  writer.Uint64(snapshot.runtime.launch_count);
  writer.Key("last_seen_at");
  writer.Int64(snapshot.runtime.last_seen_at);
  writer.Key("last_stopped_at");
  writer.Int64(snapshot.runtime.last_stopped_at);
  writer.EndObject();

  writer.Key("windows");
  writer.StartObject();
  for (std::size_t i = 0; i < kWindowNames.size(); ++i) {
    writer.Key(kWindowNames[i]);
    writeCounters(writer, windowAt(snapshot, i).counters);
  }
  writer.EndObject();

  writer.Key("country_windows");
  writeGeoWindows(writer, snapshot, false);
  writer.Key("countries");
  writeGeoArray(writer, snapshot.lifetime, false);
  writer.Key("china_region_windows");
  writeGeoWindows(writer, snapshot, true);
  writer.Key("china_regions");
  writeGeoArray(writer, snapshot.lifetime, true);

  writer.Key("series");
  writer.StartArray();
  for (const statistics_v2::SeriesPoint &point : snapshot.series) {
    writer.StartObject();
    writer.Key("time");
    writer.Int64(point.time);
    writer.Key("subscription_requests");
    writer.Uint64(point.counters.subscription_requests);
    writer.Key("rule_conversions");
    writer.Uint64(point.counters.rule_conversions);
    writer.EndObject();
  }
  writer.EndArray();
  writer.Key("request_lifecycle");
  writeRequestLifecycle(writer);
  const AsyncFetchEngineSnapshot fetch = asyncFetchEngineSnapshot();
  writer.Key("outbound_fetch");
  writer.StartObject();
  writer.Key("available");
  writer.Bool(fetch.available);
  writer.Key("wakeup_available");
  writer.Bool(fetch.wakeup_available);
  writer.Key("pending");
  writer.Uint64(fetch.pending);
  writer.Key("active");
  writer.Uint64(fetch.active);
  writer.Key("running");
  writer.Uint64(fetch.running);
  writer.Key("handle_window");
  writer.Uint64(fetch.handle_window);
  writer.Key("active_connection_limit");
  writer.Uint64(fetch.active_connection_limit);
  writer.Key("open_connection_limit");
  writer.Uint64(fetch.open_connection_limit);
  writer.Key("connection_cache_limit");
  writer.Uint64(fetch.connection_cache_limit);
  writer.Key("recoverable_retry_limit");
  writer.Uint64(fetch.recoverable_retry_limit);
  writer.Key("buffered_bytes");
  writer.Uint64(fetch.buffered_bytes);
  writer.EndObject();
  const RetainedResponseByteSnapshot retained =
      retainedResponseByteSnapshot();
  writer.Key("retained_response_bytes");
  writer.StartObject();
  writer.Key("used");
  writer.Uint64(retained.used);
  writer.Key("limit");
  writer.Uint64(retained.limit);
  writer.Key("rejected");
  writer.Uint64(retained.rejected);
  writer.EndObject();
  const SubscriptionCacheAdmissionSnapshot cache_admission =
      subscriptionCacheAdmissionSnapshot();
  writer.Key("subscription_cache_admission");
  writer.StartObject();
  writer.Key("enabled");
  writer.Bool(cache_admission.enabled);
  writer.Key("entries");
  writer.Uint64(cache_admission.entries);
  writer.Key("first_seen_bypassed_total");
  writer.Uint64(cache_admission.first_seen_bypassed_total);
  writer.Key("reuse_admitted_total");
  writer.Uint64(cache_admission.reuse_admitted_total);
  writer.EndObject();
  const ResponseMicroCacheSnapshot response_cache =
      responseMicroCacheSnapshot();
  writer.Key("response_microcache");
  writer.StartObject();
  writer.Key("entries");
  writer.Uint64(response_cache.entries);
  writer.Key("bytes");
  writer.Uint64(response_cache.bytes);
  writer.Key("max_bytes");
  writer.Uint64(response_cache.max_bytes);
  writer.EndObject();
  const SubscriptionSingleflightSnapshot singleflight =
      subscriptionSingleflightSnapshot();
  writer.Key("subscription_singleflight");
  writer.StartObject();
  writer.Key("active_owners");
  writer.Uint64(singleflight.active_owners);
  writer.Key("waiting_followers");
  writer.Uint64(singleflight.waiting_followers);
  writer.Key("owners_created_total");
  writer.Uint64(singleflight.owners_created_total);
  writer.Key("followers_attached_total");
  writer.Uint64(singleflight.followers_attached_total);
  writer.Key("followers_cancelled_total");
  writer.Uint64(singleflight.followers_cancelled_total);
  writer.Key("owners_cancelled_no_consumers_total");
  writer.Uint64(singleflight.owners_cancelled_no_consumers_total);
  writer.Key("owner_flow_rejected_total");
  writer.Uint64(singleflight.owner_flow_rejected_total);
  writer.EndObject();
  const SubscriptionOwnerAdmissionSnapshot owner_admission =
      subscriptionOwnerAdmissionSnapshot();
  writer.Key("owner_admission");
  writer.StartObject();
  writer.Key("source");
  writer.String(owner_admission.source.c_str());
  writer.Key("waiting_entries");
  writer.Uint64(owner_admission.waiting_entries);
  writer.Key("waiting_bytes");
  writer.Uint64(owner_admission.waiting_bytes);
  writer.Key("active");
  writer.Uint64(owner_admission.active);
  writer.Key("accepted_total");
  writer.Uint64(owner_admission.accepted_total);
  writer.Key("rejected_total");
  writer.Uint64(owner_admission.rejected_total);
  writer.Key("cancelled_total");
  writer.Uint64(owner_admission.cancelled_total);
  writer.Key("max_wait_entries");
  writer.Uint64(owner_admission.max_wait_entries);
  writer.Key("max_wait_bytes");
  writer.Uint64(owner_admission.max_wait_bytes);
  writer.Key("oldest_wait_ms");
  writer.Uint64(owner_admission.oldest_wait_ms);
  writer.EndObject();
  const WorkloadSchedulerSnapshot scheduler = conversionSchedulerSnapshot();
  writer.Key("conversion_scheduler");
  writer.StartObject();
  writer.Key("queued_entries");
  writer.Uint64(scheduler.queued_entries);
  writer.Key("queued_bytes");
  writer.Uint64(scheduler.queued_bytes);
  writer.Key("active");
  writer.Uint64(scheduler.active);
  writer.Key("accepted");
  writer.Uint64(scheduler.accepted);
  writer.Key("rejected");
  writer.Uint64(scheduler.rejected);
  writer.Key("cancelled");
  writer.Uint64(scheduler.cancelled);
  writer.Key("oldest_queued_age_ms");
  writer.Uint64(scheduler.oldest_queued_age_ms);
  writer.EndObject();
  const WorkloadSchedulerSnapshot legacy_flow = legacyRequestFlowSnapshot();
  writer.Key("legacy_request_flow");
  writer.StartObject();
  writer.Key("queued_entries");
  writer.Uint64(legacy_flow.queued_entries);
  writer.Key("queued_bytes");
  writer.Uint64(legacy_flow.queued_bytes);
  writer.Key("active");
  writer.Uint64(legacy_flow.active);
  writer.Key("accepted");
  writer.Uint64(legacy_flow.accepted);
  writer.Key("rejected");
  writer.Uint64(legacy_flow.rejected);
  writer.Key("cancelled");
  writer.Uint64(legacy_flow.cancelled);
  writer.Key("oldest_queued_age_ms");
  writer.Uint64(legacy_flow.oldest_queued_age_ms);
  writer.EndObject();
  const CpuPermitSnapshot cpu_permits = conversionCpuPermitSnapshot();
  writer.Key("cpu_permits");
  writer.StartObject();
  writer.Key("limit");
  writer.Uint64(cpu_permits.limit);
  writer.Key("active");
  writer.Uint64(cpu_permits.active);
  writer.Key("waiting");
  writer.Uint64(cpu_permits.waiting);
  writer.EndObject();
  const RequestAdmissionSnapshot admission = requestAdmissionSnapshot();
  writer.Key("request_admission");
  writer.StartObject();
  writer.Key("active_entries");
  writer.Uint64(admission.active_entries);
  writer.Key("active_bytes");
  writer.Uint64(admission.active_bytes);
  writer.Key("accepted");
  writer.Uint64(admission.accepted);
  writer.Key("rejected");
  writer.Uint64(admission.rejected);
  writer.Key("max_entries");
  writer.Uint64(admission.max_entries);
  writer.Key("max_bytes");
  writer.Uint64(admission.max_bytes);
  writer.EndObject();
  const ResourceControlSnapshot resources = resourceControlSnapshot();
  writer.Key("resource_control");
  writer.StartObject();
  writer.Key("mode");
  writer.String(resources.mode.c_str());
  writer.Key("effective_mode");
  writer.String(resources.effective_mode.c_str());
  writer.Key("source");
  writer.String(resources.source.c_str());
  writer.Key("controller_state");
  writer.String(resources.controller_state.c_str());
  writer.Key("controller_reason");
  writer.String(resources.controller_reason.c_str());
  writer.Key("hardware_fingerprint");
  writer.String(resources.hardware_fingerprint.c_str());
  writer.Key("sample_count");
  writer.Uint64(resources.sample_count);
  writer.Key("sample_age_ms");
  writer.Uint64(resources.sample_age_ms);
  writer.Key("effective_cpu_millis");
  writer.Uint64(resources.effective_cpu_millis);
  writer.Key("affinity_cpus");
  writer.Uint64(resources.affinity_cpus);
  writer.Key("cpuset_cpus");
  writer.Uint64(resources.cpuset_cpus);
  writer.Key("cpu_quota_millis");
  writer.Uint64(resources.cpu_quota_millis);
  writer.Key("memory_current_bytes");
  writer.Uint64(resources.memory_current_bytes);
  writer.Key("memory_high_bytes");
  writer.Uint64(resources.memory_high_bytes);
  writer.Key("memory_max_bytes");
  writer.Uint64(resources.memory_max_bytes);
  writer.Key("swap_current_bytes");
  writer.Uint64(resources.swap_current_bytes);
  writer.Key("host_total_memory_bytes");
  writer.Uint64(resources.host_total_memory_bytes);
  writer.Key("host_available_memory_bytes");
  writer.Uint64(resources.host_available_memory_bytes);
  writer.Key("nofile_soft");
  writer.Uint64(resources.nofile_soft);
  writer.Key("pids_current");
  writer.Uint64(resources.pids_current);
  writer.Key("pids_max");
  writer.Uint64(resources.pids_max);
  writer.Key("open_fds");
  writer.Uint64(resources.open_fds);
  writer.Key("memory_peak_bytes");
  writer.Uint64(resources.memory_peak_bytes);
  writer.Key("memory_events_high");
  writer.Uint64(resources.memory_events_high);
  writer.Key("memory_events_max");
  writer.Uint64(resources.memory_events_max);
  writer.Key("memory_events_oom");
  writer.Uint64(resources.memory_events_oom);
  writer.Key("memory_events_oom_kill");
  writer.Uint64(resources.memory_events_oom_kill);
  writer.Key("memory_events_sock_throttled");
  writer.Uint64(resources.memory_events_sock_throttled);
  writer.Key("cpu_psi_some_milli_percent");
  writer.Uint64(resources.cpu_psi_some_milli_percent);
  writer.Key("cpu_psi_full_milli_percent");
  writer.Uint64(resources.cpu_psi_full_milli_percent);
  writer.Key("memory_psi_some_milli_percent");
  writer.Uint64(resources.memory_psi_some_milli_percent);
  writer.Key("memory_psi_full_milli_percent");
  writer.Uint64(resources.memory_psi_full_milli_percent);
  writer.Key("io_psi_some_milli_percent");
  writer.Uint64(resources.io_psi_some_milli_percent);
  writer.Key("suggested_cpu_permits");
  writer.Uint64(resources.suggested_cpu_permits);
  writer.Key("max_cpu_permits");
  writer.Uint64(resources.max_cpu_permits);
  writer.Key("configured_cpu_cap");
  writer.Uint64(resources.configured_cpu_cap);
  writer.Key("suggested_active_flows");
  writer.Uint64(resources.suggested_active_flows);
  writer.Key("suggested_outbound_connections");
  writer.Uint64(resources.suggested_outbound_connections);
  writer.Key("telemetry_capabilities");
  writer.StartObject();
  writer.Key("cpu_pressure");
  writer.Bool(resources.cpu_pressure_available);
  writer.Key("memory_pressure");
  writer.Bool(resources.memory_pressure_available);
  writer.Key("io_pressure");
  writer.Bool(resources.io_pressure_available);
  writer.Key("memory_events");
  writer.Bool(resources.memory_events_supported);
  writer.Key("memory_events_sample_valid");
  writer.Bool(resources.memory_events_sample_valid);
  writer.Key("open_fds");
  writer.Bool(resources.open_fds_available);
  writer.Key("cgroup_scope_known");
  writer.Bool(resources.cgroup_scope_known);
  writer.EndObject();
  writer.Key("hardware_detected");
  writer.Bool(resources.hardware_detected);
  writer.Key("hardware_pin_matched");
  writer.Bool(resources.hardware_pin_matched);
  writer.Key("startup_budget_applied");
  writer.Bool(resources.startup_budget_applied);
  writer.Key("hardware_complete");
  writer.Bool(resources.hardware_complete);
  writer.Key("curve_valid");
  writer.Bool(resources.curve_valid);
  writer.Key("permits_applied");
  writer.Bool(resources.permits_applied);
  writer.Key("pressure_fallback");
  writer.Bool(resources.pressure_fallback);
  writer.EndObject();
  writer.EndObject();
  return std::string(buffer.GetString(), buffer.GetSize());
}

} // namespace

namespace statistics {

void initialize() {
  if (!global.statisticsEnabled)
    return;
  {
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    if (g_engine.initialized)
      return;
    g_engine.initialized = true;
    g_engine.stopping = false;
    g_engine.flush_interval_seconds =
        std::max(1, global.statisticsFlushInterval);
    g_engine.geo.enabled =
        !asciiEqualsIgnoreCase(global.statisticsGeoProvider, "none");
    g_engine.geo.country_headers.assign(
        global.statisticsCountryHeaders.begin(),
        global.statisticsCountryHeaders.end());
    g_engine.geo.china_region_headers.assign(
        global.statisticsChinaRegionHeaders.begin(),
        global.statisticsChinaRegionHeaders.end());
    g_engine.store.reset(
        new statistics_v2::Store(global.statisticsDataDir));
  }

  bool loaded = false;
  std::chrono::steady_clock::time_point initialization_error_log{};
  try {
    if (g_engine.store->open() == statistics_v2::StoreStatus::Ready) {
      const statistics_v2::StoreLoadResult recovered = g_engine.store->load();
      if (recovered.has_image) {
        std::lock_guard<std::mutex> lock(g_engine.mutex);
        g_engine.core.startFromImage(recovered.image, nowSeconds());
        loaded = true;
      }
    }
  } catch (const std::bad_alloc &error) {
    logPersistenceException("initial memory allocation failure", error.what(),
                            initialization_error_log);
    g_engine.store->close();
  } catch (const std::filesystem::filesystem_error &error) {
    logPersistenceException("initial filesystem exception", error.what(),
                            initialization_error_log);
    g_engine.store->close();
  } catch (const std::exception &error) {
    logPersistenceException("initial persistence exception", error.what(),
                            initialization_error_log);
    g_engine.store->close();
  } catch (...) {
    logPersistenceException("unknown initial persistence exception", nullptr,
                            initialization_error_log);
    g_engine.store->close();
  }
  if (!loaded) {
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    g_engine.core.startEmpty(nowSeconds());
  }

  g_engine.persistence_thread = std::thread(persistenceWorker);
  writeLog(LOG_LEVEL_INFO, "Statistics v2 已启用，数据目录：" +
                  global.statisticsDataDir);
}

void shutdown() {
  {
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    if (!g_engine.initialized)
      return;
    g_engine.stopping = true;
  }
  g_engine.condition.notify_all();
  if (g_engine.persistence_thread.joinable())
    g_engine.persistence_thread.join();
  std::lock_guard<std::mutex> lock(g_engine.mutex);
  g_engine.initialized = false;
}

bool isEnabled() { return global.statisticsEnabled; }

void tick() {
  // Statistics v2 owns its steady-clock persistence schedule. The retained
  // entry point keeps the existing main-loop contract unchanged.
}

void recordSubscriptionConversion(const Request &request,
                                  uint64_t rule_conversions) {
  recordSubscriptionConversion(prepareSubscriptionConversionMetadata(request),
                               rule_conversions);
}

SubscriptionConversionMetadata
prepareSubscriptionConversionMetadata(const Request &request) {
  SubscriptionConversionMetadata metadata;
  if (!effectiveSettings().statisticsEnabled || request.method != "GET")
    return metadata;
  const GeoLocation location = geoLocation(request, g_engine.geo);
  metadata.country = location.country;
  metadata.china_region = location.china_region;
  metadata.eligible = true;
  return metadata;
}

void recordSubscriptionConversion(
    const SubscriptionConversionMetadata &metadata,
    uint64_t rule_conversions) {
  if (!metadata.eligible)
    return;
  {
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    if (!g_engine.initialized)
      return;
    g_engine.core.record(nowSeconds(), metadata.country,
                         metadata.china_region, rule_conversions);
  }
}

std::string dashboardData(RESPONSE_CALLBACK_ARGS) {
  cacheHeaders(response);
  std::lock_guard<std::mutex> cache_lock(g_cache_mutex);
  const auto steady_now = std::chrono::steady_clock::now();
  if (!g_cached_dashboard.empty() &&
      steady_now - g_cached_dashboard_at < kDashboardCacheLifetime)
    return g_cached_dashboard;

  DashboardSnapshot snapshot;
  {
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    snapshot = g_engine.core.dashboardSnapshot(nowSeconds());
  }
  g_cached_dashboard = serializeDashboard(snapshot);
  g_cached_dashboard_at = steady_now;
  return g_cached_dashboard;
}

} // namespace statistics
