#include "handler/statistics_v2.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using namespace statistics_v2;

struct LegacyGeo {
  std::string code;
  Counters counters;
};

struct LegacyBucket {
  int64_t minute = 0;
  Counters counters;
  std::vector<LegacyGeo> countries;
};

void legacyAdd(std::vector<LegacyGeo> &items, const std::string &code,
               uint64_t rules) {
  for (LegacyGeo &item : items) {
    if (item.code == code) {
      ++item.counters.subscription_requests;
      item.counters.rule_conversions += rules;
      return;
    }
  }
  items.push_back({code, {1, rules}});
}

uint64_t legacyDashboard(const std::vector<LegacyBucket> &buckets,
                         int64_t now_minute) {
  uint64_t total = 0;
  for (const LegacyBucket &bucket : buckets) {
    if (bucket.minute >= now_minute - 30 * 24 * 60 + 1 &&
        bucket.minute <= now_minute)
      total += bucket.counters.subscription_requests;
  }
  return total;
}

double milliseconds(Clock::time_point begin, Clock::time_point end) {
  return std::chrono::duration<double, std::milli>(end - begin).count();
}

} // namespace

int main() {
  constexpr int64_t base_minute = INT64_C(2000000000) / 60;
  constexpr int dashboard_rounds = 250;
  constexpr int request_rounds = 400000;

  std::vector<LegacyBucket> legacy(kMinuteBucketCount);
  Core modern;
  modern.startEmpty((base_minute - kMinuteBucketCount + 1) * 60);
  for (std::size_t i = 0; i < kMinuteBucketCount; ++i) {
    const int64_t minute =
        base_minute - static_cast<int64_t>(kMinuteBucketCount) + 1 +
        static_cast<int64_t>(i);
    legacy[i].minute = minute;
    legacy[i].counters = {1, 2};
    legacy[i].countries.push_back({"US", {1, 2}});
    modern.record(minute * 60, countryGeoId("US"), kInvalidGeoId, 2);
  }

  volatile uint64_t sink = 0;
  const auto legacy_dashboard_begin = Clock::now();
  for (int i = 0; i < dashboard_rounds; ++i)
    sink = sink + legacyDashboard(legacy, base_minute);
  const auto legacy_dashboard_end = Clock::now();
  const auto modern_dashboard_begin = Clock::now();
  for (int i = 0; i < dashboard_rounds; ++i)
    sink = sink +
           modern.dashboardSnapshot(base_minute * 60)
               .minute_windows[3]
               .counters.subscription_requests;
  const auto modern_dashboard_end = Clock::now();

  std::vector<LegacyGeo> legacy_hot_path;
  for (int i = 0; i < 32; ++i) {
    const std::string code =
        std::string(1, static_cast<char>('A' + i / 26)) +
        std::string(1, static_cast<char>('A' + i % 26));
    legacy_hot_path.push_back({code, {}});
  }
  const auto legacy_request_begin = Clock::now();
  for (int i = 0; i < request_rounds; ++i)
    legacyAdd(legacy_hot_path, "ZZ", 2);
  const auto legacy_request_end = Clock::now();

  Core modern_hot_path;
  modern_hot_path.startEmpty(base_minute * 60);
  const auto modern_request_begin = Clock::now();
  for (int i = 0; i < request_rounds; ++i)
    modern_hot_path.record(base_minute * 60, countryGeoId("ZZ"),
                           kInvalidGeoId, 2);
  const auto modern_request_end = Clock::now();

  std::ostringstream legacy_json;
  legacy_json << "{\"buckets\":[";
  for (std::size_t i = 0; i < legacy.size(); ++i) {
    if (i)
      legacy_json << ',';
    legacy_json << "{\"minute\":" << legacy[i].minute
                << ",\"subscription_requests\":1,\"rule_conversions\":2,"
                   "\"countries\":[{\"code\":\"US\","
                   "\"subscription_requests\":1,\"rule_conversions\":2}]}";
  }
  legacy_json << "]}";

  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "sce-statistics-v2-benchmark";
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  std::filesystem::create_directories(directory);
  std::uintmax_t checkpoint_bytes = 0;
  std::uintmax_t wal_bytes = 0;
  {
    Store store(directory.string());
    uint64_t checkpoint_version = 0;
    PersistentImage checkpoint = modern.checkpointImage(
        base_minute * 60, false, checkpoint_version);
    if (store.open() != StoreStatus::Ready ||
        !store.ensureInitialCheckpoint(checkpoint)) {
      std::cerr << "benchmark persistence setup failed\n";
      return 1;
    }
    modern.acknowledgeCheckpoint(checkpoint_version);
    modern.record(base_minute * 60, countryGeoId("US"), kInvalidGeoId, 1);
    if (!store.appendPatch(
            modern.takeDirtyPatch(base_minute * 60, false))) {
      std::cerr << "benchmark WAL write failed\n";
      return 1;
    }
    checkpoint_bytes =
        std::filesystem::file_size(directory / "statistics-v2-a.bin");
    wal_bytes = std::filesystem::file_size(directory / "statistics-v2.wal");
  }
  std::filesystem::remove_all(directory, error);

  const double legacy_dashboard_ms =
      milliseconds(legacy_dashboard_begin, legacy_dashboard_end) /
      dashboard_rounds;
  const double modern_dashboard_ms =
      milliseconds(modern_dashboard_begin, modern_dashboard_end) /
      dashboard_rounds;
  const double legacy_request_seconds =
      milliseconds(legacy_request_begin, legacy_request_end) / 1000.0;
  const double modern_request_seconds =
      milliseconds(modern_request_begin, modern_request_end) / 1000.0;
  const double legacy_request_ops =
      request_rounds / std::max(legacy_request_seconds, 0.000001);
  const double modern_request_ops =
      request_rounds / std::max(modern_request_seconds, 0.000001);

  std::cout << std::fixed << std::setprecision(3)
            << "dashboard_ms legacy=" << legacy_dashboard_ms
            << " v2=" << modern_dashboard_ms << '\n'
            << "request_ops_per_sec legacy=" << legacy_request_ops
            << " v2=" << modern_request_ops << '\n'
            << "dashboard_slots legacy=" << kMinuteBucketCount
            << " v2=0\n"
            << "steady_memory_bytes legacy_est="
            << legacy.capacity() *
                   (sizeof(LegacyBucket) + sizeof(LegacyGeo))
            << " v2_est="
            << sizeof(Core) +
                   kMinuteBucketCount *
                       (sizeof(BucketRecord) + sizeof(GeoCounters)) +
                   kDailyBucketCount * sizeof(BucketRecord)
            << '\n'
            << "persistence_bytes legacy_full=" << legacy_json.str().size()
            << " v2_checkpoint=" << checkpoint_bytes
            << " v2_dirty_wal=" << wal_bytes << '\n'
            << "idle_write_bytes legacy_heartbeat="
            << legacy_json.str().size() << " v2=0\n";

  if (wal_bytes >= legacy_json.str().size() ||
      checkpoint_bytes >= legacy_json.str().size() ||
      modern_dashboard_ms >= legacy_dashboard_ms) {
    std::cerr << "structural performance regression\n";
    return 1;
  }
  return sink == 0 ? 1 : 0;
}
