#ifndef STATISTICS_V2_H_INCLUDED
#define STATISTICS_V2_H_INCLUDED

#include <array>
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace statistics_v2 {

constexpr std::size_t kMinuteBucketCount = 30 * 24 * 60;
constexpr std::size_t kDailyBucketCount = 366;
constexpr std::size_t kCountryCount = 26 * 26 + 1;
constexpr std::size_t kChinaRegionCount = 35;
constexpr std::size_t kGeoCount = kCountryCount + kChinaRegionCount;
constexpr uint16_t kInvalidGeoId = UINT16_MAX;

using GeoId = uint16_t;

struct Counters {
  uint64_t subscription_requests = 0;
  uint64_t rule_conversions = 0;

  bool empty() const {
    return subscription_requests == 0 && rule_conversions == 0;
  }
};

struct GeoCounters {
  GeoId id = kInvalidGeoId;
  Counters counters;
};

struct BucketRecord {
  int64_t stamp = 0;
  Counters counters;
  std::vector<GeoCounters> geo;

  bool empty() const { return counters.empty(); }
};

struct RuntimeState {
  int64_t first_started_at = 0;
  int64_t persisted_runtime_seconds = 0;
  int64_t last_seen_at = 0;
  int64_t last_stopped_at = 0;
  uint64_t launch_count = 0;
};

struct PersistentImage {
  RuntimeState runtime;
  Counters lifetime;
  std::array<Counters, kGeoCount> lifetime_geo{};
  std::vector<BucketRecord> minutes =
      std::vector<BucketRecord>(kMinuteBucketCount);
  std::vector<BucketRecord> days =
      std::vector<BucketRecord>(kDailyBucketCount);
};

struct IndexedBucket {
  uint32_t index = 0;
  BucketRecord record;
};

struct DirtyPatch {
  RuntimeState runtime;
  Counters lifetime;
  std::vector<GeoCounters> lifetime_geo;
  std::vector<IndexedBucket> minutes;
  std::vector<IndexedBucket> days;
  bool metadata_present = false;

  bool empty() const {
    return !metadata_present && lifetime_geo.empty() && minutes.empty() &&
           days.empty();
  }
};

struct WindowSnapshot {
  Counters counters;
  std::array<Counters, kGeoCount> geo{};
};

struct SeriesPoint {
  int64_t time = 0;
  Counters counters;
};

struct DashboardSnapshot {
  uint64_t revision = 0;
  int64_t generated_at = 0;
  int64_t started_at = 0;
  RuntimeState runtime;
  int64_t uptime_seconds = 0;
  int64_t total_runtime_seconds = 0;
  WindowSnapshot startup;
  std::array<WindowSnapshot, 4> minute_windows;
  std::array<WindowSnapshot, 2> daily_windows;
  WindowSnapshot lifetime;
  std::array<SeriesPoint, 24> series;
};

GeoId countryGeoId(const std::string &value);
GeoId chinaRegionGeoId(const std::string &value);
bool isCountryGeoId(GeoId id);
bool isChinaRegionGeoId(GeoId id);
std::string geoCode(GeoId id);

class Core {
public:
  Core();

  void startEmpty(int64_t now_seconds);
  void startFromImage(const PersistentImage &image, int64_t now_seconds);
  void record(int64_t now_seconds, GeoId country, GeoId china_region,
              uint64_t rule_conversions);
  DashboardSnapshot dashboardSnapshot(int64_t now_seconds);

  bool hasDirty() const;
  DirtyPatch takeDirtyPatch(int64_t now_seconds, bool stopping);
  DirtyPatch runtimePatch(int64_t now_seconds, bool stopping);
  PersistentImage persistentImage(int64_t now_seconds, bool stopping) const;
  PersistentImage checkpointImage(int64_t now_seconds, bool stopping,
                                  uint64_t &dirty_version) const;
  void acknowledgeCheckpoint(uint64_t dirty_version);

  uint64_t revision() const { return revision_; }

private:
  struct DenseBucket {
    int64_t stamp = 0;
    Counters counters;
    std::array<Counters, kGeoCount> geo{};
  };

  struct Aggregate {
    Counters counters;
    std::array<Counters, kGeoCount> geo{};
  };

  struct HourBucket {
    int64_t hour = 0;
    Counters counters;
  };

  void resetTransient();
  void activateLatestBuckets(const PersistentImage &image);
  void rebuildAggregates(int64_t now_seconds);
  void advanceTo(int64_t now_seconds);
  void advanceMinutes(int64_t target_minute);
  void advanceDays(int64_t target_day);
  void advanceHours(int64_t target_hour);
  BucketRecord minuteRecord(std::size_t index) const;
  BucketRecord dayRecord(std::size_t index) const;
  void sealMinute();
  void sealDay();
  void bumpRevision();

  RuntimeState runtime_;
  int64_t started_at_ = 0;
  Counters startup_;
  Counters lifetime_;
  std::array<Counters, kGeoCount> startup_geo_{};
  std::array<Counters, kGeoCount> lifetime_geo_{};
  DenseBucket current_minute_;
  DenseBucket current_day_;
  std::vector<BucketRecord> minutes_;
  std::vector<BucketRecord> days_;
  std::array<Aggregate, 4> minute_windows_;
  std::array<Aggregate, 2> daily_windows_;
  std::array<HourBucket, 24> hours_;
  uint64_t revision_ = 0;
  std::bitset<kMinuteBucketCount> dirty_minutes_;
  std::bitset<kDailyBucketCount> dirty_days_;
  std::bitset<kGeoCount> dirty_lifetime_geo_;
  bool runtime_dirty_ = false;
  uint64_t dirty_version_ = 0;
};

int runtimeHeartbeatIntervalSeconds(int flush_interval_seconds);

enum class StoreStatus {
  Ready,
  DirectoryUnavailable,
  LockUnavailable,
  CorruptOrEmpty
};

struct StoreLoadResult {
  bool has_image = false;
  PersistentImage image;
  uint64_t generation = 0;
  uint64_t sequence = 0;
};

class Store {
public:
  explicit Store(std::string directory);
  ~Store();

  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;

  StoreStatus open();
  void close();
  bool ready() const;
  StoreLoadResult load();
  bool appendPatch(const DirtyPatch &patch);
  bool writeCheckpoint(const PersistentImage &image);
  bool ensureInitialCheckpoint(const PersistentImage &image);
  bool compactIfNeeded(const PersistentImage &image);
  bool needsCompaction() const;
  bool cleanupLegacyFile();

  uint64_t generation() const { return generation_; }
  uint64_t sequence() const { return sequence_; }
  std::size_t walBytes() const { return wal_bytes_; }
  std::size_t walRecords() const { return wal_records_; }
  const std::string &lastError() const { return last_error_; }

  static bool inspectCheckpoint(const std::string &path,
                                StoreLoadResult &result);

private:
  class FileLock;

  std::string path(const char *name) const;
  bool replaceFile(const std::string &target,
                   const std::vector<uint8_t> &bytes);
  bool appendFile(const std::string &target,
                  const std::vector<uint8_t> &bytes);
  bool truncateWal();
  bool truncateWalTo(std::size_t size, std::size_t records);
  void setError(const std::string &message);

  std::string directory_;
  std::unique_ptr<FileLock> lock_;
  uint64_t generation_ = 0;
  uint64_t sequence_ = 0;
  std::size_t wal_bytes_ = 0;
  std::size_t wal_records_ = 0;
  bool ready_ = false;
  bool legacy_cleanup_attempted_ = false;
  std::string last_error_;
  std::chrono::steady_clock::time_point last_checkpoint_;
};

#ifdef STATISTICS_V2_TESTING
enum class TestWriteFault {
  None,
  OpenFailure,
  NoSpace,
  ShortWrite,
  FlushFailure,
  TruncateFailure
};

void setTestWriteFault(TestWriteFault fault);
#endif

} // namespace statistics_v2

#endif // STATISTICS_V2_H_INCLUDED
