#include "handler/statistics_v2.h"
#include "server/request_context.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

using namespace statistics_v2;

int failures = 0;

void expect(bool condition, const std::string &message) {
  if (condition)
    return;
  ++failures;
  std::cerr << "FAIL: " << message << '\n';
}

std::filesystem::path temporaryDirectory(const char *name) {
  const auto suffix =
      std::chrono::steady_clock::now().time_since_epoch().count();
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      (std::string("sce-statistics-v2-") + name + "-" +
       std::to_string(suffix));
  std::filesystem::create_directories(path);
  return path;
}

void removeTree(const std::filesystem::path &path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

std::vector<uint8_t> readBytes(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
}

void writeBytes(const std::filesystem::path &path,
                const std::vector<uint8_t> &bytes) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  file.write(reinterpret_cast<const char *>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
}

#ifndef _WIN32
void expectNotWorldWritable(const std::filesystem::path &path,
                            const std::string &name) {
  struct stat status {};
  expect(::stat(path.c_str(), &status) == 0,
         name + " permissions are inspectable");
  expect((status.st_mode & S_IWOTH) == 0, name + " is not world-writable");
}
#endif

uint32_t readU32(const std::vector<uint8_t> &bytes, std::size_t offset) {
  uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i)
    value |= static_cast<uint32_t>(bytes[offset + i]) << (i * 8);
  return value;
}

void writeU64(std::vector<uint8_t> &bytes, std::size_t offset,
              uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i)
    bytes[offset + i] =
        static_cast<uint8_t>((value >> (i * 8)) & UINT64_C(0xff));
}

uint64_t testChecksum(const uint8_t *data, std::size_t size) {
  uint64_t hash = UINT64_C(1469598103934665603);
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

std::size_t walRecordSize(const std::vector<uint8_t> &bytes,
                          std::size_t offset) {
  constexpr std::size_t header = 4 + 4 + 8 + 8 + 4;
  constexpr std::size_t checksum = 8;
  return header + readU32(bytes, offset + 24) + checksum;
}

void geoMappingTest() {
  std::vector<bool> seen(kCountryCount, false);
  for (char first = 'A'; first <= 'Z'; ++first) {
    for (char second = 'A'; second <= 'Z'; ++second) {
      const std::string code{first, second};
      const GeoId id = countryGeoId(code);
      expect(id < kCountryCount, "all two-letter country codes are accepted");
      expect(!seen[id], "two-letter country IDs are unique");
      seen[id] = true;
      expect(geoCode(id) == code, "country ID round trips");
    }
  }
  const GeoId tor = countryGeoId(" t1 ");
  expect(tor < kCountryCount && geoCode(tor) == "T1",
         "T1 special value round trips");
  expect(countryGeoId("invalid") == countryGeoId("ZZ"),
         "invalid countries normalize to ZZ");

  const std::vector<std::string> regions = {
      "AH", "BJ", "CQ", "FJ", "GD", "GS", "GX", "GZ", "HA", "HB",
      "HE", "HI", "HK", "HL", "HN", "JL", "JS", "JX", "LN", "MO",
      "NM", "NX", "QH", "SC", "SD", "SH", "SN", "SX", "TJ", "TW",
      "XJ", "XZ", "YN", "ZJ", "XX"};
  for (const std::string &suffix : regions) {
    const GeoId id = chinaRegionGeoId("cn_" + suffix);
    expect(isChinaRegionGeoId(id), "China region is accepted");
    expect(geoCode(id) == "CN-" + suffix, "China region round trips");
  }
}

void rollingWindowTest() {
  constexpr int64_t base = INT64_C(2000000000) / 86400 * 86400;
  const GeoId us = countryGeoId("US");
  const GeoId region = chinaRegionGeoId("CN-GD");

  Core core;
  core.startEmpty(base);
  core.record(base, us, kInvalidGeoId, 7);
  DashboardSnapshot initial = core.dashboardSnapshot(base + 59);
  expect(initial.minute_windows[0].counters.subscription_requests == 1,
         "current minute belongs to one-hour window");
  expect(initial.minute_windows[3].counters.rule_conversions == 7,
         "current minute belongs to thirty-day window");
  expect(initial.daily_windows[1].counters.subscription_requests == 1,
         "current day belongs to year window");

  DashboardSnapshot hour_expired =
      core.dashboardSnapshot(base + 60 * 60);
  expect(hour_expired.minute_windows[0].counters.subscription_requests == 0,
         "one-hour boundary expires exactly");
  expect(hour_expired.minute_windows[1].counters.subscription_requests == 1,
         "one-day window retains hour-old data");

  DashboardSnapshot day_expired =
      core.dashboardSnapshot(base + 24 * 60 * 60);
  expect(day_expired.minute_windows[1].counters.subscription_requests == 0,
         "one-day boundary expires exactly");
  expect(day_expired.minute_windows[2].counters.subscription_requests == 1,
         "seven-day window retains day-old data");

  DashboardSnapshot seven_expired =
      core.dashboardSnapshot(base + 7 * 24 * 60 * 60);
  expect(seven_expired.minute_windows[2].counters.subscription_requests == 0,
         "seven-day boundary expires exactly");
  expect(seven_expired.minute_windows[3].counters.subscription_requests == 1,
         "thirty-day window retains seven-day-old data");

  DashboardSnapshot thirty_expired =
      core.dashboardSnapshot(base + 30 * 24 * 60 * 60);
  expect(thirty_expired.minute_windows[3].counters.subscription_requests == 0,
         "thirty-day ring expires exactly");

  Core daily;
  daily.startEmpty(base);
  daily.record(base, countryGeoId("CN"), region, 1);
  expect(daily.dashboardSnapshot(base + 182 * 86400)
             .daily_windows[0]
             .counters.subscription_requests == 1,
         "half-year window includes 183 calendar buckets");
  expect(daily.dashboardSnapshot(base + 183 * 86400)
             .daily_windows[0]
             .counters.subscription_requests == 0,
         "half-year boundary expires exactly");
  expect(daily.dashboardSnapshot(base + 365 * 86400)
             .daily_windows[1]
             .counters.subscription_requests == 0,
         "year boundary expires exactly");
}

void timeJumpAndSaturationTest() {
  constexpr int64_t base = INT64_C(2000000000);
  Core core;
  core.startEmpty(base);
  core.record(base, countryGeoId("US"), kInvalidGeoId,
              std::numeric_limits<uint64_t>::max());
  core.record(base - 3600, countryGeoId("US"), kInvalidGeoId, 10);
  DashboardSnapshot backward = core.dashboardSnapshot(base - 7200);
  expect(backward.lifetime.counters.subscription_requests == 2,
         "backward clock adjustment does not lose requests");
  expect(backward.lifetime.counters.rule_conversions ==
             std::numeric_limits<uint64_t>::max(),
         "counters saturate instead of wrapping");

  DashboardSnapshot jumped =
      core.dashboardSnapshot(base + 400 * 86400);
  expect(jumped.minute_windows[3].counters.empty(),
         "large forward jump clears minute ring");
  expect(jumped.daily_windows[1].counters.empty(),
         "large forward jump clears daily ring");
  expect(jumped.lifetime.counters.subscription_requests == 2,
         "large jump preserves lifetime totals");
}

void restartWindowRecoveryTest() {
  constexpr int64_t base = INT64_C(1999987200);
  const GeoId cn = countryGeoId("CN");
  const GeoId gd = chinaRegionGeoId("CN-GD");
  Core source;
  source.startEmpty(base);
  source.record(base, cn, gd, 7);
  const PersistentImage image = source.persistentImage(base, false);

  struct RestartCase {
    const char *name;
    int64_t gap;
    std::array<bool, 4> minute_windows;
    std::array<bool, 2> daily_windows;
    bool series;
  };
  constexpr int64_t day = 24 * 60 * 60;
  const std::array<RestartCase, 7> cases = {{
      {"50 minutes", 50 * 60, {true, true, true, true}, {true, true}, true},
      {"23 hours", 23 * 60 * 60, {false, true, true, true}, {true, true},
       true},
      {"6 days", 6 * day, {false, false, true, true}, {true, true}, false},
      {"29 days", 29 * day, {false, false, false, true}, {true, true}, false},
      {"182 days", 182 * day, {false, false, false, false}, {true, true},
       false},
      {"364 days", 364 * day, {false, false, false, false}, {false, true},
       false},
      {"over 366 days", 367 * day, {false, false, false, false},
       {false, false}, false},
  }};

  for (const RestartCase &test : cases) {
    Core recovered;
    recovered.startFromImage(image, base + test.gap);
    const DashboardSnapshot snapshot =
        recovered.dashboardSnapshot(base + test.gap);
    for (std::size_t i = 0; i < test.minute_windows.size(); ++i) {
      const uint64_t expected = test.minute_windows[i] ? 1 : 0;
      expect(snapshot.minute_windows[i].counters.subscription_requests ==
                 expected,
             std::string(test.name) + " restores minute request window");
      expect(snapshot.minute_windows[i].counters.rule_conversions ==
                 (test.minute_windows[i] ? 7 : 0),
             std::string(test.name) + " restores minute rule window");
      expect(snapshot.minute_windows[i].geo[cn].subscription_requests ==
                 expected,
             std::string(test.name) + " restores country minute window");
      expect(snapshot.minute_windows[i].geo[gd].rule_conversions ==
                 (test.minute_windows[i] ? 7 : 0),
             std::string(test.name) + " restores region minute window");
    }
    for (std::size_t i = 0; i < test.daily_windows.size(); ++i) {
      const uint64_t expected = test.daily_windows[i] ? 1 : 0;
      expect(snapshot.daily_windows[i].counters.subscription_requests ==
                 expected,
             std::string(test.name) + " restores daily request window");
      expect(snapshot.daily_windows[i].counters.rule_conversions ==
                 (test.daily_windows[i] ? 7 : 0),
             std::string(test.name) + " restores daily rule window");
      expect(snapshot.daily_windows[i].geo[cn].subscription_requests ==
                 expected,
             std::string(test.name) + " restores country daily window");
      expect(snapshot.daily_windows[i].geo[gd].rule_conversions ==
                 (test.daily_windows[i] ? 7 : 0),
             std::string(test.name) + " restores region daily window");
    }
    uint64_t series_requests = 0;
    uint64_t series_rules = 0;
    for (const SeriesPoint &point : snapshot.series) {
      series_requests += point.counters.subscription_requests;
      series_rules += point.counters.rule_conversions;
    }
    expect(series_requests == (test.series ? 1 : 0),
           std::string(test.name) + " restores 24-hour request series");
    expect(series_rules == (test.series ? 7 : 0),
           std::string(test.name) + " restores 24-hour rule series");
    expect(snapshot.lifetime.counters.subscription_requests == 1 &&
               snapshot.lifetime.counters.rule_conversions == 7,
           std::string(test.name) + " leaves lifetime unchanged");
    expect(snapshot.lifetime.geo[cn].subscription_requests == 1 &&
               snapshot.lifetime.geo[gd].rule_conversions == 7,
           std::string(test.name) + " leaves lifetime geo unchanged");
    expect(snapshot.startup.counters.empty() &&
               snapshot.startup.geo[cn].empty() &&
               snapshot.startup.geo[gd].empty(),
           std::string(test.name) + " resets startup windows");
  }
}

void concurrentAndSnapshotTest() {
  constexpr int64_t base = INT64_C(2000000000);
  Core core;
  core.startEmpty(base);
  std::mutex mutex;
  std::vector<std::thread> workers;
  for (int worker = 0; worker < 8; ++worker) {
    workers.emplace_back([&] {
      for (int i = 0; i < 2000; ++i) {
        std::lock_guard<std::mutex> lock(mutex);
        core.record(base, countryGeoId("DE"), kInvalidGeoId, 2);
      }
    });
  }
  for (std::thread &worker : workers)
    worker.join();
  DashboardSnapshot snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = core.dashboardSnapshot(base);
  }
  expect(snapshot.startup.counters.subscription_requests == 16000,
         "concurrent request total is exact");
  expect(snapshot.lifetime.counters.rule_conversions == 32000,
         "concurrent rule total is exact");
  expect(snapshot.revision == core.revision(),
         "dashboard fields share one revision");
}

void persistenceRoundTripTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory("roundtrip");
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "writable store opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "initial checkpoint is created");
    core.record(base, countryGeoId("JP"), kInvalidGeoId, 3);
    DirtyPatch patch = core.takeDirtyPatch(base, false);
    expect(store.appendPatch(patch), "dirty absolute patch appends");
    expect(store.walRecords() == 1 && store.walBytes() > 0,
           "WAL records only dirty state");
#ifndef _WIN32
    expectNotWorldWritable(dir / "statistics-v2-a.bin", "checkpoint");
    expectNotWorldWritable(dir / "statistics-v2.wal", "WAL");
#endif
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "store reopens");
    const StoreLoadResult loaded = store.load();
    expect(loaded.has_image, "checkpoint plus WAL recovers");
    Core recovered;
    recovered.startFromImage(loaded.image, base + 60);
    expect(recovered.dashboardSnapshot(base + 60)
               .lifetime.counters.subscription_requests == 1,
           "recovered lifetime request total is exact");
    expect(recovered.dashboardSnapshot(base + 60)
               .lifetime.counters.rule_conversions == 3,
           "recovered lifetime rule total is exact");
  }
  removeTree(dir);
}

void corruptionFallbackTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory("corrupt");
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "corruption store opens");
    Core core;
    core.startEmpty(base);
    expect(store.writeCheckpoint(core.persistentImage(base, false)),
           "checkpoint A is written");
    core.record(base, countryGeoId("FR"), kInvalidGeoId, 1);
    expect(store.appendPatch(core.takeDirtyPatch(base, false)),
           "WAL before checkpoint B is written");
    expect(store.writeCheckpoint(core.persistentImage(base, false)),
           "checkpoint B is written");
  }

  const std::filesystem::path checkpoint_b =
      dir / "statistics-v2-b.bin";
  {
    std::fstream file(checkpoint_b, std::ios::in | std::ios::out |
                                       std::ios::binary);
    file.seekg(-1, std::ios::end);
    char bad = 0;
    file.read(&bad, 1);
    bad ^= 0x5a;
    file.seekp(-1, std::ios::end);
    file.write(&bad, 1);
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "fallback store opens");
    const StoreLoadResult loaded = store.load();
    expect(loaded.has_image && loaded.generation == 1,
           "corrupt B falls back to valid A");
  }

  const std::filesystem::path checkpoint_a =
      dir / "statistics-v2-a.bin";
  {
    std::ofstream file(checkpoint_a, std::ios::binary | std::ios::trunc);
    file << "broken";
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "empty recovery store opens");
    expect(!store.load().has_image,
           "two corrupt checkpoints recover as empty state");
  }
  removeTree(dir);
}

void walTailAndLockTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory("wal");
  {
    Store first(dir.string());
    Store second(dir.string());
    expect(first.open() == StoreStatus::Ready, "first writer gets lock");
    expect(second.open() == StoreStatus::LockUnavailable,
           "second writer degrades instead of sharing files");
    Core core;
    core.startEmpty(base);
    expect(first.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "WAL test checkpoint exists");
    core.record(base, countryGeoId("GB"), kInvalidGeoId, 2);
    expect(first.appendPatch(core.takeDirtyPatch(base, false)),
           "WAL test patch exists");
  }
  const std::filesystem::path wal = dir / "statistics-v2.wal";
  const auto original_size = std::filesystem::file_size(wal);
  std::filesystem::resize_file(wal, original_size - 3);
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "truncated WAL store opens");
    const StoreLoadResult loaded = store.load();
    expect(loaded.has_image && loaded.sequence == 0,
           "incomplete WAL tail is ignored");
  }
  removeTree(dir);
}

void walChecksumAndLengthTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory("checksum");
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "checksum store opens");
    Core core;
    core.startEmpty(base);
    uint64_t checkpoint_version = 0;
    const PersistentImage checkpoint =
        core.checkpointImage(base, false, checkpoint_version);
    expect(store.ensureInitialCheckpoint(checkpoint),
           "checksum checkpoint exists");
    core.acknowledgeCheckpoint(checkpoint_version);
    core.record(base, countryGeoId("CA"), kInvalidGeoId, 1);
    expect(store.appendPatch(core.takeDirtyPatch(base, false)),
           "first checksum patch exists");
    core.record(base, countryGeoId("CA"), kInvalidGeoId, 1);
    expect(store.appendPatch(core.takeDirtyPatch(base, false)),
           "second checksum patch exists");
  }
  const std::filesystem::path wal = dir / "statistics-v2.wal";
  {
    std::fstream file(wal, std::ios::in | std::ios::out | std::ios::binary);
    file.seekg(-1, std::ios::end);
    char value = 0;
    file.read(&value, 1);
    value ^= 0x5a;
    file.seekp(-1, std::ios::end);
    file.write(&value, 1);
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           "checksum recovery store opens");
    const StoreLoadResult loaded = store.load();
    expect(loaded.has_image && loaded.sequence == 1,
           "checksum failure stops at last valid WAL record");
    Core recovered;
    recovered.startFromImage(loaded.image, base);
    expect(recovered.dashboardSnapshot(base)
               .lifetime.counters.subscription_requests == 1,
           "corrupt WAL suffix cannot apply partial state");
  }
  removeTree(dir);

  const std::filesystem::path length_dir = temporaryDirectory("length");
  {
    Store store(length_dir.string());
    expect(store.open() == StoreStatus::Ready, "length store opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "length checkpoint exists");
  }
  {
    std::fstream file(length_dir / "statistics-v2-a.bin",
                      std::ios::in | std::ios::out | std::ios::binary);
    file.seekp(28, std::ios::beg);
    const char forged[8] = {
        static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0x7f)};
    file.write(forged, sizeof(forged));
  }
  {
    Store store(length_dir.string());
    expect(store.open() == StoreStatus::Ready,
           "forged-length store opens");
    expect(!store.load().has_image,
           "forged oversized payload length is rejected before allocation");
  }
  removeTree(length_dir);
}

enum class WalDamage {
  TruncatedTail,
  BadChecksum,
  BadMagic,
  SequenceGap
};

void walRepairAcrossTwoRestarts(WalDamage damage, const char *name) {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory(name);
  const std::filesystem::path wal = dir / "statistics-v2.wal";
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           std::string(name) + " setup store opens");
    Core core;
    core.startEmpty(base);
    uint64_t checkpoint_version = 0;
    expect(store.ensureInitialCheckpoint(
               core.checkpointImage(base, false, checkpoint_version)),
           std::string(name) + " setup checkpoint exists");
    core.acknowledgeCheckpoint(checkpoint_version);
    core.record(base, countryGeoId("US"), kInvalidGeoId, 2);
    expect(store.appendPatch(core.takeDirtyPatch(base, false)),
           std::string(name) + " valid prefix appends");
    core.record(base + 60, countryGeoId("CA"), kInvalidGeoId, 3);
    expect(store.appendPatch(core.takeDirtyPatch(base + 60, false)),
           std::string(name) + " damaged suffix initially appends");
  }

  std::vector<uint8_t> bytes = readBytes(wal);
  const std::size_t valid_prefix = walRecordSize(bytes, 0);
  const std::size_t second_size = walRecordSize(bytes, valid_prefix);
  expect(valid_prefix + second_size == bytes.size(),
         std::string(name) + " WAL contains exactly two records");
  switch (damage) {
  case WalDamage::TruncatedTail:
    bytes.resize(bytes.size() - 3);
    break;
  case WalDamage::BadChecksum:
    bytes.back() ^= 0x5a;
    break;
  case WalDamage::BadMagic:
    bytes[valid_prefix] ^= 0x5a;
    break;
  case WalDamage::SequenceGap: {
    writeU64(bytes, valid_prefix + 16, 9);
    const uint64_t value =
        testChecksum(bytes.data() + valid_prefix, second_size - 8);
    writeU64(bytes, valid_prefix + second_size - 8, value);
    break;
  }
  }
  writeBytes(wal, bytes);

  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           std::string(name) + " first recovery opens");
    const StoreLoadResult recovered = store.load();
    expect(recovered.has_image && recovered.sequence == 1,
           std::string(name) + " first recovery keeps valid prefix");
    expect(store.ready(),
           std::string(name) + " successful tail repair keeps store writable");
    expect(std::filesystem::file_size(wal) == valid_prefix,
           std::string(name) + " invalid suffix is durably truncated");
    Core core;
    core.startFromImage(recovered.image, base + 120);
    core.record(base + 120, countryGeoId("DE"), kInvalidGeoId, 5);
    expect(store.appendPatch(core.takeDirtyPatch(base + 120, false)),
           std::string(name) + " post-repair patch appends");
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           std::string(name) + " second recovery opens");
    const StoreLoadResult recovered = store.load();
    expect(recovered.has_image && recovered.sequence == 2,
           std::string(name) + " second recovery accepts post-damage data");
    Core core;
    core.startFromImage(recovered.image, base + 180);
    const DashboardSnapshot snapshot = core.dashboardSnapshot(base + 180);
    expect(snapshot.lifetime.counters.subscription_requests == 2 &&
               snapshot.lifetime.counters.rule_conversions == 7,
           std::string(name) + " second recovery preserves old and new data");
  }
  removeTree(dir);
}

void walTailRepairTest() {
  walRepairAcrossTwoRestarts(WalDamage::TruncatedTail, "repair-truncated");
  walRepairAcrossTwoRestarts(WalDamage::BadChecksum, "repair-checksum");
  walRepairAcrossTwoRestarts(WalDamage::BadMagic, "repair-magic");
  walRepairAcrossTwoRestarts(WalDamage::SequenceGap, "repair-sequence");
}

void walTruncateFailureDegradesTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path dir = temporaryDirectory("truncate-failure");
  const std::filesystem::path wal = dir / "statistics-v2.wal";
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           "truncate-failure setup store opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "truncate-failure checkpoint exists");
    core.record(base, countryGeoId("US"), kInvalidGeoId, 2);
    expect(store.appendPatch(core.takeDirtyPatch(base, false)),
           "truncate-failure valid prefix appends");
    core.record(base + 60, countryGeoId("CA"), kInvalidGeoId, 3);
    expect(store.appendPatch(core.takeDirtyPatch(base + 60, false)),
           "truncate-failure suffix appends");
  }
  std::vector<uint8_t> bytes = readBytes(wal);
  const std::size_t valid_prefix = walRecordSize(bytes, 0);
  bytes.back() ^= 0x7f;
  writeBytes(wal, bytes);

  Store store(dir.string());
  expect(store.open() == StoreStatus::Ready,
         "truncate-failure recovery store opens");
  setTestWriteFault(TestWriteFault::TruncateFailure);
  const StoreLoadResult recovered = store.load();
  setTestWriteFault(TestWriteFault::None);
  expect(recovered.has_image && recovered.sequence == 1,
         "truncate failure still returns valid in-memory prefix");
  expect(!store.ready(),
         "truncate failure closes persistence before any future append");
  Core memory;
  memory.startFromImage(recovered.image, base + 120);
  memory.record(base + 120, countryGeoId("DE"), kInvalidGeoId, 5);
  expect(memory.dashboardSnapshot(base + 120)
                 .lifetime.counters.subscription_requests == 2,
         "service state can continue in memory after truncate failure");
  expect(std::filesystem::file_size(wal) > valid_prefix,
         "failed truncate does not claim the suffix was repaired");
  removeTree(dir);
}

void runtimeHeartbeatTest() {
  constexpr int64_t base = INT64_C(2000000000);
  expect(runtimeHeartbeatIntervalSeconds(1) == 60,
         "runtime heartbeat has a sixty-second floor");
  expect(runtimeHeartbeatIntervalSeconds(90) == 90,
         "runtime heartbeat follows a longer flush interval");

  const std::filesystem::path dir = temporaryDirectory("heartbeat");
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "heartbeat store opens");
    Core core;
    core.startEmpty(base);
    uint64_t checkpoint_version = 0;
    expect(store.ensureInitialCheckpoint(
               core.checkpointImage(base, false, checkpoint_version)),
           "heartbeat initial checkpoint exists");
    core.acknowledgeCheckpoint(checkpoint_version);
    expect(!core.hasDirty(),
           "heartbeat test starts without request dirtiness");
    const DirtyPatch heartbeat = core.runtimePatch(base + 61, false);
    expect(!heartbeat.empty() && heartbeat.metadata_present,
           "idle runtime heartbeat is a real metadata patch");
    expect(heartbeat.minutes.empty() && heartbeat.days.empty() &&
               heartbeat.lifetime_geo.empty(),
           "runtime heartbeat contains no minute/day/geo buckets");
    expect(store.appendPatch(heartbeat),
           "idle runtime heartbeat appends after sixty-one seconds");
    expect(store.walBytes() < 256,
           "runtime-only heartbeat keeps the WAL record small");
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready,
           "heartbeat abnormal-exit recovery opens");
    const StoreLoadResult recovered = store.load();
    expect(recovered.has_image && recovered.sequence == 1,
           "heartbeat survives an abnormal-exit style reopen");
    expect(recovered.image.runtime.persisted_runtime_seconds >= 61 &&
               recovered.image.runtime.last_seen_at == base + 61,
           "heartbeat restores runtime metadata without shutdown");
  }
  removeTree(dir);
}

void persistenceFileLimitTest() {
  constexpr int64_t base = INT64_C(2000000000);
  constexpr std::uintmax_t checkpoint_limit =
      128U * 1024U * 1024U + 45U;
  constexpr std::uintmax_t wal_limit = 16U * 1024U * 1024U + 1U;

  const std::filesystem::path checkpoint_dir =
      temporaryDirectory("checkpoint-limit");
  {
    Store store(checkpoint_dir.string());
    expect(store.open() == StoreStatus::Ready,
           "oversized checkpoint setup opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "oversized checkpoint setup writes a valid file");
  }
  std::filesystem::resize_file(
      checkpoint_dir / "statistics-v2-a.bin", checkpoint_limit);
  {
    Store store(checkpoint_dir.string());
    expect(store.open() == StoreStatus::Ready,
           "oversized checkpoint recovery opens initially");
    expect(!store.load().has_image,
           "oversized checkpoint is rejected before allocation");
    expect(!store.ready(),
           "oversized checkpoint degrades persistence to memory");
  }
  removeTree(checkpoint_dir);

  const std::filesystem::path wal_dir = temporaryDirectory("wal-limit");
  {
    Store store(wal_dir.string());
    expect(store.open() == StoreStatus::Ready, "oversized WAL setup opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "oversized WAL setup writes a valid checkpoint");
  }
  std::filesystem::resize_file(wal_dir / "statistics-v2.wal", wal_limit);
  {
    Store store(wal_dir.string());
    expect(store.open() == StoreStatus::Ready,
           "oversized WAL recovery opens initially");
    const StoreLoadResult recovered = store.load();
    expect(recovered.has_image,
           "oversized WAL keeps the verified checkpoint in memory");
    expect(!store.ready(),
           "oversized WAL disables persistence before future appends");
  }
  removeTree(wal_dir);
}

void directoryAndLegacyTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::filesystem::path root = temporaryDirectory("legacy");
  const std::filesystem::path impossible = root / "not-a-directory";
  {
    std::ofstream file(impossible);
    file << "file";
  }
  Store bad(impossible.string());
  expect(bad.open() == StoreStatus::DirectoryUnavailable,
         "invalid data directory degrades cleanly");

  const std::filesystem::path dir = root / "stats";
  std::filesystem::create_directories(dir);
  {
    std::ofstream old(dir / "statistics.json");
    old << "{\"legacy\":true}";
  }
  {
    Store store(dir.string());
    expect(store.open() == StoreStatus::Ready, "legacy store opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "v2 checkpoint validates before cleanup");
    expect(store.cleanupLegacyFile(), "legacy file cleanup succeeds");
    expect(!std::filesystem::exists(dir / "statistics.json"),
           "legacy exact filename is removed");
  }

  const std::filesystem::path failed_dir = root / "failed-stats";
  std::filesystem::create_directories(
      failed_dir / "statistics-v2-a.bin.tmp");
  {
    std::ofstream old(failed_dir / "statistics.json");
    old << "{\"legacy\":true}";
  }
  {
    Store store(failed_dir.string());
    expect(store.open() == StoreStatus::Ready,
           "failed-checkpoint store still opens");
    Core core;
    core.startEmpty(base);
    expect(!store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "simulated checkpoint write failure is detected");
    expect(std::filesystem::exists(failed_dir / "statistics.json"),
           "legacy file remains authoritative after v2 write failure");
  }

  const std::filesystem::path symlink_dir = root / "symlink-stats";
  std::filesystem::create_directories(symlink_dir);
  {
    std::ofstream target(root / "legacy-target.json");
    target << "keep";
  }
  std::error_code symlink_error;
  std::filesystem::create_symlink(
      root / "legacy-target.json", symlink_dir / "statistics.json",
      symlink_error);
  if (!symlink_error) {
    Store store(symlink_dir.string());
    expect(store.open() == StoreStatus::Ready, "symlink store opens");
    Core core;
    core.startEmpty(base);
    expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
           "symlink store checkpoint exists");
    expect(store.cleanupLegacyFile(), "legacy symlink is ignored safely");
    expect(std::filesystem::is_symlink(
               std::filesystem::symlink_status(
                   symlink_dir / "statistics.json")),
           "legacy cleanup does not follow symlinks");
  }
  removeTree(root);
}

void persistenceFaultInjectionTest() {
  constexpr int64_t base = INT64_C(2000000000);
  const std::array<TestWriteFault, 4> faults = {
      TestWriteFault::OpenFailure, TestWriteFault::NoSpace,
      TestWriteFault::ShortWrite, TestWriteFault::FlushFailure};
  for (const TestWriteFault fault : faults) {
    const std::filesystem::path dir = temporaryDirectory("write-fault");
    Core core;
    core.startEmpty(base);
    {
      Store store(dir.string());
      expect(store.open() == StoreStatus::Ready, "fault store opens");
      setTestWriteFault(fault);
      expect(!store.ensureInitialCheckpoint(core.persistentImage(base, false)),
             "injected initial checkpoint failure is reported");
      setTestWriteFault(TestWriteFault::None);
      expect(store.ensureInitialCheckpoint(core.persistentImage(base, false)),
             "checkpoint succeeds after injected fault is cleared");
      core.record(base, countryGeoId("US"), kInvalidGeoId, 3);
      const DirtyPatch patch = core.takeDirtyPatch(base, false);
      setTestWriteFault(fault);
      expect(!store.appendPatch(patch),
             "injected WAL failure is reported");
      setTestWriteFault(TestWriteFault::None);
      expect(store.appendPatch(patch),
             "WAL append succeeds after injected fault is cleared");
    }
    {
      Store recovered(dir.string());
      expect(recovered.open() == StoreStatus::Ready,
             "fault recovery store opens");
      const StoreLoadResult loaded = recovered.load();
      expect(loaded.has_image && loaded.sequence == 1,
             "failed writes do not replace the valid persistence prefix");
      Core restored;
      restored.startFromImage(loaded.image, base);
      expect(restored.dashboardSnapshot(base)
                     .lifetime.counters.rule_conversions == 3,
             "recovery preserves the successful WAL patch");
    }
    removeTree(dir);
  }
  setTestWriteFault(TestWriteFault::None);
}

void requestLifecycleContextTest() {
  resetRequestLifecycleMetricsForTests();
  const auto now = RequestContext::Clock::now();
  auto completed = std::make_shared<RequestContext>(
      "request-context-completed", now,
      now + std::chrono::seconds(30));
  expect(completed->requestId() == "request-context-completed",
         "request context preserves its generated ID");
  expect(completed->recordAdmissionOnce(now + std::chrono::milliseconds(2)),
         "request context records admission once");
  expect(!completed->recordAdmissionOnce(now + std::chrono::milliseconds(3)),
         "request context rejects duplicate admission samples");
  completed->setCostClass(RequestCostClass::High);
  completed->setEstimatedBytes(4096);
  completed->setSingleflightRole(RequestSingleflightRole::Owner);
  expect(completed->addConsumer() && completed->consumerCount() == 2,
         "request context tracks added consumers");
  expect(completed->releaseConsumer() == 1,
         "request context tracks released consumers");
  {
    RequestStageTimer timer(completed, RequestStage::Parse);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  expect(completed->finalizeResponse(200, true),
         "completed response reaches one terminal state");
  expect(!completed->finalizeResponse(500, false),
         "completed response rejects a second terminal state");
  expect(completed->terminalState() == RequestTerminalState::Completed &&
             completed->failureAttribution() ==
                 RequestFailureAttribution::None,
         "completed response preserves terminal attribution");
  expect(completed->costClass() == RequestCostClass::High &&
             completed->estimatedBytes() == 4096 &&
             completed->singleflightRole() ==
                 RequestSingleflightRole::Owner,
         "request context preserves bounded classification metadata");

  auto cancelled = std::make_shared<RequestContext>(
      "request-context-cancelled", now,
      now + std::chrono::seconds(30));
  const RequestCancellationToken token = cancelled->cancellationToken();
  expect(!token.isCancellationRequested(),
         "fresh request cancellation token is clear");
  expect(cancelled->requestCancellation(
             RequestCancellationReason::ClientDisconnected),
         "first cancellation request wins");
  expect(!cancelled->requestCancellation(RequestCancellationReason::Shutdown),
         "cancellation reason is immutable");
  expect(token.reason() == RequestCancellationReason::ClientDisconnected,
         "cancellation token observes the source reason");
  expect(cancelled->finalizeResponse(200, true) &&
             cancelled->terminalState() == RequestTerminalState::Cancelled &&
             cancelled->failureAttribution() ==
                 RequestFailureAttribution::Client,
         "cancelled response is attributed to the client");

  auto expired = std::make_shared<RequestContext>(
      "request-context-expired", now,
      now - std::chrono::milliseconds(1));
  expect(expired->finalizeResponse(200, true) &&
             expired->terminalState() ==
                 RequestTerminalState::DeadlineExceeded,
         "expired request cannot complete as successful");

  auto raced = std::make_shared<RequestContext>(
      "request-context-raced", now,
      now + std::chrono::seconds(30));
  std::atomic<int> terminal_winners{0};
  std::vector<std::thread> contenders;
  for (int index = 0; index < 16; ++index) {
    contenders.emplace_back([&, index] {
      const bool won = index % 2 == 0
                           ? raced->tryFinish(
                                 RequestTerminalState::Failed,
                                 RequestFailureAttribution::Server)
                           : raced->tryFinish(
                                 RequestTerminalState::Cancelled,
                                 RequestFailureAttribution::Client);
      if (won)
        terminal_winners.fetch_add(1, std::memory_order_relaxed);
    });
  }
  for (std::thread &thread : contenders)
    thread.join();
  expect(terminal_winners.load(std::memory_order_relaxed) == 1,
         "terminal transition has exactly one concurrent winner");

  const RequestLifecycleMetricsSnapshot metrics =
      requestLifecycleMetricsSnapshot();
  uint64_t terminal_total = 0;
  for (uint64_t count : metrics.terminal)
    terminal_total += count;
  expect(terminal_total == 4,
         "lifecycle metrics record each request terminal exactly once");
  expect(metrics.terminal[static_cast<std::size_t>(
             RequestTerminalState::Completed)] == 1,
         "lifecycle metrics record completed requests");
  expect(metrics.terminal[static_cast<std::size_t>(
             RequestTerminalState::DeadlineExceeded)] == 1,
         "lifecycle metrics record deadline failures");
  expect(metrics.stage_samples[static_cast<std::size_t>(RequestStage::Parse)] ==
             1 &&
             metrics.stage_nanoseconds[static_cast<std::size_t>(
                 RequestStage::Parse)] > 0,
          "lifecycle metrics record bounded stage timings");
  expect(metrics.successful_owners == 1 &&
             metrics.successful_responses == 1,
         "lifecycle metrics record successful owner goodput");
  expect(requestStageLatencyQuantileMicroseconds(
             metrics, RequestStage::Parse, 50, 100) > 0 &&
             requestStageLatencyQuantileMicroseconds(
                 metrics, RequestStage::Parse, 95, 100) >=
                 requestStageLatencyQuantileMicroseconds(
                     metrics, RequestStage::Parse, 50, 100) &&
             requestStageLatencyQuantileMicroseconds(
                 metrics, RequestStage::Parse, 99, 100) >=
                 requestStageLatencyQuantileMicroseconds(
                     metrics, RequestStage::Parse, 95, 100),
         "lifecycle metrics expose monotonic latency quantiles");
}

} // namespace

int main() {
  geoMappingTest();
  rollingWindowTest();
  timeJumpAndSaturationTest();
  restartWindowRecoveryTest();
  concurrentAndSnapshotTest();
  persistenceRoundTripTest();
  corruptionFallbackTest();
  walTailAndLockTest();
  walChecksumAndLengthTest();
  walTailRepairTest();
  walTruncateFailureDegradesTest();
  runtimeHeartbeatTest();
  persistenceFileLimitTest();
  directoryAndLegacyTest();
  persistenceFaultInjectionTest();
  requestLifecycleContextTest();
  if (failures != 0) {
    std::cerr << failures << " Statistics v2 checks failed\n";
    return 1;
  }
  std::cout << "Statistics v2 checks passed\n";
  return 0;
}
