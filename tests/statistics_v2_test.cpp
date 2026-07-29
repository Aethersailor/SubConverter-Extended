#include "handler/statistics_v2.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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

} // namespace

int main() {
  geoMappingTest();
  rollingWindowTest();
  timeJumpAndSaturationTest();
  concurrentAndSnapshotTest();
  persistenceRoundTripTest();
  corruptionFallbackTest();
  walTailAndLockTest();
  walChecksumAndLengthTest();
  directoryAndLegacyTest();
  persistenceFaultInjectionTest();
  if (failures != 0) {
    std::cerr << failures << " Statistics v2 checks failed\n";
    return 1;
  }
  std::cout << "Statistics v2 checks passed\n";
  return 0;
}
