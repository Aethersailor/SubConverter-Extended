#include "handler/statistics_v2.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace statistics_v2 {
namespace {

constexpr std::array<int, 4> kMinuteWindowSizes = {60, 24 * 60,
                                                   7 * 24 * 60,
                                                   30 * 24 * 60};
constexpr std::array<int, 2> kDailyWindowSizes = {183, 365};
constexpr std::array<const char *, kChinaRegionCount> kChinaRegionSuffixes = {
    "AH", "BJ", "CQ", "FJ", "GD", "GS", "GX", "GZ", "HA", "HB", "HE", "HI",
    "HK", "HL", "HN", "JL", "JS", "JX", "LN", "MO", "NM", "NX", "QH", "SC",
    "SD", "SH", "SN", "SX", "TJ", "TW", "XJ", "XZ", "YN", "ZJ", "XX"};
constexpr std::size_t kMaxEncodedBucketBytes =
    sizeof(int64_t) + sizeof(uint64_t) * 2 + sizeof(uint32_t) +
    kGeoCount * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
constexpr std::size_t kMaxPayloadBytes =
    (kMinuteBucketCount + kDailyBucketCount) *
        (sizeof(uint32_t) + kMaxEncodedBucketBytes) +
    kGeoCount * (sizeof(uint16_t) + sizeof(uint64_t) * 2) + 256;
constexpr std::size_t kMaxCheckpointPayloadBytes =
    128U * 1024U * 1024U;
constexpr std::size_t kMaxWalPayloadBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaxWalFileBytes = 16U * 1024U * 1024U;
constexpr std::size_t kCheckpointEnvelopeBytes = 44;
constexpr std::size_t kWalCompactBytes = 4U * 1024U * 1024U;
constexpr std::size_t kWalCompactRecords = 256;
constexpr auto kCheckpointPeriod = std::chrono::hours(6);
constexpr std::array<uint8_t, 8> kCheckpointMagic = {'S', 'C', 'S', 'T',
                                                     'A', 'T', '2', 'C'};
constexpr std::array<uint8_t, 4> kWalMagic = {'S', '2', 'W', 'L'};
constexpr uint32_t kSchemaVersion = 2;
constexpr uint32_t kWalPatchType = 1;

#ifdef STATISTICS_V2_TESTING
TestWriteFault g_test_write_fault = TestWriteFault::None;
#endif

uint64_t saturatedAddValue(uint64_t lhs, uint64_t rhs) {
  if (rhs > std::numeric_limits<uint64_t>::max() - lhs)
    return std::numeric_limits<uint64_t>::max();
  return lhs + rhs;
}

int64_t saturatedRuntime(int64_t persisted, int64_t uptime) {
  if (persisted < 0)
    persisted = 0;
  if (uptime < 0)
    uptime = 0;
  if (uptime > std::numeric_limits<int64_t>::max() - persisted)
    return std::numeric_limits<int64_t>::max();
  return persisted + uptime;
}

void add(Counters &target, const Counters &value) {
  target.subscription_requests =
      saturatedAddValue(target.subscription_requests,
                        value.subscription_requests);
  target.rule_conversions =
      saturatedAddValue(target.rule_conversions, value.rule_conversions);
}

void add(Counters &target, uint64_t requests, uint64_t rules) {
  target.subscription_requests =
      saturatedAddValue(target.subscription_requests, requests);
  target.rule_conversions =
      saturatedAddValue(target.rule_conversions, rules);
}

void subtract(Counters &target, const Counters &value) {
  target.subscription_requests =
      value.subscription_requests >= target.subscription_requests
          ? 0
          : target.subscription_requests - value.subscription_requests;
  target.rule_conversions =
      value.rule_conversions >= target.rule_conversions
          ? 0
          : target.rule_conversions - value.rule_conversions;
}

char upperAscii(char ch) {
  if (ch >= 'a' && ch <= 'z')
    return static_cast<char>(ch - ('a' - 'A'));
  return ch;
}

bool whitespace(char ch) {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ||
         ch == '\f' || ch == '\v';
}

bool trimmedBounds(const std::string &value, std::size_t &begin,
                   std::size_t &end) {
  begin = 0;
  end = value.size();
  while (begin < end && whitespace(value[begin]))
    ++begin;
  while (end > begin && whitespace(value[end - 1]))
    --end;
  return begin < end;
}

const std::array<int16_t, 26 * 26> &regionLookup() {
  static const std::array<int16_t, 26 * 26> lookup = [] {
    std::array<int16_t, 26 * 26> result{};
    result.fill(-1);
    for (std::size_t i = 0; i < kChinaRegionSuffixes.size(); ++i) {
      const char *code = kChinaRegionSuffixes[i];
      result[static_cast<std::size_t>(code[0] - 'A') * 26 +
             static_cast<std::size_t>(code[1] - 'A')] =
          static_cast<int16_t>(i);
    }
    return result;
  }();
  return lookup;
}

template <std::size_t N>
void clearCounters(std::array<Counters, N> &values) {
  values.fill(Counters{});
}

template <std::size_t N>
void denseToSparse(const std::array<Counters, N> &dense,
                   std::vector<GeoCounters> &sparse) {
  sparse.clear();
  for (std::size_t i = 0; i < dense.size(); ++i) {
    if (!dense[i].empty())
      sparse.push_back(
          {static_cast<GeoId>(i), dense[static_cast<std::size_t>(i)]});
  }
}

template <typename AggregateType>
void addBucket(AggregateType &aggregate, const BucketRecord &record) {
  add(aggregate.counters, record.counters);
  for (const GeoCounters &entry : record.geo) {
    if (entry.id < kGeoCount)
      add(aggregate.geo[entry.id], entry.counters);
  }
}

template <typename AggregateType>
void subtractBucket(AggregateType &aggregate, const BucketRecord &record) {
  subtract(aggregate.counters, record.counters);
  for (const GeoCounters &entry : record.geo) {
    if (entry.id < kGeoCount)
      subtract(aggregate.geo[entry.id], entry.counters);
  }
}

class Encoder {
public:
  void u16(uint16_t value) {
    bytes_.push_back(static_cast<uint8_t>(value & 0xff));
    bytes_.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
  }

  void u32(uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
      bytes_.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
  }

  void u64(uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      bytes_.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
  }

  void i64(int64_t value) { u64(static_cast<uint64_t>(value)); }

  void raw(const uint8_t *data, std::size_t size) {
    bytes_.insert(bytes_.end(), data, data + size);
  }

  void patchU64(std::size_t offset, uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
      bytes_[offset + i] =
          static_cast<uint8_t>((value >> (i * 8)) & UINT64_C(0xff));
  }

  void patchU32(std::size_t offset, uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i)
      bytes_[offset + i] =
          static_cast<uint8_t>((value >> (i * 8)) & UINT32_C(0xff));
  }

  std::size_t size() const { return bytes_.size(); }
  const std::vector<uint8_t> &bytes() const { return bytes_; }
  std::vector<uint8_t> take() { return std::move(bytes_); }

private:
  std::vector<uint8_t> bytes_;
};

class Decoder {
public:
  Decoder(const uint8_t *data, std::size_t size) : data_(data), size_(size) {}

  bool u16(uint16_t &value) {
    if (!available(2))
      return false;
    value = static_cast<uint16_t>(data_[offset_]) |
            static_cast<uint16_t>(data_[offset_ + 1] << 8);
    offset_ += 2;
    return true;
  }

  bool u32(uint32_t &value) {
    uint64_t wide = 0;
    if (!unsignedValue(4, wide))
      return false;
    value = static_cast<uint32_t>(wide);
    return true;
  }

  bool u64(uint64_t &value) { return unsignedValue(8, value); }

  bool i64(int64_t &value) {
    uint64_t raw = 0;
    if (!u64(raw))
      return false;
    value = static_cast<int64_t>(raw);
    return true;
  }

  bool raw(uint8_t *target, std::size_t count) {
    if (!available(count))
      return false;
    std::memcpy(target, data_ + offset_, count);
    offset_ += count;
    return true;
  }

  const uint8_t *current() const { return data_ + offset_; }
  bool skip(std::size_t count) {
    if (!available(count))
      return false;
    offset_ += count;
    return true;
  }
  std::size_t remaining() const { return size_ - offset_; }
  std::size_t offset() const { return offset_; }

private:
  bool available(std::size_t count) const {
    return count <= size_ - offset_;
  }

  bool unsignedValue(std::size_t count, uint64_t &value) {
    if (!available(count))
      return false;
    value = 0;
    for (std::size_t i = 0; i < count; ++i)
      value |= static_cast<uint64_t>(data_[offset_ + i]) << (i * 8);
    offset_ += count;
    return true;
  }

  const uint8_t *data_;
  std::size_t size_;
  std::size_t offset_ = 0;
};

uint64_t checksum(const uint8_t *data, std::size_t size) {
  uint64_t hash = UINT64_C(1469598103934665603);
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

void encodeCounters(Encoder &encoder, const Counters &counters) {
  encoder.u64(counters.subscription_requests);
  encoder.u64(counters.rule_conversions);
}

bool decodeCounters(Decoder &decoder, Counters &counters) {
  return decoder.u64(counters.subscription_requests) &&
         decoder.u64(counters.rule_conversions);
}

void encodeRuntime(Encoder &encoder, const RuntimeState &runtime) {
  encoder.i64(runtime.first_started_at);
  encoder.i64(runtime.persisted_runtime_seconds);
  encoder.i64(runtime.last_seen_at);
  encoder.i64(runtime.last_stopped_at);
  encoder.u64(runtime.launch_count);
}

bool decodeRuntime(Decoder &decoder, RuntimeState &runtime) {
  if (!decoder.i64(runtime.first_started_at) ||
      !decoder.i64(runtime.persisted_runtime_seconds) ||
      !decoder.i64(runtime.last_seen_at) ||
      !decoder.i64(runtime.last_stopped_at) ||
      !decoder.u64(runtime.launch_count))
    return false;
  return runtime.first_started_at >= 0 &&
         runtime.persisted_runtime_seconds >= 0 &&
         runtime.last_seen_at >= 0 && runtime.last_stopped_at >= 0;
}

void encodeBucket(Encoder &encoder, const BucketRecord &record) {
  encoder.i64(record.stamp);
  encodeCounters(encoder, record.counters);
  encoder.u32(static_cast<uint32_t>(record.geo.size()));
  for (const GeoCounters &entry : record.geo) {
    encoder.u16(entry.id);
    encodeCounters(encoder, entry.counters);
  }
}

bool decodeBucket(Decoder &decoder, BucketRecord &record) {
  uint32_t count = 0;
  if (!decoder.i64(record.stamp) ||
      !decodeCounters(decoder, record.counters) || !decoder.u32(count) ||
      count > kGeoCount)
    return false;
  record.geo.clear();
  record.geo.reserve(count);
  std::bitset<kGeoCount> seen;
  for (uint32_t i = 0; i < count; ++i) {
    GeoCounters entry;
    if (!decoder.u16(entry.id) || entry.id >= kGeoCount ||
        seen.test(entry.id) || !decodeCounters(decoder, entry.counters))
      return false;
    seen.set(entry.id);
    if (!entry.counters.empty())
      record.geo.push_back(entry);
  }
  if (record.counters.empty()) {
    record.stamp = 0;
    record.geo.clear();
  }
  return true;
}

void encodeImagePayload(Encoder &encoder, const PersistentImage &image) {
  encodeRuntime(encoder, image.runtime);
  encodeCounters(encoder, image.lifetime);

  uint32_t geo_count = 0;
  for (const Counters &value : image.lifetime_geo)
    if (!value.empty())
      ++geo_count;
  encoder.u32(geo_count);
  for (std::size_t i = 0; i < image.lifetime_geo.size(); ++i) {
    if (image.lifetime_geo[i].empty())
      continue;
    encoder.u16(static_cast<GeoId>(i));
    encodeCounters(encoder, image.lifetime_geo[i]);
  }

  uint32_t minute_count = 0;
  for (const BucketRecord &record : image.minutes)
    if (!record.empty())
      ++minute_count;
  encoder.u32(minute_count);
  for (std::size_t i = 0; i < image.minutes.size(); ++i) {
    if (image.minutes[i].empty())
      continue;
    encoder.u32(static_cast<uint32_t>(i));
    encodeBucket(encoder, image.minutes[i]);
  }

  uint32_t day_count = 0;
  for (const BucketRecord &record : image.days)
    if (!record.empty())
      ++day_count;
  encoder.u32(day_count);
  for (std::size_t i = 0; i < image.days.size(); ++i) {
    if (image.days[i].empty())
      continue;
    encoder.u32(static_cast<uint32_t>(i));
    encodeBucket(encoder, image.days[i]);
  }
}

bool decodeImagePayload(const uint8_t *data, std::size_t size,
                        PersistentImage &image) {
  if (size > kMaxCheckpointPayloadBytes || size > kMaxPayloadBytes)
    return false;
  Decoder decoder(data, size);
  image = PersistentImage{};
  if (!decodeRuntime(decoder, image.runtime) ||
      !decodeCounters(decoder, image.lifetime))
    return false;

  uint32_t geo_count = 0;
  if (!decoder.u32(geo_count) || geo_count > kGeoCount)
    return false;
  std::bitset<kGeoCount> seen_geo;
  for (uint32_t i = 0; i < geo_count; ++i) {
    GeoId id = kInvalidGeoId;
    if (!decoder.u16(id) || id >= kGeoCount || seen_geo.test(id) ||
        !decodeCounters(decoder, image.lifetime_geo[id]))
      return false;
    seen_geo.set(id);
  }

  uint32_t minute_count = 0;
  if (!decoder.u32(minute_count) || minute_count > kMinuteBucketCount)
    return false;
  std::bitset<kMinuteBucketCount> seen_minutes;
  for (uint32_t i = 0; i < minute_count; ++i) {
    uint32_t index = 0;
    if (!decoder.u32(index) || index >= kMinuteBucketCount ||
        seen_minutes.test(index) ||
        !decodeBucket(decoder, image.minutes[index]))
      return false;
    const BucketRecord &record = image.minutes[index];
    if (!record.empty() &&
        (record.stamp <= 0 ||
         static_cast<std::size_t>(
             record.stamp % static_cast<int64_t>(kMinuteBucketCount)) !=
             index))
      return false;
    seen_minutes.set(index);
  }

  uint32_t day_count = 0;
  if (!decoder.u32(day_count) || day_count > kDailyBucketCount)
    return false;
  std::bitset<kDailyBucketCount> seen_days;
  for (uint32_t i = 0; i < day_count; ++i) {
    uint32_t index = 0;
    if (!decoder.u32(index) || index >= kDailyBucketCount ||
        seen_days.test(index) || !decodeBucket(decoder, image.days[index]))
      return false;
    const BucketRecord &record = image.days[index];
    if (!record.empty() &&
        (record.stamp <= 0 ||
         static_cast<std::size_t>(
             record.stamp % static_cast<int64_t>(kDailyBucketCount)) !=
             index))
      return false;
    seen_days.set(index);
  }
  return decoder.remaining() == 0;
}

void encodePatchPayload(Encoder &encoder, const DirtyPatch &patch) {
  encodeRuntime(encoder, patch.runtime);
  encodeCounters(encoder, patch.lifetime);
  encoder.u32(static_cast<uint32_t>(patch.lifetime_geo.size()));
  for (const GeoCounters &entry : patch.lifetime_geo) {
    encoder.u16(entry.id);
    encodeCounters(encoder, entry.counters);
  }
  encoder.u32(static_cast<uint32_t>(patch.minutes.size()));
  for (const IndexedBucket &entry : patch.minutes) {
    encoder.u32(entry.index);
    encodeBucket(encoder, entry.record);
  }
  encoder.u32(static_cast<uint32_t>(patch.days.size()));
  for (const IndexedBucket &entry : patch.days) {
    encoder.u32(entry.index);
    encodeBucket(encoder, entry.record);
  }
}

bool decodeAndApplyPatch(const uint8_t *data, std::size_t size,
                         PersistentImage &image) {
  if (size > kMaxWalPayloadBytes || size > kMaxPayloadBytes)
    return false;
  Decoder decoder(data, size);
  RuntimeState runtime;
  Counters lifetime;
  if (!decodeRuntime(decoder, runtime) ||
      !decodeCounters(decoder, lifetime))
    return false;

  uint32_t geo_count = 0;
  if (!decoder.u32(geo_count) || geo_count > kGeoCount)
    return false;
  std::vector<GeoCounters> geo;
  geo.reserve(geo_count);
  std::bitset<kGeoCount> seen_geo;
  for (uint32_t i = 0; i < geo_count; ++i) {
    GeoCounters entry;
    if (!decoder.u16(entry.id) || entry.id >= kGeoCount ||
        seen_geo.test(entry.id) || !decodeCounters(decoder, entry.counters))
      return false;
    seen_geo.set(entry.id);
    geo.push_back(entry);
  }

  uint32_t minute_count = 0;
  if (!decoder.u32(minute_count) || minute_count > kMinuteBucketCount)
    return false;
  std::vector<IndexedBucket> minutes;
  minutes.reserve(minute_count);
  std::bitset<kMinuteBucketCount> seen_minutes;
  for (uint32_t i = 0; i < minute_count; ++i) {
    IndexedBucket entry;
    if (!decoder.u32(entry.index) || entry.index >= kMinuteBucketCount ||
        seen_minutes.test(entry.index) ||
        !decodeBucket(decoder, entry.record))
      return false;
    if (!entry.record.empty() &&
        (entry.record.stamp <= 0 ||
         static_cast<std::size_t>(
             entry.record.stamp %
             static_cast<int64_t>(kMinuteBucketCount)) != entry.index))
      return false;
    seen_minutes.set(entry.index);
    minutes.push_back(std::move(entry));
  }

  uint32_t day_count = 0;
  if (!decoder.u32(day_count) || day_count > kDailyBucketCount)
    return false;
  std::vector<IndexedBucket> days;
  days.reserve(day_count);
  std::bitset<kDailyBucketCount> seen_days;
  for (uint32_t i = 0; i < day_count; ++i) {
    IndexedBucket entry;
    if (!decoder.u32(entry.index) || entry.index >= kDailyBucketCount ||
        seen_days.test(entry.index) || !decodeBucket(decoder, entry.record))
      return false;
    if (!entry.record.empty() &&
        (entry.record.stamp <= 0 ||
         static_cast<std::size_t>(
             entry.record.stamp %
             static_cast<int64_t>(kDailyBucketCount)) != entry.index))
      return false;
    seen_days.set(entry.index);
    days.push_back(std::move(entry));
  }
  if (decoder.remaining() != 0)
    return false;

  image.runtime = runtime;
  image.lifetime = lifetime;
  for (const GeoCounters &entry : geo)
    image.lifetime_geo[entry.id] = entry.counters;
  for (IndexedBucket &entry : minutes)
    image.minutes[entry.index] = std::move(entry.record);
  for (IndexedBucket &entry : days)
    image.days[entry.index] = std::move(entry.record);
  return true;
}

bool readFile(const std::string &path, std::vector<uint8_t> &bytes,
              std::size_t max_bytes =
                  kMaxCheckpointPayloadBytes + kCheckpointEnvelopeBytes) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error || size > max_bytes)
    return false;
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (!file)
    return false;
  bytes.resize(static_cast<std::size_t>(size));
  const std::size_t read =
      bytes.empty() ? 0 : std::fread(bytes.data(), 1, bytes.size(), file);
  const bool ok = read == bytes.size() && std::ferror(file) == 0;
  std::fclose(file);
  return ok;
}

std::FILE *openPersistenceFile(const std::string &path, bool append) {
#ifdef _WIN32
  return std::fopen(path.c_str(), append ? "ab" : "wb");
#else
  const int flags = O_WRONLY | O_CREAT | O_CLOEXEC |
                    (append ? O_APPEND : O_TRUNC);
  const int descriptor =
      ::open(path.c_str(), flags,
             S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (descriptor < 0)
    return nullptr;
  std::FILE *file = fdopen(descriptor, append ? "ab" : "wb");
  if (file)
    return file;
  const int error_number = errno;
  ::close(descriptor);
  errno = error_number;
  return nullptr;
#endif
}

bool flushFile(std::FILE *file) {
#ifdef STATISTICS_V2_TESTING
  if (g_test_write_fault == TestWriteFault::FlushFailure) {
    errno = EIO;
    return false;
  }
#endif
  if (std::fflush(file) != 0)
    return false;
#ifdef _WIN32
  const int descriptor = _fileno(file);
  if (descriptor < 0)
    return false;
  const intptr_t handle = _get_osfhandle(descriptor);
  return handle != -1 &&
         FlushFileBuffers(reinterpret_cast<HANDLE>(handle)) != FALSE;
#else
  const int descriptor = fileno(file);
  return descriptor >= 0 && fsync(descriptor) == 0;
#endif
}

bool writeAll(std::FILE *file, const uint8_t *data, std::size_t size) {
#ifdef STATISTICS_V2_TESTING
  if (g_test_write_fault == TestWriteFault::NoSpace) {
    errno = ENOSPC;
    return false;
  }
  if (g_test_write_fault == TestWriteFault::ShortWrite) {
    const std::size_t partial = size > 1 ? size / 2 : 0;
    if (partial != 0)
      std::fwrite(data, 1, partial, file);
    errno = EIO;
    return false;
  }
#endif
  std::size_t written = 0;
  while (written < size) {
    const std::size_t count =
        std::fwrite(data + written, 1, size - written, file);
    if (count == 0)
      return false;
    written += count;
  }
  return true;
}

std::vector<uint8_t> checkpointBytes(const PersistentImage &image,
                                     uint64_t generation, uint64_t sequence) {
  Encoder encoder;
  encoder.raw(kCheckpointMagic.data(), kCheckpointMagic.size());
  encoder.u32(kSchemaVersion);
  encoder.u64(generation);
  encoder.u64(sequence);
  const std::size_t payload_size_offset = encoder.size();
  encoder.u64(0);
  const std::size_t payload_offset = encoder.size();
  encodeImagePayload(encoder, image);
  const std::size_t payload_size = encoder.size() - payload_offset;
  if (payload_size > kMaxCheckpointPayloadBytes)
    return {};
  encoder.patchU64(payload_size_offset, payload_size);
  const uint64_t value = checksum(encoder.bytes().data(), encoder.bytes().size());
  encoder.u64(value);
  return encoder.take();
}

bool decodeCheckpoint(const std::vector<uint8_t> &bytes,
                      StoreLoadResult &result) {
  constexpr std::size_t minimum = 8 + 4 + 8 + 8 + 8 + 8;
  if (bytes.size() < minimum)
    return false;
  Decoder decoder(bytes.data(), bytes.size());
  std::array<uint8_t, 8> magic{};
  uint32_t schema = 0;
  uint64_t payload_size = 0;
  if (!decoder.raw(magic.data(), magic.size()) || magic != kCheckpointMagic ||
      !decoder.u32(schema) || schema != kSchemaVersion ||
      !decoder.u64(result.generation) || !decoder.u64(result.sequence) ||
      result.generation == 0 ||
      !decoder.u64(payload_size) ||
      payload_size > kMaxCheckpointPayloadBytes ||
      payload_size > kMaxPayloadBytes ||
      payload_size > decoder.remaining() - 8)
    return false;
  const uint8_t *payload = decoder.current();
  if (!decoder.skip(static_cast<std::size_t>(payload_size)))
    return false;
  uint64_t stored_checksum = 0;
  if (!decoder.u64(stored_checksum) || decoder.remaining() != 0)
    return false;
  const uint64_t actual_checksum =
      checksum(bytes.data(), bytes.size() - sizeof(uint64_t));
  if (stored_checksum != actual_checksum)
    return false;
  result.image = PersistentImage{};
  if (!decodeImagePayload(payload, static_cast<std::size_t>(payload_size),
                          result.image))
    return false;
  result.has_image = true;
  return true;
}

std::vector<uint8_t> walRecordBytes(const DirtyPatch &patch,
                                    uint64_t generation, uint64_t sequence) {
  Encoder encoder;
  encoder.raw(kWalMagic.data(), kWalMagic.size());
  encoder.u32(kWalPatchType);
  encoder.u64(generation);
  encoder.u64(sequence);
  const std::size_t payload_size_offset = encoder.size();
  encoder.u32(0);
  const std::size_t payload_offset = encoder.size();
  encodePatchPayload(encoder, patch);
  const std::size_t payload_size = encoder.size() - payload_offset;
  if (payload_size > kMaxWalPayloadBytes ||
      payload_size > std::numeric_limits<uint32_t>::max())
    return {};
  encoder.patchU32(payload_size_offset,
                   static_cast<uint32_t>(payload_size));
  const uint64_t value = checksum(encoder.bytes().data(), encoder.bytes().size());
  encoder.u64(value);
  return encoder.take();
}

} // namespace

GeoId countryGeoId(const std::string &value) {
  std::size_t begin = 0, end = 0;
  if (!trimmedBounds(value, begin, end) || end - begin != 2)
    return static_cast<GeoId>('Z' - 'A') * 26 + ('Z' - 'A');
  const char first = upperAscii(value[begin]);
  const char second = upperAscii(value[begin + 1]);
  if (first == 'T' && second == '1')
    return static_cast<GeoId>(26 * 26);
  if (first < 'A' || first > 'Z' || second < 'A' || second > 'Z')
    return static_cast<GeoId>('Z' - 'A') * 26 + ('Z' - 'A');
  return static_cast<GeoId>(first - 'A') * 26 +
         static_cast<GeoId>(second - 'A');
}

GeoId chinaRegionGeoId(const std::string &value) {
  std::size_t begin = 0, end = 0;
  if (!trimmedBounds(value, begin, end))
    return kInvalidGeoId;
  if (end - begin == 5 && upperAscii(value[begin]) == 'C' &&
      upperAscii(value[begin + 1]) == 'N' &&
      (value[begin + 2] == '-' || value[begin + 2] == '_'))
    begin += 3;
  if (end - begin != 2)
    return kInvalidGeoId;
  const char first = upperAscii(value[begin]);
  const char second = upperAscii(value[begin + 1]);
  if (first < 'A' || first > 'Z' || second < 'A' || second > 'Z')
    return kInvalidGeoId;
  const int16_t index =
      regionLookup()[static_cast<std::size_t>(first - 'A') * 26 +
                     static_cast<std::size_t>(second - 'A')];
  return index < 0 ? kInvalidGeoId
                   : static_cast<GeoId>(kCountryCount + index);
}

bool isCountryGeoId(GeoId id) { return id < kCountryCount; }

bool isChinaRegionGeoId(GeoId id) {
  return id >= kCountryCount && id < kGeoCount;
}

std::string geoCode(GeoId id) {
  if (id < 26 * 26) {
    std::string result(2, 'A');
    result[0] = static_cast<char>('A' + id / 26);
    result[1] = static_cast<char>('A' + id % 26);
    return result;
  }
  if (id == 26 * 26)
    return "T1";
  if (isChinaRegionGeoId(id))
    return "CN-" +
           std::string(kChinaRegionSuffixes[id - kCountryCount]);
  return "";
}

Core::Core() : minutes_(kMinuteBucketCount), days_(kDailyBucketCount) {}

void Core::resetTransient() {
  startup_ = Counters{};
  clearCounters(startup_geo_);
  for (Aggregate &aggregate : minute_windows_) {
    aggregate.counters = Counters{};
    clearCounters(aggregate.geo);
  }
  for (Aggregate &aggregate : daily_windows_) {
    aggregate.counters = Counters{};
    clearCounters(aggregate.geo);
  }
  hours_.fill(HourBucket{});
  dirty_minutes_.reset();
  dirty_days_.reset();
  dirty_lifetime_geo_.reset();
  runtime_dirty_ = false;
  dirty_version_ = 0;
}

void Core::startEmpty(int64_t now_seconds) {
  runtime_ = RuntimeState{};
  runtime_.first_started_at = now_seconds;
  runtime_.last_seen_at = now_seconds;
  runtime_.last_stopped_at = 0;
  runtime_.launch_count = 1;
  started_at_ = now_seconds;
  lifetime_ = Counters{};
  clearCounters(lifetime_geo_);
  std::fill(minutes_.begin(), minutes_.end(), BucketRecord{});
  std::fill(days_.begin(), days_.end(), BucketRecord{});
  current_minute_ = DenseBucket{};
  current_minute_.stamp = now_seconds / 60;
  current_day_ = DenseBucket{};
  current_day_.stamp = now_seconds / (24 * 60 * 60);
  resetTransient();
  runtime_dirty_ = true;
  dirty_version_ = 1;
  revision_ = 1;
}

void Core::activateLatestBuckets(const PersistentImage &image) {
  minutes_ = image.minutes;
  days_ = image.days;
  int64_t latest_minute = 0;
  std::size_t latest_minute_index = 0;
  for (std::size_t i = 0; i < minutes_.size(); ++i) {
    if (!minutes_[i].empty() && minutes_[i].stamp > latest_minute) {
      latest_minute = minutes_[i].stamp;
      latest_minute_index = i;
    }
  }
  if (latest_minute > 0) {
    current_minute_.stamp = latest_minute;
    current_minute_.counters = minutes_[latest_minute_index].counters;
    clearCounters(current_minute_.geo);
    for (const GeoCounters &entry : minutes_[latest_minute_index].geo)
      if (entry.id < kGeoCount)
        current_minute_.geo[entry.id] = entry.counters;
    minutes_[latest_minute_index] = BucketRecord{};
  }

  int64_t latest_day = 0;
  std::size_t latest_day_index = 0;
  for (std::size_t i = 0; i < days_.size(); ++i) {
    if (!days_[i].empty() && days_[i].stamp > latest_day) {
      latest_day = days_[i].stamp;
      latest_day_index = i;
    }
  }
  if (latest_day > 0) {
    current_day_.stamp = latest_day;
    current_day_.counters = days_[latest_day_index].counters;
    clearCounters(current_day_.geo);
    for (const GeoCounters &entry : days_[latest_day_index].geo)
      if (entry.id < kGeoCount)
        current_day_.geo[entry.id] = entry.counters;
    days_[latest_day_index] = BucketRecord{};
  }
}

void Core::startFromImage(const PersistentImage &image, int64_t now_seconds) {
  runtime_ = image.runtime;
  if (runtime_.first_started_at <= 0)
    runtime_.first_started_at = now_seconds;
  runtime_.last_seen_at = now_seconds;
  runtime_.last_stopped_at = 0;
  runtime_.launch_count =
      saturatedAddValue(runtime_.launch_count, static_cast<uint64_t>(1));
  started_at_ = now_seconds;
  lifetime_ = image.lifetime;
  lifetime_geo_ = image.lifetime_geo;
  current_minute_ = DenseBucket{};
  current_day_ = DenseBucket{};
  resetTransient();
  activateLatestBuckets(image);
  if (current_minute_.stamp <= 0)
    current_minute_.stamp = now_seconds / 60;
  if (current_day_.stamp <= 0)
    current_day_.stamp = now_seconds / (24 * 60 * 60);
  advanceTo(now_seconds);
  rebuildAggregates(now_seconds);
  runtime_dirty_ = true;
  dirty_version_ = std::max<uint64_t>(dirty_version_, 1);
  revision_ = 1;
}

void Core::rebuildAggregates(int64_t now_seconds) {
  for (Aggregate &aggregate : minute_windows_) {
    aggregate.counters = Counters{};
    clearCounters(aggregate.geo);
  }
  for (Aggregate &aggregate : daily_windows_) {
    aggregate.counters = Counters{};
    clearCounters(aggregate.geo);
  }
  hours_.fill(HourBucket{});
  const int64_t now_minute = now_seconds / 60;
  const int64_t now_day = now_seconds / (24 * 60 * 60);
  auto include_minute = [&](const BucketRecord &record) {
    if (record.empty() || record.stamp > now_minute)
      return;
    for (std::size_t i = 0; i < kMinuteWindowSizes.size(); ++i)
      if (record.stamp >= now_minute - kMinuteWindowSizes[i] + 1)
        addBucket(minute_windows_[i], record);
    const int64_t hour = record.stamp / 60;
    if (hour >= now_minute / 60 - 23 && hour <= now_minute / 60) {
      HourBucket &slot = hours_[static_cast<std::size_t>(hour % 24)];
      if (slot.hour != hour)
        slot = {hour, Counters{}};
      add(slot.counters, record.counters);
    }
  };
  for (const BucketRecord &record : minutes_)
    include_minute(record);
  BucketRecord active_minute;
  active_minute.stamp = current_minute_.stamp;
  active_minute.counters = current_minute_.counters;
  denseToSparse(current_minute_.geo, active_minute.geo);
  include_minute(active_minute);

  auto include_day = [&](const BucketRecord &record) {
    if (record.empty() || record.stamp > now_day)
      return;
    for (std::size_t i = 0; i < kDailyWindowSizes.size(); ++i)
      if (record.stamp >= now_day - kDailyWindowSizes[i] + 1)
        addBucket(daily_windows_[i], record);
  };
  for (const BucketRecord &record : days_)
    include_day(record);
  BucketRecord active_day;
  active_day.stamp = current_day_.stamp;
  active_day.counters = current_day_.counters;
  denseToSparse(current_day_.geo, active_day.geo);
  include_day(active_day);
}

BucketRecord Core::minuteRecord(std::size_t index) const {
  if (current_minute_.stamp > 0 &&
      static_cast<std::size_t>(current_minute_.stamp %
                               static_cast<int64_t>(kMinuteBucketCount)) ==
          index) {
    BucketRecord result;
    result.stamp = current_minute_.stamp;
    result.counters = current_minute_.counters;
    denseToSparse(current_minute_.geo, result.geo);
    if (result.empty())
      result.stamp = 0;
    return result;
  }
  return minutes_[index];
}

BucketRecord Core::dayRecord(std::size_t index) const {
  if (current_day_.stamp > 0 &&
      static_cast<std::size_t>(
          current_day_.stamp % static_cast<int64_t>(kDailyBucketCount)) ==
          index) {
    BucketRecord result;
    result.stamp = current_day_.stamp;
    result.counters = current_day_.counters;
    denseToSparse(current_day_.geo, result.geo);
    if (result.empty())
      result.stamp = 0;
    return result;
  }
  return days_[index];
}

void Core::sealMinute() {
  if (current_minute_.stamp <= 0)
    return;
  const std::size_t index = static_cast<std::size_t>(
      current_minute_.stamp % static_cast<int64_t>(kMinuteBucketCount));
  BucketRecord record;
  record.stamp = current_minute_.stamp;
  record.counters = current_minute_.counters;
  denseToSparse(current_minute_.geo, record.geo);
  if (record.empty())
    record.stamp = 0;
  minutes_[index] = std::move(record);
  dirty_minutes_.set(index);
}

void Core::sealDay() {
  if (current_day_.stamp <= 0)
    return;
  const std::size_t index = static_cast<std::size_t>(
      current_day_.stamp % static_cast<int64_t>(kDailyBucketCount));
  BucketRecord record;
  record.stamp = current_day_.stamp;
  record.counters = current_day_.counters;
  denseToSparse(current_day_.geo, record.geo);
  if (record.empty())
    record.stamp = 0;
  days_[index] = std::move(record);
  dirty_days_.set(index);
}

void Core::advanceMinutes(int64_t target_minute) {
  if (target_minute <= current_minute_.stamp)
    return;
  const int64_t delta = target_minute - current_minute_.stamp;
  if (delta >= static_cast<int64_t>(kMinuteBucketCount)) {
    std::fill(minutes_.begin(), minutes_.end(), BucketRecord{});
    for (Aggregate &aggregate : minute_windows_) {
      aggregate.counters = Counters{};
      clearCounters(aggregate.geo);
    }
    hours_.fill(HourBucket{});
    current_minute_ = DenseBucket{};
    current_minute_.stamp = target_minute;
    dirty_minutes_.set();
    return;
  }

  while (current_minute_.stamp < target_minute) {
    const int64_t next = current_minute_.stamp + 1;
    for (std::size_t i = 0; i < kMinuteWindowSizes.size(); ++i) {
      const int64_t expired = next - kMinuteWindowSizes[i];
      const BucketRecord &record =
          minutes_[static_cast<std::size_t>(
              expired % static_cast<int64_t>(kMinuteBucketCount))];
      if (record.stamp == expired)
        subtractBucket(minute_windows_[i], record);
    }
    sealMinute();
    current_minute_ = DenseBucket{};
    current_minute_.stamp = next;
    dirty_minutes_.set(static_cast<std::size_t>(
        next % static_cast<int64_t>(kMinuteBucketCount)));
    advanceHours(next / 60);
  }
}

void Core::advanceDays(int64_t target_day) {
  if (target_day <= current_day_.stamp)
    return;
  const int64_t delta = target_day - current_day_.stamp;
  if (delta >= static_cast<int64_t>(kDailyBucketCount)) {
    std::fill(days_.begin(), days_.end(), BucketRecord{});
    for (Aggregate &aggregate : daily_windows_) {
      aggregate.counters = Counters{};
      clearCounters(aggregate.geo);
    }
    current_day_ = DenseBucket{};
    current_day_.stamp = target_day;
    dirty_days_.set();
    return;
  }

  while (current_day_.stamp < target_day) {
    const int64_t next = current_day_.stamp + 1;
    for (std::size_t i = 0; i < kDailyWindowSizes.size(); ++i) {
      const int64_t expired = next - kDailyWindowSizes[i];
      const BucketRecord &record =
          days_[static_cast<std::size_t>(
              expired % static_cast<int64_t>(kDailyBucketCount))];
      if (record.stamp == expired)
        subtractBucket(daily_windows_[i], record);
    }
    sealDay();
    current_day_ = DenseBucket{};
    current_day_.stamp = next;
    dirty_days_.set(static_cast<std::size_t>(
        next % static_cast<int64_t>(kDailyBucketCount)));
  }
}

void Core::advanceHours(int64_t target_hour) {
  HourBucket &slot =
      hours_[static_cast<std::size_t>(target_hour % static_cast<int64_t>(24))];
  if (slot.hour != target_hour)
    slot = {target_hour, Counters{}};
}

void Core::advanceTo(int64_t now_seconds) {
  const int64_t target_minute = now_seconds / 60;
  const int64_t target_day = now_seconds / (24 * 60 * 60);
  const bool moved = target_minute > current_minute_.stamp ||
                     target_day > current_day_.stamp;
  advanceMinutes(target_minute);
  advanceDays(target_day);
  advanceHours(std::max(target_minute, current_minute_.stamp) / 60);
  if (moved) {
    bumpRevision();
    dirty_version_ =
        saturatedAddValue(dirty_version_, static_cast<uint64_t>(1));
  }
}

void Core::bumpRevision() {
  revision_ = saturatedAddValue(revision_, static_cast<uint64_t>(1));
}

void Core::record(int64_t now_seconds, GeoId country, GeoId china_region,
                  uint64_t rule_conversions) {
  advanceTo(now_seconds);
  if (!isCountryGeoId(country))
    country = countryGeoId("ZZ");
  if (!isChinaRegionGeoId(china_region))
    china_region = kInvalidGeoId;

  add(startup_, 1, rule_conversions);
  add(lifetime_, 1, rule_conversions);
  add(current_minute_.counters, 1, rule_conversions);
  add(current_day_.counters, 1, rule_conversions);
  for (Aggregate &aggregate : minute_windows_)
    add(aggregate.counters, 1, rule_conversions);
  for (Aggregate &aggregate : daily_windows_)
    add(aggregate.counters, 1, rule_conversions);
  HourBucket &hour = hours_[static_cast<std::size_t>(
      (current_minute_.stamp / 60) % static_cast<int64_t>(24))];
  if (hour.hour != current_minute_.stamp / 60)
    hour = {current_minute_.stamp / 60, Counters{}};
  add(hour.counters, 1, rule_conversions);

  const std::array<GeoId, 2> ids = {country, china_region};
  for (GeoId id : ids) {
    if (id == kInvalidGeoId)
      continue;
    add(startup_geo_[id], 1, rule_conversions);
    add(lifetime_geo_[id], 1, rule_conversions);
    add(current_minute_.geo[id], 1, rule_conversions);
    add(current_day_.geo[id], 1, rule_conversions);
    for (Aggregate &aggregate : minute_windows_)
      add(aggregate.geo[id], 1, rule_conversions);
    for (Aggregate &aggregate : daily_windows_)
      add(aggregate.geo[id], 1, rule_conversions);
    dirty_lifetime_geo_.set(id);
  }

  dirty_minutes_.set(static_cast<std::size_t>(
      current_minute_.stamp % static_cast<int64_t>(kMinuteBucketCount)));
  dirty_days_.set(static_cast<std::size_t>(
      current_day_.stamp % static_cast<int64_t>(kDailyBucketCount)));
  runtime_dirty_ = true;
  dirty_version_ =
      saturatedAddValue(dirty_version_, static_cast<uint64_t>(1));
  bumpRevision();
}

DashboardSnapshot Core::dashboardSnapshot(int64_t now_seconds) {
  advanceTo(now_seconds);
  DashboardSnapshot snapshot;
  snapshot.revision = revision_;
  snapshot.generated_at = now_seconds;
  snapshot.started_at = started_at_;
  snapshot.runtime = runtime_;
  snapshot.uptime_seconds =
      now_seconds > started_at_ ? now_seconds - started_at_ : 0;
  snapshot.total_runtime_seconds =
      saturatedRuntime(runtime_.persisted_runtime_seconds,
                       snapshot.uptime_seconds);
  snapshot.startup.counters = startup_;
  snapshot.startup.geo = startup_geo_;
  for (std::size_t i = 0; i < minute_windows_.size(); ++i) {
    snapshot.minute_windows[i].counters = minute_windows_[i].counters;
    snapshot.minute_windows[i].geo = minute_windows_[i].geo;
  }
  for (std::size_t i = 0; i < daily_windows_.size(); ++i) {
    snapshot.daily_windows[i].counters = daily_windows_[i].counters;
    snapshot.daily_windows[i].geo = daily_windows_[i].geo;
  }
  snapshot.lifetime.counters = lifetime_;
  snapshot.lifetime.geo = lifetime_geo_;
  const int64_t current_hour = current_minute_.stamp / 60;
  for (std::size_t i = 0; i < snapshot.series.size(); ++i) {
    const int64_t hour =
        current_hour - 23 + static_cast<int64_t>(i);
    snapshot.series[i].time = hour * 3600;
    const HourBucket &slot = hours_[static_cast<std::size_t>(
        hour % static_cast<int64_t>(hours_.size()))];
    if (slot.hour == hour)
      snapshot.series[i].counters = slot.counters;
  }
  return snapshot;
}

bool Core::hasDirty() const {
  return runtime_dirty_ || dirty_minutes_.any() || dirty_days_.any() ||
         dirty_lifetime_geo_.any();
}

DirtyPatch Core::takeDirtyPatch(int64_t now_seconds, bool stopping) {
  DirtyPatch patch = runtimePatch(now_seconds, stopping);
  patch.metadata_present = true;
  for (std::size_t i = 0; i < kGeoCount; ++i) {
    if (dirty_lifetime_geo_.test(i))
      patch.lifetime_geo.push_back(
          {static_cast<GeoId>(i), lifetime_geo_[i]});
  }
  for (std::size_t i = 0; i < kMinuteBucketCount; ++i) {
    if (dirty_minutes_.test(i))
      patch.minutes.push_back(
          {static_cast<uint32_t>(i), minuteRecord(i)});
  }
  for (std::size_t i = 0; i < kDailyBucketCount; ++i) {
    if (dirty_days_.test(i))
      patch.days.push_back({static_cast<uint32_t>(i), dayRecord(i)});
  }
  dirty_lifetime_geo_.reset();
  dirty_minutes_.reset();
  dirty_days_.reset();
  runtime_dirty_ = false;
  return patch;
}

DirtyPatch Core::runtimePatch(int64_t now_seconds, bool stopping) {
  DirtyPatch patch;
  patch.metadata_present = true;
  runtime_.last_seen_at = now_seconds;
  if (stopping)
    runtime_.last_stopped_at = now_seconds;
  patch.runtime = runtime_;
  const int64_t uptime =
      now_seconds > started_at_ ? now_seconds - started_at_ : 0;
  patch.runtime.persisted_runtime_seconds =
      saturatedRuntime(runtime_.persisted_runtime_seconds, uptime);
  patch.lifetime = lifetime_;
  return patch;
}

PersistentImage Core::persistentImage(int64_t now_seconds,
                                      bool stopping) const {
  PersistentImage image;
  image.runtime = runtime_;
  const int64_t uptime =
      now_seconds > started_at_ ? now_seconds - started_at_ : 0;
  image.runtime.persisted_runtime_seconds =
      saturatedRuntime(runtime_.persisted_runtime_seconds, uptime);
  image.runtime.last_seen_at = now_seconds;
  if (stopping)
    image.runtime.last_stopped_at = now_seconds;
  image.lifetime = lifetime_;
  image.lifetime_geo = lifetime_geo_;
  image.minutes = minutes_;
  image.days = days_;
  if (current_minute_.stamp > 0) {
    const std::size_t index = static_cast<std::size_t>(
        current_minute_.stamp % static_cast<int64_t>(kMinuteBucketCount));
    image.minutes[index] = minuteRecord(index);
  }
  if (current_day_.stamp > 0) {
    const std::size_t index = static_cast<std::size_t>(
        current_day_.stamp % static_cast<int64_t>(kDailyBucketCount));
    image.days[index] = dayRecord(index);
  }
  return image;
}

PersistentImage Core::checkpointImage(int64_t now_seconds, bool stopping,
                                      uint64_t &dirty_version) const {
  dirty_version = dirty_version_;
  return persistentImage(now_seconds, stopping);
}

void Core::acknowledgeCheckpoint(uint64_t dirty_version) {
  if (dirty_version != dirty_version_)
    return;
  dirty_lifetime_geo_.reset();
  dirty_minutes_.reset();
  dirty_days_.reset();
  runtime_dirty_ = false;
}

int runtimeHeartbeatIntervalSeconds(int flush_interval_seconds) {
  return std::max(60, std::max(1, flush_interval_seconds));
}

class Store::FileLock {
public:
  FileLock() = default;
  ~FileLock() { close(); }

  FileLock(const FileLock &) = delete;
  FileLock &operator=(const FileLock &) = delete;

  bool open(const std::string &path) {
    close();
#ifdef _WIN32
    handle_ = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                          nullptr, OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                          nullptr);
    return handle_ != INVALID_HANDLE_VALUE;
#else
    descriptor_ =
        ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC,
               S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (descriptor_ < 0)
      return false;
    if (flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
      ::close(descriptor_);
      descriptor_ = -1;
      return false;
    }
    return true;
#endif
  }

  void close() {
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (descriptor_ >= 0) {
      flock(descriptor_, LOCK_UN);
      ::close(descriptor_);
      descriptor_ = -1;
    }
#endif
  }

private:
#ifdef _WIN32
  HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
  int descriptor_ = -1;
#endif
};

Store::Store(std::string directory)
    : directory_(std::move(directory)),
      last_checkpoint_(std::chrono::steady_clock::now()) {
  if (directory_.empty())
    directory_ = "stats";
}

Store::~Store() { close(); }

std::string Store::path(const char *name) const {
  return (std::filesystem::path(directory_) / name).string();
}

void Store::setError(const std::string &message) { last_error_ = message; }

StoreStatus Store::open() {
  close();
  std::error_code error;
  std::filesystem::create_directories(directory_, error);
  if (error) {
    setError("cannot create statistics directory: " + error.message());
    return StoreStatus::DirectoryUnavailable;
  }
  const auto status = std::filesystem::symlink_status(directory_, error);
  if (error || !std::filesystem::is_directory(status)) {
    setError("statistics path is not a directory");
    return StoreStatus::DirectoryUnavailable;
  }
  lock_.reset(new FileLock());
  if (!lock_->open(path("statistics-v2.lock"))) {
    setError("statistics persistence lock is unavailable");
    lock_.reset();
    return StoreStatus::LockUnavailable;
  }
  ready_ = true;
  last_error_.clear();
  return StoreStatus::Ready;
}

void Store::close() {
  ready_ = false;
  if (lock_)
    lock_->close();
  lock_.reset();
}

bool Store::ready() const { return ready_ && lock_ != nullptr; }

bool Store::inspectCheckpoint(const std::string &path,
                              StoreLoadResult &result) {
  std::vector<uint8_t> bytes;
  return readFile(path, bytes) && decodeCheckpoint(bytes, result);
}

StoreLoadResult Store::load() {
  StoreLoadResult best;
  if (!ready())
    return best;
  StoreLoadResult first, second;
  const bool first_ok =
      inspectCheckpoint(path("statistics-v2-a.bin"), first);
  const bool second_ok =
      inspectCheckpoint(path("statistics-v2-b.bin"), second);
  if (first_ok &&
      (!second_ok || first.generation > second.generation ||
       (first.generation == second.generation &&
        first.sequence >= second.sequence)))
    best = std::move(first);
  else if (second_ok)
    best = std::move(second);

  auto oversized_checkpoint = [&](const char *name) {
    std::error_code size_error;
    const auto size = std::filesystem::file_size(path(name), size_error);
    return !size_error &&
           size > kMaxCheckpointPayloadBytes + kCheckpointEnvelopeBytes;
  };
  if (!best.has_image &&
      (oversized_checkpoint("statistics-v2-a.bin") ||
       oversized_checkpoint("statistics-v2-b.bin"))) {
    setError("statistics checkpoint exceeds the safety limit");
    close();
    return best;
  }

  generation_ = best.has_image ? best.generation : 0;
  sequence_ = best.has_image ? best.sequence : 0;
  wal_bytes_ = 0;
  wal_records_ = 0;

  std::vector<uint8_t> wal;
  const std::string wal_path = path("statistics-v2.wal");
  std::error_code error;
  if (!std::filesystem::exists(wal_path, error) || error)
    return best;
  if (!readFile(wal_path, wal, kMaxWalFileBytes)) {
    setError("statistics WAL is unreadable or exceeds the safety limit");
    close();
    return best;
  }
  wal_bytes_ = wal.size();
  Decoder decoder(wal.data(), wal.size());
  std::size_t last_valid_offset = 0;
  std::size_t valid_records = 0;
  bool invalid_suffix = false;
  while (decoder.remaining() > 0) {
    const std::size_t record_start = decoder.offset();
    std::array<uint8_t, 4> magic{};
    uint32_t type = 0;
    uint64_t generation = 0, sequence = 0;
    uint32_t payload_size = 0;
    if (!decoder.raw(magic.data(), magic.size()) || magic != kWalMagic ||
        !decoder.u32(type) || type != kWalPatchType ||
        !decoder.u64(generation) || !decoder.u64(sequence) ||
        !decoder.u32(payload_size) ||
        payload_size > kMaxWalPayloadBytes ||
        payload_size > kMaxPayloadBytes ||
        payload_size > decoder.remaining() - std::min<std::size_t>(
                                               decoder.remaining(), 8))
      {
        invalid_suffix = true;
        break;
      }
    const uint8_t *payload = decoder.current();
    if (!decoder.skip(payload_size)) {
      invalid_suffix = true;
      break;
    }
    uint64_t stored_checksum = 0;
    if (!decoder.u64(stored_checksum)) {
      invalid_suffix = true;
      break;
    }
    const std::size_t record_end_without_checksum =
        decoder.offset() - sizeof(uint64_t);
    const uint64_t actual_checksum =
        checksum(wal.data() + record_start,
                 record_end_without_checksum - record_start);
    if (stored_checksum != actual_checksum) {
      invalid_suffix = true;
      break;
    }
    if (!best.has_image)
      continue;
    if (generation != best.generation) {
      invalid_suffix = true;
      break;
    }
    if (sequence <= best.sequence) {
      PersistentImage ignored = best.image;
      if (!decodeAndApplyPatch(payload, payload_size, ignored)) {
        invalid_suffix = true;
        break;
      }
      last_valid_offset = decoder.offset();
      ++valid_records;
      continue;
    }
    if (sequence != best.sequence + 1) {
      invalid_suffix = true;
      break;
    }
    PersistentImage candidate = best.image;
    if (!decodeAndApplyPatch(payload, payload_size, candidate)) {
      invalid_suffix = true;
      break;
    }
    best.image = std::move(candidate);
    best.sequence = sequence;
    sequence_ = sequence;
    last_valid_offset = decoder.offset();
    ++valid_records;
  }
  if (best.has_image) {
    wal_records_ = valid_records;
    if (invalid_suffix || last_valid_offset < wal.size()) {
      if (!truncateWalTo(last_valid_offset, valid_records)) {
        setError("invalid statistics WAL suffix could not be truncated");
        close();
      }
    }
  }
  return best;
}

bool Store::replaceFile(const std::string &target,
                        const std::vector<uint8_t> &bytes) {
  const std::string temporary = target + ".tmp";
#ifdef STATISTICS_V2_TESTING
  std::FILE *file =
      g_test_write_fault == TestWriteFault::OpenFailure
          ? nullptr
          : openPersistenceFile(temporary, false);
  if (!file && g_test_write_fault == TestWriteFault::OpenFailure)
    errno = EACCES;
#else
  std::FILE *file = openPersistenceFile(temporary, false);
#endif
  if (!file) {
    setError("cannot open temporary persistence file");
    return false;
  }
  const bool wrote =
      writeAll(file, bytes.data(), bytes.size()) && flushFile(file);
  const bool closed = std::fclose(file) == 0;
  if (!wrote || !closed) {
    std::remove(temporary.c_str());
    setError("short or failed persistence write");
    return false;
  }
  std::vector<uint8_t> verified;
  if (!readFile(temporary, verified,
                std::max<std::size_t>(kMaxPayloadBytes + 128, bytes.size())) ||
      verified != bytes) {
    std::remove(temporary.c_str());
    setError("persistence verification failed");
    return false;
  }
#ifdef _WIN32
  if (!MoveFileExA(temporary.c_str(), target.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::remove(temporary.c_str());
    setError("cannot atomically replace persistence file");
    return false;
  }
#else
  if (std::rename(temporary.c_str(), target.c_str()) != 0) {
    std::remove(temporary.c_str());
    setError("cannot atomically replace persistence file");
    return false;
  }
  const int dir = ::open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir >= 0) {
    fsync(dir);
    ::close(dir);
  }
#endif
  return true;
}

bool Store::appendFile(const std::string &target,
                       const std::vector<uint8_t> &bytes) {
  std::error_code size_error;
  const auto existing_size = std::filesystem::file_size(target, size_error);
  const std::uintmax_t rollback_size = size_error ? 0 : existing_size;
  if (!size_error &&
      (existing_size > kMaxWalFileBytes ||
       bytes.size() > kMaxWalFileBytes - existing_size)) {
    setError("statistics WAL exceeds the safety limit");
    return false;
  }
#ifdef STATISTICS_V2_TESTING
  std::FILE *file =
      g_test_write_fault == TestWriteFault::OpenFailure
          ? nullptr
          : openPersistenceFile(target, true);
  if (!file && g_test_write_fault == TestWriteFault::OpenFailure)
    errno = EACCES;
#else
  std::FILE *file = openPersistenceFile(target, true);
#endif
  if (!file) {
    setError("cannot open statistics WAL");
    return false;
  }
  const bool wrote =
      writeAll(file, bytes.data(), bytes.size()) && flushFile(file);
  const bool closed = std::fclose(file) == 0;
  if (!wrote || !closed) {
    std::error_code rollback_error;
    std::filesystem::resize_file(target, rollback_size, rollback_error);
    if (rollback_error) {
      setError("failed WAL write could not be rolled back");
      return false;
    }
    setError("short or failed WAL write");
    return false;
  }
  return true;
}

bool Store::truncateWal() {
  return truncateWalTo(0, 0);
}

bool Store::truncateWalTo(std::size_t size, std::size_t records) {
#ifdef STATISTICS_V2_TESTING
  if (g_test_write_fault == TestWriteFault::TruncateFailure) {
    errno = EIO;
    setError("injected statistics WAL truncation failure");
    return false;
  }
#endif
  const std::string wal_path = path("statistics-v2.wal");
#ifdef _WIN32
  HANDLE file = CreateFileA(wal_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                            nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    setError("cannot open statistics WAL for truncation");
    return false;
  }
  LARGE_INTEGER offset;
  offset.QuadPart = static_cast<LONGLONG>(size);
  const bool ok =
      SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) != FALSE &&
      SetEndOfFile(file) != FALSE && FlushFileBuffers(file) != FALSE;
  CloseHandle(file);
  if (!ok) {
    setError("statistics WAL truncation could not be flushed");
    return false;
  }
  HANDLE directory = CreateFileA(
      directory_.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (directory != INVALID_HANDLE_VALUE) {
    FlushFileBuffers(directory);
    CloseHandle(directory);
  }
#else
  const int file =
      ::open(wal_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC,
             S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (file < 0) {
    setError("cannot open statistics WAL for truncation");
    return false;
  }
  const bool ok =
      ftruncate(file, static_cast<off_t>(size)) == 0 && fsync(file) == 0;
  ::close(file);
  if (!ok) {
    setError("statistics WAL truncation could not be flushed");
    return false;
  }
  const int directory =
      ::open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (directory < 0 || fsync(directory) != 0) {
    if (directory >= 0)
      ::close(directory);
    setError("statistics WAL directory metadata could not be flushed");
    return false;
  }
  ::close(directory);
#endif
  wal_bytes_ = size;
  wal_records_ = records;
  return true;
}

bool Store::appendPatch(const DirtyPatch &patch) {
  if (!ready() || generation_ == 0) {
    setError("statistics store has no active checkpoint generation");
    return false;
  }
  const uint64_t next =
      sequence_ == std::numeric_limits<uint64_t>::max() ? sequence_
                                                        : sequence_ + 1;
  if (next == sequence_) {
    setError("statistics WAL sequence exhausted");
    return false;
  }
  const std::vector<uint8_t> record =
      walRecordBytes(patch, generation_, next);
  if (record.empty()) {
    setError("statistics WAL patch exceeds the safety limit");
    return false;
  }
  if (record.size() > kMaxWalFileBytes ||
      wal_bytes_ > kMaxWalFileBytes - record.size() ||
      !appendFile(path("statistics-v2.wal"), record))
    return false;
  sequence_ = next;
  wal_bytes_ += record.size();
  ++wal_records_;
  return true;
}

bool Store::writeCheckpoint(const PersistentImage &image) {
  if (!ready())
    return false;
  const uint64_t next_generation =
      generation_ == std::numeric_limits<uint64_t>::max()
          ? generation_
          : generation_ + 1;
  if (next_generation == generation_) {
    setError("statistics checkpoint generation exhausted");
    return false;
  }
  const std::vector<uint8_t> bytes =
      checkpointBytes(image, next_generation, sequence_);
  if (bytes.empty()) {
    setError("statistics checkpoint exceeds the safety limit");
    return false;
  }
  const char *name =
      next_generation % 2 == 1 ? "statistics-v2-a.bin"
                               : "statistics-v2-b.bin";
  const std::string target = path(name);
  if (!replaceFile(target, bytes))
    return false;
  StoreLoadResult verified;
  if (!inspectCheckpoint(target, verified) ||
      verified.generation != next_generation ||
      verified.sequence != sequence_) {
    setError("new statistics checkpoint did not validate");
    return false;
  }
  generation_ = next_generation;
  if (!truncateWal())
    return false;
  last_checkpoint_ = std::chrono::steady_clock::now();
  return true;
}

bool Store::ensureInitialCheckpoint(const PersistentImage &image) {
  if (generation_ != 0)
    return true;
  return writeCheckpoint(image);
}

bool Store::compactIfNeeded(const PersistentImage &image) {
  if (!needsCompaction())
    return true;
  return writeCheckpoint(image);
}

bool Store::needsCompaction() const {
  return wal_bytes_ >= kWalCompactBytes ||
         wal_records_ >= kWalCompactRecords ||
         std::chrono::steady_clock::now() - last_checkpoint_ >=
             kCheckpointPeriod;
}

bool Store::cleanupLegacyFile() {
  if (legacy_cleanup_attempted_)
    return true;
  legacy_cleanup_attempted_ = true;
  if (generation_ == 0)
    return false;
  const std::filesystem::path legacy =
      std::filesystem::path(directory_) / "statistics.json";
  std::error_code error;
  const auto status = std::filesystem::symlink_status(legacy, error);
  if (error || status.type() == std::filesystem::file_type::not_found)
    return true;
  if (!std::filesystem::is_regular_file(status))
    return true;
  const std::filesystem::path obsolete =
      std::filesystem::path(directory_) / "statistics.json.obsolete";
  std::filesystem::rename(legacy, obsolete, error);
  if (!error) {
    std::filesystem::remove(obsolete, error);
    return !error;
  }
  error.clear();
  std::filesystem::remove(legacy, error);
  if (error) {
    setError("legacy statistics.json could not be removed");
    return false;
  }
  return true;
}

#ifdef STATISTICS_V2_TESTING
void setTestWriteFault(TestWriteFault fault) {
  g_test_write_fault = fault;
}
#endif

} // namespace statistics_v2
