#include "handler/statistics.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#include <nlohmann/json.hpp>

#include "handler/settings.h"
#include "utils/file.h"
#include "utils/logger.h"
#include "utils/string.h"

namespace {

using json = nlohmann::json;

constexpr size_t kBucketCount = 30 * 24 * 60;

struct Counters {
  uint64_t subscription_requests = 0;
  uint64_t rule_conversions = 0;
};

struct Bucket {
  int64_t minute = 0;
  Counters counters;
};

struct CountryCounters {
  uint64_t subscription_requests = 0;
  uint64_t rule_conversions = 0;
};

struct SnapshotCountry {
  std::string code;
  CountryCounters counters;
};

struct State {
  bool initialized = false;
  bool dirty = false;
  int64_t started_at = 0;
  int64_t last_flush = 0;
  Counters startup;
  Counters lifetime;
  std::array<Bucket, kBucketCount> buckets;
  std::map<std::string, CountryCounters> countries;
};

std::mutex g_mutex;
std::unique_ptr<State> g_state;

int64_t nowSeconds() { return static_cast<int64_t>(std::time(nullptr)); }

std::string normalizePath(std::string path) {
  for (char &ch : path) {
    if (ch == '\\')
      ch = '/';
  }
  while (path.size() > 1 && path.back() == '/')
    path.pop_back();
  return path;
}

bool pathIsSafe(const std::string &path) {
  if (path.empty())
    return false;
  if (path.find("..") != std::string::npos)
    return false;
#ifdef _WIN32
  if (path.size() > 1 && path[1] == ':')
    return false;
#else
  if (!path.empty() && path[0] == '/')
    return false;
#endif
  return true;
}

bool ensureDirectory(const std::string &raw_path) {
  std::string path = normalizePath(raw_path);
  if (!pathIsSafe(path))
    return false;

  std::string current;
  size_t pos = 0;
  while (pos <= path.size()) {
    size_t next = path.find('/', pos);
    std::string part =
        path.substr(pos, next == std::string::npos ? path.size() - pos
                                                   : next - pos);
    if (!part.empty()) {
      if (!current.empty())
        current += '/';
      current += part;
#ifdef _WIN32
      if (_mkdir(current.c_str()) != 0 && errno != EEXIST)
        return false;
#else
      if (mkdir(current.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0 &&
          errno != EEXIST)
        return false;
#endif
    }
    if (next == std::string::npos)
      break;
    pos = next + 1;
  }
  return true;
}

bool writeTextFile(const std::string &path, const std::string &content) {
  std::FILE *fp = std::fopen(path.c_str(), "wb");
  if (!fp)
    return false;
  size_t written = std::fwrite(content.c_str(), 1, content.size(), fp);
  std::fclose(fp);
  return written == content.size();
}

std::string dataFilePath() {
  std::string dir = normalizePath(global.statisticsDataDir);
  if (dir.empty())
    dir = "stats";
  return dir + "/statistics.json";
}

bool validCountryCode(const std::string &value) {
  if (value == "T1" || value == "XX")
    return true;
  if (value.size() != 2)
    return false;
  return std::isalpha(static_cast<unsigned char>(value[0])) &&
         std::isalpha(static_cast<unsigned char>(value[1]));
}

std::string normalizeCountryCode(std::string value) {
  value = toUpper(trimWhitespace(value, true, true));
  if (!validCountryCode(value))
    return "ZZ";
  return value;
}

std::string countryFromHeaders(const Request &request) {
  if (toLower(global.statisticsGeoProvider) == "none")
    return "ZZ";

  for (const std::string &header : global.statisticsCountryHeaders) {
    auto iter = request.headers.find(header);
    if (iter == request.headers.end())
      continue;
    std::string code = normalizeCountryCode(iter->second);
    if (code != "ZZ")
      return code;
  }
  return "ZZ";
}

void addCounters(Counters &target, uint64_t requests, uint64_t rules) {
  target.subscription_requests += requests;
  target.rule_conversions += rules;
}

Counters windowCountersLocked(int64_t now_minute, int minutes) {
  Counters result;
  if (!g_state)
    return result;
  int64_t earliest = now_minute - minutes + 1;
  for (const Bucket &bucket : g_state->buckets) {
    if (bucket.minute >= earliest && bucket.minute <= now_minute) {
      addCounters(result, bucket.counters.subscription_requests,
                  bucket.counters.rule_conversions);
    }
  }
  return result;
}

std::vector<Counters> hourlySeriesLocked(int64_t now_minute, int hours) {
  std::vector<Counters> result(static_cast<size_t>(hours));
  if (!g_state)
    return result;
  int64_t current_hour = now_minute / 60;
  int64_t first_hour = current_hour - hours + 1;
  for (const Bucket &bucket : g_state->buckets) {
    if (bucket.minute <= 0)
      continue;
    int64_t hour = bucket.minute / 60;
    if (hour < first_hour || hour > current_hour)
      continue;
    size_t index = static_cast<size_t>(hour - first_hour);
    addCounters(result[index], bucket.counters.subscription_requests,
                bucket.counters.rule_conversions);
  }
  return result;
}

json countersJson(const Counters &counters) {
  return json{{"subscription_requests", counters.subscription_requests},
              {"rule_conversions", counters.rule_conversions}};
}

void loadLocked() {
  std::string content = fileGet(dataFilePath(), false);
  if (content.empty())
    return;

  try {
    json root = json::parse(content);
    if (root.value("schema", 0) != 1)
      return;

    auto lifetime = root.value("lifetime", json::object());
    g_state->lifetime.subscription_requests =
        lifetime.value("subscription_requests", 0ULL);
    g_state->lifetime.rule_conversions =
        lifetime.value("rule_conversions", 0ULL);

    auto countries = root.value("countries", json::object());
    for (auto iter = countries.begin(); iter != countries.end(); ++iter) {
      std::string code = normalizeCountryCode(iter.key());
      CountryCounters counters;
      counters.subscription_requests =
          iter.value().value("subscription_requests", 0ULL);
      counters.rule_conversions = iter.value().value("rule_conversions", 0ULL);
      if (counters.subscription_requests || counters.rule_conversions)
        g_state->countries[code] = counters;
    }

    auto buckets = root.value("buckets", json::array());
    for (const auto &item : buckets) {
      int64_t minute = item.value("minute", 0LL);
      if (minute <= 0)
        continue;
      size_t index = static_cast<size_t>(minute % kBucketCount);
      g_state->buckets[index].minute = minute;
      g_state->buckets[index].counters.subscription_requests =
          item.value("subscription_requests", 0ULL);
      g_state->buckets[index].counters.rule_conversions =
          item.value("rule_conversions", 0ULL);
    }
  } catch (const std::exception &e) {
    writeLog(0, "统计数据加载失败：" + std::string(e.what()), LOG_LEVEL_WARNING);
  }
}

bool flushLocked() {
  std::string path = dataFilePath();
  std::string dir = normalizePath(global.statisticsDataDir);
  if (dir.empty())
    dir = "stats";
  if (!ensureDirectory(dir)) {
    writeLog(0, "无法创建统计数据目录：" + dir, LOG_LEVEL_WARNING);
    return false;
  }

  json root;
  root["schema"] = 1;
  root["updated_at"] = nowSeconds();
  root["lifetime"] = countersJson(g_state->lifetime);

  json countries = json::object();
  for (const auto &entry : g_state->countries) {
    countries[entry.first] = {
        {"subscription_requests", entry.second.subscription_requests},
        {"rule_conversions", entry.second.rule_conversions}};
  }
  root["countries"] = countries;

  json buckets = json::array();
  for (const Bucket &bucket : g_state->buckets) {
    if (bucket.minute <= 0)
      continue;
    if (!bucket.counters.subscription_requests &&
        !bucket.counters.rule_conversions)
      continue;
    buckets.push_back({{"minute", bucket.minute},
                       {"subscription_requests",
                        bucket.counters.subscription_requests},
                       {"rule_conversions",
                        bucket.counters.rule_conversions}});
  }
  root["buckets"] = buckets;

  std::string tmp = path + ".tmp";
  if (!writeTextFile(tmp, root.dump()))
    return false;
  std::remove(path.c_str());
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    std::remove(tmp.c_str());
    return false;
  }
  g_state->dirty = false;
  g_state->last_flush = nowSeconds();
  return true;
}

} // namespace

namespace statistics {

void initialize() {
  if (!global.statisticsEnabled)
    return;

  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_state && g_state->initialized)
    return;
  g_state.reset(new State());
  g_state->initialized = true;
  g_state->started_at = nowSeconds();
  loadLocked();
  writeLog(0, "统计数据已启用，数据目录：" + global.statisticsDataDir,
           LOG_LEVEL_INFO);
}

void shutdown() {
  if (!global.statisticsEnabled)
    return;
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_state && g_state->initialized && g_state->dirty)
    flushLocked();
}

bool isEnabled() { return global.statisticsEnabled; }

void recordSubscriptionConversion(const Request &request,
                                  uint64_t rule_conversions) {
  if (!global.statisticsEnabled || request.method != "GET")
    return;

  int64_t now = nowSeconds();
  int64_t minute = now / 60;
  std::string country = countryFromHeaders(request);

  std::lock_guard<std::mutex> lock(g_mutex);
  if (!g_state || !g_state->initialized)
    return;

  addCounters(g_state->startup, 1, rule_conversions);
  addCounters(g_state->lifetime, 1, rule_conversions);

  size_t index = static_cast<size_t>(minute % kBucketCount);
  if (g_state->buckets[index].minute != minute) {
    g_state->buckets[index].minute = minute;
    g_state->buckets[index].counters = Counters();
  }
  addCounters(g_state->buckets[index].counters, 1, rule_conversions);

  CountryCounters &country_counters = g_state->countries[country];
  country_counters.subscription_requests++;
  country_counters.rule_conversions += rule_conversions;

  g_state->dirty = true;
  int flush_interval = std::max(1, global.statisticsFlushInterval);
  if (now - g_state->last_flush >= flush_interval)
    flushLocked();
}

std::string dashboardData(RESPONSE_CALLBACK_ARGS) {
  response.headers["Cache-Control"] = "no-store";
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  response.content_type = "application/json; charset=utf-8";

  std::lock_guard<std::mutex> lock(g_mutex);
  int64_t now = nowSeconds();
  int64_t now_minute = now / 60;

  json root;
  root["enabled"] = global.statisticsEnabled;
  root["generated_at"] = now;
  root["started_at"] = g_state ? g_state->started_at : 0;
  root["windows"] = {
      {"startup", countersJson(g_state ? g_state->startup : Counters())},
      {"hour", countersJson(windowCountersLocked(now_minute, 60))},
      {"day", countersJson(windowCountersLocked(now_minute, 24 * 60))},
      {"seven_days", countersJson(windowCountersLocked(now_minute, 7 * 24 * 60))},
      {"thirty_days",
       countersJson(windowCountersLocked(now_minute, 30 * 24 * 60))},
      {"lifetime", countersJson(g_state ? g_state->lifetime : Counters())}};

  std::vector<SnapshotCountry> country_list;
  country_list.reserve(g_state ? g_state->countries.size() : 0);
  if (g_state) {
    for (const auto &entry : g_state->countries)
      country_list.push_back({entry.first, entry.second});
  }
  std::sort(country_list.begin(), country_list.end(),
            [](const SnapshotCountry &lhs, const SnapshotCountry &rhs) {
              if (lhs.counters.subscription_requests !=
                  rhs.counters.subscription_requests)
                return lhs.counters.subscription_requests >
                       rhs.counters.subscription_requests;
              return lhs.code < rhs.code;
            });

  json countries = json::array();
  for (const SnapshotCountry &country : country_list) {
    countries.push_back({{"code", country.code},
                         {"subscription_requests",
                          country.counters.subscription_requests},
                         {"rule_conversions",
                          country.counters.rule_conversions}});
  }
  root["countries"] = countries;

  json series = json::array();
  std::vector<Counters> hourly = hourlySeriesLocked(now_minute, 24);
  int64_t current_hour = now_minute / 60;
  int64_t first_hour = current_hour - 24 + 1;
  for (size_t i = 0; i < hourly.size(); ++i) {
    int64_t hour = first_hour + static_cast<int64_t>(i);
    series.push_back({{"time", hour * 3600},
                      {"subscription_requests",
                       hourly[i].subscription_requests},
                      {"rule_conversions", hourly[i].rule_conversions}});
  }
  root["series"] = series;

  return root.dump();
}

} // namespace statistics
