#include <atomic>
#include <cassert>
#include <string>
#include <thread>
#include <vector>

#include "handler/settings.h"
#include "handler/settings_view.h"

Settings global;

namespace {

Settings generation(unsigned long long id) {
  Settings value;
  value.configGeneration = id;
  value.defaultUrls = "generation-" + std::to_string(id);
  value.cacheConfig = static_cast<int>(id);
  value.securityProfile = id % 2 ? "lan" : "strict";
  return value;
}

void requireConsistent(const Settings &value) {
  const auto id = value.configGeneration;
  assert(value.defaultUrls == "generation-" + std::to_string(id));
  assert(value.cacheConfig == static_cast<int>(id));
  assert(value.securityProfile == (id % 2 ? "lan" : "strict"));
}

} // namespace

int main() {
  Settings first = generation(1);
  Settings second = generation(2);
  publishSettingsSnapshot(first);

  SettingsSnapshot retained = captureSettingsSnapshot();
  publishSettingsSnapshot(second);
  requireConsistent(*retained);
  assert(retained->configGeneration == 1);
  assert(captureSettingsSnapshot()->configGeneration == 2);

  {
    ScopedSettingsView request(retained);
    assert(&effectiveSettings() == retained.get());
    assert(captureEffectiveSettingsSnapshot().get() == retained.get());
    publishSettingsSnapshot(first);
    assert(effectiveSettings().configGeneration == 1);
  }
  assert(captureSettingsSnapshot()->configGeneration == 1);

  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  std::atomic<unsigned int> failures{0};
  std::vector<std::thread> readers;
  for (int index = 0; index < 8; ++index) {
    readers.emplace_back([&] {
      while (!start.load(std::memory_order_acquire))
        std::this_thread::yield();
      while (!stop.load(std::memory_order_acquire)) {
        SettingsSnapshot snapshot = captureSettingsSnapshot();
        const auto id = snapshot->configGeneration;
        if (snapshot->defaultUrls != "generation-" + std::to_string(id) ||
            snapshot->cacheConfig != static_cast<int>(id) ||
            snapshot->securityProfile != (id % 2 ? "lan" : "strict")) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  start.store(true, std::memory_order_release);
  for (unsigned long long id = 3; id < 2000; ++id) {
    Settings next = generation(id);
    publishSettingsSnapshot(next);
  }
  stop.store(true, std::memory_order_release);
  for (std::thread &reader : readers)
    reader.join();

  assert(failures.load(std::memory_order_relaxed) == 0);
  requireConsistent(*captureSettingsSnapshot());
  return 0;
}
