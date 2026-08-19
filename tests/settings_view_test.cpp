#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "handler/conversion_service.h"
#include "handler/settings.h"
#include "handler/settings_view.h"

Settings global;

namespace {

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "settings_view_test: " << message << '\n';
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition)
    fail(message);
}

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
  require(value.defaultUrls == "generation-" + std::to_string(id),
          "defaultUrls came from a different generation");
  require(value.cacheConfig == static_cast<int>(id),
          "cacheConfig came from a different generation");
  require(value.securityProfile == (id % 2 ? "lan" : "strict"),
          "securityProfile came from a different generation");
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc == 2 && std::string(argv[1]) == "--inject-invariant-failure")
    require(false, "injected invariant failure");
  if (argc != 1)
    fail("unexpected argument");

  string_icase_map conversion_headers;
  conversion_headers.emplace("X-Test", "immutable");
  ConversionResult conversion_result(202, "text/plain",
                                     std::move(conversion_headers), "body");
  const ConversionResult &conversion_view = conversion_result;
  require(conversion_view.statusCode() == 202 &&
              conversion_view.contentType() == "text/plain" &&
              conversion_view.headers().at("X-Test") == "immutable" &&
              conversion_view.body() == "body",
          "conversion result did not preserve immutable response data");
  require(std::move(conversion_result).releaseContentType() == "text/plain",
          "conversion result did not transfer content type ownership");
  require(std::move(conversion_result).releaseHeaders().at("X-Test") ==
              "immutable",
          "conversion result did not transfer header ownership");
  require(std::move(conversion_result).releaseBody() == "body",
          "conversion result did not transfer body ownership");

  Settings first = generation(1);
  Settings second = generation(2);
  publishSettingsSnapshot(first);

  SettingsSnapshot retained = captureSettingsSnapshot();
  publishSettingsSnapshot(second);
  SettingsSnapshot second_snapshot = captureSettingsSnapshot();
  requireConsistent(*retained);
  require(retained->configGeneration == 1,
          "retained snapshot changed after publication");
  require(second_snapshot->configGeneration == 2,
          "published snapshot has the wrong generation");

  {
    ScopedSettingsView request(retained);
    require(&effectiveSettings() == retained.get(),
            "request did not bind its retained snapshot");
    require(captureEffectiveSettingsSnapshot().get() == retained.get(),
            "effective snapshot did not match the request binding");
    {
      ScopedSettingsView nested(second_snapshot);
      require(&effectiveSettings() == second_snapshot.get(),
              "nested request view did not bind its snapshot");
    }
    require(&effectiveSettings() == retained.get(),
            "nested request view did not restore its parent");

    auto worker = std::async(std::launch::async, [retained] {
      ScopedSettingsView inherited(retained);
      require(captureEffectiveSettingsSnapshot().get() == retained.get(),
              "async worker did not inherit the request snapshot");
      requireConsistent(effectiveSettings());
      return effectiveSettings().configGeneration;
    });
    require(worker.get() == 1,
            "async worker observed the wrong request generation");

    publishSettingsSnapshot(generation(3));
    require(effectiveSettings().configGeneration == 1,
            "request view changed after a later publication");
  }
  require(captureSettingsSnapshot()->configGeneration == 3,
          "thread-local request view did not restore the published snapshot");

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

  require(failures.load(std::memory_order_relaxed) == 0,
          "reader observed a partially published generation");
  requireConsistent(*captureSettingsSnapshot());
  return 0;
}
