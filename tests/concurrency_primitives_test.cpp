#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "utils/bounded_executor.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/workload_scheduler.h"

using namespace std::chrono_literals;

static void testBoundedExecutor() {
  BoundedExecutor executor(2, 1);
  assert(executor.workerCount() == 2);
  assert(executor.queueCapacity() == 1);

  std::promise<void> release;
  std::shared_future<void> released = release.get_future().share();
  std::atomic<int> started{0};
  auto blocker = [&] {
    started.fetch_add(1);
    released.wait();
    return 1;
  };
  auto first = executor.submit(blocker);
  while (started.load() != 1)
    std::this_thread::yield();
  auto second = executor.submit(blocker);
  while (started.load() != 2)
    std::this_thread::yield();

  auto queued = executor.submit([] { return 3; });
  std::atomic<bool> executed{false};
  auto queue_full = executor.trySubmit([&] {
    executed.store(true);
    return 4;
  });
  assert(queue_full.status == ExecutorSubmitStatus::QueueFull);
  bool queue_full_error = false;
  try {
    (void)queue_full.future.get();
  } catch (const ExecutorSubmitError &error) {
    queue_full_error = error.status() == ExecutorSubmitStatus::QueueFull;
  }
  assert(queue_full_error);
  assert(!executed.load());

  release.set_value();
  assert(first.get() == 1);
  assert(second.get() == 1);
  assert(queued.get() == 3);

  auto nested = executor.submit([&] {
    return executor.trySubmit([] { return 7; }).status;
  });
  assert(nested.get() == ExecutorSubmitStatus::Recursive);

  auto exceptional = executor.submit([]() -> int {
    throw std::runtime_error("expected");
  });
  bool threw = false;
  try {
    (void)exceptional.get();
  } catch (const std::runtime_error &) {
    threw = true;
  }
  assert(threw);
  executor.shutdown();

  bool ran_after_shutdown = false;
  auto rejected = executor.trySubmit([&] {
    ran_after_shutdown = true;
    return 9;
  });
  assert(rejected.status == ExecutorSubmitStatus::Stopping);
  bool stopping_error = false;
  try {
    (void)rejected.future.get();
  } catch (const ExecutorSubmitError &error) {
    stopping_error = error.status() == ExecutorSubmitStatus::Stopping;
  }
  assert(stopping_error);
  assert(!ran_after_shutdown);
}

static void testWorkloadScheduler() {
  WorkloadScheduler scheduler(1, 3, 10);
  std::promise<void> release;
  std::shared_future<void> released = release.get_future().share();
  std::promise<void> started;
  std::future<void> started_future = started.get_future();
  auto blocker = scheduler.submit(
      RequestCostClass::Medium, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        started.set_value();
        released.wait();
        return 1;
      });
  assert(blocker.status == SchedulerSubmitStatus::Accepted);
  started_future.wait();

  std::mutex order_mutex;
  std::vector<int> order;
  auto low = scheduler.submit(
      RequestCostClass::Low, 4,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        std::lock_guard<std::mutex> lock(order_mutex);
        order.push_back(1);
        return 2;
      });
  auto high = scheduler.submit(
      RequestCostClass::High, 4,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        std::lock_guard<std::mutex> lock(order_mutex);
        order.push_back(3);
        return 3;
      });
  assert(low.status == SchedulerSubmitStatus::Accepted);
  assert(high.status == SchedulerSubmitStatus::Accepted);

  auto byte_rejected = scheduler.submit(
      RequestCostClass::Medium, 3,
      std::chrono::steady_clock::time_point::max(), {}, [] { return 4; });
  assert(byte_rejected.status == SchedulerSubmitStatus::ByteLimit);
  bool byte_error = false;
  try {
    (void)byte_rejected.future.get();
  } catch (const SchedulerSubmitError &error) {
    byte_error = error.status() == SchedulerSubmitStatus::ByteLimit;
  }
  assert(byte_error);

  release.set_value();
  assert(blocker.future.get() == 1);
  assert(low.future.get() == 2);
  assert(high.future.get() == 3);
  assert(order.size() == 2);
  assert(std::find(order.begin(), order.begin() + 2, 3) !=
         order.begin() + 2);

  RequestCancellationSource cancellation_source;
  cancellation_source.cancel(RequestCancellationReason::ClientDisconnected);
  auto cancelled = scheduler.submit(
      RequestCostClass::Low, 1,
      std::chrono::steady_clock::time_point::max(),
      cancellation_source.token(), [] { return 5; });
  assert(cancelled.status == SchedulerSubmitStatus::Cancelled);

  auto expired = scheduler.submit(
      RequestCostClass::Low, 1,
      std::chrono::steady_clock::now() - 1ms, {}, [] { return 6; });
  assert(expired.status == SchedulerSubmitStatus::Deadline);

  WorkloadSchedulerSnapshot snapshot;
  for (int attempt = 0; attempt < 100; ++attempt) {
    snapshot = scheduler.snapshot();
    if (snapshot.active == 0)
      break;
    std::this_thread::sleep_for(1ms);
  }
  assert(snapshot.queued_entries == 0);
  assert(snapshot.queued_bytes == 0);
  assert(snapshot.active == 0);
  assert(snapshot.accepted == 3);
  assert(snapshot.rejected == 3);
  scheduler.shutdown(true);
}

static void testConcurrentLruCache() {
  ConcurrentLruCache<std::string, std::string> cache(2, 64);
  std::atomic<int> computations{0};
  std::promise<void> start;
  std::shared_future<void> started = start.get_future().share();
  std::vector<std::future<std::string>> futures;
  for (int i = 0; i < 12; ++i) {
    futures.emplace_back(std::async(std::launch::async, [&] {
      started.wait();
      return cache.getOrCompute(
          "same-content:type-a", true,
          [&] {
            computations.fetch_add(1);
            std::this_thread::sleep_for(20ms);
            return std::string("byte-exact\nvalue");
          },
          [](const std::string &value)
              -> ConcurrentLruCache<std::string, std::string>::CacheSize {
            return value.size();
          });
    }));
  }
  start.set_value();
  for (auto &future : futures)
    assert(future.get() == "byte-exact\nvalue");
  assert(computations.load() == 1);

  auto compute = [&](const std::string &key, const std::string &value) {
    return cache.getOrCompute(
        key, true,
        [&] {
          computations.fetch_add(1);
          return value;
        },
        [](const std::string &result)
            -> ConcurrentLruCache<std::string, std::string>::CacheSize {
          return result.size();
        });
  };
  assert(compute("same-content:type-a", "wrong") == "byte-exact\nvalue");
  int after_hit = computations.load();
  assert(compute("different-content:type-a", "content-miss") ==
         "content-miss");
  assert(compute("same-content:type-b", "type-miss") == "type-miss");
  assert(computations.load() == after_hit + 2);
  assert(cache.size() == 2);

  int before_evicted = computations.load();
  assert(compute("same-content:type-a", "recomputed") == "recomputed");
  assert(computations.load() == before_evicted + 1);

  ConcurrentLruCache<std::string, std::string> small(4, 4);
  int oversized_computations = 0;
  auto oversized = [&] {
    return small.getOrCompute(
        "large", true,
        [&] {
          ++oversized_computations;
          return std::string("12345");
        },
        [](const std::string &value)
            -> ConcurrentLruCache<std::string, std::string>::CacheSize {
          return value.size();
        });
  };
  assert(oversized() == "12345");
  assert(oversized() == "12345");
  assert(oversized_computations == 2);

  int disabled_computations = 0;
  for (int i = 0; i < 2; ++i)
    assert(cache.getOrCompute(
               "disabled", false,
               [&] {
                 ++disabled_computations;
                 return std::string("disabled");
               },
               [](const std::string &value)
                   -> ConcurrentLruCache<std::string,
                                         std::string>::CacheSize {
                 return value.size();
               }) == "disabled");
  assert(disabled_computations == 2);

  int exceptional_computations = 0;
  bool cache_threw = false;
  try {
    (void)cache.getOrCompute(
        "exception", true,
        [&]() -> std::string {
          ++exceptional_computations;
          throw std::runtime_error("cache computation failed");
        },
        [](const std::string &value)
            -> ConcurrentLruCache<std::string, std::string>::CacheSize {
          return value.size();
        });
  } catch (const std::runtime_error &) {
    cache_threw = true;
  }
  assert(cache_threw);
  assert(compute("exception", "recovered") == "recovered");
  assert(exceptional_computations == 1);
}

struct MockExternalConfig {
  std::string parsed;
  std::map<std::string, std::string> local_vars;
};

static void testExternalConfigCacheSemantics() {
  ConcurrentLruCache<std::string, MockExternalConfig> cache(64,
                                                            8 * 1024 * 1024);
  int parses = 0;
  auto parse = [&](const std::string &content_hash, int context,
                   int generation, bool enabled) {
    std::string key = content_hash + ":" + std::to_string(context) + ":" +
                      std::to_string(generation) +
                      ":external-config-parser-v1";
    return cache.getOrCompute(
        key, enabled,
        [&] {
          ++parses;
          return MockExternalConfig{
              content_hash,
              {{"request_local", "copied-" + content_hash}}};
        },
        [](const MockExternalConfig &value)
            -> ConcurrentLruCache<std::string,
                                  MockExternalConfig>::CacheSize {
          return value.parsed.size() +
                 value.local_vars.begin()->first.size() +
                 value.local_vars.begin()->second.size();
        });
  };

  MockExternalConfig first = parse("content-a", 1, 7, true);
  first.local_vars["request_local"] = "request-mutation";
  MockExternalConfig hit = parse("content-a", 1, 7, true);
  assert(parses == 1);
  assert(hit.local_vars.at("request_local") == "copied-content-a");

  assert(parse("content-b", 1, 7, true).parsed == "content-b");
  assert(parse("content-a", 1, 8, true).parsed == "content-a");
  assert(parse("content-a", 2, 7, true).parsed == "content-a");
  assert(parses == 4);

  (void)parse("dynamic-content", 1, 7, false);
  (void)parse("dynamic-content", 1, 7, false);
  assert(parses == 6);
}

int main() {
  testBoundedExecutor();
  testWorkloadScheduler();
  testConcurrentLruCache();
  testExternalConfigCacheSemantics();
  return 0;
}
