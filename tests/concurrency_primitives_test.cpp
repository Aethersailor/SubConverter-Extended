#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "utils/bounded_executor.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/cooperative_cpu.h"
#include "utils/resource_control.h"
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

static void testBoundedExecutorDeadlineAndCancellation() {
  BoundedExecutor executor(1, 1);
  std::promise<void> release;
  std::shared_future<void> released = release.get_future().share();
  std::promise<void> started;
  auto active = executor.submit([&] {
    started.set_value();
    released.wait();
    return 1;
  });
  started.get_future().wait();
  auto queued = executor.submit([&] {
    released.wait();
    return 2;
  });

  std::atomic<bool> deadline_executed{false};
  auto deadline = executor.submitUntil(
      std::chrono::steady_clock::now() + 20ms, {}, [&] {
        deadline_executed.store(true);
        return 3;
      });
  assert(deadline.status == ExecutorSubmitStatus::Deadline);
  bool deadline_error = false;
  try {
    (void)deadline.future.get();
  } catch (const ExecutorSubmitError &error) {
    deadline_error = error.status() == ExecutorSubmitStatus::Deadline;
  }
  assert(deadline_error && !deadline_executed.load());

  RequestCancellationSource cancellation_source;
  cancellation_source.cancel(RequestCancellationReason::NoConsumers);
  std::atomic<bool> cancelled_executed{false};
  auto cancelled = executor.submitUntil(
      std::chrono::steady_clock::time_point::max(),
      cancellation_source.token(), [&] {
        cancelled_executed.store(true);
        return 4;
      });
  assert(cancelled.status == ExecutorSubmitStatus::Cancelled);
  bool cancelled_error = false;
  try {
    (void)cancelled.future.get();
  } catch (const ExecutorSubmitError &error) {
    cancelled_error = error.status() == ExecutorSubmitStatus::Cancelled;
  }
  assert(cancelled_error && !cancelled_executed.load());

  release.set_value();
  assert(active.get() == 1);
  assert(queued.get() == 2);
  executor.shutdown();
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

  std::promise<SchedulerAsyncResult<int>> async_promise;
  const SchedulerSubmitStatus async_status = scheduler.submitAsync(
      RequestCostClass::Medium, 1,
      std::chrono::steady_clock::time_point::max(), {}, [] { return 42; },
      [&](SchedulerAsyncResult<int> result) {
        async_promise.set_value(std::move(result));
      });
  assert(async_status == SchedulerSubmitStatus::Accepted);
  SchedulerAsyncResult<int> async_result = async_promise.get_future().get();
  assert(async_result.status == SchedulerSubmitStatus::Accepted);
  assert(!async_result.error && async_result.value == 42);

  RequestCancellationSource async_cancellation;
  async_cancellation.cancel(RequestCancellationReason::NoConsumers);
  std::atomic<int> cancellation_callbacks{0};
  SchedulerSubmitStatus cancelled_async = scheduler.submitAsync(
      RequestCostClass::Low, 1,
      std::chrono::steady_clock::time_point::max(),
      async_cancellation.token(), [] { return 0; },
      [&](SchedulerAsyncResult<int> result) {
        assert(result.status == SchedulerSubmitStatus::Cancelled);
        assert(result.error && !result.value);
        cancellation_callbacks.fetch_add(1, std::memory_order_relaxed);
      });
  assert(cancelled_async == SchedulerSubmitStatus::Cancelled);
  assert(cancellation_callbacks.load(std::memory_order_relaxed) == 1);
  auto self_join = scheduler.submit(
      RequestCostClass::Low, 1,
      std::chrono::steady_clock::time_point::max(), {},
      [&scheduler] { return scheduler.join(); });
  assert(self_join.status == SchedulerSubmitStatus::Accepted);
  assert(!self_join.future.get());
  scheduler.shutdown(true);
}

static void testCooperativeCpuPermit() {
  assert(cooperativeFlowWorkerCap(1) == 16);
  assert(cooperativeFlowWorkerCap(4) == 16);
  assert(cooperativeFlowWorkerCap(16) == 64);
  assert(cooperativeFlowWorkerCap(64) == 256);
  assert(cooperativeFlowWorkerCap(std::numeric_limits<std::size_t>::max()) ==
         256);
  CpuPermitGate gate(1);
  CpuPermitLease owner(gate, std::chrono::steady_clock::time_point::max(), {});
  assert(owner.acquire() == SchedulerSubmitStatus::Accepted);
  ScopedCpuPermit owner_scope(owner);
  assert(gate.snapshot().active == 1);

  std::promise<void> second_acquired;
  std::shared_future<void> acquired = second_acquired.get_future().share();
  const int result = waitWithoutCpuPermit([&] {
    std::thread second([&] {
      CpuPermitLease lease(gate,
                           std::chrono::steady_clock::time_point::max(), {});
      assert(lease.acquire() == SchedulerSubmitStatus::Accepted);
      second_acquired.set_value();
    });
    acquired.wait();
    second.join();
    return 42;
  });
  assert(result == 42);
  assert(owner.held());
  assert(gate.snapshot().active == 1);
  bool exception_seen = false;
  try {
    waitWithoutCpuPermit([]() -> int {
      throw std::runtime_error("blocking dependency failed");
    });
  } catch (const std::runtime_error &) {
    exception_seen = true;
  }
  assert(exception_seen && owner.held());

  const int nested = waitWithoutCpuPermit(
      [] { return waitWithoutCpuPermit([] { return 7; }); });
  assert(nested == 7 && owner.held());

  RequestCancellationSource cancelled;
  cancelled.cancel(RequestCancellationReason::NoConsumers);
  CpuPermitLease rejected(gate,
                          std::chrono::steady_clock::time_point::max(),
                          cancelled.token());
  assert(rejected.acquire() == SchedulerSubmitStatus::Cancelled);

  CpuPermitGate stopping_gate(1);
  CpuPermitLease stopping_owner(
      stopping_gate, std::chrono::steady_clock::time_point::max(), {});
  assert(stopping_owner.acquire() == SchedulerSubmitStatus::Accepted);
  std::future<SchedulerSubmitStatus> stopped_waiter =
      std::async(std::launch::async, [&] {
        CpuPermitLease waiter(
            stopping_gate, std::chrono::steady_clock::time_point::max(), {});
        return waiter.acquire();
      });
  while (stopping_gate.snapshot().waiting == 0)
    std::this_thread::yield();
  stopping_gate.requestShutdown();
  assert(stopped_waiter.get() == SchedulerSubmitStatus::Stopping);

  CpuPermitGate flow_gate(1);
  WorkloadScheduler flows(2, 2, 1024);
  std::promise<void> blocking_started;
  std::shared_future<void> blocking = blocking_started.get_future().share();
  std::promise<void> release_blocking;
  std::shared_future<void> release = release_blocking.get_future().share();
  auto blocked_flow = flows.submit(
      RequestCostClass::Medium, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        CpuPermitLease lease(
            flow_gate, std::chrono::steady_clock::time_point::max(), {});
        assert(lease.acquire() == SchedulerSubmitStatus::Accepted);
        ScopedCpuPermit scope(lease);
        return waitWithoutCpuPermit([&] {
          blocking_started.set_value();
          release.wait();
          return 1;
        });
      });
  blocking.wait();
  auto runnable_flow = flows.submit(
      RequestCostClass::Medium, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        CpuPermitLease lease(
            flow_gate, std::chrono::steady_clock::time_point::max(), {});
        assert(lease.acquire() == SchedulerSubmitStatus::Accepted);
        return 2;
      });
  assert(runnable_flow.future.wait_for(1s) == std::future_status::ready);
  assert(runnable_flow.future.get() == 2);
  release_blocking.set_value();
  assert(blocked_flow.future.get() == 1);
  flows.shutdown(true);

  CpuPermitGate shrinking_gate(2);
  CpuPermitLease first(
      shrinking_gate, std::chrono::steady_clock::time_point::max(), {});
  CpuPermitLease second(
      shrinking_gate, std::chrono::steady_clock::time_point::max(), {});
  assert(first.acquire() == SchedulerSubmitStatus::Accepted);
  assert(second.acquire() == SchedulerSubmitStatus::Accepted);
  shrinking_gate.setLimit(1);
  std::future<SchedulerSubmitStatus> after_shrink =
      std::async(std::launch::async, [&] {
        CpuPermitLease waiter(
            shrinking_gate, std::chrono::steady_clock::time_point::max(), {});
        return waiter.acquire();
      });
  while (shrinking_gate.snapshot().waiting == 0)
    std::this_thread::yield();
  first.release();
  assert(after_shrink.wait_for(20ms) == std::future_status::timeout);
  second.release();
  assert(after_shrink.get() == SchedulerSubmitStatus::Accepted);
  assert(shrinking_gate.snapshot().active == 0);
}

static void testWorkloadSchedulerActiveQueueWeights() {
  auto run_sequence = [](RequestCostClass first_class, int first_count,
                         RequestCostClass second_class, int second_count) {
    WorkloadScheduler scheduler(1, 128, 1024);
    std::promise<void> release;
    std::shared_future<void> released = release.get_future().share();
    std::promise<void> started;
    auto blocker = scheduler.submit(
        RequestCostClass::Medium, 1,
        std::chrono::steady_clock::time_point::max(), {}, [&] {
          started.set_value();
          released.wait();
        });
    started.get_future().wait();

    std::mutex mutex;
    std::vector<RequestCostClass> order;
    std::vector<std::future<void>> futures;
    auto enqueue = [&](RequestCostClass cost, int count) {
      for (int index = 0; index < count; ++index) {
        auto submitted = scheduler.submit(
            cost, 1, std::chrono::steady_clock::time_point::max(), {},
            [&, cost] {
              std::lock_guard<std::mutex> lock(mutex);
              order.push_back(cost);
            });
        assert(submitted.status == SchedulerSubmitStatus::Accepted);
        futures.emplace_back(std::move(submitted.future));
      }
    };
    enqueue(first_class, first_count);
    enqueue(second_class, second_count);
    release.set_value();
    blocker.future.get();
    for (auto &future : futures)
      future.get();
    scheduler.shutdown(true);
    return order;
  };

  const std::vector<RequestCostClass> low_high =
      run_sequence(RequestCostClass::Low, 32, RequestCostClass::High, 8);
  const auto high_in_first_eighteen = std::count(
      low_high.begin(), low_high.begin() + 18, RequestCostClass::High);
  assert(high_in_first_eighteen >= 2);

  const std::vector<RequestCostClass> medium_high =
      run_sequence(RequestCostClass::Medium, 20, RequestCostClass::High, 5);
  const auto high_in_first_ten = std::count(
      medium_high.begin(), medium_high.begin() + 10, RequestCostClass::High);
  assert(high_in_first_ten >= 2);

  WorkloadScheduler all_classes(1, 128, 1024);
  std::promise<void> release;
  std::shared_future<void> released = release.get_future().share();
  std::promise<void> started;
  auto blocker = all_classes.submit(
      RequestCostClass::Medium, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        started.set_value();
        released.wait();
      });
  started.get_future().wait();
  std::mutex all_mutex;
  std::vector<RequestCostClass> all_order;
  std::vector<std::future<void>> all_futures;
  for (const auto [cost, count] :
       std::array<std::pair<RequestCostClass, int>, 3>{
           std::pair{RequestCostClass::Low, 32},
           std::pair{RequestCostClass::Medium, 16},
           std::pair{RequestCostClass::High, 4}}) {
    for (int index = 0; index < count; ++index) {
      auto submitted = all_classes.submit(
          cost, 1, std::chrono::steady_clock::time_point::max(), {},
          [&, cost] {
            std::lock_guard<std::mutex> lock(all_mutex);
            all_order.push_back(cost);
          });
      assert(submitted.status == SchedulerSubmitStatus::Accepted);
      all_futures.emplace_back(std::move(submitted.future));
    }
  }
  release.set_value();
  blocker.future.get();
  for (auto &future : all_futures)
    future.get();
  const auto first_cycle_end = all_order.begin() + 13;
  assert(std::count(all_order.begin(), first_cycle_end,
                    RequestCostClass::Low) == 8);
  assert(std::count(all_order.begin(), first_cycle_end,
                    RequestCostClass::Medium) == 4);
  assert(std::count(all_order.begin(), first_cycle_end,
                    RequestCostClass::High) == 1);
  all_classes.shutdown(true);

  WorkloadScheduler aging(1, 64, 1024);
  std::promise<void> aging_release;
  std::shared_future<void> aging_released =
      aging_release.get_future().share();
  std::promise<void> aging_started;
  auto aging_blocker = aging.submit(
      RequestCostClass::Low, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        aging_started.set_value();
        aging_released.wait();
      });
  aging_started.get_future().wait();
  std::vector<int> aging_order;
  auto aged = aging.submit(
      RequestCostClass::High, 1,
      std::chrono::steady_clock::time_point::max(), {}, [&] {
        aging_order.push_back(1);
      });
  std::this_thread::sleep_for(520ms);
  std::vector<std::future<void>> fresh;
  for (int index = 0; index < 16; ++index) {
    auto submitted = aging.submit(
        RequestCostClass::Low, 1,
        std::chrono::steady_clock::time_point::max(), {}, [&] {
          aging_order.push_back(2);
        });
    fresh.emplace_back(std::move(submitted.future));
  }
  aging_release.set_value();
  aging_blocker.future.get();
  aged.future.get();
  for (auto &future : fresh)
    future.get();
  assert(!aging_order.empty() && aging_order.front() == 1);
  aging.shutdown(true);
}

static void testRetainedResponseByteBudget() {
  constexpr uint64_t boundary = UINT64_C(64) * 1024 * 1024;
  configureRetainedResponseByteLimit(boundary);
  assert(tryRetainResponseBytes(boundary));
  assert(!tryRetainResponseBytes(1));
  RetainedResponseByteSnapshot snapshot = retainedResponseByteSnapshot();
  assert(snapshot.limit == boundary && snapshot.used == boundary &&
         snapshot.rejected == 1);
  releaseRetainedResponseBytes(boundary);
  assert(retainedResponseByteSnapshot().used == 0);

  configureRetainedResponseByteLimit(0);
  assert(tryRetainResponseBytes(boundary + 1));
  assert(retainedResponseByteSnapshot().used == boundary + 1);
  releaseRetainedResponseBytes(boundary + 1);

  configureRetainedResponseByteLimit(boundary);
  {
    auto context = std::make_shared<RequestContext>(
        "byte-budget", RequestContext::Clock::now(),
        RequestContext::Clock::now() + 1s);
    assert(context->retainResponseBytes(boundary - 1));
    std::string completed_result(1, 'x');
    assert(context->retainResponseBytes(completed_result.size()));
    assert(retainedResponseByteSnapshot().used == boundary);
    assert(context->releaseResponseBytes(boundary / 2) == boundary / 2);
    assert(context->retainedResponseBytes() == boundary / 2);
    assert(retainedResponseByteSnapshot().used == boundary / 2);
    assert(context->releaseResponseBytes(boundary) == boundary / 2);
    assert(context->retainedResponseBytes() == 0);
    assert(retainedResponseByteSnapshot().used == 0);
  }
  assert(retainedResponseByteSnapshot().used == 0);
  configureRetainedResponseByteLimit(0);
}

static void testWorkAdmissionLifecycle() {
  resetRequestLifecycleMetricsForTests();

  auto envelope_only = std::make_shared<RequestContext>(
      "envelope-only", RequestContext::Clock::now());
  envelope_only->suggestFailure(RequestFailureAttribution::Capacity);
  RequestLifecycleMetricsSnapshot metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 0);
  assert(metrics.server_capacity_failure_after_admission == 0);

  auto admitted = std::make_shared<RequestContext>(
      "admitted-client", RequestContext::Clock::now());
  assert(admitted->markWorkAdmitted());
  assert(!admitted->markWorkAdmitted());
  admitted->suggestFailure(RequestFailureAttribution::Capacity);
  admitted->suggestFailure(RequestFailureAttribution::Capacity);
  metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 1);
  assert(metrics.server_capacity_failure_after_admission == 1);

  auto raced = std::make_shared<RequestContext>(
      "admission-race", RequestContext::Clock::now());
  raced->suggestFailure(RequestFailureAttribution::Capacity);
  assert(raced->markWorkAdmitted());
  metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 2);
  assert(metrics.server_capacity_failure_after_admission == 2);

  auto internal = std::make_shared<RequestContext>(
      "internal-work", RequestContext::Clock::now(),
      RequestContext::Clock::time_point::max(),
      RequestContextKind::InternalWork);
  assert(!internal->markWorkAdmitted());
  internal->suggestFailure(RequestFailureAttribution::Capacity);
  metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 2);
  assert(metrics.server_capacity_failure_after_admission == 2);
}

static void testActiveRequestShutdownCancellation() {
  auto first = std::make_shared<RequestContext>(
      "active-shutdown-first", RequestContext::Clock::now());
  auto second = std::make_shared<RequestContext>(
      "active-shutdown-second", RequestContext::Clock::now());
  auto sending = std::make_shared<RequestContext>(
      "active-shutdown-sending", RequestContext::Clock::now());
  std::atomic<int> callback_count{0};
  auto first_callback = first->registerCancellationCallback(
      [&] { callback_count.fetch_add(1); });
  (void)first_callback;
  auto removed = sending->registerCancellationCallback(
      [&] { callback_count.fetch_add(100); });
  removed.reset();
  sending->setCurrentStage(RequestStage::Send);
  second->requestCancellation(RequestCancellationReason::ClientDisconnected);
  cancelAllActiveRequests(RequestCancellationReason::Shutdown);
  assert(first->cancellationToken().reason() ==
         RequestCancellationReason::Shutdown);
  assert(second->cancellationToken().reason() ==
         RequestCancellationReason::ClientDisconnected);
  assert(sending->cancellationToken().reason() ==
         RequestCancellationReason::None);
  assert(callback_count.load() == 1);
  auto late_callback = first->registerCancellationCallback(
      [&] { callback_count.fetch_add(1); });
  (void)late_callback;
  assert(callback_count.load() == 2);
  assert(!first->requestCancellation(RequestCancellationReason::Deadline));
  assert(callback_count.load() == 2);
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

static void testResourceControlPrimitives() {
  assert(parseResourceControlMode("compat") == ResourceControlMode::Compat);
  assert(parseResourceControlMode("adaptive") ==
         ResourceControlMode::Adaptive);
  assert(parseResourceControlMode("force_max") ==
         ResourceControlMode::ForceMax);
  assert(!parseResourceControlMode("automatic"));

  assert(parseCpuSetCount("0-2,4,6-7") == 6);
  assert(parseCpuSetCount(" 1 , 3-5 ") == 4);
  assert(parseCpuSetCount("4-2") == 0);
  assert(parseCpuSetCount("0,x") == 0);

  assert(computeEffectiveCpu(8.0, 4.0, 2.5, 16.0) == 2.5);
  assert(computeEffectiveCpu(8.0, 0.0, 0.0, 16.0) == 8.0);
  assert(computeEffectiveCpu(0.0, 0.0, 0.0, 3.0) == 3.0);
  assert(computeEffectiveCpu(8.0, 8.0, 0.5, 16.0) == 1.0);

  const ResourcePermitBudget three_core =
      computeConservativeResourceBudget(3.75, 16);
  assert(three_core.cpu_permits == 3);
  assert(three_core.active_flows == 48);
  assert(three_core.outbound_connections == 48);
  const ResourcePermitBudget capped =
      computeConservativeResourceBudget(8.0, 4);
  assert(capped.cpu_permits == 4);
  const ResourcePermitBudget fractional =
      computeConservativeResourceBudget(0.5, 16);
  assert(fractional.cpu_permits == 1);
  assert(governorDecreaseCpuPermits(1) == 1);
  assert(governorDecreaseCpuPermits(2) == 1);
  assert(governorDecreaseCpuPermits(8) == 6);
  assert(governorRecoverCpuPermits(1, 8) == 2);
  assert(governorRecoverCpuPermits(8, 8) == 8);

  ResourceGovernorState force_governor{8, 0, 0};
  ResourceGovernorDecision decision = governorStep(
      force_governor, {8, true, true, false, false, false});
  assert(decision.permits == 8 &&
         std::string(decision.state) == "max_ready");
  decision = governorStep(
      force_governor, {8, true, true, true, false, true});
  assert(decision.permits == 6 &&
         std::string(decision.state) == "pressure_guarded");
  decision = governorStep(
      force_governor, {8, true, true, false, false, false});
  assert(decision.permits == 6 &&
         std::string(decision.state) == "recovering");
  decision = governorStep(
      force_governor, {8, true, true, false, false, false});
  assert(decision.permits == 7);
  (void)governorStep(
      force_governor, {8, true, true, false, false, false});
  decision = governorStep(
      force_governor, {8, true, true, false, false, false});
  assert(decision.permits == 8);

  ResourceGovernorState invalid_governor{8, 0, 0};
  decision = governorStep(
      invalid_governor, {8, true, false, false, false, false});
  assert(decision.permits == 6 && decision.pressure_fallback &&
         std::string(decision.reason) == "telemetry_unavailable");
  ResourceGovernorState event_governor{8, 0, 0};
  decision = governorStep(
      event_governor, {8, true, true, false, true, true});
  assert(decision.permits == 6 &&
         std::string(decision.reason) == "memory_event");

  ResourceGovernorState adaptive_governor{4, 0, 0};
  (void)governorStep(
      adaptive_governor, {8, false, true, false, false, true});
  decision = governorStep(
      adaptive_governor, {8, false, true, false, false, true});
  assert(decision.permits == 5 &&
         std::string(decision.state) == "recovering");
  for (int sample = 0; sample < 30; ++sample)
    decision = governorStep(
        adaptive_governor, {8, false, true, false, false, false});
  assert(decision.permits == 4 &&
         std::string(decision.state) == "idle_reduced");

  assert(computeForceMaxAdmissionEntries(UINT64_C(1) * 1024 * 1024 * 1024,
                                         0, 16) == 2048);
  assert(computeForceMaxAdmissionEntries(UINT64_C(1) * 1024 * 1024 * 1024,
                                         1024, 64) == 896);
  assert(computeForceMaxAdmissionEntries(UINT64_C(2) * 1024 * 1024 * 1024,
                                         0, 32) == 4096);
  assert(computeForceMaxAdmissionEntries(UINT64_C(4) * 1024 * 1024 * 1024,
                                         0, 64) == 8192);
  assert(computeForceMaxAdmissionEntries(UINT64_C(32) * 1024 * 1024 * 1024,
                                         0, 512) == 65536);
  assert(computeForceMaxAdmissionEntries(UINT64_C(128) * 1024 * 1024 * 1024,
                                         0, 2048) == 262144);
  assert(computeForceMaxRequestByteLimit(UINT64_C(1) * 1024 * 1024 * 1024) ==
         UINT64_C(64) * 1024 * 1024);
  assert(computeForceMaxRequestByteLimit(UINT64_C(4) * 1024 * 1024 * 1024) ==
         UINT64_C(256) * 1024 * 1024);
  assert(computeForceMaxRetainedByteLimit(
             UINT64_C(1) * 1024 * 1024 * 1024) ==
         UINT64_C(256) * 1024 * 1024);
  assert(computeForceMaxRetainedByteLimit(
             UINT64_C(4) * 1024 * 1024 * 1024) ==
         UINT64_C(1) * 1024 * 1024 * 1024);
  assert(computeForceMaxRetainedByteLimit(
             UINT64_C(32) * 1024 * 1024 * 1024) ==
         UINT64_C(8) * 1024 * 1024 * 1024);

  ResourceControlSnapshot uncalibrated;
  uncalibrated.mode = "force_max";
  uncalibrated.hardware_fingerprint = "hardware-a";
  uncalibrated.hardware_detected = true;
  uncalibrated.hardware_complete = true;
  assert(hardwarePinMatches(uncalibrated, ""));
  assert(!hardwarePinMatches(uncalibrated, "hardware-b"));
  assert(hardwarePinMatches(uncalibrated, "hardware-a"));
  uncalibrated.hardware_detected = false;
  uncalibrated.hardware_complete = false;
  assert(hardwarePinMatches(uncalibrated, ""));
  assert(!hardwarePinMatches(uncalibrated, "hardware-a"));
}

static void testCancellationTokenCallbacks() {
  RequestCancellationSource source;
  std::atomic<int> callbacks{0};
  RequestCancellationRegistration registration =
      source.token().registerCallback(
          [&] { callbacks.fetch_add(1, std::memory_order_relaxed); });
  assert(source.cancel(RequestCancellationReason::ClientDisconnected));
  assert(!source.cancel(RequestCancellationReason::Shutdown));
  assert(callbacks.load(std::memory_order_relaxed) == 1);

  RequestCancellationSource reset_source;
  RequestCancellationRegistration reset_registration =
      reset_source.token().registerCallback(
          [&] { callbacks.fetch_add(1, std::memory_order_relaxed); });
  reset_registration.reset();
  assert(reset_source.cancel(RequestCancellationReason::Shutdown));
  assert(callbacks.load(std::memory_order_relaxed) == 1);

  int immediate = 0;
  RequestCancellationRegistration immediate_registration =
      source.token().registerCallback([&] { ++immediate; });
  assert(immediate == 1);

  RequestCancellationSource reentrant_source;
  RequestCancellationRegistration reentrant_registration;
  std::atomic<int> reentrant_callbacks{0};
  reentrant_registration = reentrant_source.token().registerCallback([&] {
    reentrant_registration.reset();
    reentrant_callbacks.fetch_add(1, std::memory_order_relaxed);
  });
  assert(reentrant_source.cancel(RequestCancellationReason::NoConsumers));
  assert(reentrant_callbacks.load(std::memory_order_relaxed) == 1);

  for (int iteration = 0; iteration < 256; ++iteration) {
    RequestCancellationSource concurrent_source;
    RequestCancellationRegistration concurrent_registration;
    std::atomic<int> concurrent_callbacks{0};
    concurrent_registration = concurrent_source.token().registerCallback([&] {
      concurrent_callbacks.fetch_add(1, std::memory_order_relaxed);
    });
    std::thread cancel_thread([&] {
      concurrent_source.cancel(RequestCancellationReason::ClientDisconnected);
    });
    std::thread reset_thread([&] { concurrent_registration.reset(); });
    cancel_thread.join();
    reset_thread.join();
    assert(concurrent_callbacks.load(std::memory_order_relaxed) <= 1);
  }
}

int main() {
  testBoundedExecutor();
  testBoundedExecutorDeadlineAndCancellation();
  testWorkloadScheduler();
  testCooperativeCpuPermit();
  testWorkloadSchedulerActiveQueueWeights();
  testRetainedResponseByteBudget();
  testWorkAdmissionLifecycle();
  testActiveRequestShutdownCancellation();
  testCancellationTokenCallbacks();
  testConcurrentLruCache();
  testExternalConfigCacheSemantics();
  testResourceControlPrimitives();
  return 0;
}
