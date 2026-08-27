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

#include <rapidjson/writer.h>

#include "utils/bounded_executor.h"
#include "utils/bounded_output.h"
#include "runtime/compute_executor.h"
#include "runtime/blocking_io_executor.h"
#include "runtime/owner_admission.h"
#include "runtime/memory_budget.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/cooperative_cpu.h"
#include "utils/resource_control.h"
#include "utils/workload_scheduler.h"

using namespace std::chrono_literals;

static void testBoundedOutput() {
  BoundedOutputSink exact(4);
  exact.append("ab");
  exact.append("cd");
  bool rejected = false;
  try {
    exact.append("e");
  } catch (const BoundedOutputExceeded &) {
    rejected = true;
  }
  assert(rejected && exact.release() == "abcd");

  constexpr size_t double_buffer_budget = 128;
  BoundedOutputSink double_buffer(double_buffer_budget / 2);
  double_buffer.append(std::string(40, 'x'));
  const size_t staging_capacity = double_buffer.allocatedCapacity();
  const std::string abi_output = double_buffer.release();
  assert(staging_capacity + abi_output.capacity() <= double_buffer_budget);

  Base64OutputSink base64_exact(4);
  base64_exact.append("M");
  base64_exact.append("an");
  assert(base64_exact.release() == "TWFu");
  rejected = false;
  try {
    Base64OutputSink base64_short(3);
    base64_short.append("Man");
  } catch (const BoundedOutputExceeded &) {
    rejected = true;
  }
  assert(rejected);

  std::string managed_prefix = "#!MANAGED-CONFIG fixture\n\n";
  std::string generated = "payload";
  const size_t concat_limit = 1024;
  assert(boundedConcatWithRetained(managed_prefix, generated, concat_limit) ==
         managed_prefix + generated);
  rejected = false;
  try {
    (void)boundedConcatWithRetained(managed_prefix, generated, 1);
  } catch (const BoundedOutputExceeded &) {
    rejected = true;
  }
  assert(rejected);

  BoundedOutputSink json_probe(1024);
  rapidjson::Writer<BoundedOutputSink> probe_writer(json_probe);
  probe_writer.StartObject();
  probe_writer.Key("nodes");
  probe_writer.Uint(12);
  probe_writer.EndObject();
  const std::string expected_json = json_probe.release();
  BoundedOutputSink json_exact(expected_json.size());
  rapidjson::Writer<BoundedOutputSink> exact_writer(json_exact);
  exact_writer.StartObject();
  exact_writer.Key("nodes");
  exact_writer.Uint(12);
  exact_writer.EndObject();
  assert(json_exact.release() == expected_json);
  rejected = false;
  try {
    BoundedOutputSink json_short(expected_json.size() - 1);
    rapidjson::Writer<BoundedOutputSink> short_writer(json_short);
    short_writer.StartObject();
    short_writer.Key("nodes");
    short_writer.Uint(12);
    short_writer.EndObject();
  } catch (const BoundedOutputExceeded &) {
    rejected = true;
  }
  assert(rejected);

  // Model the target serializer's group x node fan-out at its append point.
  BoundedOutputSink fanout_probe(4096);
  for (int group = 0; group < 3; ++group)
    for (int node = 0; node < 4; ++node)
      fanout_probe.append("group-node\n");
  const std::string fanout = fanout_probe.release();
  BoundedOutputSink fanout_exact(fanout.size());
  for (int group = 0; group < 3; ++group)
    for (int node = 0; node < 4; ++node)
      fanout_exact.append("group-node\n");
  assert(fanout_exact.release() == fanout);
  rejected = false;
  try {
    BoundedOutputSink fanout_short(fanout.size() - 1);
    for (int group = 0; group < 3; ++group)
      for (int node = 0; node < 4; ++node)
        fanout_short.append("group-node\n");
  } catch (const BoundedOutputExceeded &) {
    rejected = true;
  }
  assert(rejected);
}

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

static void testComputeExecutor() {
  ComputeExecutor executor({1, 2, 10});
  assert(executor.ready());
  assert(executor.snapshot().workers == 1);

  std::promise<void> release;
  std::shared_future<void> released = release.get_future().share();
  std::promise<void> started;
  auto blocker = executor.submit({}, [&] {
    started.set_value();
    released.wait();
    return 1;
  });
  assert(blocker.status == SchedulerSubmitStatus::Accepted);
  started.get_future().wait();

  auto byte_rejected = executor.submit(
      {.bytes = 11}, [] { return 2; });
  assert(byte_rejected.status == SchedulerSubmitStatus::ByteLimit);
  bool byte_error = false;
  try {
    (void)byte_rejected.future.get();
  } catch (const SchedulerSubmitError &error) {
    byte_error = error.status() == SchedulerSubmitStatus::ByteLimit;
  }
  assert(byte_error);

  RequestCancellationSource cancelled_source;
  cancelled_source.cancel(RequestCancellationReason::NoConsumers);
  auto cancelled = executor.submit(
      {.cancellation = cancelled_source.token()}, [] { return 3; });
  assert(cancelled.status == SchedulerSubmitStatus::Cancelled);
  bool cancellation_error = false;
  try {
    (void)cancelled.future.get();
  } catch (const SchedulerSubmitError &error) {
    cancellation_error =
        error.status() == SchedulerSubmitStatus::Cancelled;
  }
  assert(cancellation_error);

  auto deadline = executor.submit(
      {.deadline = std::chrono::steady_clock::now() - 1ms},
      [] { return 4; });
  assert(deadline.status == SchedulerSubmitStatus::Deadline);
  bool deadline_error = false;
  try {
    (void)deadline.future.get();
  } catch (const SchedulerSubmitError &error) {
    deadline_error = error.status() == SchedulerSubmitStatus::Deadline;
  }
  assert(deadline_error);

  auto queued = executor.submit({.bytes = 5}, [] { return 5; });
  auto self_join = executor.submit(
      {.bytes = 5, .preferred_worker = 0},
      [&executor] { return executor.join(); });
  auto entry_rejected = executor.submit({}, [] { return 6; });
  assert(queued.status == SchedulerSubmitStatus::Accepted);
  assert(self_join.status == SchedulerSubmitStatus::Accepted);
  assert(entry_rejected.status == SchedulerSubmitStatus::EntryLimit);
  bool entry_error = false;
  try {
    (void)entry_rejected.future.get();
  } catch (const SchedulerSubmitError &error) {
    entry_error = error.status() == SchedulerSubmitStatus::EntryLimit;
  }
  assert(entry_error);

  release.set_value();
  assert(blocker.future.get() == 1);
  assert(queued.future.get() == 5);
  assert(!self_join.future.get());
  ComputeExecutorSnapshot snapshot = executor.snapshot();
  assert(snapshot.queued_entries == 0);
  assert(snapshot.queued_bytes == 0);
  assert(snapshot.accepted_total == 3);
  assert(snapshot.rejected_total == 4);
  assert(snapshot.worker_metrics.size() == 1);
  assert(snapshot.worker_metrics[0].executed == 3);
  assert(snapshot.worker_metrics[0].affinity_hits >= 1);
  executor.shutdown(true);
  assert(!executor.ready());

  ComputeExecutor control_affinity({2, 2, 1024, 64});
  std::promise<void> affinity_release;
  std::shared_future<void> affinity_released =
      affinity_release.get_future().share();
  std::atomic<uint64_t> affinity_blockers_started{0};
  std::promise<void> affinity_blockers_ready;
  for (std::size_t index = 0; index < 2; ++index) {
    assert(control_affinity.submit(
               {.preferred_worker = index},
               [&, index] {
                 (void)index;
                 if (affinity_blockers_started.fetch_add(
                         1, std::memory_order_acq_rel) == 1)
                   affinity_blockers_ready.set_value();
                 affinity_released.wait();
               }).status == SchedulerSubmitStatus::Accepted);
  }
  affinity_blockers_ready.get_future().wait();
  std::atomic<uint64_t> affinity_control_completed{0};
  std::promise<void> affinity_control_done;
  for (std::size_t index = 0; index < 32; ++index) {
    ComputeTaskOptions options;
    options.control = true;
    options.preferred_worker = index % 2;
    assert(control_affinity.submitContinuation(
               std::move(options), [] {},
               [&](SchedulerSubmitStatus status, std::exception_ptr error) {
                 assert(status == SchedulerSubmitStatus::Accepted);
                 assert(!error);
                 if (affinity_control_completed.fetch_add(
                         1, std::memory_order_acq_rel) == 31)
                   affinity_control_done.set_value();
               }) == SchedulerSubmitStatus::Accepted);
  }
  affinity_release.set_value();
  affinity_control_done.get_future().wait();
  const ComputeExecutorSnapshot control_affinity_snapshot =
      control_affinity.snapshot();
  assert(control_affinity_snapshot.control_queued_entries == 0);
  uint64_t control_affinity_hits = 0;
  for (const ComputeWorkerSnapshot &worker :
       control_affinity_snapshot.worker_metrics)
    control_affinity_hits += worker.affinity_hits;
  assert(control_affinity_hits > 0);
  control_affinity.shutdown(false);

  ComputeExecutor cooperative({1, 2, 1024, 2});
  std::promise<void> outer_ready;
  std::promise<void> dispatch_now;
  std::shared_future<void> dispatch_signal =
      dispatch_now.get_future().share();
  std::atomic<bool> inner_ran{false};
  auto outer = cooperative.submit({}, [&] {
    outer_ready.set_value();
    dispatch_signal.wait();
    assert(cooperative.runOnePendingCooperatively());
    assert(inner_ran.load(std::memory_order_acquire));
  });
  outer_ready.get_future().wait();
  auto inner = cooperative.submit(
      {}, [&] { inner_ran.store(true, std::memory_order_release); });
  assert(inner.status == SchedulerSubmitStatus::Accepted);
  dispatch_now.set_value();
  outer.future.get();
  inner.future.get();
  cooperative.requestShutdown(false);
  assert(cooperative.join());
  const ComputeExecutorSnapshot cooperative_snapshot =
      cooperative.snapshot();
  uint64_t cooperative_executed = 0;
  for (const ComputeWorkerSnapshot &worker :
       cooperative_snapshot.worker_metrics)
    cooperative_executed += worker.executed;
  assert(cooperative_executed == 2);

  ComputeExecutor completion_executor({1, 1, 1024});
  std::promise<void> completion_release;
  std::shared_future<void> completion_released =
      completion_release.get_future().share();
  std::promise<void> completion_started;
  auto completion_blocker = completion_executor.submit({}, [&] {
    completion_started.set_value();
    completion_released.wait();
  });
  completion_started.get_future().wait();
  std::atomic<uint64_t> completion_count{0};
  std::promise<SchedulerSubmitStatus> completion_status;
  assert(completion_executor.submitContinuation(
             {}, [] {},
             [&](SchedulerSubmitStatus status, std::exception_ptr error) {
               assert(error);
               completion_count.fetch_add(1, std::memory_order_relaxed);
               completion_status.set_value(status);
             }) == SchedulerSubmitStatus::Accepted);
  completion_executor.requestShutdown(true);
  assert(completion_status.get_future().get() ==
         SchedulerSubmitStatus::Stopping);
  completion_release.set_value();
  completion_blocker.future.get();
  assert(completion_executor.join());
  assert(completion_count.load(std::memory_order_relaxed) == 1);
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

  auto final_capacity = std::make_shared<RequestContext>(
      "final-capacity", RequestContext::Clock::now());
  final_capacity->suggestFailure(RequestFailureAttribution::Upstream);
  assert(final_capacity->markWorkAdmitted());
  final_capacity->setFinalFailureAttribution(
      RequestFailureAttribution::Capacity);
  assert(final_capacity->suggestedFailure() ==
         RequestFailureAttribution::Capacity);
  metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 3);
  assert(metrics.server_capacity_failure_after_admission == 3);

  auto internal = std::make_shared<RequestContext>(
      "internal-work", RequestContext::Clock::now(),
      RequestContext::Clock::time_point::max(),
      RequestContextKind::InternalWork);
  assert(!internal->markWorkAdmitted());
  internal->suggestFailure(RequestFailureAttribution::Capacity);
  metrics = requestLifecycleMetricsSnapshot();
  assert(metrics.work_admitted == 3);
  assert(metrics.server_capacity_failure_after_admission == 3);
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
  cache.setGrowthFrozen(true);
  assert(cache.growthFrozen());
  const size_t frozen_size = cache.size();
  const size_t frozen_bytes = cache.bytes();
  const int before_frozen_miss = computations.load();
  assert(compute("frozen-miss", "not-retained") == "not-retained");
  assert(computations.load() == before_frozen_miss + 1);
  assert(cache.size() == frozen_size && cache.bytes() == frozen_bytes);
  assert(compute("same-content:type-b", "wrong") == "type-miss");
  assert(cache.size() == frozen_size && cache.bytes() == frozen_bytes);
  cache.setGrowthFrozen(false);
  assert(!cache.growthFrozen());
  assert(compute("growth-restored", "retained") == "retained");
  cache.setLimits(1, 16);
  assert(cache.maxEntries() == 1 && cache.maxBytes() == 16 &&
         cache.size() <= 1 && cache.bytes() <= 16);

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

  PressureGuardState pressure_guard;
  PressureGuardDecision guard_decision = pressureGuardStep(
      pressure_guard, {false, false, "telemetry_error"});
  assert(!guard_decision.guarded && !guard_decision.limits_changed &&
         std::string(guard_decision.state) == "max_ready" &&
         std::string(guard_decision.reason) ==
             "telemetry_unavailable_full");
  guard_decision = pressureGuardStep(
      pressure_guard, {true, true, "memory_high_event"});
  assert(guard_decision.guarded && guard_decision.limits_changed &&
         pressure_guard.activations == 1 &&
         std::string(guard_decision.state) == "pressure_guarded");
  guard_decision = pressureGuardStep(
      pressure_guard, {true, true, "memory_high_event"});
  assert(guard_decision.guarded && !guard_decision.limits_changed &&
         pressure_guard.activations == 1);
  guard_decision = pressureGuardStep(
      pressure_guard, {false, true, "none"});
  assert(guard_decision.guarded &&
         std::string(guard_decision.state) == "recovery_confirm");
  guard_decision = pressureGuardStep(
      pressure_guard, {false, true, "none"});
  assert(guard_decision.guarded);
  guard_decision = pressureGuardStep(
      pressure_guard, {false, true, "none"});
  assert(!guard_decision.guarded && guard_decision.limits_changed &&
         pressure_guard.recoveries == 1);
  guard_decision = pressureGuardStep(
      pressure_guard, {true, true, "nofile_headroom_exhausted"});
  assert(guard_decision.guarded && pressure_guard.activations == 2 &&
         pressure_guard.repeated_activations == 1);
  guard_decision = pressureGuardStep(
      pressure_guard, {false, false, "telemetry_error"});
  assert(!guard_decision.guarded && guard_decision.limits_changed &&
         pressure_guard.recoveries == 2);

  ResourceGovernorState adaptive_governor{4, 0, 0};
  ResourceGovernorDecision decision = governorStep(
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

  ResourceEnvelope bounded_envelope;
  bounded_envelope.schedulable_cpu_millis = 6000;
  bounded_envelope.memory_current_bytes =
      UINT64_C(512) * 1024 * 1024;
  bounded_envelope.memory_max_bytes =
      UINT64_C(12) * 1024 * 1024 * 1024;
  bounded_envelope.host_available_memory_bytes =
      UINT64_C(10) * 1024 * 1024 * 1024;
  bounded_envelope.nofile_soft = 524288;
  bounded_envelope.nofile_hard = 524288;
  bounded_envelope.open_fds = 32;
  bounded_envelope.pids_current = 24;
  bounded_envelope.pids_max = 4096;
  bounded_envelope.complete = true;
  const ForceMaxBudget deterministic_first =
      calculateForceMaxBudget(bounded_envelope);
  const ForceMaxBudget deterministic_second =
      calculateForceMaxBudget(bounded_envelope);
  assert(deterministic_first == deterministic_second);
  assert(deterministic_first.valid);
  assert(deterministic_first.envelope_complete);
  assert(deterministic_first.compute_workers == 6);
  assert(deterministic_first.inbound_connections == 384);
  assert(deterministic_first.active_owners <=
         deterministic_first.active_flows);
  assert(deterministic_first.outbound_per_host <=
         deterministic_first.outbound_active);
  assert(deterministic_first.outbound_active <=
         deterministic_first.outbound_open);
  assert(deterministic_first.quickjs_workers == 3);
  assert(deterministic_first.formula_revision == "force-max-v4");
  assert(deterministic_first.startup_memory_bytes ==
         bounded_envelope.memory_current_bytes);
  assert(deterministic_first.memory_headroom_bytes ==
         bounded_envelope.host_available_memory_bytes);
  assert(deterministic_first.memory_capacity_bytes ==
         bounded_envelope.memory_current_bytes +
             bounded_envelope.host_available_memory_bytes);
  assert(deterministic_first.memory_budget_total ==
         deterministic_first.memory_headroom_bytes);
  assert(deterministic_first.quickjs_heap_bytes_per_worker > 0);
  assert(deterministic_first.quickjs_stack_bytes_per_worker > 0);
  assert(deterministic_first.blocking_io_queue_entries > 0);
  assert(deterministic_first.blocking_io_queue_bytes > 0);
  assert(deterministic_first.quickjs_queue_bytes +
             deterministic_first.quickjs_workers *
                 (deterministic_first.quickjs_heap_bytes_per_worker +
                  deterministic_first.quickjs_stack_bytes_per_worker) <=
         deterministic_first.working_memory_bytes);
  assert(deterministic_first.transport_active_bytes > 0);
  assert(deterministic_first.owner_active_bytes > 0);
  const uint64_t owner_reservation = forceMaxOwnerWorkingReservation(
      deterministic_first, 4096, UINT64_C(1) * 1024 * 1024);
  assert(owner_reservation >= UINT64_C(4) * 1024 * 1024);
  assert(owner_reservation >=
         deterministic_first.owner_active_bytes /
             deterministic_first.active_owners);
  assert(owner_reservation <= deterministic_first.owner_active_bytes);
  assert(forceMaxOwnerWorkingReservation(
             deterministic_first,
             deterministic_first.owner_active_bytes + 1,
             UINT64_C(1) * 1024 * 1024) ==
         deterministic_first.owner_active_bytes);
  assert(deterministic_first.reserved_pids == 6);
  assert(deterministic_first.fixed_threads == 7);
  assert(deterministic_first.resolver_thread_budget == 96);
  assert(deterministic_first.thread_budget_total ==
         deterministic_first.reserved_pids +
             deterministic_first.fixed_threads +
             deterministic_first.resolver_thread_budget +
             deterministic_first.compute_workers +
             deterministic_first.io_runners +
             deterministic_first.handler_permits +
             deterministic_first.quickjs_workers +
             deterministic_first.io_runners);
  ResourceEnvelope cares_envelope = bounded_envelope;
  cares_envelope.resolver_threads_per_transfer = 0;
  const ForceMaxBudget cares_budget =
      calculateForceMaxBudget(cares_envelope);
  assert(cares_budget.valid);
  assert(cares_budget.compute_workers ==
         deterministic_first.compute_workers);
  assert(cares_budget.resolver_thread_budget == 0);
  assert(cares_budget.thread_budget_total +
             deterministic_first.resolver_thread_budget ==
         deterministic_first.thread_budget_total);

  ResourceEnvelope httplib_envelope = bounded_envelope;
  httplib_envelope.http_handler_control_reserve = 1;
  const ForceMaxBudget httplib_budget =
      calculateForceMaxBudget(httplib_envelope);
  assert(httplib_budget.valid);
  assert(httplib_budget.compute_workers ==
         deterministic_first.compute_workers);
  assert(httplib_budget.handler_permits ==
         deterministic_first.handler_permits + 1);
  assert(httplib_budget.thread_budget_total ==
         deterministic_first.thread_budget_total + 1);
  ResourceEnvelope live_httplib_envelope = bounded_envelope;
  live_httplib_envelope.http_handler_threads_per_compute = 64;
  live_httplib_envelope.http_handler_control_reserve = 2;
  live_httplib_envelope.http_handler_stack_bytes =
      UINT64_C(8) * 1024 * 1024;
  live_httplib_envelope.http_handlers_own_inbound = true;
  const ForceMaxBudget live_httplib_budget =
      calculateForceMaxBudget(live_httplib_envelope);
  assert(live_httplib_budget.valid);
  assert(live_httplib_budget.compute_workers == 6);
  assert(live_httplib_budget.inbound_connections == 384);
  assert(live_httplib_budget.handler_permits == 386);
  assert(live_httplib_budget.handler_stack_bytes ==
         UINT64_C(386) * 8 * 1024 * 1024);
  ResourceEnvelope fd_clamped_httplib = live_httplib_envelope;
  fd_clamped_httplib.nofile_soft = 256;
  fd_clamped_httplib.nofile_hard = 256;
  fd_clamped_httplib.open_fds = 32;
  fd_clamped_httplib.pids_current = 24;
  fd_clamped_httplib.pids_max = 174;
  const ForceMaxBudget fd_clamped_httplib_budget =
      calculateForceMaxBudget(fd_clamped_httplib);
  assert(fd_clamped_httplib_budget.valid);
  assert(fd_clamped_httplib_budget.compute_workers == 6);
  assert(fd_clamped_httplib_budget.inbound_connections == 80);
  assert(fd_clamped_httplib_budget.handler_permits == 82);
  assert(fd_clamped_httplib_budget.resolver_thread_budget == 23);
  assert(fd_clamped_httplib_budget.thread_budget_total == 131);
  assert(fd_clamped_httplib_budget.active_flows == 39);
  assert(fd_clamped_httplib_budget.active_owners == 39);
  ResourceEnvelope more_nofile_httplib = fd_clamped_httplib;
  more_nofile_httplib.nofile_soft = 512;
  more_nofile_httplib.nofile_hard = 512;
  const ForceMaxBudget more_nofile_httplib_budget =
      calculateForceMaxBudget(more_nofile_httplib);
  assert(more_nofile_httplib_budget.valid);
  assert(more_nofile_httplib_budget.compute_workers ==
         fd_clamped_httplib_budget.compute_workers);
  assert(more_nofile_httplib_budget.inbound_connections >=
         fd_clamped_httplib_budget.inbound_connections);
  assert(more_nofile_httplib_budget.active_flows >=
         fd_clamped_httplib_budget.active_flows);
  assert(more_nofile_httplib_budget.outbound_active >=
         fd_clamped_httplib_budget.outbound_active);
  ResourceEnvelope cares_httplib = more_nofile_httplib;
  cares_httplib.resolver_threads_per_transfer = 0;
  const ForceMaxBudget cares_httplib_budget =
      calculateForceMaxBudget(cares_httplib);
  assert(cares_httplib_budget.valid);
  assert(cares_httplib_budget.compute_workers ==
         more_nofile_httplib_budget.compute_workers);
  assert(cares_httplib_budget.handler_permits >=
         more_nofile_httplib_budget.handler_permits);
  assert(cares_httplib_budget.inbound_connections >=
         more_nofile_httplib_budget.inbound_connections);
  assert(cares_httplib_budget.resolver_thread_budget == 0);

  ResourceEnvelope memory_clamped_httplib = live_httplib_envelope;
  memory_clamped_httplib.memory_max_bytes =
      UINT64_C(2560) * 1024 * 1024;
  const ForceMaxBudget memory_clamped_httplib_budget =
      calculateForceMaxBudget(memory_clamped_httplib);
  assert(memory_clamped_httplib_budget.valid);
  assert(memory_clamped_httplib_budget.compute_workers == 6);
  assert(memory_clamped_httplib_budget.handler_permits == 223);
  assert(memory_clamped_httplib_budget.handler_stack_bytes ==
         UINT64_C(223) * 8 * 1024 * 1024);
  ResourceEnvelope overflowing_handler_envelope = bounded_envelope;
  overflowing_handler_envelope.http_handler_control_reserve = UINT64_MAX;
  const ForceMaxBudget overflowing_handler_budget =
      calculateForceMaxBudget(overflowing_handler_envelope);
  assert(!overflowing_handler_budget.valid);
  assert(overflowing_handler_budget.validation_error ==
         "integer_overflow");

  ResourceEnvelope fractional_envelope = bounded_envelope;
  fractional_envelope.schedulable_cpu_millis = 500;
  const ForceMaxBudget fractional_budget =
      calculateForceMaxBudget(fractional_envelope);
  assert(fractional_budget.valid);
  assert(fractional_budget.compute_workers == 1);

  ResourceEnvelope two_cpu_envelope = bounded_envelope;
  two_cpu_envelope.schedulable_cpu_millis = 2000;
  const ForceMaxBudget two_cpu =
      calculateForceMaxBudget(two_cpu_envelope);
  assert(two_cpu.valid);
  assert(deterministic_first.compute_workers >= two_cpu.compute_workers);
  assert(deterministic_first.compute_permits >= two_cpu.compute_permits);
  assert(deterministic_first.active_owners >= two_cpu.active_owners);
  assert(deterministic_first.active_flows >= two_cpu.active_flows);
  assert(deterministic_first.inbound_connections >=
         two_cpu.inbound_connections);
  assert(deterministic_first.outbound_active >= two_cpu.outbound_active);

  ResourceEnvelope small_memory_envelope = bounded_envelope;
  small_memory_envelope.memory_max_bytes =
      UINT64_C(1) * 1024 * 1024 * 1024;
  const ForceMaxBudget small_memory =
      calculateForceMaxBudget(small_memory_envelope);
  assert(small_memory.valid);
  assert(deterministic_first.memory_budget_total >=
         small_memory.memory_budget_total);
  assert(deterministic_first.retained_response_bytes >=
         small_memory.retained_response_bytes);
  assert(deterministic_first.fetch_bytes >= small_memory.fetch_bytes);
  assert(deterministic_first.cache_bytes >= small_memory.cache_bytes);
  assert(deterministic_first.working_memory_bytes >=
         small_memory.working_memory_bytes);
  assert(deterministic_first.quickjs_heap_bytes_per_worker >=
         small_memory.quickjs_heap_bytes_per_worker);

  ResourceEnvelope occupied_envelope = bounded_envelope;
  occupied_envelope.memory_current_bytes =
      UINT64_C(4) * 1024 * 1024 * 1024;
  const ForceMaxBudget occupied =
      calculateForceMaxBudget(occupied_envelope);
  assert(occupied.valid);
  assert(occupied.memory_capacity_bytes ==
         bounded_envelope.memory_max_bytes);
  assert(occupied.memory_headroom_bytes ==
         UINT64_C(8) * 1024 * 1024 * 1024);
  assert(occupied.memory_budget_total <
         deterministic_first.memory_budget_total);

  ResourceEnvelope portable_envelope;
  portable_envelope.schedulable_cpu_millis = 1500;
  portable_envelope.memory_current_bytes =
      UINT64_C(128) * 1024 * 1024;
  portable_envelope.host_total_memory_bytes =
      UINT64_C(512) * 1024 * 1024;
  portable_envelope.host_available_memory_bytes =
      UINT64_C(256) * 1024 * 1024;
  const ForceMaxBudget portable =
      calculateForceMaxBudget(portable_envelope);
  assert(portable.valid);
  assert(!portable.envelope_complete);
  assert(portable.startup_memory_bytes ==
         portable_envelope.memory_current_bytes);
  assert(portable.memory_headroom_bytes ==
         portable_envelope.host_available_memory_bytes);
  assert(portable.memory_capacity_bytes ==
         UINT64_C(384) * 1024 * 1024);

  ResourceEnvelope unknown_cgroup_envelope = portable_envelope;
  unknown_cgroup_envelope.cgroup_scope_known = false;
  const ForceMaxBudget unknown_cgroup =
      calculateForceMaxBudget(unknown_cgroup_envelope);
  assert(!unknown_cgroup.valid);
  assert(unknown_cgroup.validation_error == "unknown_cgroup_scope");

  ResourceEnvelope missing_current_envelope = portable_envelope;
  missing_current_envelope.memory_current_bytes = 0;
  const ForceMaxBudget missing_current =
      calculateForceMaxBudget(missing_current_envelope);
  assert(!missing_current.valid);
  assert(missing_current.validation_error ==
         "memory_current_unavailable");

  std::string validation_error;
  ResourceEnvelope low_headroom_envelope = bounded_envelope;
  low_headroom_envelope.memory_current_bytes =
      UINT64_C(64) * 1024 * 1024;
  low_headroom_envelope.memory_max_bytes =
      UINT64_C(72) * 1024 * 1024;
  low_headroom_envelope.host_available_memory_bytes =
      UINT64_C(128) * 1024 * 1024;
  const ForceMaxBudget low_headroom =
      calculateForceMaxBudget(low_headroom_envelope);
  assert(low_headroom.valid);
  assert(!validateForceMaxFetchContract(
      low_headroom, UINT64_C(2) * 1024 * 1024,
      &validation_error));
  assert(validation_error ==
         "fetch_budget_below_download_contract");
  assert(validateForceMaxFetchContract(
      low_headroom, UINT64_C(256) * 1024,
      &validation_error));
  assert(validation_error.empty());

  ResourceEnvelope exhausted_memory_envelope = bounded_envelope;
  exhausted_memory_envelope.memory_current_bytes =
      exhausted_memory_envelope.memory_max_bytes;
  const ForceMaxBudget exhausted_memory =
      calculateForceMaxBudget(exhausted_memory_envelope);
  assert(!exhausted_memory.valid);
  assert(exhausted_memory.validation_error ==
         "memory_headroom_exhausted");

  ResourceEnvelope overflowing_memory_envelope;
  overflowing_memory_envelope.memory_current_bytes = UINT64_MAX - 3;
  overflowing_memory_envelope.host_available_memory_bytes = 16;
  const ResourceMemoryLedger overflowing_memory =
      resourceEnvelopeMemoryLedger(overflowing_memory_envelope);
  assert(overflowing_memory.valid);
  assert(overflowing_memory.startup_bytes == UINT64_MAX - 3);
  assert(overflowing_memory.headroom_bytes == 3);
  assert(overflowing_memory.capacity_bytes == UINT64_MAX);

  ResourceEnvelope low_nofile_envelope = portable_envelope;
  low_nofile_envelope.nofile_soft = 160;
  low_nofile_envelope.open_fds = 8;
  const ForceMaxBudget low_nofile =
      calculateForceMaxBudget(low_nofile_envelope);
  assert(low_nofile.valid);
  assert(low_nofile.compute_workers == 2);
  assert(low_nofile.outbound_open + low_nofile.inbound_connections <= 88);

  ResourceEnvelope exhausted_nofile_envelope = portable_envelope;
  exhausted_nofile_envelope.nofile_soft = 8;
  exhausted_nofile_envelope.open_fds = 8;
  const ForceMaxBudget exhausted_nofile =
      calculateForceMaxBudget(exhausted_nofile_envelope);
  assert(!exhausted_nofile.valid);
  assert(exhausted_nofile.validation_error == "nofile_exhausted");

  ForceMaxBudget overflow = deterministic_first;
  overflow.transport_queue_bytes = UINT64_MAX;
  overflow.owner_queue_bytes = 1;
  assert(!validateForceMaxBudget(overflow, &validation_error));
  assert(validation_error == "queue_budget_overflow");

  ResourceEnvelope tight_pids_envelope = bounded_envelope;
  tight_pids_envelope.pids_current = 24;
  tight_pids_envelope.pids_max = 59;
  const ForceMaxBudget tight_pids =
      calculateForceMaxBudget(tight_pids_envelope);
  assert(tight_pids.valid);
  assert(tight_pids.compute_workers == 3);
  assert(tight_pids.handler_permits == 12);
  assert(tight_pids.thread_budget_total == 35);
  assert(tight_pids.fixed_threads == 7);
  assert(tight_pids.resolver_thread_budget == 6);
  assert(tight_pids.resolver_thread_budget == tight_pids.outbound_active);
  assert(tight_pids.reserved_pids == 4);

  ResourceEnvelope tight_pids_beast_envelope = tight_pids_envelope;
  tight_pids_beast_envelope.http_handler_threads_per_compute = 1;
  tight_pids_beast_envelope.pids_max = 74;
  ResourceEnvelope tight_pids_httplib_peer = tight_pids_beast_envelope;
  tight_pids_httplib_peer.http_handler_threads_per_compute = 4;
  const ForceMaxBudget tight_pids_beast =
      calculateForceMaxBudget(tight_pids_beast_envelope);
  const ForceMaxBudget tight_pids_httplib_peer_budget =
      calculateForceMaxBudget(tight_pids_httplib_peer);
  assert(tight_pids_beast.valid);
  assert(tight_pids_httplib_peer_budget.valid);
  assert(tight_pids_beast.compute_workers >
         tight_pids_httplib_peer_budget.compute_workers);
  assert(tight_pids_beast.handler_permits ==
         tight_pids_beast.compute_workers);
  assert(tight_pids_beast.thread_budget_total <=
         tight_pids_beast_envelope.pids_max -
             tight_pids_beast_envelope.pids_current);
  assert(!forceMaxPidsHeadroomExhausted(59, 55, 4));
  assert(forceMaxPidsHeadroomExhausted(59, 56, 4));
  assert(forceMaxRequiredPidHeadroom(4, 16, 0) == 20);
  assert(forceMaxRequiredPidHeadroom(4, 16, 5) == 15);
  assert(forceMaxRequiredPidHeadroom(4, 16, 16) == 4);
  ResourceEnvelope exhausted_pids_envelope = tight_pids_envelope;
  exhausted_pids_envelope.pids_max = 43;
  const ForceMaxBudget exhausted_pids =
      calculateForceMaxBudget(exhausted_pids_envelope);
  assert(!exhausted_pids.valid);
  assert(exhausted_pids.validation_error == "pids_exhausted");
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

static void testOwnerAdmission() {
  OwnerAdmission admission({1, 10, 3, 20});
  const auto settings_deadline =
      RequestContext::Clock::now() + 10s;
  auto first_context = std::make_shared<RequestContext>(
      "owner-first", RequestContext::Clock::now(), settings_deadline);
  std::promise<OwnerAdmissionResult> first_completion;
  auto first_future = first_completion.get_future();
  const OwnerAdmissionStatus first_submit = admission.admit(
      {.cost = RequestCostClass::Medium,
       .bytes = 6,
       .request_context = first_context},
      [&](OwnerAdmissionResult result) {
        first_completion.set_value(std::move(result));
      });
  OwnerAdmissionResult first = first_future.get();
  assert(first_submit == OwnerAdmissionStatus::Granted);
  assert(first.status == OwnerAdmissionStatus::Granted && first.lease);

  auto cancelled_context = std::make_shared<RequestContext>(
      "owner-cancelled", RequestContext::Clock::now(), settings_deadline);
  std::promise<OwnerAdmissionResult> cancelled_completion;
  auto cancelled_future = cancelled_completion.get_future();
  const OwnerAdmissionStatus cancelled_submit = admission.admit(
      {.cost = RequestCostClass::Low,
       .bytes = 5,
       .request_context = cancelled_context},
      [&](OwnerAdmissionResult result) {
        cancelled_completion.set_value(std::move(result));
      });
  assert(cancelled_submit == OwnerAdmissionStatus::Granted);
  const bool cancellation_requested =
      cancelled_context->requestCancellation(
          RequestCancellationReason::ClientDisconnected);
  OwnerAdmissionResult cancelled = cancelled_future.get();
  assert(cancellation_requested);
  assert(cancelled.status == OwnerAdmissionStatus::Cancelled);

  auto next_context = std::make_shared<RequestContext>(
      "owner-next", RequestContext::Clock::now(), settings_deadline);
  std::promise<OwnerAdmissionResult> next_completion;
  auto next_future = next_completion.get_future();
  const OwnerAdmissionStatus next_submit = admission.admit(
      {.cost = RequestCostClass::High,
       .bytes = 4,
       .request_context = next_context},
      [&](OwnerAdmissionResult result) {
        next_completion.set_value(std::move(result));
      });
  assert(next_submit == OwnerAdmissionStatus::Granted);
  assert(next_future.wait_for(0ms) != std::future_status::ready);
  first.lease.reset();
  OwnerAdmissionResult next = next_future.get();
  assert(next.status == OwnerAdmissionStatus::Granted && next.lease);

  auto deadline_context = std::make_shared<RequestContext>(
      "owner-deadline", RequestContext::Clock::now(),
      RequestContext::Clock::now() + 50ms);
  std::promise<OwnerAdmissionResult> deadline_completion;
  auto deadline_future = deadline_completion.get_future();
  const OwnerAdmissionStatus deadline_submit = admission.admit(
      {.cost = RequestCostClass::Medium,
       .bytes = 4,
       .request_context = deadline_context},
      [&](OwnerAdmissionResult result) {
        deadline_completion.set_value(std::move(result));
      });
  assert(deadline_submit == OwnerAdmissionStatus::Granted);
  OwnerAdmissionResult deadline = deadline_future.get();
  assert(deadline.status == OwnerAdmissionStatus::Deadline);

  std::promise<OwnerAdmissionResult> oversized_completion;
  auto oversized_future = oversized_completion.get_future();
  const OwnerAdmissionStatus oversized_submit = admission.admit(
      {.cost = RequestCostClass::Medium,
       .bytes = 11,
       .request_context = std::make_shared<RequestContext>(
           "owner-oversized", RequestContext::Clock::now(),
           settings_deadline)},
      [&](OwnerAdmissionResult result) {
        oversized_completion.set_value(std::move(result));
      });
  OwnerAdmissionResult oversized = oversized_future.get();
  assert(oversized_submit == OwnerAdmissionStatus::ByteLimit);
  assert(oversized.status == OwnerAdmissionStatus::ByteLimit);

  std::vector<std::shared_ptr<RequestContext>> pending_contexts;
  std::vector<std::shared_ptr<std::promise<OwnerAdmissionResult>>>
      pending_promises;
  std::vector<std::future<OwnerAdmissionResult>> pending_futures;
  for (int index = 0; index < 3; ++index) {
    auto context = std::make_shared<RequestContext>(
        "owner-pending-" + std::to_string(index),
        RequestContext::Clock::now(), settings_deadline);
    auto completion =
        std::make_shared<std::promise<OwnerAdmissionResult>>();
    pending_futures.emplace_back(completion->get_future());
    const OwnerAdmissionStatus status = admission.admit(
        {.cost = RequestCostClass::Medium,
         .bytes = 1,
         .request_context = context},
        [completion](OwnerAdmissionResult result) {
          completion->set_value(std::move(result));
        });
    assert(status == OwnerAdmissionStatus::Granted);
    pending_contexts.emplace_back(std::move(context));
    pending_promises.emplace_back(std::move(completion));
  }
  std::promise<OwnerAdmissionResult> full_completion;
  auto full_future = full_completion.get_future();
  const OwnerAdmissionStatus full_submit = admission.admit(
      {.cost = RequestCostClass::Medium,
       .bytes = 1,
       .request_context = std::make_shared<RequestContext>(
           "owner-full", RequestContext::Clock::now(),
           settings_deadline)},
      [&](OwnerAdmissionResult result) {
        full_completion.set_value(std::move(result));
      });
  OwnerAdmissionResult full = full_future.get();
  assert(full_submit == OwnerAdmissionStatus::EntryLimit);
  assert(full.status == OwnerAdmissionStatus::EntryLimit);

  admission.requestShutdown();
  for (auto &future : pending_futures) {
    OwnerAdmissionResult pending = future.get();
    assert(pending.status == OwnerAdmissionStatus::Shutdown);
  }
  next.lease.reset();
  const bool joined = admission.join();
  const OwnerAdmissionSnapshot snapshot = admission.snapshot();
  assert(joined && snapshot.ready && snapshot.stopping && snapshot.joined);
  assert(snapshot.active_entries == 0 && snapshot.active_bytes == 0);
  assert(snapshot.waiting_entries == 0 && snapshot.waiting_bytes == 0);
  assert(snapshot.accepted_total == 2);
  assert(snapshot.rejected_total == 2);
  assert(snapshot.cancelled_total == 1);
  assert(snapshot.deadline_total == 1);
  assert(snapshot.shutdown_total == 3);

  OwnerAdmission fair({1, 100, 8, 800});
  auto submit_probe = [&](std::string id, RequestCostClass cost) {
    auto promise =
        std::make_shared<std::promise<OwnerAdmissionResult>>();
    auto future = promise->get_future();
    const OwnerAdmissionStatus status = fair.admit(
        {.cost = cost,
         .bytes = 1,
         .request_context = std::make_shared<RequestContext>(
             std::move(id), RequestContext::Clock::now(),
             RequestContext::Clock::now() + 10s)},
        [promise](OwnerAdmissionResult result) {
          promise->set_value(std::move(result));
        });
    assert(status == OwnerAdmissionStatus::Granted);
    return future;
  };
  auto held_future = submit_probe("fair-held", RequestCostClass::Medium);
  OwnerAdmissionResult held = held_future.get();
  auto high_future = submit_probe("fair-high", RequestCostClass::High);
  auto low_future = submit_probe("fair-low", RequestCostClass::Low);
  held.lease.reset();
  OwnerAdmissionResult low = low_future.get();
  assert(low.status == OwnerAdmissionStatus::Granted);
  assert(high_future.wait_for(0ms) != std::future_status::ready);
  low.lease.reset();
  OwnerAdmissionResult high = high_future.get();

  auto aged_high_future =
      submit_probe("fair-aged-high", RequestCostClass::High);
  std::this_thread::sleep_for(520ms);
  auto new_low_future =
      submit_probe("fair-new-low", RequestCostClass::Low);
  high.lease.reset();
  OwnerAdmissionResult aged_high = aged_high_future.get();
  assert(aged_high.status == OwnerAdmissionStatus::Granted);
  assert(new_low_future.wait_for(0ms) != std::future_status::ready);
  aged_high.lease.reset();
  OwnerAdmissionResult new_low = new_low_future.get();
  assert(new_low.status == OwnerAdmissionStatus::Granted);
  new_low.lease.reset();
  fair.requestShutdown();
  const bool fair_joined = fair.join();
  assert(fair_joined);

  OwnerAdmission dynamic({2, 20, 4, 40});
  auto dynamic_submit = [&](std::string id) {
    auto promise =
        std::make_shared<std::promise<OwnerAdmissionResult>>();
    auto future = promise->get_future();
    const OwnerAdmissionStatus status = dynamic.admit(
        {.cost = RequestCostClass::Medium,
         .bytes = 5,
         .request_context = std::make_shared<RequestContext>(
             std::move(id), RequestContext::Clock::now(),
             RequestContext::Clock::now() + 10s)},
        [promise](OwnerAdmissionResult result) {
          promise->set_value(std::move(result));
        });
    assert(status == OwnerAdmissionStatus::Granted);
    return future;
  };
  auto dynamic_first_future = dynamic_submit("dynamic-first");
  auto dynamic_second_future = dynamic_submit("dynamic-second");
  OwnerAdmissionResult dynamic_first = dynamic_first_future.get();
  OwnerAdmissionResult dynamic_second = dynamic_second_future.get();
  const bool limits_lowered = dynamic.setActiveLimits(1, 10);
  const OwnerAdmissionSnapshot lowered = dynamic.snapshot();
  assert(limits_lowered && lowered.max_active_entries == 1 &&
         lowered.max_active_bytes == 10 && lowered.active_entries == 2);
  auto dynamic_waiter_future = dynamic_submit("dynamic-waiter");
  dynamic_first.lease.reset();
  assert(dynamic_waiter_future.wait_for(0ms) != std::future_status::ready);
  dynamic_second.lease.reset();
  OwnerAdmissionResult dynamic_waiter = dynamic_waiter_future.get();
  assert(dynamic_waiter.status == OwnerAdmissionStatus::Granted &&
         dynamic_waiter.lease);
  const bool limits_restored = dynamic.setActiveLimits(2, 20);
  const OwnerAdmissionSnapshot restored = dynamic.snapshot();
  assert(limits_restored && restored.max_active_entries == 2 &&
         restored.max_active_bytes == 20);
  dynamic_waiter.lease.reset();
  dynamic.requestShutdown();
  const bool dynamic_joined = dynamic.join();
  assert(dynamic_joined);

  const GlobalOwnerAdmissionInitStatus invalid_global =
      initializeGlobalOwnerAdmission({0, 1, 1, 1});
  const GlobalOwnerAdmissionInitStatus initialized_global =
      initializeGlobalOwnerAdmission({2, 32, 4, 64});
  const GlobalOwnerAdmissionInitStatus same_global =
      initializeGlobalOwnerAdmission({2, 32, 4, 64});
  const GlobalOwnerAdmissionInitStatus mismatch_global =
      initializeGlobalOwnerAdmission({3, 32, 4, 64});
  assert(invalid_global ==
         GlobalOwnerAdmissionInitStatus::InvalidBudget);
  assert(initialized_global ==
         GlobalOwnerAdmissionInitStatus::Initialized);
  assert(same_global ==
         GlobalOwnerAdmissionInitStatus::AlreadyInitialized);
  assert(mismatch_global ==
         GlobalOwnerAdmissionInitStatus::BudgetMismatch);
  assert(globalOwnerAdmission() != nullptr);
  const bool global_limits =
      setGlobalOwnerAdmissionActiveLimits(1, 16);
  const OwnerAdmissionSnapshot global_limited =
      globalOwnerAdmissionSnapshot();
  assert(global_limits && global_limited.max_active_entries == 1 &&
         global_limited.max_active_bytes == 16);
  requestGlobalOwnerAdmissionShutdown();
  const bool global_joined = joinGlobalOwnerAdmission();
  const OwnerAdmissionSnapshot global_snapshot =
      globalOwnerAdmissionSnapshot();
  assert(global_joined && global_snapshot.stopping &&
         global_snapshot.joined);
}

static void testBlockingIoExecutor() {
  const BlockingIoExecutorInitStatus invalid =
      initializeBlockingIoExecutor({0, 1, 1});
  const BlockingIoExecutorInitStatus initialized =
      initializeBlockingIoExecutor({2, 4, 1024});
  const BlockingIoExecutorInitStatus same =
      initializeBlockingIoExecutor({2, 4, 1024});
  const BlockingIoExecutorInitStatus mismatch =
      initializeBlockingIoExecutor({3, 4, 1024});
  assert(invalid == BlockingIoExecutorInitStatus::InvalidBudget);
  assert(initialized == BlockingIoExecutorInitStatus::Initialized);
  assert(same == BlockingIoExecutorInitStatus::AlreadyInitialized);
  assert(mismatch == BlockingIoExecutorInitStatus::BudgetMismatch);

  std::promise<SchedulerSubmitStatus> completed;
  auto completed_future = completed.get_future();
  std::atomic<bool> ran{false};
  ComputeTaskOptions options;
  options.cost = RequestCostClass::Low;
  options.bytes = 5;
  const SchedulerSubmitStatus submitted = submitBlockingIo(
      std::move(options),
      [&] { ran.store(true, std::memory_order_release); },
      [&](SchedulerSubmitStatus status, std::exception_ptr error) {
        completed.set_value(error ? SchedulerSubmitStatus::Stopping
                                  : status);
      });
  assert(submitted == SchedulerSubmitStatus::Accepted);
  const SchedulerSubmitStatus completion_status = completed_future.get();
  assert(completion_status == SchedulerSubmitStatus::Accepted);
  assert(ran.load(std::memory_order_acquire));
  const ComputeExecutorSnapshot active = blockingIoExecutorSnapshot();
  assert(active.initialized && active.ready && active.workers == 2);

  requestBlockingIoExecutorShutdown();
  const bool joined = joinBlockingIoExecutor();
  const ComputeExecutorSnapshot stopped = blockingIoExecutorSnapshot();
  assert(joined && stopped.stopping && stopped.queued_entries == 0 &&
         stopped.queued_bytes == 0 && stopped.active_workers == 0);
}

static void testFetchMemoryBudget() {
  configureGlobalFetchMemoryBudget(64);
  const FetchMemoryBudgetSnapshot configured =
      globalFetchMemoryBudgetSnapshot();
  assert(configured.enabled && configured.limit == 64 &&
         configured.used == 0);

  FetchMemoryLease first;
  FetchMemoryLease second;
  FetchMemoryLease oversized;
  assert(!oversized.acquire(65));
  assert(first.acquire(40));
  assert(!second.acquire(32));
  noteGlobalFetchMemoryWaiterAdded();
  FetchMemoryBudgetSnapshot waiting = globalFetchMemoryBudgetSnapshot();
  assert(waiting.used == 40 && waiting.peak == 40 &&
         waiting.waiters == 1 && waiting.wait_total == 1);

  const uint64_t before_release = waiting.capacity_generation;
  first.reset();
  assert(globalFetchMemoryCapacityGeneration() > before_release);
  assert(second.acquire(32));
  noteGlobalFetchMemoryWaiterRemoved(true);
  FetchMemoryLease moved = std::move(second);
  assert(moved.bytes() == 32 && second.bytes() == 0);
  moved.reset();

  const FetchMemoryBudgetSnapshot released =
      globalFetchMemoryBudgetSnapshot();
  assert(released.used == 0 && released.waiters == 0 &&
         released.resumed_total == 1);
}

int main() {
  testBoundedOutput();
  testBoundedExecutor();
  testBoundedExecutorDeadlineAndCancellation();
  testComputeExecutor();
  testWorkloadScheduler();
  testCooperativeCpuPermit();
  testWorkloadSchedulerActiveQueueWeights();
  testRetainedResponseByteBudget();
  testWorkAdmissionLifecycle();
  testActiveRequestShutdownCancellation();
  testCancellationTokenCallbacks();
  testOwnerAdmission();
  testBlockingIoExecutor();
  testFetchMemoryBudget();
  testConcurrentLruCache();
  testExternalConfigCacheSemantics();
  testResourceControlPrimitives();
  return 0;
}
