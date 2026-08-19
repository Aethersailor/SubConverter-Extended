#ifndef BOUNDED_EXECUTOR_H_INCLUDED
#define BOUNDED_EXECUTOR_H_INCLUDED

#include <condition_variable>
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "server/request_context.h"

enum class ExecutorSubmitStatus {
  Accepted,
  QueueFull,
  Recursive,
  Deadline,
  Cancelled,
  Stopping,
};

class ExecutorSubmitError : public std::runtime_error {
public:
  explicit ExecutorSubmitError(ExecutorSubmitStatus status)
      : std::runtime_error(message(status)), status_(status) {}

  ExecutorSubmitStatus status() const noexcept { return status_; }

private:
  static std::string message(ExecutorSubmitStatus status) {
    switch (status) {
    case ExecutorSubmitStatus::QueueFull:
      return "bounded executor queue is full";
    case ExecutorSubmitStatus::Recursive:
      return "bounded executor rejected recursive submission";
    case ExecutorSubmitStatus::Deadline:
      return "bounded executor deadline exceeded";
    case ExecutorSubmitStatus::Cancelled:
      return "bounded executor request cancelled";
    case ExecutorSubmitStatus::Stopping:
      return "bounded executor is stopping";
    case ExecutorSubmitStatus::Accepted:
      break;
    }
    return "bounded executor submission error";
  }

  ExecutorSubmitStatus status_;
};

template <class Result> struct ExecutorSubmission {
  ExecutorSubmitStatus status = ExecutorSubmitStatus::Stopping;
  std::future<Result> future;
};

class BoundedExecutor {
public:
  BoundedExecutor(size_t worker_count, size_t queue_capacity)
      : queue_capacity_(queue_capacity ? queue_capacity : 1) {
    if (worker_count == 0)
      throw std::invalid_argument("BoundedExecutor requires at least one worker");
    workers_.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i)
      workers_.emplace_back([this] { workerLoop(); });
  }

  BoundedExecutor(const BoundedExecutor &) = delete;
  BoundedExecutor &operator=(const BoundedExecutor &) = delete;

  ~BoundedExecutor() { shutdown(); }

  template <class Function>
  auto trySubmit(Function &&function)
      -> ExecutorSubmission<std::invoke_result_t<std::decay_t<Function>>> {
    using Result = std::invoke_result_t<std::decay_t<Function>>;
    auto task = std::make_shared<std::packaged_task<Result()>>(
        std::forward<Function>(function));
    std::future<Result> future = task->get_future();
    std::function<void()> invoke = [task] { (*task)(); };
    ExecutorSubmitStatus status = ExecutorSubmitStatus::Accepted;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_) {
        status = ExecutorSubmitStatus::Stopping;
      } else if (current_executor_ == this) {
        status = ExecutorSubmitStatus::Recursive;
      } else if (tasks_.size() >= queue_capacity_) {
        status = ExecutorSubmitStatus::QueueFull;
      } else {
        tasks_.emplace_back(std::move(invoke));
      }
    }

    if (status == ExecutorSubmitStatus::Accepted) {
      cv_.notify_one();
      return {status, std::move(future)};
    }
    task.reset();
    std::promise<Result> rejected;
    std::future<Result> rejected_future = rejected.get_future();
    rejected.set_exception(
        std::make_exception_ptr(ExecutorSubmitError(status)));
    return {status, std::move(rejected_future)};
  }

  template <class Function>
  auto submitUntil(std::chrono::steady_clock::time_point deadline,
                   RequestCancellationToken cancellation,
                   Function &&function)
      -> ExecutorSubmission<std::invoke_result_t<std::decay_t<Function>>> {
    using Result = std::invoke_result_t<std::decay_t<Function>>;
    auto task = std::make_shared<std::packaged_task<Result()>>(
        std::forward<Function>(function));
    std::future<Result> future = task->get_future();
    std::function<void()> invoke = [task] { (*task)(); };
    ExecutorSubmitStatus status = ExecutorSubmitStatus::Accepted;
    const auto queue_wait_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    {
      std::unique_lock<std::mutex> lock(mutex_);
      for (;;) {
        if (stopping_) {
          status = ExecutorSubmitStatus::Stopping;
          break;
        }
        if (current_executor_ == this) {
          status = ExecutorSubmitStatus::Recursive;
          break;
        }
        if (cancellation.isCancellationRequested()) {
          status = ExecutorSubmitStatus::Cancelled;
          break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (deadline != std::chrono::steady_clock::time_point::max() &&
            now >= deadline) {
          status = ExecutorSubmitStatus::Deadline;
          break;
        }
        if (now >= queue_wait_deadline) {
          status = ExecutorSubmitStatus::QueueFull;
          break;
        }
        if (tasks_.size() < queue_capacity_) {
          tasks_.emplace_back(std::move(invoke));
          break;
        }
        auto wake = now + std::chrono::milliseconds(10);
        wake = std::min(wake, queue_wait_deadline);
        if (deadline != std::chrono::steady_clock::time_point::max())
          wake = std::min(wake, deadline);
        space_cv_.wait_until(lock, wake);
      }
    }
    if (status == ExecutorSubmitStatus::Accepted) {
      cv_.notify_one();
      return {status, std::move(future)};
    }
    task.reset();
    std::promise<Result> rejected;
    std::future<Result> rejected_future = rejected.get_future();
    rejected.set_exception(
        std::make_exception_ptr(ExecutorSubmitError(status)));
    return {status, std::move(rejected_future)};
  }

  template <class Function>
  auto submit(Function &&function)
      -> std::future<std::invoke_result_t<std::decay_t<Function>>> {
    return trySubmit(std::forward<Function>(function)).future;
  }

  void requestShutdown(bool cancel_pending = false) {
    std::deque<std::function<void()>> cancelled_tasks;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return;
      stopping_ = true;
      if (cancel_pending)
        cancelled_tasks.swap(tasks_);
    }
    cv_.notify_all();
    space_cv_.notify_all();
  }

  void join() noexcept {
    for (std::thread &worker : workers_) {
      if (worker.joinable())
        worker.join();
    }
  }

  void shutdown(bool cancel_pending = false) {
    requestShutdown(cancel_pending);
    join();
  }

  size_t workerCount() const { return workers_.size(); }
  size_t queueCapacity() const { return queue_capacity_; }

private:
  void workerLoop() {
    current_executor_ = this;
    for (;;) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
        if (stopping_ && tasks_.empty())
          break;
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      space_cv_.notify_all();
      task();
    }
    current_executor_ = nullptr;
  }

  inline static thread_local BoundedExecutor *current_executor_ = nullptr;
  const size_t queue_capacity_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::condition_variable space_cv_;
  std::deque<std::function<void()>> tasks_;
  std::vector<std::thread> workers_;
  bool stopping_ = false;
};

#endif // BOUNDED_EXECUTOR_H_INCLUDED
