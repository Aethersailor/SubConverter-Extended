#ifndef BOUNDED_EXECUTOR_H_INCLUDED
#define BOUNDED_EXECUTOR_H_INCLUDED

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

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
  auto submit(Function &&function)
      -> std::future<std::invoke_result_t<std::decay_t<Function>>> {
    using Result = std::invoke_result_t<std::decay_t<Function>>;
    auto task = std::make_shared<std::packaged_task<Result()>>(
        std::forward<Function>(function));
    std::future<Result> future = task->get_future();
    std::function<void()> invoke = [task] { (*task)(); };
    bool run_inline = false;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_ || current_executor_ == this ||
          tasks_.size() >= queue_capacity_) {
        run_inline = true;
      } else {
        tasks_.emplace_back(std::move(invoke));
      }
    }

    if (run_inline)
      invoke();
    else
      cv_.notify_one();
    return future;
  }

  void shutdown() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return;
      stopping_ = true;
    }
    cv_.notify_all();
    for (std::thread &worker : workers_) {
      if (worker.joinable())
        worker.join();
    }
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
      task();
    }
    current_executor_ = nullptr;
  }

  inline static thread_local BoundedExecutor *current_executor_ = nullptr;
  const size_t queue_capacity_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> tasks_;
  std::vector<std::thread> workers_;
  bool stopping_ = false;
};

#endif // BOUNDED_EXECUTOR_H_INCLUDED
