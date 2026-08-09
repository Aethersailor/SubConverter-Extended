#include "handler/curl_handle_pool.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <utility>

static std::atomic<CurlHandlePool *> activeGlobalCurlHandlePool {nullptr};

CurlHandleLease::CurlHandleLease(CurlHandleLease &&other) noexcept
    : pool_(std::exchange(other.pool_, nullptr)),
      handle_(std::exchange(other.handle_, nullptr)) {}

CurlHandleLease &
CurlHandleLease::operator=(CurlHandleLease &&other) noexcept {
  if (this != &other) {
    reset();
    pool_ = std::exchange(other.pool_, nullptr);
    handle_ = std::exchange(other.handle_, nullptr);
  }
  return *this;
}

CurlHandleLease::~CurlHandleLease() { reset(); }

void CurlHandleLease::reset() {
  if (pool_ && handle_)
    pool_->release(handle_);
  pool_ = nullptr;
  handle_ = nullptr;
}

CurlHandlePool::CurlHandlePool(size_t capacity)
    : capacity_(std::max<size_t>(1, capacity)) {
  idle_.reserve(capacity_);
}

CurlHandlePool::~CurlHandlePool() { shutdown(); }

void CurlHandlePool::shutdown() {
  std::vector<CURL *> handles;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_)
      return;
    assert(created_ == idle_.size());
    stopping_ = true;
    handles.swap(idle_);
  }
  cv_.notify_all();
  for (CURL *handle : handles)
    curl_easy_cleanup(handle);
}

CurlHandleLease CurlHandlePool::acquire() {
  std::unique_lock<std::mutex> lock(mutex_);
  cv_.wait(lock, [this] {
    return stopping_ || !idle_.empty() || created_ < capacity_;
  });
  if (stopping_)
    return {};
  if (!idle_.empty()) {
    CURL *handle = idle_.back();
    idle_.pop_back();
    return CurlHandleLease(this, handle);
  }

  ++created_;
  lock.unlock();
  CURL *handle = curl_easy_init();
  if (!handle) {
    lock.lock();
    --created_;
    lock.unlock();
    cv_.notify_one();
    return {};
  }
  return CurlHandleLease(this, handle);
}

void CurlHandlePool::release(CURL *handle) {
  if (!handle)
    return;

  curl_easy_setopt(handle, CURLOPT_COOKIELIST, "ALL");
  curl_easy_reset(handle);

  bool cleanup = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_) {
      --created_;
      cleanup = true;
    } else {
      idle_.push_back(handle);
    }
  }
  if (cleanup)
    curl_easy_cleanup(handle);
  else
    cv_.notify_one();
}

CurlHandlePool &globalCurlHandlePool(size_t configured_capacity) {
  static CurlHandlePool pool(configured_capacity);
  static const bool registered =
      (activeGlobalCurlHandlePool.store(&pool, std::memory_order_release), true);
  (void)registered;
  return pool;
}

size_t curlHandlePoolCapacity(size_t configured_capacity) {
  return globalCurlHandlePool(configured_capacity).capacity();
}

void shutdownGlobalCurlHandlePool() {
  CurlHandlePool *pool =
      activeGlobalCurlHandlePool.load(std::memory_order_acquire);
  if (pool)
    pool->shutdown();
}
