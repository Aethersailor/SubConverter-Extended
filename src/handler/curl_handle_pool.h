#ifndef CURL_HANDLE_POOL_H_INCLUDED
#define CURL_HANDLE_POOL_H_INCLUDED

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <vector>

#include <curl/curl.h>

class CurlHandlePool;

class CurlHandleLease {
public:
  CurlHandleLease() = default;
  CurlHandleLease(const CurlHandleLease &) = delete;
  CurlHandleLease &operator=(const CurlHandleLease &) = delete;
  CurlHandleLease(CurlHandleLease &&other) noexcept;
  CurlHandleLease &operator=(CurlHandleLease &&other) noexcept;
  ~CurlHandleLease();

  CURL *get() const { return handle_; }
  explicit operator bool() const { return handle_ != nullptr; }

private:
  friend class CurlHandlePool;
  CurlHandleLease(CurlHandlePool *pool, CURL *handle)
      : pool_(pool), handle_(handle) {}
  void reset();

  CurlHandlePool *pool_ = nullptr;
  CURL *handle_ = nullptr;
};

class CurlHandlePool {
public:
  explicit CurlHandlePool(size_t capacity);
  CurlHandlePool(const CurlHandlePool &) = delete;
  CurlHandlePool &operator=(const CurlHandlePool &) = delete;
  ~CurlHandlePool();

  CurlHandleLease acquire();
  void shutdown();
  size_t capacity() const { return capacity_; }

private:
  friend class CurlHandleLease;
  void release(CURL *handle);

  const size_t capacity_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::vector<CURL *> idle_;
  size_t created_ = 0;
  bool stopping_ = false;
};

CurlHandlePool &globalCurlHandlePool(size_t configured_capacity);
size_t curlHandlePoolCapacity(size_t configured_capacity);
void shutdownGlobalCurlHandlePool();

#endif // CURL_HANDLE_POOL_H_INCLUDED
