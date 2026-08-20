#ifndef CONCURRENT_LRU_CACHE_H_INCLUDED
#define CONCURRENT_LRU_CACHE_H_INCLUDED

#include <cstddef>
#include <exception>
#include <future>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>

#include "utils/cooperative_cpu.h"

template <class Key, class Value, class Hash = std::hash<Key>>
class ConcurrentLruCache {
public:
  using CacheSize = std::optional<size_t>;

  ConcurrentLruCache(size_t max_entries, size_t max_bytes)
      : max_entries_(max_entries), max_bytes_(max_bytes) {}

  ConcurrentLruCache(const ConcurrentLruCache &) = delete;
  ConcurrentLruCache &operator=(const ConcurrentLruCache &) = delete;

  template <class Compute, class SizeOf>
  Value getOrCompute(const Key &key, bool cache_enabled, Compute &&compute,
                     SizeOf &&size_of, bool *cache_hit = nullptr) {
    if (cache_hit)
      *cache_hit = false;
    if (!cache_enabled)
      return compute();

    std::shared_future<Value> future;
    std::shared_ptr<std::promise<Value>> promise;
    bool owner = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto cached = entries_.find(key);
      if (cached != entries_.end()) {
        touch(cached);
        if (cache_hit)
          *cache_hit = true;
        return cached->second.value;
      }

      auto inflight = inflight_.find(key);
      if (inflight != inflight_.end()) {
        future = inflight->second;
      } else {
        promise = std::make_shared<std::promise<Value>>();
        future = promise->get_future().share();
        inflight_.emplace(key, future);
        owner = true;
      }
    }

    if (!owner)
      return waitWithoutCpuPermit([&] { return future.get(); });

    try {
      Value value = compute();
      CacheSize bytes = size_of(value);
      if (bytes && *bytes <= max_bytes_ && max_entries_ != 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        insert(key, value, *bytes);
      }
      promise->set_value(value);
    } catch (...) {
      promise->set_exception(std::current_exception());
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      inflight_.erase(key);
    }
    return waitWithoutCpuPermit([&] { return future.get(); });
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  size_t bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bytes_;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    lru_.clear();
    bytes_ = 0;
  }

private:
  struct Entry {
    Value value;
    size_t bytes = 0;
    typename std::list<Key>::iterator lru;
  };

  using EntryMap = std::unordered_map<Key, Entry, Hash>;

  void touch(typename EntryMap::iterator entry) {
    lru_.splice(lru_.begin(), lru_, entry->second.lru);
    entry->second.lru = lru_.begin();
  }

  void insert(const Key &key, const Value &value, size_t bytes) {
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
      bytes_ -= existing->second.bytes;
      lru_.erase(existing->second.lru);
      entries_.erase(existing);
    }

    lru_.push_front(key);
    entries_.emplace(key, Entry{value, bytes, lru_.begin()});
    bytes_ += bytes;
    while (!entries_.empty() &&
           (entries_.size() > max_entries_ || bytes_ > max_bytes_)) {
      const Key &evicted_key = lru_.back();
      auto evicted = entries_.find(evicted_key);
      if (evicted != entries_.end()) {
        bytes_ -= evicted->second.bytes;
        entries_.erase(evicted);
      }
      lru_.pop_back();
    }
  }

  const size_t max_entries_;
  const size_t max_bytes_;
  mutable std::mutex mutex_;
  std::list<Key> lru_;
  EntryMap entries_;
  std::unordered_map<Key, std::shared_future<Value>, Hash> inflight_;
  size_t bytes_ = 0;
};

#endif // CONCURRENT_LRU_CACHE_H_INCLUDED
