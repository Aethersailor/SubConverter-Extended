#ifndef QUICKJS_ALLOCATOR_H_INCLUDED
#define QUICKJS_ALLOCATOR_H_INCLUDED

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <quickjs/quickjs.h>
#if defined(_WIN32) || defined(__linux__)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#include "utils/force_max_memory.h"

inline thread_local bool quick_js_memory_capacity_failed = false;

namespace force_max_quickjs {
struct alignas(std::max_align_t) Allocation {
  size_t size;
  size_t accounted;
};

inline size_t physicalSize(const Allocation *allocation, size_t requested) noexcept {
  (void)requested;
#ifdef _WIN32
  return _msize(const_cast<Allocation *>(allocation)) + 2 * sizeof(void *);
#elif defined(__linux__)
  return malloc_usable_size(const_cast<Allocation *>(allocation)) + 2 * sizeof(void *);
#elif defined(__APPLE__)
  return malloc_size(allocation) + 2 * sizeof(void *);
#else
  return requested + 4 * sizeof(void *);
#endif
}

inline void *allocate(JSMallocState *state, size_t size,
                      size_t credit = 0) noexcept {
  constexpr size_t overhead = sizeof(Allocation) + alignof(Allocation) + 4 * sizeof(void *);
  if (size == 0 || size > SIZE_MAX - overhead) return nullptr;
  const size_t total = size + overhead;
  if (total > state->malloc_limit ||
      state->malloc_size - credit > state->malloc_limit - total) {
    quick_js_memory_capacity_failed = true;
    return nullptr;
  }
  if (!force_max_memory::acquire(total)) {
    force_max_memory::reclaimCaches();
    if (!force_max_memory::acquire(total)) {
      quick_js_memory_capacity_failed = true;
      return nullptr;
    }
  }
  auto *allocation = static_cast<Allocation *>(std::malloc(size + sizeof(Allocation)));
  if (!allocation) {
    force_max_memory::release(total);
    quick_js_memory_capacity_failed = true;
    return nullptr;
  }
  allocation->size = size;
  allocation->accounted = physicalSize(allocation, size + sizeof(Allocation));
  if (allocation->accounted > total) {
    const size_t extra = allocation->accounted - total;
    if (allocation->accounted > state->malloc_limit ||
        state->malloc_size - credit > state->malloc_limit - allocation->accounted ||
        !force_max_memory::acquire(extra)) {
      std::free(allocation);
      force_max_memory::release(total);
      quick_js_memory_capacity_failed = true;
      return nullptr;
    }
  } else {
    force_max_memory::release(total - allocation->accounted);
  }
  ++state->malloc_count;
  state->malloc_size += allocation->accounted;
  return allocation + 1;
}

inline void free(JSMallocState *state, void *pointer) noexcept {
  if (!pointer) return;
  auto *allocation = static_cast<Allocation *>(pointer) - 1;
  const size_t total = allocation->accounted;
  --state->malloc_count;
  state->malloc_size -= total;
  std::free(allocation);
  force_max_memory::release(total);
}

inline void *reallocate(JSMallocState *state, void *pointer, size_t size) noexcept {
  if (!pointer) return allocate(state, size);
  if (size == 0) { free(state, pointer); return nullptr; }
  const auto *allocation = static_cast<Allocation *>(pointer) - 1;
  // Keeping a smaller allocation avoids a second buffer and preserves exact
  // accounting until it is freed. Growth charges old and new simultaneously.
  if (size <= allocation->size) return pointer;
  void *next = allocate(state, size, allocation->accounted);
  if (!next) return nullptr;
  std::memcpy(next, pointer, allocation->size);
  free(state, pointer);
  return next;
}

inline size_t usableSize(const void *pointer) noexcept {
  return pointer ? (static_cast<const Allocation *>(pointer) - 1)->size : 0;
}

inline void *malloc(JSMallocState *state, size_t size) noexcept {
  return allocate(state, size);
}

inline constexpr JSMallocFunctions functions{malloc, free, reallocate, usableSize};
} // namespace force_max_quickjs

inline const JSMallocFunctions *forceMaxQuickJsAllocator() noexcept {
  return force_max_memory::limit.load() != 0 ? &force_max_quickjs::functions
                                            : nullptr;
}

#endif
