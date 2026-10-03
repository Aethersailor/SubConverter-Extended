#include <cassert>
#include <cstring>
#include <quickjspp.hpp>
#include "runtime/quickjs_allocator.h"

int main() {
  assert(forceMaxQuickJsAllocator() == nullptr);
  assert(force_max_memory::configure(512));
  JSMallocState state{0, 0, SIZE_MAX, nullptr};
  void *first = force_max_quickjs::malloc(&state, 128);
  assert(first && state.malloc_count == 1);
  std::memset(first, 42, 128);
  const uint64_t before = force_max_memory::used;
  // The old and new buffers must coexist; net-size-only charging would
  // incorrectly allow this growth beyond the physical memory envelope.
  assert(force_max_quickjs::reallocate(&state, first, 400) == nullptr);
  assert(quick_js_memory_capacity_failed && force_max_memory::used == before);
  void *next = force_max_quickjs::reallocate(&state, first, 256);
  assert(next && state.malloc_count == 1);
  assert(static_cast<unsigned char *>(next)[127] == 42);
  assert(force_max_quickjs::usableSize(next) == 256);
  force_max_quickjs::free(&state, next);
  assert(state.malloc_count == 0 && state.malloc_size == 0);
  assert(force_max_memory::used == 0);

  assert(force_max_memory::configure(1024 * 1024));
  quick_js_memory_capacity_failed = false;
  {
    qjs::Runtime runtime(forceMaxQuickJsAllocator());
    qjs::Context context(runtime);
    const char source[] = "new Array(1000000).fill(123)";
    JSValue value = JS_Eval(context.ctx, source, sizeof(source) - 1,
                            "allocator-test", JS_EVAL_TYPE_GLOBAL);
    assert(JS_IsException(value));
    JS_FreeValue(context.ctx, JS_GetException(context.ctx));
    JS_FreeValue(context.ctx, value);
    assert(quick_js_memory_capacity_failed);
    assert(force_max_memory::peak <= force_max_memory::limit);
  }
  assert(force_max_memory::used == 0);
  assert(force_max_memory::configure(0));
}
