#include <string>
#include <type_traits>
#include <utility>

#include "utils/logger.h"

template <typename... Args>
concept LogCallable = requires(Args &&...args) {
  writeLog(std::forward<Args>(args)...);
};

static_assert(LogCallable<LogLevel, std::string>);
static_assert(LogCallable<int, std::string, LogLevel>);
static_assert(!LogCallable<int, std::string>);
static_assert(!LogCallable<int, std::string, int>);
static_assert(!std::is_convertible_v<int, LogLevel>);

int main() { return 0; }
