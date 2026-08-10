#ifndef LOGGER_H_INCLUDED
#define LOGGER_H_INCLUDED

#include <string>
#include <typeinfo>

enum class LogLevel : int {
    Fatal,
    Error,
    Warning,
    Info,
    Debug,
    Verbose,
};

inline constexpr LogLevel LOG_LEVEL_FATAL = LogLevel::Fatal;
inline constexpr LogLevel LOG_LEVEL_ERROR = LogLevel::Error;
inline constexpr LogLevel LOG_LEVEL_WARNING = LogLevel::Warning;
inline constexpr LogLevel LOG_LEVEL_INFO = LogLevel::Info;
inline constexpr LogLevel LOG_LEVEL_DEBUG = LogLevel::Debug;
inline constexpr LogLevel LOG_LEVEL_VERBOSE = LogLevel::Verbose;

std::string getTime(int type);
bool shouldLog(LogLevel level);
void writeLog(LogLevel level, const std::string &content);

// Attach a server-generated request identifier to every log emitted in the
// current synchronous request scope. Nested scopes restore the previous value.
class ScopedLogRequestContext {
public:
    explicit ScopedLogRequestContext(const std::string &request_id);
    ~ScopedLogRequestContext();
    ScopedLogRequestContext(const ScopedLogRequestContext &) = delete;
    ScopedLogRequestContext &operator=(const ScopedLogRequestContext &) = delete;

private:
    std::string previous_request_id_;
};

std::string currentLogRequestId();

// Keep a candidate configuration's log threshold local to the loader thread
// until the corresponding immutable Settings snapshot is published. Other
// request and worker threads continue using their own/published snapshot.
class ScopedLogLevelOverride {
public:
    ScopedLogLevelOverride();
    ~ScopedLogLevelOverride();
    void set(LogLevel level);
    ScopedLogLevelOverride(const ScopedLogLevelOverride &) = delete;
    ScopedLogLevelOverride &operator=(const ScopedLogLevelOverride &) = delete;

private:
    bool previous_active_ = false;
    LogLevel previous_level_ = LOG_LEVEL_INFO;
};

// Source-compatibility adapter for downstream zero-category callers.
// Project code uses the LogLevel-first overload; no default severity exists.
inline void writeLog(int, const std::string &content, LogLevel level) {
    writeLog(level, content);
}
void writeLog(int, const std::string &) = delete;
std::string demangle(const char* name);

template <class T>
std::string type(const T& t) {

    return demangle(typeid(t).name());
}

#endif // LOGGER_H_INCLUDED
