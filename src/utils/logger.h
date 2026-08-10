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

// Transitional wrapper for existing zero-category three-argument callers.
// The removed default argument makes every severity intentional.
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
