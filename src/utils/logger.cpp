#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <iostream>
#include <thread>
#include <utility>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "defer.h"
#include "lock.h"
#include "logger.h"
#include "redact.h"
#include "time_compat.h"

std::string getTime(int type)
{
    time_t lt;
    char tmpbuf[32], cMillis[7];
    std::string format;
    timeval tv = {};
    gettimeofday(&tv, nullptr);
    snprintf(cMillis, 7, "%.6ld", (long)tv.tv_usec);
    lt = time(nullptr);
    struct tm local_tm;
    localtime_r(&lt, &local_tm);
    switch(type)
    {
    case 1:
        format = "%Y%m%d-%H%M%S";
        break;
    case 2:
        format = "%Y/%m/%d %a %H:%M:%S.";
        format += cMillis;
        break;
    case 3:
    default:
        format = "%Y-%m-%d %H:%M:%S";
        break;
    }
    strftime(tmpbuf, 32, format.data(), &local_tm);
    return {tmpbuf};
}

static std::string get_thread_name()
{
    static std::atomic_int counter = 0;
    static std::map<std::thread::id, std::string> thread_names;
    static RWLock lock;
    std::thread::id id = std::this_thread::get_id();
    lock.readLock();
    if (thread_names.find(id) != thread_names.end())
    {
        defer(lock.readUnlock();)
        return thread_names[id];
    }
    lock.readUnlock();
    lock.writeLock();
    std::string name = "Thread-" + std::to_string(++counter);
    thread_names[id] = name;
    lock.writeUnlock();
    return name;
}

std::mutex log_mutex;
thread_local std::string log_request_id;
thread_local bool log_level_override_active = false;
thread_local LogLevel log_level_override = LOG_LEVEL_INFO;

namespace {

#ifndef _WIN32
off_t configuredLogFileMaxBytes() {
    static const off_t configured = []() -> off_t {
        const char *value = std::getenv("SUBCONVERTER_LOG_FILE_MAX_BYTES");
        if (value == nullptr || *value == '\0')
            return 0;
        errno = 0;
        char *end = nullptr;
        const unsigned long long parsed = std::strtoull(value, &end, 10);
        if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
            parsed > static_cast<unsigned long long>(
                         std::numeric_limits<off_t>::max()))
            return 0;
        return static_cast<off_t>(parsed);
    }();
    return configured;
}

void truncateBoundedStderrLog() {
    const off_t maximum = configuredLogFileMaxBytes();
    if (maximum == 0)
        return;

    struct stat status = {};
    if (fstat(STDERR_FILENO, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < maximum)
        return;
    std::cerr.flush();
    if (ftruncate(STDERR_FILENO, 0) == 0)
        (void)lseek(STDERR_FILENO, 0, SEEK_SET);
}
#else
void truncateBoundedStderrLog() {}
#endif

LogLevel effectiveLogThreshold() {
#ifdef NO_WEBGET
    return effectiveSettings().logLevel;
#else
    return captureEffectiveSettingsSnapshot()->logLevel;
#endif
}

} // namespace

ScopedLogRequestContext::ScopedLogRequestContext(
    const std::string &request_id)
    : previous_request_id_(std::move(log_request_id)) {
    log_request_id = request_id;
}

ScopedLogRequestContext::~ScopedLogRequestContext() {
    log_request_id = std::move(previous_request_id_);
}

std::string currentLogRequestId() { return log_request_id; }

ScopedLogLevelOverride::ScopedLogLevelOverride()
    : previous_active_(log_level_override_active),
      previous_level_(log_level_override) {
    if (!previous_active_)
        log_level_override = effectiveLogThreshold();
    log_level_override_active = true;
}

ScopedLogLevelOverride::~ScopedLogLevelOverride() {
    log_level_override_active = previous_active_;
    log_level_override = previous_level_;
}

void ScopedLogLevelOverride::set(LogLevel level) {
    log_level_override = level;
}

bool shouldLog(LogLevel level)
{
    const LogLevel threshold = log_level_override_active
                                   ? log_level_override
                                   : effectiveLogThreshold();
    return static_cast<int>(level) <=
           static_cast<int>(threshold);
}

namespace {

const char *logLevelLabel(LogLevel level) {
    switch (level) {
    case LogLevel::Fatal:
        return "[FATL]";
    case LogLevel::Error:
        return "[ERRO]";
    case LogLevel::Warning:
        return "[WARN]";
    case LogLevel::Info:
        return "[INFO]";
    case LogLevel::Debug:
        return "[DEBG]";
    case LogLevel::Verbose:
        return "[VERB]";
    }
    return "[UNKN]";
}

} // namespace

void writeLog(LogLevel level, const std::string &content)
{
    if(!shouldLog(level))
        return;
    const std::string safe_content = sanitizeLogLine(content);
    const std::string request_id = currentLogRequestId();
    std::lock_guard<std::mutex> lock(log_mutex);
    truncateBoundedStderrLog();
    std::cerr<<getTime(2)<<" ["<<getpid()<<" "<<get_thread_name()<<"]"<<logLevelLabel(level);
    if (!request_id.empty())
        std::cerr<<" request_id="<<request_id;
    std::cerr<<" "<<safe_content<<"\n";
}


#ifdef __GNUG__
#include <cstdlib>
#include <memory>
#include <cxxabi.h>

std::string demangle(const char* name)
{
    int status = -4;
    std::unique_ptr<char, void(*)(void*)> res {
        abi::__cxa_demangle(name, nullptr, nullptr, &status),
        std::free
    };
    return (status == 0) ? res.get() : name;
}

#else

std::string demangle(const char* name)
{
    return name;
}

#endif
