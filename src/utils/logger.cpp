#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <iostream>
#include <thread>
#include <sys/time.h>
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

bool shouldLog(LogLevel level)
{
    return static_cast<int>(level) <=
           static_cast<int>(effectiveSettings().logLevel);
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
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cerr<<getTime(2)<<" ["<<getpid()<<" "<<get_thread_name()<<"]"<<logLevelLabel(level);
    std::cerr<<" "<<redactSensitiveLogText(content)<<"\n";
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
