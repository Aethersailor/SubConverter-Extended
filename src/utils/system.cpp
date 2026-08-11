#include <string>
#include <chrono>
#include <thread>
#include <stdlib.h>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif // _WIN32

#include "string.h"

#ifdef _WIN32
namespace {

class RegistryKey {
public:
    RegistryKey() = default;
    ~RegistryKey()
    {
        if(value_ != nullptr)
            RegCloseKey(value_);
    }

    HKEY *put() { return &value_; }
    HKEY get() const { return value_; }

    RegistryKey(const RegistryKey &) = delete;
    RegistryKey &operator=(const RegistryKey &) = delete;

private:
    HKEY value_ = nullptr;
};

bool readRegistryDword(HKEY key, const char *name, DWORD &value)
{
    DWORD type = 0;
    DWORD size = sizeof(value);
    return RegQueryValueExA(key, name, nullptr, &type,
                            reinterpret_cast<BYTE *>(&value), &size) ==
               ERROR_SUCCESS &&
           type == REG_DWORD && size == sizeof(value);
}

bool readRegistryString(HKEY key, const char *name, std::string &value)
{
    DWORD type = 0;
    DWORD size = 0;
    if(RegQueryValueExA(key, name, nullptr, &type, nullptr, &size) !=
           ERROR_SUCCESS ||
       type != REG_SZ || size == 0)
        return false;

    std::vector<char> buffer(static_cast<size_t>(size) + 1, '\0');
    if(RegQueryValueExA(key, name, nullptr, &type,
                        reinterpret_cast<BYTE *>(buffer.data()), &size) !=
           ERROR_SUCCESS ||
       type != REG_SZ)
        return false;

    // RegQueryValueEx does not guarantee that REG_SZ data is terminated.
    buffer.back() = '\0';
    value.assign(buffer.data());
    return true;
}

} // namespace
#endif

void sleepMs(int interval)
{
    /*
    #ifdef _WIN32
        Sleep(interval);
    #else
        // Portable sleep for platforms other than Windows.
        struct timeval wait = { 0, interval * 1000 };
        select(0, NULL, NULL, NULL, &wait);
    #endif
    */
    //upgrade to c++11 standard
    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
}

std::string getEnv(const std::string &name)
{
    std::string retVal;
#ifdef _WIN32
    DWORD capacity = GetEnvironmentVariableA(name.c_str(), nullptr, 0);
    while(capacity > 0)
    {
        std::vector<char> buffer(static_cast<size_t>(capacity), '\0');
        const DWORD length = GetEnvironmentVariableA(
            name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if(length == 0)
            return "";
        if(length < buffer.size())
            return std::string(buffer.data(), static_cast<size_t>(length));
        // The value grew between the size query and read. Windows returns the
        // newly required size (including the terminator), so retry exactly.
        capacity = length;
    }
#else
    char *env = getenv(name.c_str());
    if(env != NULL)
        retVal.assign(env);
#endif // _WIN32
    return retVal;
}

std::string getSystemProxy()
{
#ifdef _WIN32
    RegistryKey key;
    if(RegOpenKeyExA(
           HKEY_CURRENT_USER,
           R"(Software\Microsoft\Windows\CurrentVersion\Internet Settings)",
           0, KEY_QUERY_VALUE, key.put()) != ERROR_SUCCESS)
        return "";

    DWORD proxy_enabled = 0;
    if(!readRegistryDword(key.get(), "ProxyEnable", proxy_enabled) ||
       proxy_enabled == 0)
        return "";

    std::string proxy_server;
    return readRegistryString(key.get(), "ProxyServer", proxy_server)
               ? proxy_server
               : "";
#else
    string_array proxy_env = {"all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"};
    for(std::string &x : proxy_env)
    {
        char* proxy = getenv(x.c_str());
        if(proxy != NULL)
            return std::string(proxy);
    }
    return "";
#endif // _WIN32
}
