#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif // _WIN32

// UTF8 to ANSI code page (GBK on 936)
std::string utf8ToACP(const std::string &str_src)
{
#ifdef _WIN32
    const int wide_size = MultiByteToWideChar(CP_UTF8, 0, str_src.c_str(), -1,
                                             nullptr, 0);
    if (wide_size == 0)
        return {};
    std::wstring wide(wide_size, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, str_src.c_str(), -1, wide.data(),
                            wide_size) == 0)
        return {};

    const int acp_size = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1,
                                            nullptr, 0, nullptr, nullptr);
    if (acp_size == 0)
        return {};
    std::string result(acp_size, '\0');
    if (WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, result.data(),
                            acp_size, nullptr, nullptr) == 0)
        return {};
    result.pop_back(); // The conversion size includes the terminating null.
    return result;
#else
    return str_src;
#endif
}
