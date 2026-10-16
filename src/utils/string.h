#ifndef STRING_H_INCLUDED
#define STRING_H_INCLUDED

#include <iterator>
#include <numeric>
#include <string>
#include <sstream>
#include <vector>
#include <map>

using string = std::string;
using string_size = std::string::size_type;
using string_array = std::vector<std::string>;
using string_view_array = std::vector<std::string_view>;
using string_map = std::map<std::string, std::string>;
using string_multimap = std::multimap<std::string, std::string>;

std::vector<std::string> split(const std::string &s, const std::string &separator);
std::vector<std::string_view> split(std::string_view s, char separator);
void split(std::vector<std::string_view> &result, std::string_view s, char separator);
std::string join(const string_array &arr, const std::string &delimiter);

template <typename InputIt>
std::string join(InputIt first, InputIt last, const std::string &delimiter)
{
    if(first == last)
        return "";
    if(std::next(first) == last)
        return *first;

    std::string result = *first;
    for(++first; first != last; ++first)
    {
        result.append(delimiter);
        result.append(*first);
    }
    return result;
}

std::string getUrlArg(const std::string &url, const std::string &request);
std::string getUrlArg(const string_multimap &args, const std::string &request);
std::string replaceAllDistinct(std::string str, const std::string &old_value, const std::string &new_value);
std::string trimOf(const std::string& str, char target, bool before = true, bool after = true);
std::string trim(const std::string& str, bool before = true, bool after = true);
std::string trimQuote(const std::string &str, bool before = true, bool after = true);
std::string trimWhitespace(const std::string &str, bool before = false, bool after = true);
std::string randomStr(int len);
bool isStrUTF8(const std::string &data);

std::string toLower(const std::string &str);
std::string toUpper(const std::string &str);
void processEscapeChar(std::string &str);
void processEscapeCharReverse(std::string &str);

inline bool strFind(const std::string &str, const std::string &target)
{
    return str.find(target) != std::string::npos;
}

#if __cpp_lib_starts_ends_with >= 201711L

inline bool startsWith(const std::string &hay, const std::string &needle)
{
    return hay.starts_with(needle);
}

inline bool endsWith(const std::string &hay, const std::string &needle)
{
    return hay.ends_with(needle);
}

#else

inline bool startsWith(const std::string &hay, const std::string &needle)
{
    return hay.find(needle) == 0;
}

inline bool endsWith(const std::string &hay, const std::string &needle)
{
    auto hay_size = hay.size(), needle_size = needle.size();
    return hay_size >= needle_size && hay.rfind(needle) == hay_size - needle_size;
}

#endif

inline bool count_least(const std::string &hay, const char needle, size_t cnt)
{
    string_size pos = hay.find(needle);
    while(pos != std::string::npos)
    {
        cnt--;
        if(!cnt)
            return true;
        pos = hay.find(needle, pos + 1);
    }
    return false;
}

inline char getLineBreak(const std::string &str)
{
    return count_least(str, '\n', 1) ? '\n' : '\r';
}

template <typename T>
concept Arithmetic = std::is_arithmetic_v<T>;

template <typename OutType, typename InType>
requires Arithmetic<OutType>
inline OutType to_number(const InType &value, OutType def_value = 0)
{
    OutType retval = 0;
    char c;
    std::stringstream ss;
    ss << value;
    if(!(ss >> retval) || ss >> c)
        return def_value;
    else
        return retval;
}

int to_int(const std::string &str, int def_value = 0);

#ifndef HAVE_TO_STRING
namespace std
{
template <typename T> std::string to_string(const T& n)
{
    std::ostringstream ss;
    ss << n;
    return ss.str();
}
}
#endif // HAVE_TO_STRING

#endif // STRING_H_INCLUDED
