#ifndef MD5_INTERFACE_H_INCLUDED
#define MD5_INTERFACE_H_INCLUDED

#include <string>

#include "md5.h"

inline std::string getMD5(const std::string &data)
{
    std::string result;

    char result_str[MD5_STRING_SIZE];
    md5::md5_t md5;
    md5.process(data.data(), data.size());
    md5.finish();
    md5.get_string(result_str);
    result.assign(result_str);

    return result;
}

#endif // MD5_INTERFACE_H_INCLUDED
