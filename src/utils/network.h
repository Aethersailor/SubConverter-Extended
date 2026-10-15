#ifndef NETWORK_H_INCLUDED
#define NETWORK_H_INCLUDED

#include <string>

#include "string.h"

std::string getUrlArg(const std::string &url, const std::string &request);
bool isIPv4(const std::string &address);
bool isIPv6(const std::string &address);
std::string hostnameToIPAddr(const std::string &host);

inline bool isLink(const std::string &url)
{
    return startsWith(url, "https://") || startsWith(url, "http://") || startsWith(url, "data:");
}

#endif // NETWORK_H_INCLUDED
