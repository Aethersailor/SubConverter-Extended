#ifndef TIME_COMPAT_H_INCLUDED
#define TIME_COMPAT_H_INCLUDED

#include <ctime>

#ifdef _WIN32
inline tm *localtime_r(const time_t *timep, tm *result) {
  if (timep == nullptr || result == nullptr)
    return nullptr;
  return localtime_s(result, timep) == 0 ? result : nullptr;
}
#endif // _WIN32

#endif // TIME_COMPAT_H_INCLUDED
