#ifndef COCR_SOURCE_URL_H_INCLUDED
#define COCR_SOURCE_URL_H_INCLUDED

#include <string>

struct CocrSourceResolution {
  std::string effective_url;
  bool rewritten = false;
};

CocrSourceResolution resolveCocrSourceUrl(const std::string &url,
                                          bool enabled);

#endif // COCR_SOURCE_URL_H_INCLUDED
