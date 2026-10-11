#ifndef CACHE_STORAGE_H_INCLUDED
#define CACHE_STORAGE_H_INCLUDED

#include <string>

enum class CacheUpdateResult {
    Complete,
    Unchanged,
    UnchangedHeadersInvalidated,
    HeadersInvalidated,
    BodyCommittedUnsynced,
};

CacheUpdateResult updateCacheFiles(const std::string &body_path,
                                   const std::string &header_path,
                                   const std::string &body,
                                   const std::string &headers);
std::string readCachedResponseHeaders(const std::string &header_path);

#endif // CACHE_STORAGE_H_INCLUDED
