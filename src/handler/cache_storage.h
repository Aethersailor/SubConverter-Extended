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

#ifdef CACHE_STORAGE_TESTING
enum class CacheStorageTestFailure {
    None,
    RemoveInvalidation,
};
void setCacheStorageTestFailure(CacheStorageTestFailure failure);
#endif

#endif // CACHE_STORAGE_H_INCLUDED
