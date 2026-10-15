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

// Internal cache files are scoped to the operator-managed cache directory,
// which may itself be a symlink (OpenWrt keeps this directory in tmpfs).
std::string readCacheFile(const std::string &path);
CacheUpdateResult updateCacheFiles(const std::string &body_path,
                                   const std::string &header_path,
                                   const std::string &body,
                                   const std::string &headers);
std::string readCachedResponseHeaders(const std::string &header_path);

#endif // CACHE_STORAGE_H_INCLUDED
