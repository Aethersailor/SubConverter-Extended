#include "cache_storage.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <filesystem>

#include "utils/file.h"

namespace {

#ifdef CACHE_STORAGE_TESTING
std::atomic<CacheStorageTestFailure> cache_storage_failure {
    CacheStorageTestFailure::None};
#endif

std::string invalidationPath(const std::string &header_path) {
    return header_path + "_invalid";
}

bool removeInvalidation(const std::string &path) {
#ifdef CACHE_STORAGE_TESTING
    if(cache_storage_failure.load() ==
       CacheStorageTestFailure::RemoveInvalidation)
        return false;
#endif
    errno = 0;
    return std::remove(path.c_str()) == 0 || errno == ENOENT;
}

bool invalidationPresent(const std::string &path) {
    std::error_code error;
    const bool exists = std::filesystem::exists(path, error);
    // A marker that cannot be inspected must fail closed: cached headers are
    // optional metadata, so omitting them is safer than pairing stale values.
    return exists || static_cast<bool>(error);
}

} // namespace

CacheUpdateResult updateCacheFiles(const std::string &body_path,
                                   const std::string &header_path,
                                   const std::string &body,
                                   const std::string &headers) {
    const std::string invalidation_path = invalidationPath(header_path);
    const bool invalidation_was_present =
        invalidationPresent(invalidation_path);
    const FileCommitResult invalidation_result = static_cast<FileCommitResult>(
        fileWrite(invalidation_path, "invalid\n", true));
    if(invalidation_result != FileCommitResult::Durable)
        return invalidationPresent(invalidation_path)
                   ? CacheUpdateResult::UnchangedHeadersInvalidated
                   : CacheUpdateResult::Unchanged;

    const FileCommitResult body_result =
        static_cast<FileCommitResult>(fileWrite(body_path, body, true));
    if(fileCommitFailed(body_result)) {
        if(invalidation_was_present)
            return CacheUpdateResult::UnchangedHeadersInvalidated;
        return removeInvalidation(invalidation_path)
                   ? CacheUpdateResult::Unchanged
                   : CacheUpdateResult::UnchangedHeadersInvalidated;
    }
    if(body_result == FileCommitResult::CommittedUnsynced)
        return CacheUpdateResult::BodyCommittedUnsynced;

    const FileCommitResult header_result =
        static_cast<FileCommitResult>(fileWrite(header_path, headers, true));
    if(header_result != FileCommitResult::Durable)
        return CacheUpdateResult::HeadersInvalidated;

    return removeInvalidation(invalidation_path)
               ? CacheUpdateResult::Complete
               : CacheUpdateResult::HeadersInvalidated;
}

std::string readCachedResponseHeaders(const std::string &header_path) {
    if(invalidationPresent(invalidationPath(header_path)))
        return "";
    return fileGet(header_path, true);
}

#ifdef CACHE_STORAGE_TESTING
void setCacheStorageTestFailure(CacheStorageTestFailure failure) {
    cache_storage_failure.store(failure);
}
#endif
