#include <filesystem>
#include <stdexcept>
#include <string>

#include "handler/cache_storage.h"
#include "utils/file.h"

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct TemporaryTree {
  std::filesystem::path path = std::filesystem::current_path() / "build" /
                               "cache-storage-test-runtime";
  TemporaryTree() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
    std::filesystem::create_directories(path);
  }
  ~TemporaryTree() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

} // namespace

int main() {
  TemporaryTree temporary;
  const std::filesystem::path body = temporary.path / "entry";
  const std::filesystem::path headers = temporary.path / "entry_header";

  require(fileWrite(body.string(), "old-body", true) == 0 &&
              fileWrite(headers.string(), "old-headers", true) == 0,
          "cache fixture failed");
  require(updateCacheFiles(body.string(), headers.string(), "new-body",
                           "new-headers") == CacheUpdateResult::Complete,
          "complete cache update failed");
  require(fileGet(body.string(), false) == "new-body" &&
              readCachedResponseHeaders(headers.string()) == "new-headers",
          "complete cache pair changed");

  const std::filesystem::path header_alias = temporary.path / "header-alias";
  std::error_code hardlink_error;
  std::filesystem::create_hard_link(headers, header_alias, hardlink_error);
  require(!hardlink_error, "deterministic header-write failure fixture failed");
  require(updateCacheFiles(body.string(), headers.string(), "latest-body",
                           "uncommitted-headers") ==
              CacheUpdateResult::HeadersInvalidated,
          "header write failure was not isolated");
  require(fileGet(body.string(), false) == "latest-body" &&
              readCachedResponseHeaders(headers.string()).empty() &&
              fileGet(headers.string(), false) == "new-headers",
          "stale headers remained usable after body replacement");
  std::filesystem::remove(header_alias);

  setCacheStorageTestFailure(CacheStorageTestFailure::RemoveInvalidation);
  require(updateCacheFiles(body.string(), headers.string(), "marker-body",
                           "marker-headers") ==
              CacheUpdateResult::HeadersInvalidated,
          "invalidation removal failure reported a complete pair");
  setCacheStorageTestFailure(CacheStorageTestFailure::None);
  require(fileGet(body.string(), false) == "marker-body" &&
              readCachedResponseHeaders(headers.string()).empty(),
          "failed invalidation removal exposed cached headers");

  const std::filesystem::path invalidation =
      std::filesystem::path(headers.string() + "_invalid");
  const std::filesystem::path invalidation_alias =
      temporary.path / "invalidation-alias";
  std::error_code invalidation_link_error;
  std::filesystem::create_hard_link(invalidation, invalidation_alias,
                                    invalidation_link_error);
  require(!invalidation_link_error,
          "deterministic invalidation-write failure fixture failed");
  require(updateCacheFiles(body.string(), headers.string(), "must-not-commit",
                           "must-not-commit") ==
              CacheUpdateResult::UnchangedHeadersInvalidated &&
              fileGet(body.string(), false) == "marker-body" &&
              readCachedResponseHeaders(headers.string()).empty(),
          "invalidation write failure changed or exposed a cache pair");
  std::filesystem::remove(invalidation_alias);

  const std::filesystem::path body_alias = temporary.path / "body-alias";
  std::error_code body_link_error;
  std::filesystem::create_hard_link(body, body_alias, body_link_error);
  require(!body_link_error, "deterministic body-write failure fixture failed");
  require(updateCacheFiles(body.string(), headers.string(), "must-not-commit",
                           "must-not-commit") ==
              CacheUpdateResult::UnchangedHeadersInvalidated &&
              fileGet(body.string(), false) == "marker-body" &&
              readCachedResponseHeaders(headers.string()).empty(),
          "body write failure cleared a pre-existing invalidation marker");
  std::filesystem::remove(body_alias);

  require(updateCacheFiles(body.string(), headers.string(), "final-body", "") ==
              CacheUpdateResult::Complete,
          "empty-header cache update failed");
  require(fileGet(body.string(), false) == "final-body" &&
              readCachedResponseHeaders(headers.string()).empty(),
          "empty-header cache pair changed");

  setFileIoTestFailure(FileIoTestFailure::ReplaceAndTemporaryCleanup);
  require(updateCacheFiles(body.string(), headers.string(), "must-not-commit",
                           "must-not-commit") == CacheUpdateResult::Unchanged,
          "negative cleanup result advanced the cache transaction");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(body.string(), false) == "final-body" &&
              readCachedResponseHeaders(headers.string()).empty(),
          "cleanup failure changed the cache pair");
  bool cleanup_residual_found = false;
  for (const auto &entry : std::filesystem::directory_iterator(temporary.path)) {
    if (entry.path().filename().string().find(
            ".entry_header_invalid.subconverter-tmp-") == 0) {
      cleanup_residual_found = true;
      std::filesystem::remove(entry.path());
    }
  }
  require(cleanup_residual_found,
          "cache cleanup residual was not observable for diagnostics");
  return 0;
}
