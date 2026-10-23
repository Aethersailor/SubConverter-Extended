#ifndef FILE_H_INCLUDED
#define FILE_H_INCLUDED

#include <string>
#include <string.h>

#ifdef _WIN32
#include <unistd.h>
#define PATH_SLASH "\\"
#else
#include <sys/types.h>
#include <sys/stat.h>
#define PATH_SLASH "//"
#endif // _WIN32

#include <sys/types.h>

// scope_limit=false intentionally permits trusted local configuration to read
// an arbitrary operator-selected path. Request-controlled paths must pass true.
std::string fileGet(const std::string &path, bool scope_limit = false);
std::string fileGetBounded(const std::string &path, std::size_t max_bytes,
                           bool scope_limit = false);
bool fileExist(const std::string &path, bool scope_limit = false);
// Check read access without loading the file, using the same platform path
// handling and canonical containment check as fileGet.
bool fileReadable(const std::string &path, bool scope_limit = false);
bool isInScope(const std::string &path);
bool isPathInScope(const std::string &path, const std::string &root);

// Atomic replacement can reach the point where the new complete file is
// visible but the containing directory entry cannot be synchronised (or a
// temporary link cannot be conclusively cleaned). Keep that state distinct
// from a pre-commit failure: callers must not assume the old file is still
// present when CommittedUnsynced is returned.
// FailedTemporaryRemaining is still a pre-commit failure and leaves the old
// target untouched, but reports that best-effort temporary cleanup failed.
enum class FileCommitResult : int {
    FailedTemporaryRemaining = -2,
    Failed = -1,
    Durable = 0,
    CommittedUnsynced = 1,
};
inline bool fileCommitFailed(FileCommitResult result) {
    return static_cast<int>(result) < 0;
}
inline bool fileCommitFailed(int result) { return result < 0; }
inline bool fileCommitDurabilityUnconfirmed(FileCommitResult result) {
    return static_cast<int>(result) > 0;
}
inline bool fileCommitDurabilityUnconfirmed(int result) { return result > 0; }
inline bool fileCommitTemporaryRemaining(FileCommitResult result) {
    return result == FileCommitResult::FailedTemporaryRemaining;
}
inline bool fileCommitTemporaryRemaining(int result) {
    return result ==
           static_cast<int>(FileCommitResult::FailedTemporaryRemaining);
}
FileCommitResult fileCopyDetailed(const std::string &source,
                                  const std::string &dest);
int fileWrite(const std::string &path, const std::string &content, bool overwrite);

inline int md(const char *path)
{
#ifdef _WIN32
    return mkdir(path);
#else
    return mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif // _WIN32
}

#endif // FILE_H_INCLUDED
