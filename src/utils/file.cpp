#include <atomic>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cwctype>
#include <cwchar>
#include <filesystem>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/xattr.h>
#endif
#endif

#include "utils/file.h"

namespace {

#ifndef S_ISREG
#if defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#elif defined(_S_IFMT) && defined(_S_IFREG)
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#else
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#endif
#endif

bool pathComponentEqual(const std::filesystem::path &left,
                        const std::filesystem::path &right) {
#ifdef _WIN32
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
#else
    return left == right;
#endif
}

#ifdef FILE_IO_TESTING
std::atomic<FileIoTestFailure> file_io_failure {FileIoTestFailure::None};
std::atomic<unsigned int> file_io_write_calls {0};
#endif

std::atomic<std::uint64_t> temporary_file_counter {0};
constexpr std::size_t file_lock_stripe_count = 64;
std::array<std::mutex, file_lock_stripe_count> file_write_mutexes;

bool removeTemporaryFile(const std::filesystem::path &path) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() ==
       FileIoTestFailure::ReplaceAndTemporaryCleanup)
        return false;
#endif
    std::error_code error;
    if(std::filesystem::remove(path, error) && !error)
        return true;
    if(error)
        return false;
    return !std::filesystem::exists(path, error) && !error;
}

void reportTemporaryFileRemaining(bool committed) {
    std::fputs(committed
                   ? "FILE_ATOMIC_COMMIT_TEMPORARY_REMAINING "
                     "new_file_visible=true durability=unconfirmed\n"
                   : "FILE_ATOMIC_WRITE_FAILED "
                     "temporary_file_remaining=true new_file_visible=false\n",
               stderr);
}

struct TargetState {
    bool exists = false;
#ifdef _WIN32
    DWORD volume_serial = 0;
    DWORD file_index_high = 0;
    DWORD file_index_low = 0;
    DWORD file_size_high = 0;
    DWORD file_size_low = 0;
    FILETIME last_write_time {};
#else
    dev_t device = 0;
    ino_t inode = 0;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
    off_t size = 0;
    timespec modified {};
    timespec changed {};
#endif
};

std::size_t fileLockStripe(const std::filesystem::path &path) {
#ifdef _WIN32
    std::wstring key = path.native();
    for(wchar_t &character : key)
        character = static_cast<wchar_t>(std::towlower(character));
    return std::hash<std::wstring>{}(key) % file_lock_stripe_count;
#else
    return std::hash<std::string>{}(path.native()) % file_lock_stripe_count;
#endif
}

#ifndef _WIN32
timespec modifiedTime(const struct stat &status) {
#ifdef __APPLE__
    return status.st_mtimespec;
#else
    return status.st_mtim;
#endif
}

timespec changedTime(const struct stat &status) {
#ifdef __APPLE__
    return status.st_ctimespec;
#else
    return status.st_ctim;
#endif
}

bool sameTime(const timespec &left, const timespec &right) {
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}
#endif

class TemporaryFileGuard {
  public:
    explicit TemporaryFileGuard(std::filesystem::path path)
        : path_(std::move(path)) {}

    ~TemporaryFileGuard() {
        if(!active_)
            return;
        removeNow(false);
    }

    void dismiss() { active_ = false; }
    bool removeNow(bool committed) {
        if(!active_)
            return true;
        const bool removed = removeTemporaryFile(path_);
        active_ = false;
        if(!removed)
            reportTemporaryFileRemaining(committed);
        return removed;
    }

  private:
    std::filesystem::path path_;
    bool active_ = true;
};

std::FILE *openFile(const char *path, const char *mode) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Open)
        return nullptr;
#endif
    return std::fopen(path, mode);
}

std::size_t writeFile(const void *data, std::size_t size, std::size_t count,
                      std::FILE *file) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::ShortWrite) {
        if(file_io_write_calls.fetch_add(1) > 0)
            return 0;
        const std::size_t partial = count > 1 ? count / 2 : 0;
        return partial ? std::fwrite(data, size, partial, file) : 0;
    }
#endif
    return std::fwrite(data, size, count, file);
}

int flushFile(std::FILE *file) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Flush)
        return EOF;
#endif
    return std::fflush(file);
}

int closeFile(std::FILE *file) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Close) {
        const int result = std::fclose(file);
        return result == 0 ? EOF : result;
    }
#endif
    return std::fclose(file);
}

int syncFile(std::FILE *file) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Sync)
        return -1;
#endif
#ifdef _WIN32
    return _commit(_fileno(file));
#else
    return ::fsync(fileno(file));
#endif
}

int syncParentDirectory(const std::filesystem::path &target) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::ParentDirectorySync)
        return -1;
#endif
#ifdef _WIN32
    // ReplaceFileW and first-create MoveFileExW use write-through semantics.
    // Windows does not expose a portable directory fsync equivalent.
    (void)target;
    return 0;
#else
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    const int descriptor = ::open(target.parent_path().c_str(), flags);
    if(descriptor < 0)
        return -1;
    const int sync_result = ::fsync(descriptor);
    const int close_result = ::close(descriptor);
    return sync_result == 0 && close_result == 0 ? 0 : -1;
#endif
}

std::filesystem::path resolvedWriteTarget(const std::string &path,
                                          std::error_code &error) {
    std::filesystem::path absolute = std::filesystem::absolute(path, error);
    if(error)
        return {};
    const std::filesystem::file_status link_status =
        std::filesystem::symlink_status(absolute, error);
    if(error && error != std::errc::no_such_file_or_directory)
        return {};
    error.clear();
    if(std::filesystem::is_symlink(link_status)) {
        std::filesystem::path link_target =
            std::filesystem::read_symlink(absolute, error);
        if(error)
            return {};
        if(link_target.is_relative())
            link_target = absolute.parent_path() / link_target;
        return std::filesystem::weakly_canonical(link_target, error);
    }
    return std::filesystem::weakly_canonical(absolute, error);
}

#ifdef _WIN32
bool windowsFileIdentity(const std::filesystem::path &path,
                         BY_HANDLE_FILE_INFORMATION &information) {
    HANDLE handle = CreateFileW(
        path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(handle == INVALID_HANDLE_VALUE)
        return false;
    const BOOL result = GetFileInformationByHandle(handle, &information);
    CloseHandle(handle);
    return result != FALSE;
}
#endif

bool inspectTarget(const std::filesystem::path &path, TargetState &state) {
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if(attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            state = TargetState{};
            return true;
        }
        return false;
    }
    if((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return false;
    if(_waccess(path.c_str(), 2) != 0)
        return false;
    BY_HANDLE_FILE_INFORMATION information {};
    if(!windowsFileIdentity(path, information) || information.nNumberOfLinks > 1)
        return false;
    state.exists = true;
    state.volume_serial = information.dwVolumeSerialNumber;
    state.file_index_high = information.nFileIndexHigh;
    state.file_index_low = information.nFileIndexLow;
    state.file_size_high = information.nFileSizeHigh;
    state.file_size_low = information.nFileSizeLow;
    state.last_write_time = information.ftLastWriteTime;
    return true;
#else
    struct stat information {};
    if(::stat(path.c_str(), &information) != 0) {
        if(errno == ENOENT) {
            state = TargetState{};
            return true;
        }
        return false;
    }
    if(!S_ISREG(information.st_mode) || information.st_nlink > 1 ||
       ::access(path.c_str(), W_OK) != 0)
        return false;
    state.exists = true;
    state.device = information.st_dev;
    state.inode = information.st_ino;
    state.mode = information.st_mode;
    state.owner = information.st_uid;
    state.group = information.st_gid;
    state.size = information.st_size;
    state.modified = modifiedTime(information);
    state.changed = changedTime(information);
    return true;
#endif
}

bool targetUnchanged(const std::filesystem::path &path,
                     const TargetState &expected) {
    if(!expected.exists) {
        std::error_code error;
        return !std::filesystem::exists(path, error) && !error;
    }
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION information {};
    return windowsFileIdentity(path, information) &&
           information.nNumberOfLinks == 1 &&
           information.dwVolumeSerialNumber == expected.volume_serial &&
           information.nFileIndexHigh == expected.file_index_high &&
           information.nFileIndexLow == expected.file_index_low &&
           information.nFileSizeHigh == expected.file_size_high &&
           information.nFileSizeLow == expected.file_size_low &&
           CompareFileTime(&information.ftLastWriteTime,
                           &expected.last_write_time) == 0;
#else
    struct stat information {};
    return ::stat(path.c_str(), &information) == 0 &&
           information.st_nlink == 1 && information.st_dev == expected.device &&
           information.st_ino == expected.inode &&
           information.st_size == expected.size &&
           sameTime(modifiedTime(information), expected.modified) &&
           sameTime(changedTime(information), expected.changed);
#endif
}

std::uint64_t processId() {
#ifdef _WIN32
    return static_cast<std::uint64_t>(_getpid());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

std::FILE *openUniqueTemporaryFile(const std::filesystem::path &target,
                                   std::filesystem::path &temporary_path,
                                   bool &temporary_cleanup_failed) {
    temporary_cleanup_failed = false;
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Open)
        return nullptr;
#endif
    const std::filesystem::path parent = target.parent_path();
    for(unsigned int attempt = 0; attempt < 128; ++attempt) {
        const std::uint64_t counter = temporary_file_counter.fetch_add(1);
#ifdef _WIN32
        const std::wstring name = L"." + target.filename().wstring() +
                                  L".subconverter-tmp-" +
                                  std::to_wstring(processId()) + L"-" +
                                  std::to_wstring(counter);
#else
        const std::string name = "." + target.filename().string() +
                                 ".subconverter-tmp-" +
                                 std::to_string(processId()) + "-" +
                                 std::to_string(counter);
#endif
        temporary_path = parent / name;
#ifdef _WIN32
        const int descriptor = _wopen(
            temporary_path.c_str(),
            _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT,
            _S_IREAD | _S_IWRITE);
        if(descriptor >= 0) {
            std::FILE *file = _fdopen(descriptor, "wb");
            if(file)
                return file;
            _close(descriptor);
            if(!removeTemporaryFile(temporary_path)) {
                temporary_cleanup_failed = true;
                reportTemporaryFileRemaining(false);
            }
            return nullptr;
        }
        if(errno != EEXIST)
            return nullptr;
#else
        const int descriptor = ::open(
            temporary_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(descriptor >= 0) {
            std::FILE *file = fdopen(descriptor, "wb");
            if(file)
                return file;
            ::close(descriptor);
            if(!removeTemporaryFile(temporary_path)) {
                temporary_cleanup_failed = true;
                reportTemporaryFileRemaining(false);
            }
            return nullptr;
        }
        if(errno != EEXIST)
            return nullptr;
#endif
    }
    return nullptr;
}

bool copyFileToStream(const std::filesystem::path &source, std::FILE *output) {
    std::FILE *input =
#ifdef _WIN32
        _wfopen(source.c_str(), L"rb");
#else
        std::fopen(source.c_str(), "rb");
#endif
    if(!input)
        return false;
    char buffer[64 * 1024];
    bool success = true;
    while(true) {
        const std::size_t count = std::fread(buffer, 1, sizeof(buffer), input);
        std::size_t offset = 0;
        while(offset < count) {
            const std::size_t written =
                writeFile(buffer + offset, 1, count - offset, output);
            if(written == 0) {
                success = false;
                break;
            }
            offset += written;
        }
        if(!success || count < sizeof(buffer)) {
            if(std::ferror(input))
                success = false;
            break;
        }
    }
    if(std::fclose(input) != 0)
        success = false;
    return success;
}

bool writeStringToStream(const std::string &content, std::FILE *output) {
    std::size_t offset = 0;
    while(offset < content.size()) {
        const std::size_t written =
            writeFile(content.data() + offset, 1, content.size() - offset,
                      output);
        if(written == 0)
            return false;
        offset += written;
    }
    return true;
}

bool preserveTargetMetadata(std::FILE *file,
                            const std::filesystem::path &target_path,
                            const TargetState &target) {
    if(!target.exists)
        return true;
#ifdef _WIN32
    // ReplaceFileW preserves the target file's ACL and other replaceable
    // metadata. No pre-replacement mutation is required here.
    (void)file;
    (void)target_path;
    return true;
#else
    const int descriptor = fileno(file);
    struct stat temporary {};
    if(::fstat(descriptor, &temporary) != 0)
        return false;
    if((temporary.st_uid != target.owner || temporary.st_gid != target.group) &&
       ::fchown(descriptor, target.owner, target.group) != 0)
        return false;
    if(::fchmod(descriptor, target.mode & 07777) != 0)
        return false;
#ifdef __linux__
    const ssize_t names_size = ::listxattr(target_path.c_str(), nullptr, 0);
    if(names_size < 0)
        return errno == ENOTSUP || errno == EOPNOTSUPP;
    if(names_size > 0) {
        std::vector<char> names(static_cast<std::size_t>(names_size));
        if(::listxattr(target_path.c_str(), names.data(), names.size()) !=
           names_size)
            return false;
        std::size_t offset = 0;
        while(offset < names.size()) {
            const char *name = names.data() + offset;
            const std::size_t length = std::strlen(name);
            if(length == 0)
                break;
            const ssize_t value_size =
                ::getxattr(target_path.c_str(), name, nullptr, 0);
            if(value_size < 0)
                return false;
            std::vector<char> value(static_cast<std::size_t>(value_size));
            if(value_size > 0 &&
               ::getxattr(target_path.c_str(), name, value.data(), value.size()) !=
                   value_size)
                return false;
            const ssize_t existing_size =
                ::fgetxattr(descriptor, name, nullptr, 0);
            bool already_equal = existing_size == value_size;
            if(already_equal && value_size > 0) {
                std::vector<char> existing(
                    static_cast<std::size_t>(existing_size));
                already_equal =
                    ::fgetxattr(descriptor, name, existing.data(),
                                existing.size()) == existing_size &&
                    existing == value;
            }
            if(!already_equal &&
               ::fsetxattr(descriptor, name,
                           value_size > 0 ? value.data() : nullptr,
                           static_cast<std::size_t>(value_size), 0) != 0)
                return false;
            offset += length + 1;
        }
    }
#endif
    return true;
#endif
}

enum class ReplaceResult {
    NotCommitted,
    Committed,
    CommittedTemporaryLinkRemaining,
};

ReplaceResult replaceTarget(const std::filesystem::path &temporary,
                            const std::filesystem::path &target,
                            const TargetState &state) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Replace ||
       file_io_failure.load() ==
           FileIoTestFailure::ReplaceAndTemporaryCleanup)
        return ReplaceResult::NotCommitted;
    if(file_io_failure.load() ==
           FileIoTestFailure::TargetChangedBeforeReplace &&
       state.exists) {
#ifdef _WIN32
        std::FILE *external = _wfopen(target.c_str(), L"ab");
#else
        std::FILE *external = std::fopen(target.c_str(), "ab");
#endif
        static const char mutation[] = "external-append";
        if(!external)
            return ReplaceResult::NotCommitted;
        bool mutation_ok =
            std::fwrite(mutation, 1, sizeof(mutation) - 1, external) ==
            sizeof(mutation) - 1;
        if(std::fflush(external) != 0)
            mutation_ok = false;
        if(std::fclose(external) != 0)
            mutation_ok = false;
        if(!mutation_ok)
            return ReplaceResult::NotCommitted;
    }
#endif
    if(!targetUnchanged(target, state))
        return ReplaceResult::NotCommitted;
#ifdef _WIN32
    if(state.exists) {
        for(unsigned int attempt = 0; attempt < 20; ++attempt) {
            if(ReplaceFileW(target.c_str(), temporary.c_str(), nullptr, 0,
                            nullptr, nullptr) != FALSE)
                return ReplaceResult::Committed;
            const DWORD error = GetLastError();
            // Antivirus/indexing readers can briefly hold the old inode
            // without delete sharing. These errors guarantee that both files
            // retain their original names, so a bounded retry is safe. Do not
            // retry ambiguous partial-replacement errors.
            if(error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED &&
                error != ERROR_UNABLE_TO_REMOVE_REPLACED)
                return ReplaceResult::NotCommitted;
            if(!targetUnchanged(target, state))
                return ReplaceResult::NotCommitted;
            Sleep(5);
        }
        return ReplaceResult::NotCommitted;
    }
    return MoveFileExW(temporary.c_str(), target.c_str(),
                       MOVEFILE_WRITE_THROUGH) != FALSE
               ? ReplaceResult::Committed
               : ReplaceResult::NotCommitted;
#else
    if(!state.exists) {
        if(::link(temporary.c_str(), target.c_str()) != 0)
            return ReplaceResult::NotCommitted;
        if(::unlink(temporary.c_str()) != 0) {
            // The target is already a complete, durable inode. Leaving the
            // target in place is safer than rolling back a successful create.
            return ReplaceResult::CommittedTemporaryLinkRemaining;
        }
        return ReplaceResult::Committed;
    }
    return ::rename(temporary.c_str(), target.c_str()) == 0
               ? ReplaceResult::Committed
               : ReplaceResult::NotCommitted;
#endif
}

FileCommitResult atomicWriteLocked(const std::filesystem::path &target,
                                   const std::filesystem::path *prefix_source,
                                   const std::string &content) {
    TargetState target_state;
    if(!inspectTarget(target, target_state))
        return FileCommitResult::Failed;

    std::filesystem::path temporary_path;
    bool open_cleanup_failed = false;
    std::FILE *file = openUniqueTemporaryFile(
        target, temporary_path, open_cleanup_failed);
    if(!file)
        return open_cleanup_failed
                   ? FileCommitResult::FailedTemporaryRemaining
                   : FileCommitResult::Failed;
    TemporaryFileGuard cleanup(temporary_path);

    bool success = true;
    if(prefix_source)
        success = copyFileToStream(*prefix_source, file);
    if(success)
        success = writeStringToStream(content, file);
    if(success && std::ferror(file))
        success = false;
    if(success && !preserveTargetMetadata(file, target, target_state))
        success = false;
    if(success && flushFile(file) != 0)
        success = false;
    if(success && syncFile(file) != 0)
        success = false;
    if(closeFile(file) != 0)
        success = false;
    if(!success)
        return cleanup.removeNow(false)
                   ? FileCommitResult::Failed
                   : FileCommitResult::FailedTemporaryRemaining;

    const ReplaceResult replace_result =
        replaceTarget(temporary_path, target, target_state);
    if(replace_result == ReplaceResult::NotCommitted)
        return cleanup.removeNow(false)
                   ? FileCommitResult::Failed
                   : FileCommitResult::FailedTemporaryRemaining;

    bool temporary_removed =
        replace_result != ReplaceResult::CommittedTemporaryLinkRemaining;
    if(temporary_removed)
        cleanup.dismiss();
    else
        temporary_removed = cleanup.removeNow(true);

    const bool directory_synced = syncParentDirectory(target) == 0;
    return temporary_removed && directory_synced
               ? FileCommitResult::Durable
               : FileCommitResult::CommittedUnsynced;
}

} // namespace

bool isPathInScope(const std::string &path, const std::string &root)
{
    if(path.empty() || root.empty())
        return false;

    std::error_code error;
    std::filesystem::path absolute_candidate =
        std::filesystem::absolute(path, error);
    if(error)
        return false;
    std::filesystem::path candidate =
        std::filesystem::weakly_canonical(absolute_candidate, error);
    if(error)
        return false;
    std::filesystem::path absolute_root =
        std::filesystem::absolute(root, error);
    if(error)
        return false;
    std::filesystem::path canonical_root =
        std::filesystem::weakly_canonical(absolute_root, error);
    if(error)
        return false;

    auto candidate_component = candidate.begin();
    for(auto root_component = canonical_root.begin();
        root_component != canonical_root.end();
        ++root_component, ++candidate_component)
    {
        if(candidate_component == candidate.end() ||
           !pathComponentEqual(*candidate_component, *root_component))
            return false;
    }
    return true;
}

bool isInScope(const std::string &path)
{
    std::error_code error;
    const std::filesystem::path root = std::filesystem::current_path(error);
    return !error && isPathInScope(path, root.string());
}

#ifdef FILE_IO_TESTING
void setFileIoTestFailure(FileIoTestFailure failure) {
    file_io_write_calls.store(0);
    file_io_failure.store(failure);
}
#endif

// TODO: Add preprocessor option to disable (open web service safety)
std::string fileGet(const std::string &path, bool scope_limit)
{
    std::string content;

    if(scope_limit && !isInScope(path))
        return "";

    // An unrestricted read is an intentional local-operator API used for
    // preference files and configured scripts. Request-controlled callers set
    // scope_limit=true and must pass the canonical working-tree containment
    // check above before this sink is reached.
    // codeql[cpp/path-injection]
    std::FILE *fp = openFile(path.c_str(), "rb");
    if(!fp)
        return "";
    if(std::fseek(fp, 0, SEEK_END) != 0)
    {
        closeFile(fp);
        return "";
    }
    const long total = std::ftell(fp);
    if(total < 0 || std::fseek(fp, 0, SEEK_SET) != 0)
    {
        closeFile(fp);
        return "";
    }
    content.resize(static_cast<std::size_t>(total));
    std::size_t offset = 0;
    while(offset < content.size())
    {
        const std::size_t count =
            std::fread(&content[offset], 1, content.size() - offset, fp);
        if(count == 0)
        {
            content.clear();
            break;
        }
        offset += count;
    }
    if(std::ferror(fp) || closeFile(fp) != 0)
        content.clear();
    return content;
}

bool fileExist(const std::string &path, bool scope_limit)
{
    //using c++17 standard, but may cause problem on clang
    //return std::filesystem::exists(path);
    if(scope_limit && !isInScope(path))
        return false;
    struct stat st;
    return stat(path.data(), &st) == 0 && S_ISREG(st.st_mode);
}

FileCommitResult fileCopyDetailed(const std::string &source,
                                  const std::string &dest)
{
    std::error_code source_error, destination_error;
    const std::filesystem::path source_path =
        resolvedWriteTarget(source, source_error);
    const std::filesystem::path destination_path =
        resolvedWriteTarget(dest, destination_error);
    if(source_error || destination_error || source_path.empty() ||
       destination_path.empty())
        return FileCommitResult::Failed;

    auto copy_resolved = [&]() {
        std::error_code source_status_error;
        if(!std::filesystem::is_regular_file(source_path, source_status_error) ||
           source_status_error)
            return FileCommitResult::Failed;
        return atomicWriteLocked(destination_path, &source_path, "");
    };

    const std::size_t source_stripe = fileLockStripe(source_path);
    const std::size_t destination_stripe = fileLockStripe(destination_path);
    if(source_stripe == destination_stripe) {
        std::lock_guard<std::mutex> lock(file_write_mutexes[source_stripe]);
        return copy_resolved();
    }
    std::scoped_lock lock(file_write_mutexes[source_stripe],
                          file_write_mutexes[destination_stripe]);
    return copy_resolved();
}

bool fileCopy(const std::string &source, const std::string &dest)
{
    return fileCopyDetailed(source, dest) == FileCommitResult::Durable;
}

int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    std::error_code error;
    const std::filesystem::path target = resolvedWriteTarget(path, error);
    if(error || target.empty())
        return static_cast<int>(FileCommitResult::Failed);
    std::lock_guard<std::mutex> lock(
        file_write_mutexes[fileLockStripe(target)]);
    if(!overwrite && content.empty()) {
        std::error_code status_error;
        const std::filesystem::file_status status =
            std::filesystem::status(target, status_error);
        if(status_error && status_error != std::errc::no_such_file_or_directory)
            return static_cast<int>(FileCommitResult::Failed);
        if(!status_error && std::filesystem::exists(status)) {
            if(!std::filesystem::is_regular_file(status))
                return static_cast<int>(FileCommitResult::Failed);
#ifdef _WIN32
            return _waccess(target.c_str(), 2) == 0
                       ? static_cast<int>(FileCommitResult::Durable)
                       : static_cast<int>(FileCommitResult::Failed);
#else
            return ::access(target.c_str(), W_OK) == 0
                       ? static_cast<int>(FileCommitResult::Durable)
                       : static_cast<int>(FileCommitResult::Failed);
#endif
        }
    }
    const std::filesystem::path *prefix_source = nullptr;
    std::error_code existence_error;
    if(!overwrite && std::filesystem::exists(target, existence_error) &&
       !existence_error)
        prefix_source = &target;
    else if(existence_error)
        return static_cast<int>(FileCommitResult::Failed);
    return static_cast<int>(
        atomicWriteLocked(target, prefix_source, content));
}
