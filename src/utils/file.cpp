#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
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
std::mutex file_write_mutex;

struct TargetState {
    bool exists = false;
#ifdef _WIN32
    DWORD volume_serial = 0;
    DWORD file_index_high = 0;
    DWORD file_index_low = 0;
#else
    dev_t device = 0;
    ino_t inode = 0;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
#endif
};

class TemporaryFileGuard {
  public:
    explicit TemporaryFileGuard(std::filesystem::path path)
        : path_(std::move(path)) {}

    ~TemporaryFileGuard() {
        if(!active_)
            return;
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

    void dismiss() { active_ = false; }

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
           information.nFileIndexLow == expected.file_index_low;
#else
    struct stat information {};
    return ::stat(path.c_str(), &information) == 0 &&
           information.st_nlink == 1 && information.st_dev == expected.device &&
           information.st_ino == expected.inode;
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
                                   std::filesystem::path &temporary_path) {
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
            std::error_code cleanup_error;
            std::filesystem::remove(temporary_path, cleanup_error);
            return nullptr;
        }
        if(errno != EEXIST)
            return nullptr;
#else
        const int descriptor = ::open(
            temporary_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            0666);
        if(descriptor >= 0) {
            std::FILE *file = fdopen(descriptor, "wb");
            if(file)
                return file;
            ::close(descriptor);
            std::error_code cleanup_error;
            std::filesystem::remove(temporary_path, cleanup_error);
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

bool replaceTarget(const std::filesystem::path &temporary,
                   const std::filesystem::path &target,
                   const TargetState &state) {
#ifdef FILE_IO_TESTING
    if(file_io_failure.load() == FileIoTestFailure::Replace)
        return false;
#endif
    if(!targetUnchanged(target, state))
        return false;
#ifdef _WIN32
    if(state.exists) {
        for(unsigned int attempt = 0; attempt < 20; ++attempt) {
            if(ReplaceFileW(target.c_str(), temporary.c_str(), nullptr, 0,
                            nullptr, nullptr) != FALSE)
                return true;
            const DWORD error = GetLastError();
            // Antivirus/indexing readers can briefly hold the old inode
            // without delete sharing. These errors guarantee that both files
            // retain their original names, so a bounded retry is safe. Do not
            // retry ambiguous partial-replacement errors.
            if(error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED &&
               error != ERROR_UNABLE_TO_REMOVE_REPLACED)
                return false;
            if(!targetUnchanged(target, state))
                return false;
            Sleep(5);
        }
        return false;
    }
    return MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) !=
           FALSE;
#else
    if(!state.exists) {
        if(::link(temporary.c_str(), target.c_str()) != 0)
            return false;
        if(::unlink(temporary.c_str()) != 0) {
            // The target is already a complete, durable inode. Leaving the
            // temporary hardlink is safer than removing the successfully
            // created target and reporting a destructive failure.
            return false;
        }
        return true;
    }
    return ::rename(temporary.c_str(), target.c_str()) == 0;
#endif
}

int atomicWriteLocked(const std::filesystem::path &target,
                      const std::filesystem::path *prefix_source,
                      const std::string &content) {
    TargetState target_state;
    if(!inspectTarget(target, target_state))
        return -1;

    std::filesystem::path temporary_path;
    std::FILE *file = openUniqueTemporaryFile(target, temporary_path);
    if(!file)
        return -1;
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
        return -1;

    if(!replaceTarget(temporary_path, target, target_state))
        return -1;
    cleanup.dismiss();
    return 0;
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

bool fileCopy(const std::string &source, const std::string &dest)
{
    std::lock_guard<std::mutex> lock(file_write_mutex);
    std::error_code source_error, destination_error;
    const std::filesystem::path source_path =
        resolvedWriteTarget(source, source_error);
    const std::filesystem::path destination_path =
        resolvedWriteTarget(dest, destination_error);
    if(source_error || destination_error || source_path.empty() ||
       destination_path.empty())
        return false;
    std::error_code source_status_error;
    if(!std::filesystem::is_regular_file(source_path, source_status_error) ||
       source_status_error)
        return false;
    return atomicWriteLocked(destination_path, &source_path, "") == 0;
}

int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    std::lock_guard<std::mutex> lock(file_write_mutex);
    std::error_code error;
    const std::filesystem::path target = resolvedWriteTarget(path, error);
    if(error || target.empty())
        return -1;
    if(!overwrite && content.empty()) {
        std::error_code status_error;
        const std::filesystem::file_status status =
            std::filesystem::status(target, status_error);
        if(status_error && status_error != std::errc::no_such_file_or_directory)
            return -1;
        if(!status_error && std::filesystem::exists(status)) {
            if(!std::filesystem::is_regular_file(status))
                return -1;
#ifdef _WIN32
            return _waccess(target.c_str(), 2) == 0 ? 0 : -1;
#else
            return ::access(target.c_str(), W_OK) == 0 ? 0 : -1;
#endif
        }
    }
    const std::filesystem::path *prefix_source = nullptr;
    std::error_code existence_error;
    if(!overwrite && std::filesystem::exists(target, existence_error) &&
       !existence_error)
        prefix_source = &target;
    else if(existence_error)
        return -1;
    return atomicWriteLocked(target, prefix_source, content);
}
