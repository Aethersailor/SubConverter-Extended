#include <atomic>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <string>
#include <fstream>
#include <sys/stat.h>

#include "utils/file.h"
#include "utils/string.h"

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
    std::ifstream infile;
    std::ofstream outfile;
    infile.open(source, std::ios::binary);
    if(!infile)
        return false;
    outfile.open(dest, std::ios::binary);
    if(!outfile)
        return false;
    try
    {
        outfile<<infile.rdbuf();
    }
    catch (std::exception &e)
    {
        return false;
    }
    infile.close();
    outfile.close();
    return true;
}

int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    /*
    std::fstream outfile;
    std::ios_base::openmode mode = overwrite ? std::ios_base::out : std::ios_base::app;
    mode |= std::ios_base::binary;
    outfile.open(path, mode);
    outfile << content;
    outfile.close();
    return 0;
    */
    const char *mode = overwrite ? "wb" : "ab";
    std::FILE *fp = openFile(path.c_str(), mode);
    if(!fp)
        return -1;

    std::size_t offset = 0;
    bool failed = false;
    while(offset < content.size())
    {
        const std::size_t written =
            writeFile(content.data() + offset, 1, content.size() - offset, fp);
        if(written == 0)
        {
            failed = true;
            break;
        }
        offset += written;
    }
    if(std::ferror(fp) || flushFile(fp) != 0)
        failed = true;
    if(closeFile(fp) != 0)
        failed = true;
    return failed ? -1 : 0;
}
