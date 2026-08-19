#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef _WIN32
#include <sys/stat.h>
#ifdef __linux__
#include <sys/xattr.h>
#endif
#endif

#include "utils/file.h"

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct TemporaryTree {
  std::filesystem::path path;
  ~TemporaryTree() {
#ifdef _WIN32
    // MSYS/UCRT may represent directory symlinks (and a symlink whose target
    // does not yet exist) as junction reparse points. std::filesystem's
    // remove_all can stop at those entries, so remove the test reparse points
    // explicitly before deleting the temporary tree.
    for (const auto &relative : {"configured-root-link", "scope/escape",
                                 "scope/broken-write.txt",
                                 "scope/symlink-write.txt"}) {
      const std::filesystem::path candidate = path / relative;
      const DWORD attributes = GetFileAttributesW(candidate.c_str());
      if (attributes == INVALID_FILE_ATTRIBUTES ||
          (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
        continue;
      if (!DeleteFileW(candidate.c_str()))
        RemoveDirectoryW(candidate.c_str());
    }
#endif
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

std::size_t temporaryFileCount(const std::filesystem::path &target) {
  const std::string prefix = "." + target.filename().string() +
                             ".subconverter-tmp-";
  std::size_t count = 0;
  for (const auto &entry :
       std::filesystem::directory_iterator(target.parent_path())) {
    if (entry.path().filename().string().rfind(prefix, 0) == 0)
      ++count;
  }
  return count;
}

void requireFailurePreservesFile(const std::filesystem::path &target,
                                 FileIoTestFailure failure,
                                 bool overwrite) {
  const std::string original = fileGet(target.string(), false);
  setFileIoTestFailure(failure);
  require(fileWrite(target.string(), "replacement-secret", overwrite) != 0,
          "injected write failure reported success");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(target.string(), false) == original,
          "injected write failure changed the original file");
  require(temporaryFileCount(target) == 0,
          "injected write failure left a temporary file");
}

} // namespace

int main() {
  namespace fs = std::filesystem;
  require(fileCommitFailed(FileCommitResult::Failed) &&
              fileCommitFailed(FileCommitResult::FailedTemporaryRemaining) &&
              !fileCommitFailed(FileCommitResult::CommittedUnsynced) &&
              fileCommitDurabilityUnconfirmed(
                  FileCommitResult::CommittedUnsynced),
          "file commit tri-state helper contract changed");
  const fs::path working_root = fs::current_path();
  const fs::path fixture = "tests/fixtures/sample-subscription.txt";
  require(isInScope(fixture.string()), "relative fixture rejected");
  require(fileExist(fixture.string(), true), "relative fixture not found");
  require(!fileGet(fixture.string(), true).empty(), "relative fixture unreadable");

  const fs::path absolute_fixture = fs::absolute(fixture);
  require(isInScope(absolute_fixture.string()),
          "absolute path inside working root rejected");
  require(fileExist(absolute_fixture.string(), true),
          "absolute in-root fixture not found");
  require(!fileGet(absolute_fixture.string(), true).empty(),
          "absolute in-root fixture unreadable");
  require(isInScope("tests/../tests/fixtures/sample-subscription.txt"),
          "normalized in-root path rejected");

  const fs::path outside_candidate =
      working_root.parent_path() / "subconverter-file-scope-outside.txt";
  require(!isInScope(outside_candidate.string()),
          "parent traversal escaped the working root");
#ifdef _WIN32
  require(!isInScope("C:/Windows/System32/drivers/etc/hosts"),
          "Windows forward-slash absolute path accepted");
  require(!isInScope("C:\\Windows\\System32\\drivers\\etc\\hosts"),
          "Windows backslash absolute path accepted");
  require(!isInScope("\\\\server\\share\\secret.txt"),
          "UNC path accepted");
#else
  require(!isInScope("/etc/passwd"), "POSIX absolute path accepted");
#endif

  const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
  TemporaryTree temporary {
      working_root / "build" / ("file-scope-test-" + std::to_string(unique))};
  const fs::path scoped_root = temporary.path / "scope";
  const fs::path external_root = temporary.path / "external";
  const fs::path sibling_root = temporary.path / "scope-sibling";
  fs::create_directories(scoped_root);
  fs::create_directories(external_root);
  fs::create_directories(sibling_root);

  const fs::path dotted_name = scoped_root / "legal..name.txt";
  require(fileWrite(dotted_name.string(), "alpha", true) == 0,
          "initial file write failed");
  require(fileWrite(dotted_name.string(), "-beta", false) == 0,
          "append file write failed");
  require(fileGet(dotted_name.string(), false) == "alpha-beta",
          "write/append content changed");
  require(isPathInScope(dotted_name.string(), scoped_root.string()),
          "legal filename containing two dots rejected");

  const fs::path escaped_file = external_root / "escaped.txt";
  require(fileWrite(escaped_file.string(), "outside", true) == 0,
          "external fixture write failed");
  require(!isPathInScope(escaped_file.string(), scoped_root.string()),
          "custom root accepted an outside file");
  require(!isPathInScope((sibling_root / "prefix.txt").string(),
                         scoped_root.string()),
          "component-prefix sibling was accepted");

  std::error_code symlink_error;
  const fs::path root_link = temporary.path / "configured-root-link";
  fs::create_directory_symlink(scoped_root, root_link, symlink_error);
  if (!symlink_error) {
    require(isPathInScope((root_link / dotted_name.filename()).string(),
                          root_link.string()),
            "configured symlink root rejected its own descendant");
  }

  const fs::path broken_symlink_target = scoped_root / "broken-target.txt";
  const fs::path broken_symlink_path = scoped_root / "broken-write.txt";
  symlink_error.clear();
  fs::create_symlink(broken_symlink_target.filename(), broken_symlink_path,
                     symlink_error);
  if (!symlink_error) {
    require(fileWrite(broken_symlink_path.string(), "created-through-link", true) ==
                0,
            "write through a broken symlink failed");
    require(fs::is_symlink(fs::symlink_status(broken_symlink_path)),
            "write through a broken symlink replaced the link itself");
    require(fileGet(broken_symlink_target.string(), false) ==
                "created-through-link",
            "broken symlink target was not created");
  }

  symlink_error.clear();
  const fs::path escape_link = scoped_root / "escape";
  fs::create_directory_symlink(external_root, escape_link, symlink_error);
  if (!symlink_error) {
    require(!isPathInScope((escape_link / escaped_file.filename()).string(),
                           scoped_root.string()),
            "descendant symlink escaped the configured root");
  }

  const fs::path failure_file = scoped_root / "failure.txt";
  require(fileWrite(failure_file.string(), "original", true) == 0,
          "failure fixture write failed");
  setFileIoTestFailure(FileIoTestFailure::Open);
  require(fileGet(dotted_name.string(), false).empty(),
          "read-open failure returned content");
  setFileIoTestFailure(FileIoTestFailure::None);

  const std::vector<FileIoTestFailure> failures = {
      FileIoTestFailure::Open,       FileIoTestFailure::ShortWrite,
      FileIoTestFailure::Flush,      FileIoTestFailure::Sync,
      FileIoTestFailure::Close,      FileIoTestFailure::Replace,
  };
  for (FileIoTestFailure failure : failures) {
    requireFailurePreservesFile(failure_file, failure, true);
    requireFailurePreservesFile(failure_file, failure, false);
  }

  setFileIoTestFailure(FileIoTestFailure::ReplaceAndTemporaryCleanup);
  require(fileWrite(failure_file.string(), "cleanup-observable", true) ==
              static_cast<int>(FileCommitResult::FailedTemporaryRemaining),
          "pre-commit cleanup failure was not observable by the caller");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(failure_file.string(), false) == "original" &&
              temporaryFileCount(failure_file) == 1,
          "pre-commit cleanup failure changed the target or hid the residual");
  for (const auto &entry : fs::directory_iterator(failure_file.parent_path())) {
    if (entry.path().filename().string().find(
            ".failure.txt.subconverter-tmp-") == 0)
      fs::remove(entry.path());
  }
  require(temporaryFileCount(failure_file) == 0,
          "cleanup failure fixture left an unmanaged test residual");

  setFileIoTestFailure(FileIoTestFailure::TargetChangedBeforeReplace);
  require(fileWrite(failure_file.string(), "our-append", false) ==
              static_cast<int>(FileCommitResult::Failed),
          "external append race was silently overwritten");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(failure_file.string(), false) == "originalexternal-append",
          "failed append race lost the external writer's content");

#ifndef _WIN32
  setFileIoTestFailure(FileIoTestFailure::ParentDirectorySync);
  require(fileWrite(failure_file.string(), "committed-unsynced", true) ==
              static_cast<int>(FileCommitResult::CommittedUnsynced),
          "parent-directory sync failure lost its committed-state result");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(failure_file.string(), false) == "committed-unsynced",
          "post-commit sync failure was falsely treated as pre-commit");
  require(temporaryFileCount(failure_file) == 0,
          "post-commit sync failure left a temporary file");

  const fs::path unsynced_create = scoped_root / "unsynced-create.txt";
  setFileIoTestFailure(FileIoTestFailure::ParentDirectorySync);
  require(fileWrite(unsynced_create.string(), "complete-create", true) ==
              static_cast<int>(FileCommitResult::CommittedUnsynced),
          "first-create directory sync failure lost committed state");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(unsynced_create.string(), false) == "complete-create" &&
              temporaryFileCount(unsynced_create) == 0,
          "first-create sync failure left incomplete state");
#endif

  const fs::path first_create = scoped_root / "first-create.txt";
  require(fileWrite(first_create.string(), "created", true) == 0,
          "first atomic create failed");
  require(fileGet(first_create.string(), false) == "created",
          "first atomic create changed content");
#ifndef _WIN32
  struct stat first_create_status {};
  require(::stat(first_create.c_str(), &first_create_status) == 0 &&
              (first_create_status.st_mode & (S_IWGRP | S_IWOTH)) == 0,
          "first atomic create granted group or world write access");
#endif
  require(temporaryFileCount(first_create) == 0,
          "first atomic create left a temporary file");
  require(fileWrite(first_create.string(), "", true) == 0,
          "empty atomic overwrite failed");
  require(fileExist(first_create.string()) &&
              fileGet(first_create.string(), false).empty(),
          "empty atomic overwrite did not leave an empty file");
  require(fileWrite(first_create.string(), "append-created", false) == 0,
          "append to empty file failed");
  require(fileWrite(first_create.string(), "", false) == 0,
          "empty append failed");
  require(fileGet(first_create.string(), false) == "append-created",
          "append semantics changed");
  require(fileWrite(scoped_root.string(), "", false) != 0,
          "empty append reported success for a directory");

  const fs::path missing_append = scoped_root / "missing-append.txt";
  require(fileWrite(missing_append.string(), "created-by-append", false) == 0,
          "append did not create a missing file");
  require(fileGet(missing_append.string(), false) == "created-by-append",
          "append-created content changed");

  const fs::path concurrent_overwrite = scoped_root / "concurrent-overwrite.txt";
  require(fileWrite(concurrent_overwrite.string(), "seed", true) == 0,
          "concurrent overwrite fixture failed");
  std::vector<std::string> complete_values;
  std::vector<std::thread> writers;
  for (int index = 0; index < 12; ++index) {
    complete_values.push_back("complete-value-" + std::to_string(index) +
                              std::string(2048, static_cast<char>('a' + index)));
  }
  std::atomic<bool> concurrent_writes_ok {true};
  for (int index = 0; index < 12; ++index) {
    writers.emplace_back([&, index] {
      if (fileWrite(concurrent_overwrite.string(), complete_values[index], true) !=
          0)
        concurrent_writes_ok.store(false);
    });
  }
  for (auto &writer : writers)
    writer.join();
  require(concurrent_writes_ok.load(), "concurrent overwrite failed");
  const std::string concurrent_result =
      fileGet(concurrent_overwrite.string(), false);
  require(std::find(complete_values.begin(), complete_values.end(),
                    concurrent_result) != complete_values.end(),
          "concurrent overwrite exposed partial content");
  require(temporaryFileCount(concurrent_overwrite) == 0,
          "concurrent overwrite left a temporary file");

  const fs::path concurrent_append = scoped_root / "concurrent-append.txt";
  require(fileWrite(concurrent_append.string(), "", true) == 0,
          "concurrent append fixture failed");
  writers.clear();
  concurrent_writes_ok.store(true);
  for (int index = 0; index < 12; ++index) {
    writers.emplace_back([&, index] {
      const std::string marker = "[" + std::to_string(index) + "]";
      if (fileWrite(concurrent_append.string(), marker, false) != 0)
        concurrent_writes_ok.store(false);
    });
  }
  for (auto &writer : writers)
    writer.join();
  require(concurrent_writes_ok.load(), "concurrent append failed");
  const std::string appended = fileGet(concurrent_append.string(), false);
  for (int index = 0; index < 12; ++index) {
    const std::string marker = "[" + std::to_string(index) + "]";
    require(appended.find(marker) != std::string::npos,
            "concurrent append lost a complete append");
  }

  const fs::path copy_source = scoped_root / "copy-source.txt";
  const fs::path copy_dest = scoped_root / "copy-dest.txt";
  require(fileWrite(copy_source.string(), "copy-source-content", true) == 0,
          "copy source fixture failed");
  require(fileWrite(copy_dest.string(), "copy-destination-original", true) == 0,
          "copy destination fixture failed");
  setFileIoTestFailure(FileIoTestFailure::Replace);
  require(!fileCopy(copy_source.string(), copy_dest.string()),
          "copy replace failure reported success");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileGet(copy_dest.string(), false) == "copy-destination-original",
          "failed copy damaged its destination");
  require(temporaryFileCount(copy_dest) == 0,
          "failed copy left a temporary file");
  require(fileCopy(copy_source.string(), copy_dest.string()),
          "successful atomic copy failed");
  require(fileGet(copy_dest.string(), false) == "copy-source-content",
          "successful atomic copy changed content");

  const fs::path symlink_target = scoped_root / "symlink-target.txt";
  const fs::path symlink_path = scoped_root / "symlink-write.txt";
  require(fileWrite(symlink_target.string(), "symlink-original", true) == 0,
          "symlink target fixture failed");
  symlink_error.clear();
  fs::create_symlink(symlink_target.filename(), symlink_path, symlink_error);
  if (!symlink_error) {
    require(fileWrite(symlink_path.string(), "symlink-updated", true) == 0,
            "write through symlink failed");
    require(fs::is_symlink(fs::symlink_status(symlink_path)),
            "atomic write replaced the symlink itself");
    require(fileGet(symlink_target.string(), false) == "symlink-updated",
            "atomic write did not update the symlink target");
  }

  const fs::path hardlink_source = scoped_root / "hardlink-source.txt";
  const fs::path hardlink_alias = scoped_root / "hardlink-alias.txt";
  require(fileWrite(hardlink_source.string(), "hardlink-original", true) == 0,
          "hardlink fixture failed");
  std::error_code hardlink_error;
  fs::create_hard_link(hardlink_source, hardlink_alias, hardlink_error);
  if (!hardlink_error) {
    require(fileWrite(hardlink_source.string(), "", false) == 0,
            "empty append should remain a no-op for a writable hardlink");
    require(fileWrite(hardlink_source.string(), "must-not-split-hardlink", true) !=
                0,
            "atomic write silently split a shared hardlink inode");
    require(fileGet(hardlink_source.string(), false) == "hardlink-original" &&
                fileGet(hardlink_alias.string(), false) == "hardlink-original",
            "hardlink-safe failure changed shared content");
  }

#ifndef _WIN32
  const fs::path mode_file = scoped_root / "mode.txt";
  require(fileWrite(mode_file.string(), "mode-original", true) == 0,
          "mode fixture failed");
  require(::chmod(mode_file.c_str(), 0640) == 0, "chmod fixture failed");
  require(fileWrite(mode_file.string(), "mode-updated", true) == 0,
          "permission-preserving overwrite failed");
  struct stat mode_status {};
  require(::stat(mode_file.c_str(), &mode_status) == 0,
          "stat after overwrite failed");
  require((mode_status.st_mode & 07777) == 0640,
          "atomic overwrite changed POSIX mode bits");
#ifdef __linux__
  const char attribute_name[] = "user.subconverter.atomic-write";
  const char attribute_value[] = "preserved";
  if (::setxattr(mode_file.c_str(), attribute_name, attribute_value,
                 sizeof(attribute_value) - 1, 0) == 0) {
    require(fileWrite(mode_file.string(), "xattr-updated", true) == 0,
            "extended-attribute-preserving overwrite failed");
    char observed[32] {};
    const ssize_t observed_size =
        ::getxattr(mode_file.c_str(), attribute_name, observed, sizeof(observed));
    require(observed_size == static_cast<ssize_t>(sizeof(attribute_value) - 1) &&
                std::string(observed, static_cast<std::size_t>(observed_size)) ==
                    attribute_value,
            "atomic overwrite changed a POSIX extended attribute");
  }
#endif
#endif

  const fs::path missing_parent = temporary.path / "missing" / "file.txt";
  require(fileWrite(missing_parent.string(), "no-crash", true) != 0,
          "missing parent write reported success");
  return 0;
}
