#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>

#include "utils/file.h"

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct TemporaryTree {
  std::filesystem::path path;
  ~TemporaryTree() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

} // namespace

int main() {
  namespace fs = std::filesystem;
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

  symlink_error.clear();
  const fs::path escape_link = scoped_root / "escape";
  fs::create_directory_symlink(external_root, escape_link, symlink_error);
  if (!symlink_error) {
    require(!isPathInScope((escape_link / escaped_file.filename()).string(),
                           scoped_root.string()),
            "descendant symlink escaped the configured root");
  }

  const fs::path failure_file = scoped_root / "failure.txt";
  setFileIoTestFailure(FileIoTestFailure::Open);
  require(fileGet(dotted_name.string(), false).empty(),
          "read-open failure returned content");
  require(fileWrite(failure_file.string(), "open", true) != 0,
          "open failure reported success");
  setFileIoTestFailure(FileIoTestFailure::ShortWrite);
  require(fileWrite(failure_file.string(), "short-write", true) != 0,
          "short write reported success");
  setFileIoTestFailure(FileIoTestFailure::Flush);
  require(fileWrite(failure_file.string(), "flush", true) != 0,
          "flush failure reported success");
  setFileIoTestFailure(FileIoTestFailure::Close);
  require(fileWrite(failure_file.string(), "close", true) != 0,
          "close failure reported success");
  setFileIoTestFailure(FileIoTestFailure::None);
  require(fileWrite(failure_file.string(), "success", true) == 0,
          "successful write reported failure");
  require(fileGet(failure_file.string(), false) == "success",
          "successful write content changed");

  const fs::path missing_parent = temporary.path / "missing" / "file.txt";
  require(fileWrite(missing_parent.string(), "no-crash", true) != 0,
          "missing parent write reported success");
  return 0;
}
