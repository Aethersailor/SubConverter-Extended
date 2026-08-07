#include <filesystem>
#include <stdexcept>
#include <string>

#include "config/preference_file.h"
#include "utils/file.h"

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct TemporaryWorkingDirectory {
  std::filesystem::path original = std::filesystem::current_path();
  std::filesystem::path path =
      original / "build" / "preference-file-test-runtime";
  TemporaryWorkingDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
    std::filesystem::create_directories(path);
    std::filesystem::current_path(path);
  }
  ~TemporaryWorkingDirectory() {
    std::filesystem::current_path(original);
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

} // namespace

int main() {
  TemporaryWorkingDirectory temporary;

  require(fileWrite("pref.toml", "existing", true) == 0,
          "existing preference fixture failed");
  PreferenceFileSelection selection = prepareDefaultPreferenceFile();
  require(selection.status == PreferenceFileStatus::Ready &&
              selection.path == "pref.toml" &&
              fileGet("pref.toml", false) == "existing",
          "existing preference selection changed");
  std::filesystem::remove("pref.toml");

  require(fileWrite("pref.example.yml", "example-yaml", true) == 0,
          "example preference fixture failed");
  selection = prepareDefaultPreferenceFile();
  require(selection.status == PreferenceFileStatus::Ready &&
              selection.path == "pref.yml" &&
              fileGet("pref.yml", false) == "example-yaml",
          "first-start preference copy failed");
  std::filesystem::remove("pref.yml");

  setFileIoTestFailure(FileIoTestFailure::Replace);
  selection = prepareDefaultPreferenceFile();
  setFileIoTestFailure(FileIoTestFailure::None);
  require(selection.status == PreferenceFileStatus::CopyFailed &&
              selection.source == "pref.example.yml" &&
              selection.path == "pref.yml" && !fileExist("pref.yml"),
          "first-start copy failure was not reported deterministically");
  require(defaultPreferenceRequiresExit(selection, "pref.yml"),
          "main startup would continue after default copy failure");
  require(!defaultPreferenceRequiresExit(selection, "explicit-pref.toml"),
          "explicit -f preference no longer overrides default copy failure");

  setFileIoTestFailure(FileIoTestFailure::ReplaceAndTemporaryCleanup);
  selection = prepareDefaultPreferenceFile();
  setFileIoTestFailure(FileIoTestFailure::None);
  require(selection.status ==
              PreferenceFileStatus::CopyFailedTemporaryRemaining &&
              selection.path == "pref.yml" && !fileExist("pref.yml") &&
              defaultPreferenceRequiresExit(selection, "pref.yml") &&
              !defaultPreferenceRequiresExit(selection, "explicit-pref.toml"),
          "first-start cleanup failure state was not preserved");
  for (const auto &entry : std::filesystem::directory_iterator(".")) {
    if (entry.path().filename().string().find(
            ".pref.yml.subconverter-tmp-") == 0)
      std::filesystem::remove(entry.path());
  }

#ifndef _WIN32
  setFileIoTestFailure(FileIoTestFailure::ParentDirectorySync);
  selection = prepareDefaultPreferenceFile();
  setFileIoTestFailure(FileIoTestFailure::None);
  require(selection.status ==
              PreferenceFileStatus::CopyCommittedUnsynced &&
              selection.path == "pref.yml" && fileExist("pref.yml") &&
              !defaultPreferenceRequiresExit(selection, "pref.yml"),
          "visible first-start copy would incorrectly stop startup");
  std::filesystem::remove("pref.yml");
#endif

  std::filesystem::remove("pref.example.yml");
  selection = prepareDefaultPreferenceFile();
  require(selection.status == PreferenceFileStatus::NotFound &&
              selection.path == "pref.ini",
          "missing default preference behavior changed");
  return 0;
}
