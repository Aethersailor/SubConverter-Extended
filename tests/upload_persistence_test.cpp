#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>

#include "handler/settings.h"
#include "handler/upload.h"
#include "handler/webget.h"
#include "utils/file.h"
#include "utils/logger.h"

Settings global;

namespace {

std::string captured_logs;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct TemporaryWorkingDirectory {
  std::filesystem::path original = std::filesystem::current_path();
  std::filesystem::path path =
      original / "build" / "upload-persistence-test-runtime";

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

bool shouldLog(int) { return true; }

void writeLog(int, const std::string &content, int) {
  captured_logs += content + "\n";
}

std::string getEnv(const std::string &) { return ""; }

ProxyPolicy parseProxy(const std::string &) { return {}; }

int webPost(const std::string &, const std::string &, const ProxyPolicy &,
            const string_icase_map &, std::string *ret_data) {
  *ret_data = R"({"id":"fixture-id","owner":{"login":"fixture-user"}})";
  return 201;
}

int webPatch(const std::string &, const std::string &, const ProxyPolicy &,
             const string_icase_map &, std::string *ret_data) {
  *ret_data = R"({"id":"fixture-id","owner":{"login":"fixture-user"}})";
  return 200;
}

int main() {
  TemporaryWorkingDirectory temporary;
  const std::string initial = "[common]\ntoken=fixture-token\n";

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "Gist fixture write failed");
  captured_logs.clear();
  setFileIoTestFailure(FileIoTestFailure::ParentDirectorySync);
  const int unsynced_result =
      uploadGist("clash", "artifact.yaml", "payload", false);
  setFileIoTestFailure(FileIoTestFailure::None);
  require(unsynced_result == 0,
          "visible but unsynced Gist state was reported as HTTP failure");
  require(fileGet("gistconf.ini", false).find("fixture-id") !=
              std::string::npos,
          "visible Gist state was not complete");
  require(captured_logs.find(
              "GIST_UPLOAD_COMPLETE target=clash") != std::string::npos &&
              captured_logs.find(
                  "local_state=visible durability=unconfirmed") !=
                  std::string::npos &&
              captured_logs.find("local_state=persisted") ==
                  std::string::npos,
          "unsynced Gist completion diagnostics were ambiguous");

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "cleanup Gist fixture reset failed");
  captured_logs.clear();
  setFileIoTestFailure(FileIoTestFailure::ReplaceAndTemporaryCleanup);
  const int cleanup_result =
      uploadGist("clash", "artifact.yaml", "payload", false);
  setFileIoTestFailure(FileIoTestFailure::None);
  require(cleanup_result < 0 && fileGet("gistconf.ini", false) == initial,
          "pre-commit cleanup failure changed or completed Gist state");
  require(captured_logs.find(
              "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED") !=
              std::string::npos &&
              captured_logs.find("temporary_file_remaining=true") !=
                  std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE") == std::string::npos,
          "Gist cleanup residual was not reported");
  for (const auto &entry : std::filesystem::directory_iterator(".")) {
    if (entry.path().filename().string().find(
            ".gistconf.ini.subconverter-tmp-") == 0)
      std::filesystem::remove(entry.path());
  }

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "hardlink Gist fixture reset failed");
  std::filesystem::create_hard_link("gistconf.ini", "gistconf-alias.ini");
  captured_logs.clear();
  require(uploadGist("clash", "artifact.yaml", "payload", false) < 0,
          "pre-commit Gist persistence failure was reported as success");
  require(captured_logs.find(
              "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED") !=
              std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE") == std::string::npos,
          "pre-commit Gist persistence diagnostics were ambiguous");
  return 0;
}
