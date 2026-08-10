#include <filesystem>
#include <initializer_list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include "handler/settings.h"
#include "handler/upload.h"
#include "handler/webget.h"
#include "utils/file.h"
#include "utils/logger.h"

Settings global;

namespace {

std::string captured_logs;
int remote_status = 201;
int remote_calls = 0;
std::string remote_response =
    R"({"id":"fixture-id","owner":{"login":"fixture-user"}})";

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void requireLogsOmit(std::initializer_list<std::string> secrets,
                     const char *message) {
  for (const std::string &secret : secrets) {
    if (!secret.empty() && captured_logs.find(secret) != std::string::npos)
      throw std::runtime_error(message);
  }
}

void resetRemote(
    int status = 201,
    std::string response =
        R"({"id":"fixture-id","owner":{"login":"fixture-user"}})") {
  remote_status = status;
  remote_response = std::move(response);
  remote_calls = 0;
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

bool shouldLog(LogLevel) { return true; }

void writeLog(LogLevel, const std::string &content) {
  captured_logs += content + "\n";
}

std::string getEnv(const std::string &) { return ""; }

ProxyPolicy parseProxy(const std::string &, const std::string &) { return {}; }

int webPost(const std::string &, const std::string &, const ProxyPolicy &,
            const string_icase_map &, std::string *ret_data) {
  remote_calls++;
  *ret_data = remote_response;
  return remote_status;
}

int webPatch(const std::string &, const std::string &, const ProxyPolicy &,
             const string_icase_map &, std::string *ret_data) {
  remote_calls++;
  *ret_data = remote_response;
  return remote_status;
}

int main() {
  TemporaryWorkingDirectory temporary;
  const std::string token = "native-upload-token-secret";
  const std::string content = "native-user-body-secret";
  const std::string path = "native-query-path-secret.yaml";
  const std::string initial = "[common]\ntoken=" + token + "\n";
  const std::string remote_failure =
      R"({"body":"remote-user-body-secret","query":"remote-query-secret","headers":"Authorization: token native-upload-token-secret"})";

  captured_logs.clear();
  resetRemote();
  require(uploadGist("clash", path, content, false) < 0,
          "missing Gist configuration was reported as success");
  require(remote_calls == 0 &&
              captured_logs.find("未找到 gistconf.ini") != std::string::npos,
          "missing Gist configuration diagnostics changed");

  require(fileWrite("gistconf.ini",
                    "[invalid]\ntoken=invalid-section-token\n", true) == 0,
          "invalid Gist fixture write failed");
  captured_logs.clear();
  resetRemote();
  require(uploadGist("clash", path, content, false) < 0,
          "invalid Gist configuration was reported as success");
  require(remote_calls == 0 &&
              captured_logs.find("gistconf.ini 格式不正确") !=
                  std::string::npos,
          "invalid Gist configuration diagnostics changed");
  requireLogsOmit({"invalid-section-token", content, path},
                  "invalid Gist diagnostics leaked request data");

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "Gist success fixture write failed");
  captured_logs.clear();
  resetRemote();
  require(uploadGist("clash", path, content, false) == 0,
          "successful Gist upload was reported as failure");
  require(remote_calls == 1 &&
              fileGet("gistconf.ini", false).find("fixture-id") !=
                  std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE target=clash") !=
                  std::string::npos,
          "successful Gist upload completion changed");
  requireLogsOmit({token, content, path},
                  "successful Gist diagnostics leaked request data");

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "Gist remote failure fixture reset failed");
  captured_logs.clear();
  resetRemote(502, remote_failure);
  require(uploadGist("clash", path, content, false) < 0,
          "failed Gist create request was reported as success");
  require(remote_calls == 1 && fileGet("gistconf.ini", false) == initial &&
              captured_logs.find(
                  "GIST_CREATE_FAILED status=502 detail=length=") !=
                  std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE") == std::string::npos,
          "failed Gist create diagnostics changed");
  requireLogsOmit({token, content, path, "remote-user-body-secret",
                   "remote-query-secret", "Authorization"},
                  "failed Gist create diagnostics leaked request data");

  const std::string existing = initial +
                               "id=existing-id\n"
                               "username=fixture-user\n";
  require(fileWrite("gistconf.ini", existing, true) == 0,
          "Gist update failure fixture write failed");
  captured_logs.clear();
  resetRemote(503, remote_failure);
  require(uploadGist("clash", path, content, false) < 0,
          "failed Gist update request was reported as success");
  require(remote_calls == 1 && fileGet("gistconf.ini", false) == existing &&
              captured_logs.find(
                  "GIST_UPDATE_FAILED status=503 detail=length=") !=
                  std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE") == std::string::npos,
          "failed Gist update diagnostics changed");
  requireLogsOmit({token, content, path, "existing-id", "fixture-user",
                   "remote-user-body-secret", "remote-query-secret",
                   "Authorization"},
                  "failed Gist update diagnostics leaked request data");

  resetRemote();

  require(fileWrite("gistconf.ini", initial, true) == 0,
          "Gist fixture write failed");
  captured_logs.clear();
  setFileIoTestFailure(FileIoTestFailure::ParentDirectorySync);
  const int unsynced_result =
      uploadGist("clash", path, content, false);
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
      uploadGist("clash", path, content, false);
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
  require(uploadGist("clash", path, content, false) < 0,
          "pre-commit Gist persistence failure was reported as success");
  require(captured_logs.find(
              "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED") !=
              std::string::npos &&
              captured_logs.find("GIST_UPLOAD_COMPLETE") == std::string::npos,
          "pre-commit Gist persistence diagnostics were ambiguous");
  requireLogsOmit({token, content, path},
                  "Gist persistence diagnostics leaked request data");
  return 0;
}
