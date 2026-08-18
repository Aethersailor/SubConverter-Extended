#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/settings_snapshot.h"
#include "parser/mihomo_bridge.h"
#include "server/webserver.h"
#include "utils/logger.h"

WebServer webServer;

namespace mihomo {

std::vector<ProxyNode> parseSubscription(const std::string &) {
  throw std::runtime_error(
      "Mihomo parsing is unavailable in the settings snapshot helper");
}

bool isMihomoParserAvailable() { return false; }

AgeRecipient resolveAgeRecipient(const std::string &) {
  throw std::runtime_error(
      "Age recipient resolution is unavailable in the settings snapshot helper");
}

std::string encryptAgeArmored(const std::string &, const std::string &) {
  throw std::runtime_error(
      "Age encryption is unavailable in the settings snapshot helper");
}

} // namespace mihomo

int main(int argc, char *argv[]) {
  const bool expect_reload_failure =
      argc == 4 && std::string(argv[3]) == "--expect-reload-failure";
  if ((argc != 2 && argc != 3 && argc != 4) ||
      (argc == 4 && !expect_reload_failure)) {
    std::cerr << "usage: settings_snapshot_test_helper <config> "
                 "[reload-config [--expect-reload-failure]]\n";
    return 2;
  }

  const std::filesystem::path config =
      std::filesystem::absolute(argv[1]).lexically_normal();
  if (!config.has_filename()) {
    std::cerr << "configuration path has no filename\n";
    return 2;
  }

  std::filesystem::current_path(config.parent_path());
  global.prefPath = config.filename().string();
  if (!readConf())
    return 1;

  if (argc >= 3) {
    const std::filesystem::path reload_config =
        std::filesystem::absolute(argv[2]).lexically_normal();
    if (!reload_config.has_filename()) {
      std::cerr << "reload configuration path has no filename\n";
      return 2;
    }
    std::filesystem::current_path(reload_config.parent_path());
    global.prefPath = reload_config.filename().string();
    const bool reloaded = readConf();
    if (expect_reload_failure ? reloaded : !reloaded) {
      std::cerr << (expect_reload_failure
                        ? "reload unexpectedly succeeded\n"
                        : "reload failed\n");
      return 1;
    }
    if (expect_reload_failure)
      writeLog(LOG_LEVEL_VERBOSE, "SETTINGS_RELOAD_LEVEL_PROBE");
  }

  std::cout << sanitizedSettingsSnapshot(global);
  return 0;
}
