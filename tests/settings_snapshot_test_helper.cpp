#include <filesystem>
#include <iostream>
#include <string>

#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/settings_snapshot.h"
#include "server/webserver.h"

WebServer webServer;

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "usage: settings_snapshot_test_helper <config>\n";
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

  std::cout << sanitizedSettingsSnapshot(global);
  return 0;
}
