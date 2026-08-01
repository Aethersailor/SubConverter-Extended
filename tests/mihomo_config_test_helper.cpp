#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "parser/mihomo_bridge.h"

namespace {

int validateConfig(const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    std::cerr << "unable to read config: " << path << "\n";
    return 2;
  }
  const std::string content((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
  const std::string error = mihomo::validateMihomoRuleConfig(content);
  if (!error.empty()) {
    std::cerr << error << "\n";
    return 1;
  }
  return 0;
}

int parseRegex(const std::string &rule) {
  const std::string result = mihomo::parseMihomoRegexRule(rule);
  std::cout << result << "\n";
  return result.find("\"error\"") == std::string::npos ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc == 3 && std::string(argv[1]) == "--regex")
    return parseRegex(argv[2]);
  if (argc == 2)
    return validateConfig(argv[1]);

  std::cerr << "usage: mihomo_config_test_helper <config>\n"
               "       mihomo_config_test_helper --regex <rule>\n";
  return 2;
}
