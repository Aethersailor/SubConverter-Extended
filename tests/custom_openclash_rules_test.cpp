#include <cassert>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/custom_openclash_rules.h"
#include "handler/custom_openclash_rules_endpoint.h"
#include "utils/urlencode.h"

namespace {

using custom_openclash_rules::ResourceKind;

struct MatchCase {
  std::string url;
  ResourceKind kind;
  std::string path;
};

std::string manifestLine(char digest, const std::string &path) {
  return std::string(64, digest) + "  main/" + path + "\n";
}

void expectMatch(const MatchCase &test) {
  auto actual = custom_openclash_rules::matchRepositoryUrl(test.url);
  if (actual.kind != test.kind || actual.repository_path != test.path) {
    std::cerr << "URL mismatch: " << test.url << '\n';
    std::exit(1);
  }
}

} // namespace

int main() {
  const std::vector<std::string> expected_directories = {
      "cfg",       "cfg/yaml",      "rule", "game_rule",
      "overwrite", "overwrite/yaml", "shell"};
  assert(custom_openclash_rules::allowedDirectories() ==
         expected_directories);

  const std::vector<MatchCase> valid = {
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/Fixture.ini",
       ResourceKind::ConfigIni, "cfg/Fixture.ini"},
      {"https://raw.githubusercontent.com/AETHERSAILOR/"
       "CUSTOM_OPENCLASH_RULES/refs/heads/main/cfg/yaml/Fixture.yaml",
       ResourceKind::StaticFile, "cfg/yaml/Fixture.yaml"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/raw/main/"
       "rule/Fixture.list?download=1",
       ResourceKind::RuleList, "rule/Fixture.list"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/refs/"
       "heads/main/rule/Fixture.yaml?raw=1#fragment",
       ResourceKind::RuleYaml, "rule/Fixture.yaml"},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/game_rule/Fixture.yml",
       ResourceKind::RuleYaml, "game_rule/Fixture.yml"},
      {"https://testingcf.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@refs/heads/main/game_rule/Fixture.mrs",
       ResourceKind::RuleMrs, "game_rule/Fixture.mrs"},
      {"https://gcore.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/overwrite/Fixture.conf",
       ResourceKind::StaticFile, "overwrite/Fixture.conf"},
      {"https://jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/overwrite/yaml/Fixture.json",
       ResourceKind::StaticFile, "overwrite/yaml/Fixture.json"},
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/shell/Fixture.sh",
       ResourceKind::StaticFile, "shell/Fixture.sh"},
  };
  for (const MatchCase &test : valid)
    expectMatch(test);

  const std::vector<std::string> invalid = {
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/dev/rule/Fixture.list",
      "https://cdn.jsdelivr.net/gh/Other/"
      "Custom_OpenClash_Rules@main/rule/Fixture.list",
      "https://cdn.jsdelivr.net.evil.example/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/Fixture.list",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/../README.md",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/doc/Fixture.txt",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/README.md",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/nested/Fixture.list",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/cfg/test/Fixture.ini",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/shell/subdir/Fixture.sh",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/overwrite/yaml/nested/Fixture.conf",
      "file:///base/Custom_OpenClash_Rules/main/rule/Fixture.list",
  };
  for (const std::string &url : invalid) {
    if (custom_openclash_rules::matchRepositoryUrl(url).matched()) {
      std::cerr << "Unexpected URL match: " << url << '\n';
      return 1;
    }
  }

  const std::string encoded =
      urlDecode("/Custom_OpenClash_Rules/main/cfg/yaml/"
                "Fixture%26Airport.yaml");
  auto published = custom_openclash_rules::matchPublishedPath(encoded);
  assert(published.matched());
  assert(published.repository_path == "cfg/yaml/Fixture&Airport.yaml");
  assert(custom_openclash_rules::publishedUrl(
             published, "https://test-api.asailor.org/") ==
         "https://test-api.asailor.org/Custom_OpenClash_Rules/main/cfg/yaml/"
         "Fixture&Airport.yaml");

  const std::vector<std::string> unsafe_published_paths = {
      "/Custom_OpenClash_Rules/main/rule/%2e%2e",
      "/Custom_OpenClash_Rules/main/rule/../Fixture.list",
      "/Custom_OpenClash_Rules/main/rule\\Fixture.list",
      "/Custom_OpenClash_Rules/main/rule/README.md",
      "/Custom_OpenClash_Rules/main/rule/nested/Fixture.list",
      urlDecode("/Custom_OpenClash_Rules/main/rule/%252e%252e"),
      urlDecode("/Custom_OpenClash_Rules/main/rule/%25252e%25252e"),
  };
  for (const std::string &path : unsafe_published_paths)
    assert(!custom_openclash_rules::matchPublishedPath(path).matched());

  const std::vector<std::string> valid_directories = {
      "/Custom_OpenClash_Rules/main",
      "/Custom_OpenClash_Rules/main/",
      "/Custom_OpenClash_Rules/main/cfg/",
      "/Custom_OpenClash_Rules/main/cfg/yaml/",
      "/Custom_OpenClash_Rules/main/rule/",
      "/Custom_OpenClash_Rules/main/game_rule/",
      "/Custom_OpenClash_Rules/main/overwrite/",
      "/Custom_OpenClash_Rules/main/overwrite/yaml/",
      "/Custom_OpenClash_Rules/main/shell/"};
  for (const std::string &path : valid_directories)
    assert(custom_openclash_rules::matchPublishedDirectory(path).matched());

  const std::vector<std::string> invalid_directories = {
      "/Custom_OpenClash_Rules/mainly/",
      "/Custom_OpenClash_Rules/main/doc/",
      "/Custom_OpenClash_Rules/main/cfg/../",
      "/Custom_OpenClash_Rules/main/cfg/%2e%2e/",
      "/Custom_OpenClash_Rules/main//",
      "/Custom_OpenClash_Rules/main/cfg/nested/",
      "/Custom_OpenClash_Rules/main/rule/archived/",
      "/Custom_OpenClash_Rules/main/cfg\\yaml/"};
  for (const std::string &path : invalid_directories)
    assert(!custom_openclash_rules::matchPublishedDirectory(path).matched());

  const std::vector<std::pair<std::string, std::string>> mime_cases = {
      {"cfg/yaml/a.yaml", "application/yaml; charset=utf-8"},
      {"overwrite/yaml/a.json", "application/json; charset=utf-8"},
      {"cfg/a.ini", "text/plain; charset=utf-8"},
      {"rule/a.list", "text/plain; charset=utf-8"},
      {"overwrite/a.conf", "text/plain; charset=utf-8"},
      {"shell/a.txt", "text/plain; charset=utf-8"},
      {"shell/a.sh", "text/plain; charset=utf-8"},
      {"game_rule/a.mrs", "application/octet-stream"},
      {"shell/a.bin", "application/octet-stream"},
  };
  for (const auto &test : mime_cases) {
    auto resource = custom_openclash_rules::matchPublishedPath(
        "/Custom_OpenClash_Rules/main/" + test.first);
    assert(resource.matched());
    assert(custom_openclash_rules::contentType(resource) == test.second);
  }

  const std::string fixture_name = "Fixture&<Airport>.yaml";
  const std::string unicode_name = "测试规则.yaml";
  const std::string manifest =
      manifestLine('a', "cfg/yaml/" + fixture_name) +
      manifestLine('b', "overwrite/Fixture Name.conf") +
      manifestLine('c', "rule/" + unicode_name);
  const std::set<std::string> available = {
      "cfg/yaml/" + fixture_name,
      "overwrite/Fixture Name.conf",
      "rule/" + unicode_name,
  };
  custom_openclash_rules_endpoint::DirectoryIndexSnapshot pages;
  std::string index_error;
  assert(custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      manifest, available, pages, &index_error));
  assert(pages.size() == 8);
  for (const std::string &directory : expected_directories)
    assert(pages.count(directory) == 1);
  assert(pages.at("").content.find("href=\"cfg/\"") != std::string::npos);
  assert(pages.at("").content.find("href=\"game_rule/\"") !=
         std::string::npos);
  assert(pages.at("").content.find("href=\"overwrite/\"") !=
         std::string::npos);
  assert(pages.at("").content.find("href=\"shell/\"") !=
         std::string::npos);
  assert(pages.at("cfg").content.find("href=\"yaml/\"") !=
         std::string::npos);
  assert(pages.at("cfg/yaml").content.find(
             "href=\"Fixture%26%3CAirport%3E.yaml\"") != std::string::npos);
  assert(pages.at("cfg/yaml").content.find(
             "Fixture&amp;&lt;Airport&gt;.yaml") != std::string::npos);
  assert(pages.at("overwrite").content.find("href=\"Fixture%20Name.conf\"") !=
         std::string::npos);
  assert(pages.at("rule").content.find(urlEncode(unicode_name)) !=
         std::string::npos);
  assert(pages.at("game_rule").content.find("Fixture") ==
         std::string::npos);

  custom_openclash_rules_endpoint::DirectoryIndexSnapshot same_pages;
  assert(custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      manifest, available, same_pages));
  assert(same_pages.at("").etag == pages.at("").etag);
  assert(same_pages.at("cfg/yaml").etag == pages.at("cfg/yaml").etag);

  const std::string added_manifest =
      manifest + manifestLine('d', "shell/added.sh");
  std::set<std::string> added_available = available;
  added_available.insert("shell/added.sh");
  custom_openclash_rules_endpoint::DirectoryIndexSnapshot added_pages;
  assert(custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      added_manifest, added_available, added_pages));
  assert(added_pages.at("").etag == pages.at("").etag);
  assert(added_pages.at("shell").etag != pages.at("shell").etag);
  assert(added_pages.at("rule").etag == pages.at("rule").etag);

  custom_openclash_rules_endpoint::DirectoryIndexSnapshot rejected_pages;
  assert(!custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      manifestLine('a', "rule/nested/rejected.yaml"),
      {"rule/nested/rejected.yaml"}, rejected_pages));
  assert(!custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      manifestLine('a', "rule/README.md"), {"rule/README.md"},
      rejected_pages));
  assert(!custom_openclash_rules_endpoint::buildDirectoryIndexSnapshot(
      manifestLine('a', "rule/duplicate.yaml") +
          manifestLine('b', "rule/duplicate.yaml"),
      {"rule/duplicate.yaml"}, rejected_pages));

  YAML::Node root = YAML::Load(R"(
rule-providers:
  rule-yaml:
    url: https://cdn.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@main/rule/Fixture.yaml
    path: ./providers/rule.mrs
  game-mrs:
    url: https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/game_rule/Game.mrs
    path: ./providers/game.yaml
  overwrite:
    url: https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/overwrite/Fixture.yaml
  shell:
    url: https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/shell/Fixture.yaml
)");
  assert(custom_openclash_rules::rewriteRuleProviderUrls(
             root, "https://test-api.asailor.org") == 2);
  assert(root["rule-providers"]["rule-yaml"]["url"].as<std::string>() ==
         "https://test-api.asailor.org/Custom_OpenClash_Rules/main/rule/"
         "Fixture.yaml");
  assert(root["rule-providers"]["rule-yaml"]["format"].as<std::string>() ==
         "yaml");
  assert(root["rule-providers"]["rule-yaml"]["path"].as<std::string>() ==
         "./providers/rule.yaml");
  assert(root["rule-providers"]["game-mrs"]["url"].as<std::string>() ==
         "https://test-api.asailor.org/Custom_OpenClash_Rules/main/game_rule/"
         "Game.mrs");
  assert(root["rule-providers"]["game-mrs"]["format"].as<std::string>() ==
         "mrs");
  assert(root["rule-providers"]["game-mrs"]["path"].as<std::string>() ==
         "./providers/game.mrs");
  assert(root["rule-providers"]["overwrite"]["url"].as<std::string>().find(
             "raw.githubusercontent.com") != std::string::npos);
  assert(root["rule-providers"]["shell"]["url"].as<std::string>().find(
             "raw.githubusercontent.com") != std::string::npos);

  std::cout << "Custom_OpenClash_Rules policy tests passed\n";
  return 0;
}
