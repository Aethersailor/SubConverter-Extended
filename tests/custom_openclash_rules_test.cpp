#include <iostream>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/custom_openclash_rules.h"

struct MatchCase {
  std::string url;
  custom_openclash_rules::ResourceKind kind;
  std::string path;
};

int main() {
  using custom_openclash_rules::ResourceKind;

  const std::vector<MatchCase> valid = {
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini",
       ResourceKind::ConfigIni, "cfg/Custom_Clash.ini"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/refs/"
       "heads/main/rule/Custom_Direct.list?raw=1",
       ResourceKind::RuleList, "rule/Custom_Direct.list"},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/rule/Custom_Direct_Domain.yaml",
       ResourceKind::RuleYaml, "rule/Custom_Direct_Domain.yaml"},
      {"https://testingcf.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@refs/heads/main/rule/Custom_Direct_Domain.mrs",
       ResourceKind::RuleMrs, "rule/Custom_Direct_Domain.mrs"},
      {"HTTPS://GCORE.JSDELIVR.NET/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/rule/archived/Emby.list#fragment",
       ResourceKind::RuleList, "rule/archived/Emby.list"},
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/yaml/Custom_Clash.yaml",
       ResourceKind::StaticFile, "cfg/yaml/Custom_Clash.yaml"},
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/test/Nested.ini",
       ResourceKind::StaticFile, "cfg/test/Nested.ini"},
  };

  for (const MatchCase &test : valid) {
    auto actual = custom_openclash_rules::matchRepositoryUrl(test.url);
    if (actual.kind != test.kind || actual.repository_path != test.path) {
      std::cerr << "URL mismatch: " << test.url << '\n';
      return 1;
    }
  }

  const std::vector<std::string> invalid = {
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/dev/rule/Custom_Direct.list",
      "https://cdn.jsdelivr.net/gh/Other/"
      "Custom_OpenClash_Rules@main/rule/Custom_Direct.list",
      "https://cdn.jsdelivr.net.evil.example/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/Custom_Direct.list",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/../README.md",
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/doc/README.md",
      "file:///base/Custom_OpenClash_Rules/main/rule/Custom_Direct.list",
  };

  for (const std::string &url : invalid) {
    if (custom_openclash_rules::matchRepositoryUrl(url).matched()) {
      std::cerr << "Unexpected URL match: " << url << '\n';
      return 1;
    }
  }

  auto published = custom_openclash_rules::matchPublishedPath(
      "/Custom_OpenClash_Rules/main/rule/archived/Emby.list");
  if (published.kind != ResourceKind::RuleList ||
      custom_openclash_rules::publishedUrl(
          published, "https://test-api.asailor.org/") !=
          "https://test-api.asailor.org/Custom_OpenClash_Rules/main/rule/"
          "archived/Emby.list") {
    std::cerr << "Published path mapping failed\n";
    return 1;
  }

  if (custom_openclash_rules::matchPublishedPath(
          "/Custom_OpenClash_Rules/main/rule/%2e%2e/README.md")
          .matched()) {
    std::cerr << "Encoded traversal path matched\n";
    return 1;
  }

  YAML::Node root = YAML::Load(R"(
rule-providers:
  direct:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@main/rule/Custom_Direct_Domain.mrs
    path: ./providers/direct.yaml
  third-party:
    type: http
    behavior: domain
    url: https://example.com/domain.yaml
)");
  if (custom_openclash_rules::rewriteRuleProviderUrls(
          root, "https://test-api.asailor.org") != 1 ||
      root["rule-providers"]["direct"]["url"].as<std::string>() !=
          "https://test-api.asailor.org/Custom_OpenClash_Rules/main/rule/"
          "Custom_Direct_Domain.mrs" ||
      root["rule-providers"]["direct"]["format"].as<std::string>() != "mrs" ||
      root["rule-providers"]["direct"]["path"].as<std::string>() !=
          "./providers/direct.mrs" ||
      root["rule-providers"]["third-party"]["url"].as<std::string>() !=
          "https://example.com/domain.yaml") {
    std::cerr << "Rule provider rewrite failed\n";
    return 1;
  }

  std::cout << "Custom_OpenClash_Rules tests passed\n";
  return 0;
}
