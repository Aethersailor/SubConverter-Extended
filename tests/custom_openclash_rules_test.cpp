#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "config/custom_openclash_rules.h"
#include "handler/custom_openclash_rules_endpoint.h"

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

  const std::vector<std::string> valid_directories = {
      "/Custom_OpenClash_Rules/main",
      "/Custom_OpenClash_Rules/main/",
      "/Custom_OpenClash_Rules/main/cfg/",
      "/Custom_OpenClash_Rules/main/rule/archived/"};
  for (const std::string &path : valid_directories) {
    if (!custom_openclash_rules::matchPublishedDirectory(path).matched()) {
      std::cerr << "Directory path did not match: " << path << '\n';
      return 1;
    }
  }

  const std::vector<std::string> invalid_directories = {
      "/Custom_OpenClash_Rules/mainly/",
      "/Custom_OpenClash_Rules/main/doc/",
      "/Custom_OpenClash_Rules/main/cfg/../",
      "/Custom_OpenClash_Rules/main/cfg/%2e%2e/",
      "/Custom_OpenClash_Rules/main//",
      "/Custom_OpenClash_Rules/main/cfg//archived/",
      "/Custom_OpenClash_Rules/main/cfg\\archived/"};
  for (const std::string &path : invalid_directories) {
    if (custom_openclash_rules::matchPublishedDirectory(path).matched()) {
      std::cerr << "Unexpected directory path match: " << path << '\n';
      return 1;
    }
  }

  auto requestPath = [](const std::string &path, const std::string &etag = "") {
    Request request;
    Response response;
    request.method = "GET";
    request.url = path;
    if (!etag.empty())
      request.headers["If-None-Match"] = etag;
    std::string content =
        custom_openclash_rules_endpoint::serve(request, response);
    return std::make_tuple(response, content);
  };

  auto root_redirect = requestPath("/Custom_OpenClash_Rules/main");
  if (std::get<0>(root_redirect).status_code != 308 ||
      std::get<0>(root_redirect).headers["Location"] !=
          "/Custom_OpenClash_Rules/main/") {
    std::cerr << "Root directory redirect failed\n";
    return 1;
  }

  auto root_page = requestPath("/Custom_OpenClash_Rules/main/");
  const Response &root_response = std::get<0>(root_page);
  const std::string &root_content = std::get<1>(root_page);
  if (root_response.status_code != 200 ||
      root_response.content_type != "text/html; charset=utf-8" ||
      root_content.find("href=\"cfg/\"") == std::string::npos ||
      root_content.find("href=\"rule/\"") == std::string::npos ||
      root_content.find("manifest.sha256") != std::string::npos ||
      root_response.headers.find("Content-Security-Policy") ==
          root_response.headers.end() ||
      root_response.headers.find("X-Robots-Tag") ==
          root_response.headers.end()) {
    std::cerr << "Root directory page failed\n";
    return 1;
  }

  auto cfg_page = requestPath("/Custom_OpenClash_Rules/main/cfg/");
  if (std::get<0>(cfg_page).status_code != 200 ||
      std::get<1>(cfg_page).find("Custom_Clash.ini") == std::string::npos ||
      std::get<1>(cfg_page).find("href=\"archived/\"") ==
          std::string::npos ||
      std::get<1>(cfg_page).find("href=\"yaml/\"") == std::string::npos ||
      std::get<1>(cfg_page).find("Custom_Direct.list") !=
          std::string::npos) {
    std::cerr << "Cfg directory page failed\n";
    return 1;
  }

  auto yaml_page = requestPath("/Custom_OpenClash_Rules/main/cfg/yaml/");
  if (std::get<0>(yaml_page).status_code != 200 ||
      std::get<1>(yaml_page).find("Custom_Clash_DIY%26Airport.yaml") ==
          std::string::npos) {
    std::cerr << "Encoded directory link failed\n";
    return 1;
  }

  auto nested_redirect = requestPath(
      "/Custom_OpenClash_Rules/main/cfg/archived");
  if (std::get<0>(nested_redirect).status_code != 308 ||
      std::get<0>(nested_redirect).headers["Location"] !=
          "/Custom_OpenClash_Rules/main/cfg/archived/") {
    std::cerr << "Nested directory redirect failed\n";
    return 1;
  }

  std::string root_etag = root_response.headers.at("ETag");
  auto cached_root =
      requestPath("/Custom_OpenClash_Rules/main/", root_etag);
  if (std::get<0>(cached_root).status_code != 304 ||
      !std::get<1>(cached_root).empty()) {
    std::cerr << "Directory ETag handling failed\n";
    return 1;
  }

  auto file_response = requestPath(
      "/Custom_OpenClash_Rules/main/rule/Custom_Direct_Domain.yaml");
  if (std::get<0>(file_response).status_code != 200 ||
      std::get<0>(file_response).content_type !=
          "application/yaml; charset=utf-8" ||
      std::get<1>(file_response).empty()) {
    std::cerr << "Existing file serving regressed\n";
    return 1;
  }

  const std::vector<std::string> missing_paths = {
      "/Custom_OpenClash_Rules/main/doc/",
      "/Custom_OpenClash_Rules/main/cfg/missing/",
      "/Custom_OpenClash_Rules/main/cfg/../rule/",
      "/Custom_OpenClash_Rules/main/manifest.sha256",
      "/Custom_OpenClash_Rules/main/rule/Custom_Direct_Domain.yaml/"};
  for (const std::string &path : missing_paths) {
    auto missing = requestPath(path);
    if (std::get<0>(missing).status_code != 404) {
      std::cerr << "Unsafe or missing path did not return 404: " << path
                << '\n';
      return 1;
    }
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
