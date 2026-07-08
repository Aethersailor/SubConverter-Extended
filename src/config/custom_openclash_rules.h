#ifndef CUSTOM_OPENCLASH_RULES_H_INCLUDED
#define CUSTOM_OPENCLASH_RULES_H_INCLUDED

#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace custom_openclash_rules {

enum class ResourceKind {
  None,
  ConfigIni,
  RuleList,
  RuleYaml,
  RuleMrs,
  StaticFile
};

struct Resource {
  ResourceKind kind = ResourceKind::None;
  std::string repository_path;

  bool matched() const { return kind != ResourceKind::None; }
};

struct PublishedDirectory {
  bool valid = false;
  bool trailing_slash = false;
  std::string repository_path;

  bool matched() const { return valid; }
};

Resource matchRepositoryUrl(const std::string &url);
Resource matchPublishedPath(const std::string &path);
PublishedDirectory matchPublishedDirectory(const std::string &path);

std::vector<std::string> localPathCandidates(const Resource &resource);
std::string publishedPath(const Resource &resource);
std::string publishedUrl(const Resource &resource,
                         const std::string &base_url);
std::string contentType(const Resource &resource);

bool isDirectProvider(const Resource &resource);
bool hasMrsExtension(const std::string &path_or_url);

size_t rewriteRuleProviderUrls(YAML::Node &root,
                               const std::string &base_url);

} // namespace custom_openclash_rules

#endif // CUSTOM_OPENCLASH_RULES_H_INCLUDED
