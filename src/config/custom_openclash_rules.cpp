#include "custom_openclash_rules.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace custom_openclash_rules {
namespace {

const std::string PUBLISHED_PREFIX = "/Custom_OpenClash_Rules/main/";
const std::string LOCAL_PREFIX = "Custom_OpenClash_Rules/main/";

std::string toLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return value;
}

bool equalsIgnoreCase(const std::string &lhs, const std::string &rhs) {
  return toLower(lhs) == toLower(rhs);
}

std::vector<std::string> splitPath(const std::string &path) {
  std::vector<std::string> segments;
  size_t start = !path.empty() && path.front() == '/' ? 1 : 0;

  while (start <= path.size()) {
    size_t end = path.find('/', start);
    std::string segment =
        path.substr(start, end == std::string::npos ? std::string::npos
                                                   : end - start);
    if (segment.empty())
      return {};
    segments.emplace_back(std::move(segment));
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  return segments;
}

bool isSafeSegment(const std::string &segment) {
  if (segment.empty() || segment == "." || segment == "..")
    return false;
  for (unsigned char c : segment) {
    if (c < 0x20 || c == 0x7f || c == '\\' || c == '%' || c == ':')
      return false;
  }
  return true;
}

bool isRepository(const std::vector<std::string> &segments, size_t offset) {
  return segments.size() > offset + 1 &&
         equalsIgnoreCase(segments[offset], "Aethersailor") &&
         equalsIgnoreCase(segments[offset + 1], "Custom_OpenClash_Rules");
}

std::string extensionOf(const std::string &path_or_url) {
  size_t path_end = path_or_url.find_first_of("?#");
  std::string path = path_or_url.substr(0, path_end);
  size_t slash = path.rfind('/');
  size_t dot = path.rfind('.');
  if (dot == std::string::npos ||
      (slash != std::string::npos && dot < slash))
    return "";
  return toLower(path.substr(dot));
}

Resource buildResource(const std::vector<std::string> &segments,
                       size_t offset) {
  if (segments.size() <= offset + 1)
    return {};

  for (size_t i = offset; i < segments.size(); ++i) {
    if (!isSafeSegment(segments[i]))
      return {};
  }

  bool cfg = equalsIgnoreCase(segments[offset], "cfg");
  bool rule = equalsIgnoreCase(segments[offset], "rule");
  if (!cfg && !rule)
    return {};

  std::string repository_path;
  for (size_t i = offset; i < segments.size(); ++i) {
    if (!repository_path.empty())
      repository_path += '/';
    repository_path += segments[i];
  }

  std::string extension = extensionOf(repository_path);
  ResourceKind kind = ResourceKind::StaticFile;
  if (cfg && segments.size() == offset + 2 && extension == ".ini")
    kind = ResourceKind::ConfigIni;
  else if (rule && extension == ".list")
    kind = ResourceKind::RuleList;
  else if (rule && (extension == ".yaml" || extension == ".yml"))
    kind = ResourceKind::RuleYaml;
  else if (rule && extension == ".mrs")
    kind = ResourceKind::RuleMrs;

  return {kind, repository_path};
}

Resource matchRawGitHub(const std::vector<std::string> &segments) {
  if (!isRepository(segments, 0))
    return {};

  if (segments.size() >= 5 && equalsIgnoreCase(segments[2], "main"))
    return buildResource(segments, 3);

  if (segments.size() >= 7 && equalsIgnoreCase(segments[2], "refs") &&
      equalsIgnoreCase(segments[3], "heads") &&
      equalsIgnoreCase(segments[4], "main"))
    return buildResource(segments, 5);

  return {};
}

Resource matchGitHub(const std::vector<std::string> &segments) {
  if (!isRepository(segments, 0) || segments.size() < 6 ||
      (!equalsIgnoreCase(segments[2], "raw") &&
       !equalsIgnoreCase(segments[2], "blob")))
    return {};

  if (equalsIgnoreCase(segments[3], "main"))
    return buildResource(segments, 4);

  if (segments.size() >= 8 && equalsIgnoreCase(segments[3], "refs") &&
      equalsIgnoreCase(segments[4], "heads") &&
      equalsIgnoreCase(segments[5], "main"))
    return buildResource(segments, 6);

  return {};
}

Resource matchJsDelivr(const std::vector<std::string> &segments) {
  if (segments.size() < 5 || !equalsIgnoreCase(segments[0], "gh") ||
      !equalsIgnoreCase(segments[1], "Aethersailor"))
    return {};

  if (equalsIgnoreCase(segments[2], "Custom_OpenClash_Rules@main"))
    return buildResource(segments, 3);

  if (segments.size() >= 7 &&
      equalsIgnoreCase(segments[2], "Custom_OpenClash_Rules@refs") &&
      equalsIgnoreCase(segments[3], "heads") &&
      equalsIgnoreCase(segments[4], "main"))
    return buildResource(segments, 5);

  return {};
}

} // namespace

Resource matchRepositoryUrl(const std::string &url) {
  size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos)
    return {};

  std::string scheme = toLower(url.substr(0, scheme_end));
  if (scheme != "http" && scheme != "https")
    return {};

  size_t authority_start = scheme_end + 3;
  size_t path_start = url.find('/', authority_start);
  if (path_start == std::string::npos)
    return {};

  std::string authority =
      url.substr(authority_start, path_start - authority_start);
  if (authority.empty() || authority.find('@') != std::string::npos)
    return {};

  size_t port_start = authority.find(':');
  std::string host =
      toLower(authority.substr(0, port_start == std::string::npos
                                     ? authority.size()
                                     : port_start));
  size_t path_end = url.find_first_of("?#", path_start);
  std::string path =
      url.substr(path_start, path_end == std::string::npos
                                 ? std::string::npos
                                 : path_end - path_start);
  std::vector<std::string> segments = splitPath(path);
  if (segments.empty())
    return {};

  if (host == "raw.githubusercontent.com")
    return matchRawGitHub(segments);
  if (host == "github.com")
    return matchGitHub(segments);
  if (host == "jsdelivr.net" ||
      (host.size() > 13 &&
       host.compare(host.size() - 13, 13, ".jsdelivr.net") == 0))
    return matchJsDelivr(segments);

  return {};
}

Resource matchPublishedPath(const std::string &path) {
  if (path.compare(0, PUBLISHED_PREFIX.size(), PUBLISHED_PREFIX) != 0)
    return {};

  std::string relative = path.substr(PUBLISHED_PREFIX.size());
  std::vector<std::string> segments = splitPath(relative);
  if (segments.empty())
    return {};
  return buildResource(segments, 0);
}

std::vector<std::string> localPathCandidates(const Resource &resource) {
  if (!resource.matched())
    return {};
  std::string runtime_path = LOCAL_PREFIX + resource.repository_path;
  return {runtime_path, "base/" + runtime_path};
}

std::string publishedPath(const Resource &resource) {
  if (!resource.matched())
    return "";
  return PUBLISHED_PREFIX + resource.repository_path;
}

std::string publishedUrl(const Resource &resource,
                         const std::string &base_url) {
  if (!resource.matched() || base_url.empty())
    return "";

  std::string normalized = base_url;
  while (normalized.size() > 1 && normalized.back() == '/')
    normalized.pop_back();
  return normalized + publishedPath(resource);
}

std::string contentType(const Resource &resource) {
  std::string extension = extensionOf(resource.repository_path);
  if (extension == ".yaml" || extension == ".yml")
    return "application/yaml; charset=utf-8";
  if (extension == ".ini" || extension == ".list" || extension == ".md")
    return "text/plain; charset=utf-8";
  if (extension == ".mrs")
    return "application/octet-stream";
  return "application/octet-stream";
}

bool isDirectProvider(const Resource &resource) {
  return resource.kind == ResourceKind::RuleYaml ||
         resource.kind == ResourceKind::RuleMrs;
}

bool hasMrsExtension(const std::string &path_or_url) {
  return extensionOf(path_or_url) == ".mrs";
}

size_t rewriteRuleProviderUrls(YAML::Node &root,
                               const std::string &base_url) {
  if (base_url.empty() || !root["rule-providers"].IsMap())
    return 0;

  size_t rewritten = 0;
  YAML::Node providers = root["rule-providers"];
  for (auto provider_entry : providers) {
    YAML::Node provider = provider_entry.second;
    if (!provider.IsMap() || !provider["url"].IsScalar())
      continue;

    Resource resource =
        matchRepositoryUrl(provider["url"].as<std::string>());
    if (!isDirectProvider(resource))
      continue;

    provider["url"] = publishedUrl(resource, base_url);
    provider["format"] =
        resource.kind == ResourceKind::RuleMrs ? "mrs" : "yaml";
    if (provider["path"].IsScalar()) {
      std::string path = provider["path"].as<std::string>();
      size_t dot = path.rfind('.');
      if (dot != std::string::npos)
        path.erase(dot);
      path += resource.kind == ResourceKind::RuleMrs ? ".mrs" : ".yaml";
      provider["path"] = path;
    }
    ++rewritten;
  }
  return rewritten;
}

} // namespace custom_openclash_rules
