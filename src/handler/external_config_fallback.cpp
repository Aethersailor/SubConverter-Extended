#include "external_config_fallback.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace external_config_fallback {
namespace {

const std::unordered_set<std::string> BUNDLED_CONFIG_NAMES = {
    "Custom_Clash.ini",
    "Custom_Clash_Full.ini",
    "Custom_Clash_GFW.ini",
    "Custom_Clash_Lite.ini",
    "Custom_Clash_Mainland.ini"};

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
  size_t start = path.empty() || path.front() != '/' ? 0 : 1;

  while (start <= path.size()) {
    size_t end = path.find('/', start);
    if (end == std::string::npos) {
      segments.emplace_back(path.substr(start));
      break;
    }
    segments.emplace_back(path.substr(start, end - start));
    start = end + 1;
  }
  return segments;
}

bool isRepository(const std::vector<std::string> &segments, size_t offset) {
  return segments.size() > offset + 1 &&
         equalsIgnoreCase(segments[offset], "Aethersailor") &&
         equalsIgnoreCase(segments[offset + 1], "Custom_OpenClash_Rules");
}

std::string allowedConfigName(const std::string &name) {
  return BUNDLED_CONFIG_NAMES.count(name) ? name : "";
}

std::string matchRawGitHub(const std::vector<std::string> &segments) {
  if (!isRepository(segments, 0))
    return "";

  if (segments.size() == 5 && equalsIgnoreCase(segments[2], "main") &&
      equalsIgnoreCase(segments[3], "cfg"))
    return allowedConfigName(segments[4]);

  if (segments.size() == 7 && equalsIgnoreCase(segments[2], "refs") &&
      equalsIgnoreCase(segments[3], "heads") &&
      equalsIgnoreCase(segments[4], "main") &&
      equalsIgnoreCase(segments[5], "cfg"))
    return allowedConfigName(segments[6]);

  return "";
}

std::string matchGitHub(const std::vector<std::string> &segments) {
  if (!isRepository(segments, 0) || segments.size() < 6 ||
      (!equalsIgnoreCase(segments[2], "raw") &&
       !equalsIgnoreCase(segments[2], "blob")))
    return "";

  if (segments.size() == 6 && equalsIgnoreCase(segments[3], "main") &&
      equalsIgnoreCase(segments[4], "cfg"))
    return allowedConfigName(segments[5]);

  if (segments.size() == 8 && equalsIgnoreCase(segments[3], "refs") &&
      equalsIgnoreCase(segments[4], "heads") &&
      equalsIgnoreCase(segments[5], "main") &&
      equalsIgnoreCase(segments[6], "cfg"))
    return allowedConfigName(segments[7]);

  return "";
}

std::string matchJsDelivr(const std::vector<std::string> &segments) {
  if (segments.size() < 5 || !equalsIgnoreCase(segments[0], "gh") ||
      !equalsIgnoreCase(segments[1], "Aethersailor"))
    return "";

  const std::string repoMain = "Custom_OpenClash_Rules@main";
  const std::string repoRefs = "Custom_OpenClash_Rules@refs";

  if (segments.size() == 5 && equalsIgnoreCase(segments[2], repoMain) &&
      equalsIgnoreCase(segments[3], "cfg"))
    return allowedConfigName(segments[4]);

  if (segments.size() == 7 && equalsIgnoreCase(segments[2], repoRefs) &&
      equalsIgnoreCase(segments[3], "heads") &&
      equalsIgnoreCase(segments[4], "main") &&
      equalsIgnoreCase(segments[5], "cfg"))
    return allowedConfigName(segments[6]);

  return "";
}

} // namespace

std::string bundledCustomClashConfigName(const std::string &url) {
  size_t schemeEnd = url.find("://");
  if (schemeEnd == std::string::npos)
    return "";

  std::string scheme = toLower(url.substr(0, schemeEnd));
  if (scheme != "http" && scheme != "https")
    return "";

  size_t authorityStart = schemeEnd + 3;
  size_t pathStart = url.find('/', authorityStart);
  if (pathStart == std::string::npos)
    return "";

  std::string authority = url.substr(authorityStart, pathStart - authorityStart);
  if (authority.find('@') != std::string::npos)
    return "";

  size_t portStart = authority.find(':');
  std::string host =
      toLower(authority.substr(0, portStart == std::string::npos
                                     ? authority.size()
                                     : portStart));
  size_t pathEnd = url.find_first_of("?#", pathStart);
  std::string path = url.substr(
      pathStart, pathEnd == std::string::npos ? std::string::npos
                                              : pathEnd - pathStart);
  std::vector<std::string> segments = splitPath(path);

  if (host == "raw.githubusercontent.com")
    return matchRawGitHub(segments);
  if (host == "github.com")
    return matchGitHub(segments);
  if (host == "jsdelivr.net" ||
      (host.size() > 13 &&
       host.compare(host.size() - 13, 13, ".jsdelivr.net") == 0))
    return matchJsDelivr(segments);

  return "";
}

} // namespace external_config_fallback
