#include "handler/cocr_source_url.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace {

constexpr const char *kTargetPrefix =
    "https://git.asailor.org/Custom_OpenClash_Rules/main/";

std::string toLowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return value;
}

bool equalsIgnoreCase(const std::string &lhs, const std::string &rhs) {
  return toLowerAscii(lhs) == toLowerAscii(rhs);
}

std::vector<std::string> splitCanonicalPath(const std::string &path) {
  if (path.empty() || path.front() != '/')
    return {};

  std::vector<std::string> segments;
  size_t start = 1;
  while (start <= path.size()) {
    size_t end = path.find('/', start);
    std::string segment =
        path.substr(start, end == std::string::npos ? std::string::npos
                                                    : end - start);
    if (segment.empty() || segment == "." || segment == "..")
      return {};
    for (unsigned char c : segment) {
      // Encoded or ambiguous paths are left to the existing fetch path. This
      // resolver never rejects them; it merely declines to rewrite them.
      if (c < 0x20 || c == 0x7f || c == '\\' || c == '%' || c == ':')
        return {};
    }
    segments.emplace_back(std::move(segment));
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  return segments;
}

bool isOfficialRepository(const std::vector<std::string> &segments,
                          size_t offset) {
  return segments.size() > offset + 1 &&
         equalsIgnoreCase(segments[offset], "Aethersailor") &&
         equalsIgnoreCase(segments[offset + 1],
                          "Custom_OpenClash_Rules");
}

bool mainPathStart(const std::vector<std::string> &segments, size_t offset,
                   size_t &path_start) {
  if (segments.size() > offset &&
      equalsIgnoreCase(segments[offset], "main")) {
    path_start = offset + 1;
    return path_start < segments.size();
  }
  if (segments.size() > offset + 2 &&
      equalsIgnoreCase(segments[offset], "refs") &&
      equalsIgnoreCase(segments[offset + 1], "heads") &&
      equalsIgnoreCase(segments[offset + 2], "main")) {
    path_start = offset + 3;
    return path_start < segments.size();
  }
  return false;
}

bool rawGitHubPath(const std::vector<std::string> &segments,
                   size_t &path_start) {
  return isOfficialRepository(segments, 0) &&
         mainPathStart(segments, 2, path_start);
}

bool githubPath(const std::vector<std::string> &segments,
                size_t &path_start) {
  if (!isOfficialRepository(segments, 0) || segments.size() < 5 ||
      (!equalsIgnoreCase(segments[2], "raw") &&
       !equalsIgnoreCase(segments[2], "blob")))
    return false;
  return mainPathStart(segments, 3, path_start);
}

bool jsDelivrPath(const std::vector<std::string> &segments,
                  size_t &path_start) {
  if (segments.size() < 4 || !equalsIgnoreCase(segments[0], "gh") ||
      !equalsIgnoreCase(segments[1], "Aethersailor"))
    return false;

  if (equalsIgnoreCase(segments[2], "Custom_OpenClash_Rules@main")) {
    path_start = 3;
    return true;
  }
  if (segments.size() > 5 &&
      equalsIgnoreCase(segments[2], "Custom_OpenClash_Rules@refs") &&
      equalsIgnoreCase(segments[3], "heads") &&
      equalsIgnoreCase(segments[4], "main")) {
    path_start = 5;
    return true;
  }
  return false;
}

bool isJsDelivrHost(const std::string &host) {
  return host == "jsdelivr.net" ||
         (host.size() > 13 &&
          host.compare(host.size() - 13, 13, ".jsdelivr.net") == 0);
}

std::string joinPath(const std::vector<std::string> &segments,
                     size_t start) {
  std::string result;
  for (size_t i = start; i < segments.size(); ++i) {
    if (!result.empty())
      result += '/';
    result += segments[i];
  }
  return result;
}

} // namespace

CocrSourceResolution resolveCocrSourceUrl(const std::string &url,
                                          bool enabled) {
  CocrSourceResolution result{url, false};
  if (!enabled)
    return result;

  size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos)
    return result;
  std::string scheme = toLowerAscii(url.substr(0, scheme_end));
  if (scheme != "http" && scheme != "https")
    return result;

  size_t authority_start = scheme_end + 3;
  size_t path_start_pos = url.find('/', authority_start);
  if (path_start_pos == std::string::npos)
    return result;
  std::string authority =
      url.substr(authority_start, path_start_pos - authority_start);
  if (authority.empty() || authority.find('@') != std::string::npos)
    return result;

  size_t port_start = authority.find(':');
  std::string host = toLowerAscii(authority.substr(
      0, port_start == std::string::npos ? authority.size() : port_start));
  size_t suffix_start = url.find_first_of("?#", path_start_pos);
  std::string path =
      url.substr(path_start_pos, suffix_start == std::string::npos
                                     ? std::string::npos
                                     : suffix_start - path_start_pos);
  std::vector<std::string> segments = splitCanonicalPath(path);
  if (segments.empty())
    return result;

  size_t repository_path_start = 0;
  bool matched = false;
  if (host == "raw.githubusercontent.com")
    matched = rawGitHubPath(segments, repository_path_start);
  else if (host == "github.com")
    matched = githubPath(segments, repository_path_start);
  else if (isJsDelivrHost(host))
    matched = jsDelivrPath(segments, repository_path_start);

  if (!matched || repository_path_start >= segments.size())
    return result;

  result.effective_url =
      std::string(kTargetPrefix) + joinPath(segments, repository_path_start);
  if (suffix_start != std::string::npos)
    result.effective_url += url.substr(suffix_start);
  result.rewritten = true;
  return result;
}
