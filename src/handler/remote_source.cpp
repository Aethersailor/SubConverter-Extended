#include "handler/remote_source.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

namespace remote_source {
namespace {

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::tolower(c));
                 });
  return value;
}

bool equalsIgnoreCase(const std::string &lhs, const std::string &rhs) {
  return lower(lhs) == lower(rhs);
}

bool hasControl(const std::string &value) {
  for (unsigned char c : value) {
    if (c < 0x20 || c == 0x7f)
      return true;
  }
  return false;
}

std::string withoutQueryFragment(const std::string &url) {
  const std::string::size_type end = url.find_first_of("?#");
  return end == std::string::npos ? url : url.substr(0, end);
}

bool splitPath(const std::string &path, std::vector<std::string> &segments) {
  if (path.empty() || path.front() != '/')
    return false;
  size_t begin = 1;
  while (begin <= path.size()) {
    const size_t end = path.find('/', begin);
    const size_t length = end == std::string::npos ? std::string::npos
                                                     : end - begin;
    const std::string segment = path.substr(begin, length);
    if (segment.empty())
      return false;
    segments.push_back(segment);
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  return !segments.empty();
}

bool safeSegment(const std::string &segment) {
  if (segment.empty() || segment == "." || segment == "..")
    return false;
  for (unsigned char c : segment) {
    if (c < 0x20 || c == 0x7f || c == '\\' || c == '%' || c == ':')
      return false;
  }
  return true;
}

bool safeSegments(const std::vector<std::string> &segments, size_t begin) {
  if (begin >= segments.size())
    return false;
  for (size_t i = begin; i < segments.size(); ++i) {
    if (!safeSegment(segments[i]))
      return false;
  }
  return true;
}

bool parseAuthority(const std::string &url, std::string &scheme,
                    std::string &host, std::string &path) {
  const std::string::size_type scheme_end = url.find("://");
  if (scheme_end == std::string::npos)
    return false;
  scheme = lower(url.substr(0, scheme_end));
  if (scheme != "http" && scheme != "https")
    return false;

  const size_t authority_begin = scheme_end + 3;
  const size_t path_begin = url.find('/', authority_begin);
  if (path_begin == std::string::npos)
    return false;
  const std::string authority = url.substr(authority_begin,
                                            path_begin - authority_begin);
  if (authority.empty() || authority.find('@') != std::string::npos)
    return false;

  std::string port;
  const size_t colon = authority.find(':');
  if (colon == std::string::npos) {
    host = lower(authority);
  } else {
    host = lower(authority.substr(0, colon));
    port = authority.substr(colon + 1);
    if (host.empty() || port.empty())
      return false;
    for (unsigned char c : port) {
      if (!std::isdigit(c))
        return false;
    }
    if (port != "80" && port != "443")
      return false;
  }
  if (host.empty() || host.find('[') != std::string::npos ||
      host.find(']') != std::string::npos)
    return false;
  path = url.substr(path_begin);
  return true;
}

bool isJsDelivrHost(const std::string &host) {
  return host == "jsdelivr.net" ||
         (host.size() > 13 &&
          host.compare(host.size() - 13, 13, ".jsdelivr.net") == 0);
}

bool isCocrRepository(const std::string &owner, const std::string &repo) {
  return equalsIgnoreCase(owner, "Aethersailor") &&
         equalsIgnoreCase(repo, "Custom_OpenClash_Rules");
}

std::string join(const std::vector<std::string> &segments, size_t begin) {
  std::string result;
  for (size_t i = begin; i < segments.size(); ++i) {
    if (!result.empty())
      result += '/';
    result += segments[i];
  }
  return result;
}

bool parseRefPath(const std::vector<std::string> &segments, size_t begin,
                 std::string &ref, std::string &path) {
  if (segments.size() <= begin + 1 || !safeSegments(segments, begin))
    return false;
  size_t path_begin = begin + 1;
  if (segments[begin] == "refs") {
    if (segments.size() <= begin + 3 ||
        (segments[begin + 1] != "heads" &&
         segments[begin + 1] != "tags"))
      return false;
    // The target service accepts the branch/tag name itself. Normalizing
    // refs/heads/main and refs/tags/v1 to the final ref segment also gives
    // Raw, GitHub-file and jsDelivr URLs one logical identity.
    ref = segments[begin + 2];
    path_begin = begin + 3;
  } else {
    ref = segments[begin];
  }
  if (path_begin >= segments.size() || !safeSegment(ref))
    return false;
  path = join(segments, path_begin);
  return !path.empty();
}

bool parseGithub(const std::string &scheme, const std::string &host,
                 const std::string &path, Kind kind, ParsedUrl &parsed) {
  std::vector<std::string> segments;
  if (!splitPath(path, segments) || segments.size() < 4)
    return false;
  if (!safeSegments(segments, 0))
    return false;

  const size_t ref_begin = kind == Kind::GithubFile ? 3 : 2;
  if (kind == Kind::GithubFile &&
      (segments.size() < 5 ||
       (segments[2] != "raw" && segments[2] != "blob")))
    return false;
  if (segments.size() <= ref_begin || !safeSegment(segments[0]) ||
      !safeSegment(segments[1]))
    return false;

  LogicalResource resource;
  resource.owner = segments[0];
  resource.repository = segments[1];
  if (!parseRefPath(segments, ref_begin, resource.ref, resource.path))
    return false;
  resource.valid = true;

  parsed.valid = true;
  parsed.kind = kind;
  parsed.resource = resource;
  parsed.normalized_url = scheme + "://" + host + path;
  parsed.canonical_raw_url = scheme + "://raw.githubusercontent.com/" +
                             resource.owner + "/" + resource.repository +
                             "/" + resource.ref + "/" + resource.path;
  parsed.canonical_jsdelivr_url = scheme + "://cdn.jsdelivr.net/gh/" +
                                  resource.owner + "/" + resource.repository +
                                  "@" + resource.ref + "/" + resource.path;
  return true;
}

bool parseJsDelivr(const std::string &scheme, const std::string &host,
                   const std::string &path, ParsedUrl &parsed) {
  std::vector<std::string> segments;
  if (!splitPath(path, segments) || segments.size() < 4 ||
      !equalsIgnoreCase(segments[0], "gh") || !safeSegments(segments, 0))
    return false;

  const size_t at = segments[2].find('@');
  if (at == std::string::npos || at == 0 || at + 1 >= segments[2].size())
    return false;
  LogicalResource resource;
  resource.owner = segments[1];
  resource.repository = segments[2].substr(0, at);
  resource.ref = segments[2].substr(at + 1);
  size_t path_begin = 3;
  if (resource.ref == "refs") {
    if (segments.size() <= 5 ||
        (segments[3] != "heads" && segments[3] != "tags"))
      return false;
    resource.ref = segments[4];
    path_begin = 5;
  }
  if (!safeSegment(resource.owner) || !safeSegment(resource.repository) ||
      !safeSegment(resource.ref) || path_begin >= segments.size() ||
      !safeSegments(segments, path_begin))
    return false;
  resource.path = join(segments, path_begin);
  resource.valid = !resource.path.empty();
  if (!resource.valid)
    return false;

  parsed.valid = true;
  parsed.kind = Kind::JsDelivr;
  parsed.resource = resource;
  parsed.normalized_url = scheme + "://" + host + path;
  parsed.canonical_raw_url = scheme + "://raw.githubusercontent.com/" +
                             resource.owner + "/" + resource.repository +
                             "/" + resource.ref + "/" + resource.path;
  parsed.canonical_jsdelivr_url = scheme + "://cdn.jsdelivr.net/gh/" +
                                  resource.owner + "/" + resource.repository +
                                  "@" + resource.ref + "/" + resource.path;
  return true;
}

bool parseGitAsailor(const std::string &scheme, const std::string &host,
                     const std::string &path, ParsedUrl &parsed) {
  std::vector<std::string> segments;
  if (!splitPath(path, segments) || segments.size() < 3 ||
      !equalsIgnoreCase(segments[0], "Custom_OpenClash_Rules") ||
      !safeSegments(segments, 0))
    return false;
  LogicalResource resource;
  resource.owner = "Aethersailor";
  resource.repository = "Custom_OpenClash_Rules";
  resource.ref = segments[1];
  resource.path = join(segments, 2);
  if (!safeSegment(resource.ref) || resource.path.empty())
    return false;
  resource.valid = true;
  parsed.valid = true;
  parsed.kind = Kind::GitAsailor;
  parsed.resource = resource;
  parsed.normalized_url = scheme + "://" + host + path;
  parsed.rewritten_url = buildCocrRewrite(resource);
  return true;
}

} // namespace

bool LogicalResource::isCocr() const {
  return valid && isCocrRepository(owner, repository);
}

std::string LogicalResource::key() const {
  if (!valid)
    return "";
  return lower(owner) + "/" + lower(repository) + "\n" + ref + "\n" +
         path;
}

bool ParsedUrl::isGithubSource() const {
  return kind == Kind::GithubRaw || kind == Kind::GithubFile;
}

bool ParsedUrl::isJsDelivrSource() const { return kind == Kind::JsDelivr; }

bool ParsedUrl::isCocr() const { return resource.isCocr(); }

ParsedUrl parse(const std::string &url) {
  ParsedUrl parsed;
  const std::string clean = withoutQueryFragment(url);
  parsed.normalized_url = clean;
  if (clean.empty() || hasControl(clean))
    return parsed;

  std::string scheme, host, path;
  if (!parseAuthority(clean, scheme, host, path))
    return parsed;

  if (host == "raw.githubusercontent.com") {
    parsed.recognized_host = true;
    if (!parseGithub(scheme, host, path, Kind::GithubRaw, parsed))
      parsed.valid = false;
    return parsed;
  }
  if (host == "github.com") {
    parsed.recognized_host = true;
    if (!parseGithub(scheme, host, path, Kind::GithubFile, parsed))
      parsed.valid = false;
    return parsed;
  }
  if (isJsDelivrHost(host)) {
    parsed.recognized_host = true;
    if (!parseJsDelivr(scheme, host, path, parsed))
      parsed.valid = false;
    return parsed;
  }
  if (host == "git.asailor.org") {
    parsed.recognized_host = true;
    if (!parseGitAsailor(scheme, host, path, parsed))
      parsed.valid = false;
    return parsed;
  }

  parsed.kind = Kind::Generic;
  parsed.valid = true;
  parsed.normalized_url = clean;
  return parsed;
}

std::string buildCocrRewrite(const LogicalResource &resource) {
  if (!resource.isCocr())
    return "";
  return "https://git.asailor.org/Custom_OpenClash_Rules/" + resource.ref +
         "/" + resource.path;
}

std::string redactForLog(const std::string &url) {
  std::string clean = withoutQueryFragment(url);
  for (char &value : clean) {
    const unsigned char ch = static_cast<unsigned char>(value);
    if (ch < 0x20 || ch == 0x7f)
      value = '?';
  }
  const std::string::size_type scheme_end = clean.find("://");
  if (scheme_end == std::string::npos)
    return "[redacted-url]";
  const size_t authority_begin = scheme_end + 3;
  const size_t path_begin = clean.find('/', authority_begin);
  if (path_begin == std::string::npos)
    return clean.substr(0, scheme_end + 3) + "[redacted-host]";
  std::string host = clean.substr(authority_begin, path_begin - authority_begin);
  const size_t at = host.rfind('@');
  if (at != std::string::npos)
    host.erase(0, at + 1);
  const size_t colon = host.find(':');
  if (colon != std::string::npos)
    host.erase(colon);
  return clean.substr(0, scheme_end + 3) + lower(host) +
         clean.substr(path_begin);
}

const char *kindName(Kind kind) {
  switch (kind) {
  case Kind::GithubRaw:
    return "github_raw";
  case Kind::GithubFile:
    return "github_file";
  case Kind::JsDelivr:
    return "jsdelivr";
  case Kind::GitAsailor:
    return "git_asailor";
  case Kind::Generic:
    return "generic";
  case Kind::Unknown:
  default:
    return "unknown";
  }
}

} // namespace remote_source
