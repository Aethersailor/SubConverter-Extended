#include "custom_openclash_rules_endpoint.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "config/custom_openclash_rules.h"
#include "utils/file.h"
#include "utils/md5/md5_interface.h"
#include "utils/urlencode.h"

namespace custom_openclash_rules_endpoint {
namespace {

const std::string PUBLISHED_ROOT = "/Custom_OpenClash_Rules/main";

struct DirectoryPage {
  std::string content;
  std::string etag;
};

struct DirectoryIndex {
  bool available = false;
  std::map<std::string, DirectoryPage> pages;
};

std::string htmlEscape(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (char c : value) {
    switch (c) {
    case '&':
      escaped += "&amp;";
      break;
    case '<':
      escaped += "&lt;";
      break;
    case '>':
      escaped += "&gt;";
      break;
    case '"':
      escaped += "&quot;";
      break;
    case '\'':
      escaped += "&#39;";
      break;
    default:
      escaped += c;
      break;
    }
  }
  return escaped;
}

std::vector<std::string> splitRepositoryPath(const std::string &path) {
  std::vector<std::string> segments;
  size_t start = 0;
  while (start < path.size()) {
    size_t end = path.find('/', start);
    segments.emplace_back(path.substr(
        start, end == std::string::npos ? std::string::npos : end - start));
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  return segments;
}

std::string joinRepositoryPath(const std::vector<std::string> &segments,
                               size_t count) {
  std::string result;
  for (size_t i = 0; i < count; ++i) {
    if (!result.empty())
      result += '/';
    result += segments[i];
  }
  return result;
}

std::string canonicalDirectoryPath(const std::string &repository_path) {
  std::string result = PUBLISHED_ROOT + "/";
  for (const std::string &segment : splitRepositoryPath(repository_path))
    result += urlEncode(segment) + "/";
  return result;
}

bool isHexDigest(const std::string &value) {
  if (value.size() != 64)
    return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0;
  });
}

bool bundledFileExists(
    const custom_openclash_rules::Resource &resource) {
  for (const std::string &candidate :
       custom_openclash_rules::localPathCandidates(resource)) {
    if (fileExist(candidate, true))
      return true;
  }
  return false;
}

std::string loadManifest() {
  const std::vector<std::string> candidates = {
      "Custom_OpenClash_Rules/manifest.sha256",
      "base/Custom_OpenClash_Rules/manifest.sha256"};
  for (const std::string &candidate : candidates) {
    if (fileExist(candidate, true))
      return fileGet(candidate, true);
  }
  return "";
}

std::string renderDirectoryPage(
    const std::string &repository_path,
    const std::map<std::string, bool> &children) {
  std::string display_path = PUBLISHED_ROOT + "/";
  if (!repository_path.empty())
    display_path += repository_path + "/";

  std::ostringstream output;
  output << "<!doctype html>\n<html lang=\"en\">\n<head>\n"
         << "<meta charset=\"utf-8\">\n"
         << "<meta name=\"viewport\" content=\"width=device-width, "
            "initial-scale=1\">\n"
         << "<title>Index of " << htmlEscape(display_path) << "</title>\n"
         << "</head>\n<body>\n<h1>Index of " << htmlEscape(display_path)
         << "</h1>\n<ul>\n";

  if (!repository_path.empty())
    output << "<li><a href=\"../\">../</a></li>\n";

  for (const auto &child : children) {
    if (!child.second)
      continue;
    std::string encoded = urlEncode(child.first);
    output << "<li>[DIR] <a href=\"" << htmlEscape(encoded)
           << "/\">" << htmlEscape(child.first) << "/</a></li>\n";
  }
  for (const auto &child : children) {
    if (child.second)
      continue;
    std::string encoded = urlEncode(child.first);
    output << "<li><a href=\"" << htmlEscape(encoded) << "\">"
           << htmlEscape(child.first) << "</a></li>\n";
  }

  output << "</ul>\n</body>\n</html>\n";
  return output.str();
}

DirectoryIndex buildDirectoryIndex() {
  DirectoryIndex index;
  std::string manifest = loadManifest();
  if (manifest.empty())
    return index;

  std::map<std::string, std::map<std::string, bool>> directories;
  directories[""];
  std::istringstream stream(manifest);
  std::string line;
  size_t files = 0;

  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.size() <= 66 || line[64] != ' ' || line[65] != ' ' ||
        !isHexDigest(line.substr(0, 64)))
      return {};

    std::string manifest_path = line.substr(66);
    if (manifest_path.compare(0, 5, "main/") != 0)
      return {};
    std::string repository_path = manifest_path.substr(5);
    custom_openclash_rules::Resource resource =
        custom_openclash_rules::matchPublishedPath(PUBLISHED_ROOT + "/" +
                                                   repository_path);
    if (!resource.matched() || resource.repository_path != repository_path ||
        !bundledFileExists(resource))
      return {};

    std::vector<std::string> segments =
        splitRepositoryPath(repository_path);
    if (segments.size() < 2)
      return {};

    for (size_t i = 0; i < segments.size(); ++i) {
      std::string parent = joinRepositoryPath(segments, i);
      bool directory = i + 1 < segments.size();
      auto inserted = directories[parent].emplace(segments[i], directory);
      if (!inserted.second && inserted.first->second != directory)
        return {};
      if (directory)
        directories[joinRepositoryPath(segments, i + 1)];
    }
    ++files;
  }

  if (!files || !directories.count("cfg") || !directories.count("rule"))
    return {};

  for (const auto &directory : directories) {
    DirectoryPage page;
    page.content = renderDirectoryPage(directory.first, directory.second);
    page.etag = "\"" + getMD5(page.content) + "\"";
    index.pages.emplace(directory.first, std::move(page));
  }
  index.available = true;
  return index;
}

const DirectoryIndex &directoryIndex() {
  static const DirectoryIndex index = buildDirectoryIndex();
  return index;
}

void setDirectorySecurityHeaders(Response &response) {
  response.headers["Cache-Control"] = "public, max-age=3600";
  response.headers["Content-Security-Policy"] =
      "default-src 'none'; base-uri 'none'; form-action 'none'; "
      "frame-ancestors 'none'";
  response.headers["Referrer-Policy"] = "no-referrer";
  response.headers["X-Content-Type-Options"] = "nosniff";
  response.headers["X-Frame-Options"] = "DENY";
  response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive";
}

bool etagMatches(const Request &request, const std::string &etag) {
  auto if_none_match = request.headers.find("If-None-Match");
  return if_none_match != request.headers.end() &&
         if_none_match->second == etag;
}

std::string serveDirectory(const custom_openclash_rules::PublishedDirectory &dir,
                           Request &request, Response &response,
                           bool &handled) {
  const DirectoryIndex &index = directoryIndex();
  if (!index.available) {
    if (dir.repository_path.empty() || dir.trailing_slash ||
        dir.repository_path == "cfg" || dir.repository_path == "rule") {
      handled = true;
      response.status_code = 503;
      response.content_type = "text/plain; charset=utf-8";
      response.headers["Cache-Control"] = "no-store";
      response.headers["X-Content-Type-Options"] = "nosniff";
      return "Directory index unavailable.\n";
    }
    return "";
  }

  auto page = index.pages.find(dir.repository_path);
  if (page == index.pages.end())
    return "";

  handled = true;
  setDirectorySecurityHeaders(response);
  if (!dir.trailing_slash) {
    response.status_code = 308;
    response.content_type = "text/plain; charset=utf-8";
    response.headers["Location"] =
        canonicalDirectoryPath(dir.repository_path);
    return "Redirecting to directory URL.\n";
  }

  response.content_type = "text/html; charset=utf-8";
  response.headers["ETag"] = page->second.etag;
  if (etagMatches(request, page->second.etag)) {
    response.status_code = 304;
    return "";
  }
  return page->second.content;
}

} // namespace

std::string serve(RESPONSE_CALLBACK_ARGS) {
  custom_openclash_rules::PublishedDirectory directory =
      custom_openclash_rules::matchPublishedDirectory(request.url);
  if (directory.matched()) {
    bool handled = false;
    std::string result =
        serveDirectory(directory, request, response, handled);
    if (handled)
      return result;
  }

  custom_openclash_rules::Resource resource =
      custom_openclash_rules::matchPublishedPath(request.url);
  if (!resource.matched()) {
    response.status_code = 404;
    return "Not found.\n";
  }

  std::string path;
  for (const std::string &candidate :
       custom_openclash_rules::localPathCandidates(resource)) {
    if (fileExist(candidate, true)) {
      path = candidate;
      break;
    }
  }
  if (path.empty()) {
    response.status_code = 404;
    return "Not found.\n";
  }

  std::string content = fileGet(path, true);
  std::string etag = "\"" + getMD5(content) + "\"";
  response.content_type = custom_openclash_rules::contentType(resource);
  response.headers["Cache-Control"] = "public, max-age=3600";
  response.headers["ETag"] = etag;
  response.headers["X-Content-Type-Options"] = "nosniff";

  if (etagMatches(request, etag)) {
    response.status_code = 304;
    return "";
  }
  return content;
}

} // namespace custom_openclash_rules_endpoint
