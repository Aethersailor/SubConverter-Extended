#include "custom_openclash_rules_endpoint.h"

#include <string>

#include "config/custom_openclash_rules.h"
#include "utils/file.h"
#include "utils/md5/md5_interface.h"

namespace custom_openclash_rules_endpoint {

std::string serve(RESPONSE_CALLBACK_ARGS) {
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

  auto if_none_match = request.headers.find("If-None-Match");
  if (if_none_match != request.headers.end() && if_none_match->second == etag) {
    response.status_code = 304;
    return "";
  }
  return content;
}

} // namespace custom_openclash_rules_endpoint
