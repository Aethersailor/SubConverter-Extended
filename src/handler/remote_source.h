#ifndef REMOTE_SOURCE_H_INCLUDED
#define REMOTE_SOURCE_H_INCLUDED

#include <string>
#include <vector>

namespace remote_source {

enum class Kind {
  Unknown,
  GithubRaw,
  GithubFile,
  JsDelivr,
  GitAsailor,
  Generic
};

struct LogicalResource {
  bool valid = false;
  std::string owner;
  std::string repository;
  std::string ref;
  std::string path;

  bool isCocr() const;
  std::string key() const;
};

struct ParsedUrl {
  bool valid = false;
  bool recognized_host = false;
  Kind kind = Kind::Unknown;
  std::string normalized_url;
  std::string canonical_raw_url;
  std::string canonical_jsdelivr_url;
  std::string rewritten_url;
  LogicalResource resource;

  bool isGithubSource() const;
  bool isJsDelivrSource() const;
  bool isCocr() const;
};

struct FetchCandidate {
  std::string url;
  std::string source_kind;
};

struct FetchPlan {
  std::vector<FetchCandidate> candidates;
  bool cocr_rewrite_used = false;
  bool cocr_rewrite_failed = false;
  std::string logical_resource;
};

// Parses only the source forms for which the service has explicit source
// semantics. Unknown HTTP(S) URLs remain valid generic sources at the fetch
// layer. A recognized host with an invalid path is deliberately distinguishable
// so malformed GitHub/jsDelivr/git.asailor.org URLs fail closed.
ParsedUrl parse(const std::string &url);

// Builds the exact source candidates that the fetch layer is allowed to
// request. This is deliberately independent of networking so the directional
// source policy can be tested without contacting external services.
FetchPlan buildFetchPlan(const std::string &requested_url,
                         const ParsedUrl &parsed,
                         bool cocr_fallback_enabled,
                         bool is_get);

std::string buildCocrRewrite(const LogicalResource &resource);
std::string redactForLog(const std::string &url);
const char *kindName(Kind kind);

} // namespace remote_source

#endif // REMOTE_SOURCE_H_INCLUDED
