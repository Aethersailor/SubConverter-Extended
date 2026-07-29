#ifndef CUSTOM_OPENCLASH_RULES_ENDPOINT_H_INCLUDED
#define CUSTOM_OPENCLASH_RULES_ENDPOINT_H_INCLUDED

#include <map>
#include <set>
#include <string>

#include "server/webserver.h"

namespace custom_openclash_rules_endpoint {

struct DirectoryPageSnapshot {
  std::string content;
  std::string etag;
};

using DirectoryIndexSnapshot =
    std::map<std::string, DirectoryPageSnapshot>;

bool buildDirectoryIndexSnapshot(
    const std::string &manifest,
    const std::set<std::string> &available_repository_paths,
    DirectoryIndexSnapshot &pages, std::string *error = nullptr);

std::string serve(RESPONSE_CALLBACK_ARGS);

} // namespace custom_openclash_rules_endpoint

#endif // CUSTOM_OPENCLASH_RULES_ENDPOINT_H_INCLUDED
