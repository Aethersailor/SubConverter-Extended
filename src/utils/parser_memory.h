#ifndef PARSER_MEMORY_H_INCLUDED
#define PARSER_MEMORY_H_INCLUDED

#include <algorithm>
#include <string>
#include <string_view>
#include "parser/config/proxy.h"
#include "utils/base64/base64.h"
#include "utils/bounded_output.h"

// Preflight actual input before parsers create their object graphs. Count
// source records as well as bytes: many short nodes can expand far beyond a
// byte-only multiplier. The node allowance covers native/Go parse objects,
// vector growth, canonical data and the eventual Proxy structures.
inline void reserveSubscriptionParseMemory(const std::string &content) {
  if (!bounded_output_reservation) return;
  if (content.size() > UINT64_MAX / 8) throw BoundedOutputExceeded();
  reserveBoundedOutputBytes(content.size() * 8);
  const auto records = [](std::string_view text) {
    uint64_t count = 0;
    for (const auto token : {std::string_view("://"), std::string_view("\"type\""),
                             std::string_view("type:")}) {
      size_t offset = 0;
      while ((offset = text.find(token, offset)) != std::string_view::npos) {
        ++count;
        offset += token.size();
      }
    }
    return count;
  };
  uint64_t count = records(content);
  if (count == 0) {
    const std::string decoded = urlSafeBase64Decode(content);
    count = records(decoded);
    if (count == 0)
      count = 1 + std::count(content.begin(), content.end(), '\n');
  }
  const uint64_t per_node = sizeof(Proxy) * 8 + 4096;
  if (count > UINT64_MAX / per_node) throw BoundedOutputExceeded();
  reserveBoundedOutputBytes(count * per_node);
}

#endif
