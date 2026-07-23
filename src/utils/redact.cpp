#include <algorithm>

#include "string.h"
#include "redact.h"

namespace {

bool isUrlTerminator(char character) {
  return character == '\0' || character == '\'' || character == '\"' ||
         character == '<' || character == '>' || character == '\r' ||
         character == '\n' || character == ' ' || character == '\t';
}

bool sensitiveParameter(const std::string &name) {
  const std::string lower = toLower(name);
  return lower == "token" || lower == "access_token" || lower == "api_key" ||
         lower == "apikey" || lower == "key" || lower == "secret" ||
         lower == "password" || lower == "pass" || lower == "authorization";
}

std::string redactUrl(std::string url) {
  const std::string::size_type scheme_end = url.find("://");
  if (scheme_end == std::string::npos)
    return url;

  const std::string::size_type authority_start = scheme_end + 3;
  const std::string::size_type authority_end =
      url.find_first_of("/?#", authority_start);
  const std::string::size_type at = url.rfind(
      '@', authority_end == std::string::npos ? std::string::npos : authority_end);
  if (at != std::string::npos && at >= authority_start)
    url.erase(authority_start, at + 1 - authority_start);

  const std::string::size_type query_start = url.find('?');
  if (query_start == std::string::npos)
    return url;
  const std::string::size_type fragment_start = url.find('#', query_start);
  const std::string query = url.substr(
      query_start + 1, fragment_start == std::string::npos
                           ? std::string::npos
                           : fragment_start - query_start - 1);
  string_array pairs = split(query, "&");
  for (std::string &pair : pairs) {
    const std::string::size_type equals = pair.find('=');
    const std::string name = pair.substr(0, equals);
    if (sensitiveParameter(name) && equals != std::string::npos)
      pair.erase(equals + 1), pair += "<redacted>";
  }
  url.replace(query_start + 1,
              fragment_start == std::string::npos ? std::string::npos
                                                   : fragment_start - query_start - 1,
              join(pairs, "&"));
  return url;
}

std::string redactHeaders(std::string text) {
  const std::string lower = toLower(text);
  const std::string::size_type proxy_authorization =
      lower.find("proxy-authorization:");
  if (proxy_authorization != std::string::npos)
    return text.substr(0, proxy_authorization + 20) + " <redacted>";
  const std::string::size_type authorization = lower.find("authorization:");
  if (authorization != std::string::npos)
    return text.substr(0, authorization + 14) + " <redacted>";
  return text;
}

} // namespace

std::string redactSensitiveLogText(const std::string &text) {
  std::string result = redactHeaders(text);
  static const string_array schemes = {"http://", "https://", "socks4://",
                                       "socks4a://", "socks5://", "socks5h://"};
  std::string lower = toLower(result);
  std::string::size_type position = 0;
  while (position < result.size()) {
    std::string::size_type start = std::string::npos;
    for (const std::string &scheme : schemes) {
      const std::string::size_type candidate = lower.find(scheme, position);
      if (candidate != std::string::npos &&
          (start == std::string::npos || candidate < start))
        start = candidate;
    }
    if (start == std::string::npos)
      break;
    std::string::size_type end = start;
    while (end < result.size() && !isUrlTerminator(result[end]))
      end++;
    const std::string replacement = redactUrl(result.substr(start, end - start));
    result.replace(start, end - start, replacement);
    lower = toLower(result);
    position = start + replacement.size();
  }
  return result;
}
