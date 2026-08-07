#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>

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
         lower == "password" || lower == "pass" || lower == "authorization" ||
         lower == "cookie" || lower == "set-cookie" ||
         lower == "url" || lower == "config" || lower == "userinfo" ||
         lower == "profile_data";
}

bool opaqueSecretScheme(const std::string &scheme) {
  static const string_array schemes = {
      "data", "ss", "ssr", "ssd", "vmess", "vless", "trojan",
      "hysteria", "hysteria2", "hy2", "tuic", "wireguard"};
  return std::find(schemes.begin(), schemes.end(), toLower(scheme)) !=
         schemes.end();
}

std::string urlScheme(const std::string &url) {
  const std::string::size_type colon = url.find(':');
  if (colon == std::string::npos || colon == 0)
    return "";
  for (std::string::size_type index = 0; index < colon; ++index) {
    const unsigned char character = static_cast<unsigned char>(url[index]);
    if (!std::isalnum(character) && character != '+' && character != '-' &&
        character != '.')
      return "";
  }
  return toLower(url.substr(0, colon));
}

std::string shortDiagnosticHash(const std::string &value) {
  std::uint64_t hash = 0xCBF29CE484222325ULL;
  for (unsigned char character : value) {
    hash ^= character;
    hash *= 0x100000001B3ULL;
  }
  std::ostringstream stream;
  stream << std::hex << std::setw(12) << std::setfill('0')
         << (hash & 0xffffffffffffULL);
  return stream.str();
}

bool safeAuthorityForLog(const std::string &authority) {
  return !authority.empty() &&
         std::all_of(authority.begin(), authority.end(), [](unsigned char ch) {
           return std::isalnum(ch) || ch == '.' || ch == '-' || ch == ':' ||
                  ch == '[' || ch == ']';
         });
}

std::string redactNamedParameters(std::string text) {
  std::string::size_type equals = 0;
  while ((equals = text.find('=', equals)) != std::string::npos) {
    std::string::size_type name_start = equals;
    while (name_start > 0) {
      const unsigned char character =
          static_cast<unsigned char>(text[name_start - 1]);
      if (!std::isalnum(character) && character != '_' && character != '-' &&
          character != '.')
        break;
      --name_start;
    }
    const std::string name = text.substr(name_start, equals - name_start);
    if (!sensitiveParameter(name)) {
      ++equals;
      continue;
    }

    std::string::size_type value_end = equals + 1;
    while (value_end < text.size()) {
      const char character = text[value_end];
      if (character == '&' || character == '|' || character == '\r' ||
          character == '\n' || character == '\t' || character == ' ' ||
          character == '\'' || character == '"' || character == '<' ||
          character == '>')
        break;
      ++value_end;
    }
    static const std::string replacement = "<redacted>";
    text.replace(equals + 1, value_end - equals - 1, replacement);
    equals += replacement.size() + 1;
  }
  return text;
}

std::string redactUrl(std::string url) {
  const std::string scheme = urlScheme(url);
  if (opaqueSecretScheme(scheme))
    return scheme + "://<redacted>";

  const std::string::size_type scheme_end = url.find("://");
  if (scheme_end == std::string::npos)
    return redactNamedParameters(url);

  const std::string::size_type authority_start = scheme_end + 3;
  const std::string::size_type authority_end =
      url.find_first_of("/?#", authority_start);
  const std::string::size_type at = url.rfind(
      '@', authority_end == std::string::npos ? std::string::npos : authority_end);
  if (at != std::string::npos && at >= authority_start)
    url.erase(authority_start, at + 1 - authority_start);

  if ((scheme == "http" || scheme == "https") &&
      authority_end != std::string::npos) {
    const std::string::size_type sanitized_authority_end =
        url.find_first_of("/?#", authority_start);
    url.erase(sanitized_authority_end);
    url += "/<redacted>";
    return url;
  }

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
  return redactNamedParameters(url);
}

std::string redactHeaders(std::string text) {
  static const string_array header_names = {
      "proxy-authorization", "authorization", "set-cookie", "cookie"};
  std::string lower = toLower(text);
  std::string::size_type search_from = 0;
  while (search_from < text.size()) {
    std::string::size_type header_start = std::string::npos;
    std::string matched_name;
    for (const std::string &name : header_names) {
      std::string::size_type candidate = lower.find(name + ":", search_from);
      while (candidate != std::string::npos && candidate > 0) {
        const unsigned char before =
            static_cast<unsigned char>(lower[candidate - 1]);
        if (!std::isalnum(before) && before != '_' && before != '-')
          break;
        candidate = lower.find(name + ":", candidate + 1);
      }
      if (candidate != std::string::npos &&
          (header_start == std::string::npos || candidate < header_start)) {
        header_start = candidate;
        matched_name = name;
      }
    }
    if (header_start == std::string::npos)
      break;

    const std::string::size_type colon = header_start + matched_name.size();
    std::string::size_type value_end = text.find_first_of("\r\n", colon + 1);
    if (value_end == std::string::npos)
      value_end = text.size();
    else {
      // Obsolete folded HTTP headers are still seen in diagnostic dumps. A
      // continuation line begins with whitespace and belongs to the same
      // secret value, so redact it together with the first line.
      std::string::size_type next_line = value_end;
      while (next_line < text.size()) {
        if (text[next_line] == '\r')
          ++next_line;
        if (next_line < text.size() && text[next_line] == '\n')
          ++next_line;
        if (next_line >= text.size() ||
            (text[next_line] != ' ' && text[next_line] != '\t'))
          break;
        value_end = text.find_first_of("\r\n", next_line);
        if (value_end == std::string::npos) {
          value_end = text.size();
          break;
        }
        next_line = value_end;
      }
    }
    static const std::string replacement = " <redacted>";
    text.replace(colon + 1, value_end - colon - 1, replacement);
    lower = toLower(text);
    search_from = colon + 1 + replacement.size();
  }
  return text;
}

} // namespace

std::string redactSensitiveLogText(const std::string &text) {
  std::string result = redactNamedParameters(redactHeaders(text));
  static const string_array schemes = {
      "http://",      "https://",    "socks4://", "socks4a://",
      "socks5://",    "socks5h://",  "ss://",     "ssr://",
      "ssd://",       "vmess://",    "vless://",  "trojan://",
      "hysteria://",  "hysteria2://", "hy2://",   "tuic://",
      "wireguard://", "data:"};
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

std::string summarizeSensitiveTextForLog(const std::string &value) {
  return "length=" + std::to_string(value.size()) +
         " hash=" + shortDiagnosticHash(value);
}

std::string summarizeUrlForLog(const std::string &value) {
  const std::string scheme = urlScheme(value);
  std::string summary = "scheme=" + (scheme.empty() ? "opaque" : scheme);

  if ((scheme == "http" || scheme == "https") &&
      value.find("://") != std::string::npos) {
    const std::string::size_type authority_start = value.find("://") + 3;
    const std::string::size_type authority_end =
        value.find_first_of("/?#", authority_start);
    std::string authority = value.substr(
        authority_start, authority_end == std::string::npos
                             ? std::string::npos
                             : authority_end - authority_start);
    const std::string::size_type at = authority.rfind('@');
    if (at != std::string::npos)
      authority.erase(0, at + 1);
    if (safeAuthorityForLog(authority))
      summary += " host=" + authority;
  }

  summary += " " + summarizeSensitiveTextForLog(value);
  return summary;
}
