#include <algorithm>
#include <cctype>

#include "string.h"
#include "redact.h"

namespace {

bool isUrlTerminator(char character) {
  return character == '\0' || character == '\'' || character == '\"' ||
         character == '<' || character == '>' || character == '\r' ||
         character == '\n' || character == ' ' || character == '\t';
}

bool sensitiveParameter(const std::string &name) {
  std::string lower = toLower(name);
  std::replace(lower.begin(), lower.end(), '-', '_');
  std::replace(lower.begin(), lower.end(), '.', '_');
  const auto has_suffix = [&](const std::string &suffix) {
    return lower.size() >= suffix.size() &&
           lower.compare(lower.size() - suffix.size(), suffix.size(), suffix) ==
               0;
  };
  return lower == "token" || lower == "access_token" || lower == "api_key" ||
         lower == "apikey" || lower == "key" || lower == "secret" ||
         lower == "password" || lower == "pass" || lower == "authorization" ||
         lower == "cookie" || lower == "set_cookie" ||
         lower == "url" || lower == "config" || lower == "userinfo" ||
         lower == "profile_data" || lower == "dev_id" ||
         lower == "upload_path" || lower == "groups" ||
         lower == "ruleset" || lower == "rename" ||
         lower == "filter_script" || lower == "private_key" ||
         lower == "pre_shared_key" || lower == "privatekey" ||
         lower == "presharedkey" || lower == "quicsecret" ||
         lower == "userid" || lower == "auth" || lower == "authstr" ||
         lower == "auth_str" || lower == "psk" ||
         lower == "shadowtlspassword" || has_suffix("_token") ||
         has_suffix("_secret") || has_suffix("_password") ||
         has_suffix("_api_key") || has_suffix("_apikey") ||
         has_suffix("_private_key");
}

std::string redactCurlAuthUser(std::string text) {
  static const std::string marker = " with user '";
  std::string lower = toLower(text);
  std::string::size_type search_from = 0;
  while (true) {
    const std::string::size_type marker_start =
        lower.find(marker, search_from);
    if (marker_start == std::string::npos)
      break;
    const std::string::size_type value_start = marker_start + marker.size();
    const std::string::size_type next_marker = lower.find(marker, value_start);
    const std::string::size_type scope_end =
        next_marker == std::string::npos ? text.size() : next_marker;
    std::string::size_type value_end =
        scope_end == 0 ? std::string::npos : text.rfind('\'', scope_end - 1);
    if (value_end == std::string::npos || value_end < value_start)
      value_end = scope_end;
    static const std::string replacement = "<redacted>";
    text.replace(value_start, value_end - value_start, replacement);
    lower.replace(value_start, value_end - value_start, replacement);
    search_from = value_start + replacement.size();
  }
  return text;
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

bool safeAuthorityForLog(const std::string &authority) {
  return !authority.empty() &&
         std::all_of(authority.begin(), authority.end(), [](unsigned char ch) {
           return std::isalnum(ch) || ch == '.' || ch == '-' || ch == ':' ||
                  ch == '[' || ch == ']';
         });
}

bool structuredKeyCharacter(unsigned char character) {
  return std::isalnum(character) || character == '_' || character == '-' ||
         character == '.';
}

bool structuredKeyBoundary(const std::string &text,
                           std::string::size_type position) {
  if (position == 0)
    return true;
  const unsigned char character =
      static_cast<unsigned char>(text[position - 1]);
  return std::isspace(character) || character == '{' || character == '[' ||
         character == ',' || character == '-';
}

bool escapedQuote(const std::string &text, std::string::size_type position) {
  std::string::size_type backslashes = 0;
  while (position > backslashes && text[position - backslashes - 1] == '\\')
    ++backslashes;
  return backslashes % 2 != 0;
}

bool insideStructuredContainerOnLine(const std::string &text,
                                     std::string::size_type position) {
  const std::string::size_type line_break = text.find_last_of("\r\n", position);
  const std::string::size_type line_start =
      line_break == std::string::npos ? 0 : line_break + 1;
  unsigned int depth = 0;
  char quote = '\0';
  for (std::string::size_type index = line_start; index < position; ++index) {
    const char character = text[index];
    if (quote != '\0') {
      if (character == quote && !escapedQuote(text, index))
        quote = '\0';
      continue;
    }
    if (character == '\'' || character == '"') {
      quote = character;
    } else if (character == '{' || character == '[') {
      ++depth;
    } else if ((character == '}' || character == ']') && depth > 0) {
      --depth;
    }
  }
  return depth > 0;
}

std::string::size_type quotedValueEnd(const std::string &text,
                                      std::string::size_type quote_start) {
  const char quote = text[quote_start];
  std::string::size_type position = quote_start + 1;
  while ((position = text.find(quote, position)) != std::string::npos) {
    if (!escapedQuote(text, position))
      return position;
    ++position;
  }
  return text.find_first_of("\r\n", quote_start + 1);
}

std::string::size_type compositeValueEnd(const std::string &text,
                                         std::string::size_type value_start) {
  const char opening = text[value_start];
  const char closing = opening == '{' ? '}' : ']';
  unsigned int depth = 0;
  char quote = '\0';
  for (std::string::size_type position = value_start; position < text.size();
       ++position) {
    const char character = text[position];
    if (quote != '\0') {
      if (character == quote && !escapedQuote(text, position))
        quote = '\0';
      continue;
    }
    if (character == '\'' || character == '"') {
      quote = character;
      continue;
    }
    if (character == opening)
      ++depth;
    else if (character == closing && --depth == 0)
      return position + 1;
  }
  const std::string::size_type line_end =
      text.find_first_of("\r\n", value_start);
  return line_end == std::string::npos ? text.size() : line_end;
}

std::string::size_type yamlBlockValueEnd(const std::string &text,
                                         std::string::size_type key_start,
                                         std::string::size_type value_start) {
  const std::string::size_type key_line_start =
      text.rfind('\n', key_start) == std::string::npos
          ? 0
          : text.rfind('\n', key_start) + 1;
  const std::string::size_type key_indent = key_start - key_line_start;

  std::string::size_type line_end = text.find('\n', value_start);
  if (line_end == std::string::npos)
    return text.size();
  std::string::size_type block_end = line_end;
  std::string::size_type line_start = line_end + 1;
  while (line_start < text.size()) {
    line_end = text.find('\n', line_start);
    const std::string::size_type physical_end =
        line_end == std::string::npos ? text.size() : line_end;
    const std::string::size_type content_end =
        physical_end > line_start && text[physical_end - 1] == '\r'
            ? physical_end - 1
            : physical_end;
    std::string::size_type content_start = line_start;
    while (content_start < content_end &&
           (text[content_start] == ' ' || text[content_start] == '\t'))
      ++content_start;
    if (content_start != content_end &&
        content_start - line_start <= key_indent)
      break;
    block_end = physical_end;
    if (line_end == std::string::npos)
      return text.size();
    line_start = line_end + 1;
  }
  return block_end;
}

std::string redactStructuredFields(std::string text) {
  static const std::string replacement = "<redacted>";
  std::string::size_type colon = 0;
  while ((colon = text.find(':', colon)) != std::string::npos) {
    std::string::size_type key_end = colon;
    while (key_end > 0 &&
           std::isspace(static_cast<unsigned char>(text[key_end - 1])) &&
           text[key_end - 1] != '\r' && text[key_end - 1] != '\n')
      --key_end;

    std::string::size_type key_start = key_end;
    std::string key;
    if (key_end >= 2 &&
        (text[key_end - 1] == '\'' || text[key_end - 1] == '"')) {
      const char quote = text[key_end - 1];
      const std::string::size_type quote_start =
          text.rfind(quote, key_end - 2);
      if (quote_start != std::string::npos &&
          structuredKeyBoundary(text, quote_start)) {
        key_start = quote_start;
        key = text.substr(quote_start + 1, key_end - quote_start - 2);
      }
    } else {
      while (key_start > 0 && structuredKeyCharacter(
                                  static_cast<unsigned char>(text[key_start - 1])))
        --key_start;
      if (structuredKeyBoundary(text, key_start))
        key = text.substr(key_start, key_end - key_start);
    }

    if (!sensitiveParameter(key)) {
      ++colon;
      continue;
    }

    std::string::size_type value_start = colon + 1;
    while (value_start < text.size() &&
           (text[value_start] == ' ' || text[value_start] == '\t'))
      ++value_start;
    if (value_start >= text.size() || text[value_start] == '\r' ||
        text[value_start] == '\n') {
      colon = value_start;
      continue;
    }

    std::string::size_type replace_start = value_start;
    std::string::size_type value_end = value_start;
    if (text[value_start] == '\'' || text[value_start] == '"') {
      replace_start = value_start + 1;
      value_end = quotedValueEnd(text, value_start);
      if (value_end == std::string::npos)
        value_end = text.size();
    } else if (text[value_start] == '{' || text[value_start] == '[') {
      value_end = compositeValueEnd(text, value_start);
    } else if (text[value_start] == '|' || text[value_start] == '>') {
      value_end = yamlBlockValueEnd(text, key_start, value_start);
    } else {
      value_end = text.find_first_of(",}]#\r\n", value_start);
      if (value_end == std::string::npos)
        value_end = text.size();
      while (value_end > value_start &&
             std::isspace(static_cast<unsigned char>(text[value_end - 1])))
        --value_end;
    }

    text.replace(replace_start, value_end - replace_start, replacement);
    colon = replace_start + replacement.size();
  }
  return text;
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
      while (candidate != std::string::npos) {
        const bool valid_boundary =
            candidate == 0 ||
            (!std::isalnum(static_cast<unsigned char>(lower[candidate - 1])) &&
             lower[candidate - 1] != '_' && lower[candidate - 1] != '-');
        if (valid_boundary &&
            !insideStructuredContainerOnLine(text, candidate))
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
    const std::string::size_type value_length = value_end - colon - 1;
    text.replace(colon + 1, value_length, replacement);
    lower.replace(colon + 1, value_length, toLower(replacement));
    search_from = colon + 1 + replacement.size();
  }
  return text;
}

} // namespace

std::string redactSensitiveLogText(const std::string &text) {
  std::string result = redactCurlAuthUser(
      redactStructuredFields(redactNamedParameters(redactHeaders(text))));
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
    const std::string::size_type url_length = end - start;
    const std::string replacement = redactUrl(result.substr(start, end - start));
    result.replace(start, url_length, replacement);
    lower.replace(start, url_length, toLower(replacement));
    position = start + replacement.size();
  }
  return result;
}

std::string sanitizeLogLine(const std::string &text) {
  static constexpr size_t kMaxRawLogContentBytes = 64 * 1024;
  static constexpr size_t kMaxLogContentBytes = 16 * 1024;
  static constexpr char kHex[] = "0123456789ABCDEF";

  // Avoid multiplying attacker-controlled exception or request text into
  // several large redaction/escaping buffers. Oversized content is not useful
  // as an operational log event and is therefore summarized fail-closed. A
  // conventional stable event name is retained so operators still know which
  // subsystem produced the oversized payload.
  if (text.size() > kMaxRawLogContentBytes) {
    std::string event_name;
    const std::string::size_type separator = text.find(' ');
    if (separator != std::string::npos && separator > 0 && separator <= 64 &&
        std::all_of(text.begin(), text.begin() + separator,
                    [](unsigned char ch) {
                      return (ch >= 'A' && ch <= 'Z') ||
                             (ch >= '0' && ch <= '9') || ch == '_';
                    })) {
      event_name = text.substr(0, separator) + " ";
    }
    return event_name +
           "<redacted oversized_log_content original_bytes=" +
           std::to_string(text.size()) + ">";
  }

  const std::string redacted = redactSensitiveLogText(text);
  std::string escaped;
  escaped.reserve(std::min(redacted.size(), kMaxLogContentBytes));
  for (const unsigned char ch : redacted) {
    switch (ch) {
    case '\r':
      escaped += "\\r";
      break;
    case '\n':
      escaped += "\\n";
      break;
    case '\t':
      escaped += "\\t";
      break;
    default:
      if (ch < 0x20 || ch == 0x7f) {
        escaped += "\\x";
        escaped.push_back(kHex[(ch >> 4) & 0x0f]);
        escaped.push_back(kHex[ch & 0x0f]);
      } else {
        escaped.push_back(static_cast<char>(ch));
      }
      break;
    }
  }

  if (escaped.size() <= kMaxLogContentBytes)
    return escaped;

  const std::string suffix =
      "...[truncated original_bytes=" + std::to_string(text.size()) + "]";
  size_t limit = kMaxLogContentBytes > suffix.size()
                     ? kMaxLogContentBytes - suffix.size()
                     : 0;

  // Find the last complete UTF-8 sequence inside the retained prefix. Invalid
  // bytes are treated as single-byte data; the logger must remain available
  // even when a dependency returns malformed text.
  size_t cursor = 0;
  size_t safe = 0;
  while (cursor < escaped.size() && cursor < limit) {
    const unsigned char lead = static_cast<unsigned char>(escaped[cursor]);
    size_t width = 1;
    if ((lead & 0xe0) == 0xc0)
      width = 2;
    else if ((lead & 0xf0) == 0xe0)
      width = 3;
    else if ((lead & 0xf8) == 0xf0)
      width = 4;

    bool valid = cursor + width <= escaped.size();
    for (size_t index = 1; valid && index < width; ++index) {
      const unsigned char continuation =
          static_cast<unsigned char>(escaped[cursor + index]);
      valid = (continuation & 0xc0) == 0x80;
    }
    if (!valid)
      width = 1;
    if (cursor + width > limit)
      break;
    cursor += width;
    safe = cursor;
  }
  escaped.resize(safe);
  escaped += suffix;
  return escaped;
}

std::string summarizeSensitiveTextForLog(const std::string &value) {
  return "length=" + std::to_string(value.size());
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
