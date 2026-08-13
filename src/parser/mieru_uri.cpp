#include "mieru_uri.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <string_view>
#include <utility>

namespace {

int hexValue(unsigned char ch) {
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

bool percentDecode(std::string_view value, bool plus_as_space,
                   std::string &decoded) {
  decoded.clear();
  decoded.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    unsigned char ch = static_cast<unsigned char>(value[i]);
    if (ch == '%') {
      if (i + 2 >= value.size())
        return false;
      const int high = hexValue(static_cast<unsigned char>(value[i + 1]));
      const int low = hexValue(static_cast<unsigned char>(value[i + 2]));
      if (high < 0 || low < 0)
        return false;
      ch = static_cast<unsigned char>((high << 4) | low);
      i += 2;
    } else if (plus_as_space && ch == '+') {
      ch = ' ';
    }
    if (std::iscntrl(ch))
      return false;
    decoded.push_back(static_cast<char>(ch));
  }
  return true;
}

bool parseUnsigned(std::string_view value, unsigned minimum, unsigned maximum,
                   unsigned &parsed) {
  if (value.empty() ||
      !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
      }))
    return false;
  unsigned long long result = 0;
  for (unsigned char ch : value) {
    const unsigned digit = static_cast<unsigned>(ch - '0');
    if (result > (maximum - digit) / 10)
      return false;
    result = result * 10 + digit;
  }
  if (result < minimum)
    return false;
  parsed = static_cast<unsigned>(result);
  return true;
}

bool readVarint(const std::vector<unsigned char> &data, size_t &offset,
                uint64_t &value) {
  value = 0;
  for (unsigned shift = 0; shift < 64 && offset < data.size(); shift += 7) {
    const unsigned char byte = data[offset++];
    if (shift == 63 && byte > 1)
      return false;
    value |= static_cast<uint64_t>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0)
      return true;
  }
  return false;
}

bool validProtobufWire(const std::vector<unsigned char> &data) {
  if (data.empty())
    return false;
  size_t offset = 0;
  while (offset < data.size()) {
    uint64_t tag = 0;
    if (!readVarint(data, offset, tag) || tag >> 3 == 0 ||
        tag >> 3 > 0x1fffffff)
      return false;
    switch (tag & 7) {
    case 0: {
      uint64_t ignored = 0;
      if (!readVarint(data, offset, ignored))
        return false;
      break;
    }
    case 1:
      if (data.size() - offset < 8)
        return false;
      offset += 8;
      break;
    case 2: {
      uint64_t length = 0;
      if (!readVarint(data, offset, length) || length > data.size() - offset)
        return false;
      offset += static_cast<size_t>(length);
      break;
    }
    case 5:
      if (data.size() - offset < 4)
        return false;
      offset += 4;
      break;
    default:
      return false;
    }
  }
  return true;
}

bool decodeAndValidateProtobufBase64(const std::string &value) {
  if (value.empty() || value.size() % 4 != 0)
    return false;
  size_t padding_start = value.size();
  for (size_t i = 0; i < value.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(value[i]);
    if (ch == '=') {
      padding_start = std::min(padding_start, i);
      continue;
    }
    if (padding_start != value.size() ||
        !(std::isalnum(ch) || ch == '+' || ch == '/'))
      return false;
  }
  const size_t padding = value.size() - padding_start;
  if (padding > 2 ||
      !(padding == 0 ||
        (padding == 1 && padding_start % 4 == 3) ||
        (padding == 2 && padding_start % 4 == 2)))
    return false;

  static const std::string alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<unsigned char> decoded;
  decoded.reserve(value.size() / 4 * 3 - padding);
  unsigned accumulator = 0;
  unsigned bits = 0;
  for (size_t i = 0; i < padding_start; ++i) {
    const size_t index = alphabet.find(value[i]);
    if (index == std::string::npos)
      return false;
    accumulator = (accumulator << 6) | static_cast<unsigned>(index);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded.push_back(
          static_cast<unsigned char>((accumulator >> bits) & 0xff));
    }
  }
  if (bits != 0 && (accumulator & ((1u << bits) - 1u)) != 0)
    return false;
  return validProtobufWire(decoded);
}

using QueryValues = std::map<std::string, std::vector<std::string>>;

bool parseQuery(std::string_view query, QueryValues &values) {
  values.clear();
  size_t start = 0;
  while (start <= query.size()) {
    const size_t separator = query.find('&', start);
    const size_t end = separator == std::string_view::npos ? query.size()
                                                            : separator;
    const std::string_view part = query.substr(start, end - start);
    if (!part.empty()) {
      const size_t equals = part.find('=');
      const std::string_view raw_key = part.substr(0, equals);
      const std::string_view raw_value =
          equals == std::string_view::npos ? std::string_view()
                                           : part.substr(equals + 1);
      std::string key;
      std::string value;
      if (!percentDecode(raw_key, true, key) ||
          !percentDecode(raw_value, true, value))
        return false;
      values[std::move(key)].emplace_back(std::move(value));
    }
    if (separator == std::string_view::npos)
      break;
    start = separator + 1;
  }
  return true;
}

const std::vector<std::string> *queryValues(const QueryValues &values,
                                            const std::string &key) {
  const auto it = values.find(key);
  return it == values.end() ? nullptr : &it->second;
}

bool readSingleton(const QueryValues &values, const std::string &key,
                   bool required, std::string &value) {
  const auto *items = queryValues(values, key);
  if (items == nullptr) {
    value.clear();
    return !required;
  }
  if (items->size() != 1 || items->front().empty())
    return false;
  value = items->front();
  return true;
}

} // namespace

bool isValidMieruMultiplexing(const std::string &value) {
  return value.empty() || value == "MULTIPLEXING_OFF" ||
         value == "MULTIPLEXING_LOW" ||
         value == "MULTIPLEXING_MIDDLE" ||
         value == "MULTIPLEXING_HIGH";
}

bool isValidMieruHandshakeMode(const std::string &value) {
  return value.empty() || value == "HANDSHAKE_STANDARD" ||
         value == "HANDSHAKE_NO_WAIT";
}

bool isValidMieruTrafficPattern(const std::string &value) {
  return value.empty() || decodeAndValidateProtobufBase64(value);
}

bool parseMieruPortBinding(const std::string &port,
                           const std::string &protocol,
                           MieruPortBinding &binding) {
  if (protocol != "TCP" && protocol != "UDP")
    return false;

  const size_t dash = port.find('-');
  unsigned first = 0;
  unsigned last = 0;
  if (dash == std::string::npos) {
    if (!parseUnsigned(port, 1, 65535, first))
      return false;
    binding.port = std::to_string(first);
    binding.protocol = protocol;
    binding.is_range = false;
    return true;
  }
  if (dash == 0 || dash + 1 >= port.size() ||
      port.find('-', dash + 1) != std::string::npos ||
      !parseUnsigned(std::string_view(port).substr(0, dash), 1, 65535, first) ||
      !parseUnsigned(std::string_view(port).substr(dash + 1), 1, 65535, last) ||
      first > last)
    return false;

  binding.port = std::to_string(first) + "-" + std::to_string(last);
  binding.protocol = protocol;
  binding.is_range = true;
  return true;
}

bool parseMieruSimpleUri(const std::string &uri, MieruSimpleConfig &config) {
  constexpr std::string_view prefix = "mierus://";
  if (uri.size() <= prefix.size() ||
      uri.compare(0, prefix.size(), prefix) != 0)
    return false;

  MieruSimpleConfig parsed;
  std::string_view body(uri.data() + prefix.size(), uri.size() - prefix.size());
  const size_t fragment_pos = body.find('#');
  if (fragment_pos != std::string_view::npos) {
    if (!percentDecode(body.substr(fragment_pos + 1), false, parsed.remark))
      return false;
    body = body.substr(0, fragment_pos);
  }

  std::string_view raw_query;
  const size_t query_pos = body.find('?');
  if (query_pos != std::string_view::npos) {
    raw_query = body.substr(query_pos + 1);
    body = body.substr(0, query_pos);
  }
  if (body.empty() || body.find('/') != std::string_view::npos)
    return false;

  const size_t at = body.rfind('@');
  if (at == std::string_view::npos || at == 0 || at + 1 >= body.size())
    return false;
  const std::string_view userinfo = body.substr(0, at);
  const size_t colon = userinfo.find(':');
  if (colon == std::string_view::npos || colon == 0 ||
      colon + 1 >= userinfo.size() ||
      !percentDecode(userinfo.substr(0, colon), false, parsed.username) ||
      !percentDecode(userinfo.substr(colon + 1), false, parsed.password) ||
      parsed.username.empty() || parsed.password.empty())
    return false;

  const std::string_view authority = body.substr(at + 1);
  if (authority.front() == '[') {
    if (authority.size() < 3 || authority.back() != ']')
      return false;
    if (!percentDecode(authority.substr(1, authority.size() - 2), false,
                       parsed.host))
      return false;
  } else {
    if (authority.find(':') != std::string_view::npos ||
        !percentDecode(authority, false, parsed.host))
      return false;
  }
  if (parsed.host.empty() ||
      std::any_of(parsed.host.begin(), parsed.host.end(),
                  [](unsigned char ch) { return std::isspace(ch) != 0; }) ||
      parsed.host.find_first_of("/?#@[]") != std::string::npos ||
      (authority.front() != '[' &&
       parsed.host.find(':') != std::string::npos))
    return false;

  QueryValues query;
  if (!parseQuery(raw_query, query) ||
      !readSingleton(query, "profile", true, parsed.profile) ||
      !readSingleton(query, "multiplexing", false, parsed.multiplexing) ||
      !readSingleton(query, "handshake-mode", false,
                     parsed.handshake_mode) ||
      !readSingleton(query, "traffic-pattern", false,
                     parsed.traffic_pattern) ||
      !isValidMieruMultiplexing(parsed.multiplexing) ||
      !isValidMieruHandshakeMode(parsed.handshake_mode) ||
      !isValidMieruTrafficPattern(parsed.traffic_pattern))
    return false;

  std::string mtu;
  if (!readSingleton(query, "mtu", false, mtu))
    return false;
  if (!mtu.empty()) {
    unsigned parsed_mtu = 0;
    if (!parseUnsigned(mtu, 1280, 1400, parsed_mtu))
      return false;
    parsed.mtu = static_cast<uint16_t>(parsed_mtu);
  }

  const auto *ports = queryValues(query, "port");
  const auto *protocols = queryValues(query, "protocol");
  if (ports == nullptr || protocols == nullptr || ports->empty() ||
      ports->size() != protocols->size())
    return false;
  parsed.port_bindings.reserve(ports->size());
  for (size_t i = 0; i < ports->size(); ++i) {
    MieruPortBinding binding;
    if (!parseMieruPortBinding((*ports)[i], (*protocols)[i], binding))
      return false;
    parsed.port_bindings.emplace_back(std::move(binding));
  }

  config = std::move(parsed);
  return true;
}
