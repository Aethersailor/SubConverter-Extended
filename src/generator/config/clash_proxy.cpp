#include "clash_proxy.h"

#include <cstdint>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>
#include <yaml-cpp/emitter.h>
#include <yaml-cpp/eventhandler.h>
#include <yaml-cpp/parser.h>

#include "parser/param_compat.h"

namespace {

constexpr const char *kQuotedCanonicalStringTag =
    "tag:aethersailor.github.io,2026:canonical-string";

bool isDigit(char value) { return value >= '0' && value <= '9'; }

bool allDigitsInBase(const std::string &value, size_t start, int base) {
  if (start == value.size())
    return false;
  for (size_t i = start; i < value.size(); ++i) {
    const char c = value[i];
    if (isDigit(c)) {
      if (c - '0' >= base)
        return false;
      continue;
    }
    if (base == 16 && ((c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F')))
      continue;
    return false;
  }
  return true;
}

bool isYamlNumericScalar(const std::string &value) {
  if (value.empty())
    return false;
  const char first = value.front();
  if (!isDigit(first) && first != '+' && first != '-' && first != '.')
    return false;

  std::string plain;
  plain.reserve(value.size());
  for (char c : value) {
    if (c != '_')
      plain.push_back(c);
  }

  size_t pos = 0;
  if (plain[pos] == '+' || plain[pos] == '-') {
    if (++pos == plain.size())
      return false;
  }

  if (pos + 2 <= plain.size() && plain[pos] == '0') {
    const char prefix = plain[pos + 1];
    if (prefix == 'x' || prefix == 'X')
      return allDigitsInBase(plain, pos + 2, 16);
    if (prefix == 'o' || prefix == 'O')
      return allDigitsInBase(plain, pos + 2, 8);
    if (prefix == 'b' || prefix == 'B')
      return allDigitsInBase(plain, pos + 2, 2);
  }

  bool has_mantissa_digit = false;
  while (pos < plain.size() && isDigit(plain[pos])) {
    has_mantissa_digit = true;
    ++pos;
  }
  if (pos < plain.size() && plain[pos] == '.') {
    ++pos;
    while (pos < plain.size() && isDigit(plain[pos])) {
      has_mantissa_digit = true;
      ++pos;
    }
  }
  if (!has_mantissa_digit)
    return false;

  if (pos < plain.size() && (plain[pos] == 'e' || plain[pos] == 'E')) {
    ++pos;
    if (pos < plain.size() && (plain[pos] == '+' || plain[pos] == '-'))
      ++pos;
    const size_t exponent_start = pos;
    while (pos < plain.size() && isDigit(plain[pos]))
      ++pos;
    if (pos == exponent_start)
      return false;
  }
  return pos == plain.size();
}

bool isYamlTimestampScalar(const std::string &value) {
  if (value.size() < 8 || !isDigit(value[0]) || !isDigit(value[1]) ||
      !isDigit(value[2]) || !isDigit(value[3]) || value[4] != '-')
    return false;

  size_t pos = 5;
  size_t digits = 0;
  while (pos < value.size() && digits < 2 && isDigit(value[pos])) {
    ++pos;
    ++digits;
  }
  if (digits == 0 || pos == value.size() || value[pos++] != '-')
    return false;
  digits = 0;
  while (pos < value.size() && digits < 2 && isDigit(value[pos])) {
    ++pos;
    ++digits;
  }
  if (digits == 0)
    return false;
  return pos == value.size() || value[pos] == 'T' || value[pos] == 't' ||
         value[pos] == ' ';
}

bool requiresExplicitStringStyle(const std::string &value) {
  // Match the non-string scalar forms resolved by gopkg.in/yaml.v3, which is
  // used by Mihomo. yaml-cpp does not automatically quote every one of these
  // when the original value came from a JSON string (notably leading-zero
  // integers), so relying on its default emitter loses canonical JSON types.
  static const std::unordered_set<std::string> resolved_literals = {
      "",      "~",     "null",  "Null",  "NULL",  "true",
      "True",  "TRUE",  "false", "False", "FALSE", ".nan",
      ".NaN",  ".NAN",  ".inf",  ".Inf",  ".INF",  "+.inf",
      "+.Inf", "+.INF", "-.inf", "-.Inf", "-.INF", "<<",
  };
  if (resolved_literals.find(value) != resolved_literals.end())
    return true;

  if (isYamlNumericScalar(value))
    return true;

  // yaml.v3 recognizes dates and RFC3339-like timestamps. Quoting the same
  // syntactic family (including an invalid date) is conservative and keeps a
  // JSON string a string without changing its value.
  return isYamlTimestampScalar(value);
}

YAML::Node stringToYaml(const std::string &value, bool force_quoted = false) {
  YAML::Node result(value);
  if (force_quoted || requiresExplicitStringStyle(value))
    result.SetTag(kQuotedCanonicalStringTag);
  return result;
}

bool requiresCompatibilityQuote(const std::vector<std::string> &path) {
  // The former formatter always quoted Reality short IDs. Keep that stable
  // presentation while moving the behavior into the structured serializer.
  return path.size() == 2 && path[0] == "reality-opts" &&
         path[1] == "short-id";
}

YAML::Node jsonToYaml(const nlohmann::json &value,
                      std::vector<std::string> &path) {
  if (value.is_null())
    return YAML::Node(YAML::NodeType::Null);
  if (value.is_boolean())
    return YAML::Node(value.get<bool>());
  if (value.is_number_unsigned())
    return YAML::Node(value.get<std::uint64_t>());
  if (value.is_number_integer())
    return YAML::Node(value.get<std::int64_t>());
  if (value.is_number_float())
    return YAML::Node(value.get<double>());
  if (value.is_string())
    return stringToYaml(value.get<std::string>(),
                        requiresCompatibilityQuote(path));

  if (value.is_array()) {
    YAML::Node result(YAML::NodeType::Sequence);
    for (const auto &item : value) {
      path.push_back("[]");
      result.push_back(jsonToYaml(item, path));
      path.pop_back();
    }
    return result;
  }

  if (value.is_object()) {
    YAML::Node result(YAML::NodeType::Map);
    for (auto item = value.begin(); item != value.end(); ++item) {
      YAML::Node key = stringToYaml(item.key());
      path.push_back(item.key());
      result[key] = jsonToYaml(item.value(), path);
      path.pop_back();
    }
    return result;
  }

  throw std::runtime_error("unsupported canonical proxy JSON value");
}

void applyBooleanOverlay(YAML::Node &mapping, const std::string &protocol,
                         const std::string &parameter,
                         const tribool &requested) {
  if (requested.is_undef() ||
      !mihomo::isParamSupported(protocol, parameter) ||
      mihomo::isParamHardcoded(protocol, parameter))
    return;
  mapping[parameter] = requested.get();
}

class CanonicalStringEventHandler final : public YAML::EventHandler {
public:
  explicit CanonicalStringEventHandler(YAML::Emitter &emitter)
      : emitter_(emitter) {}

  void OnDocumentStart(const YAML::Mark &) override {}

  void OnDocumentEnd() override {}

  void OnNull(const YAML::Mark &, YAML::anchor_t anchor) override {
    beginNode();
    emitProperties("", anchor);
    emitter_ << YAML::Null;
  }

  void OnAlias(const YAML::Mark &, YAML::anchor_t anchor) override {
    beginNode();
    emitter_ << YAML::Alias(anchorToString(anchor));
  }

  void OnScalar(const YAML::Mark &, const std::string &tag,
                YAML::anchor_t anchor, const std::string &value) override {
    beginNode();
    if (tag == kQuotedCanonicalStringTag) {
      ++converted_strings_;
      emitProperties("", anchor);
      emitter_ << YAML::DoubleQuoted << value;
      return;
    }
    emitProperties(tag, anchor);
    emitter_ << value;
  }

  void OnSequenceStart(const YAML::Mark &, const std::string &tag,
                       YAML::anchor_t anchor,
                       YAML::EmitterStyle::value style) override {
    beginNode();
    emitProperties(tag, anchor);
    applyCollectionStyle(style);
    emitter_.RestoreGlobalModifiedSettings();
    emitter_ << YAML::BeginSeq;
    states_.push(State::SequenceEntry);
  }

  void OnSequenceEnd() override {
    emitter_ << YAML::EndSeq;
    if (states_.empty() || states_.top() != State::SequenceEntry)
      throw std::runtime_error(
          "canonical Clash YAML sequence event state is invalid");
    states_.pop();
  }

  void OnMapStart(const YAML::Mark &, const std::string &tag,
                  YAML::anchor_t anchor,
                  YAML::EmitterStyle::value style) override {
    beginNode();
    emitProperties(tag, anchor);
    applyCollectionStyle(style);
    emitter_.RestoreGlobalModifiedSettings();
    emitter_ << YAML::BeginMap;
    states_.push(State::MapKey);
  }

  void OnMapEnd() override {
    emitter_ << YAML::EndMap;
    if (states_.empty() || states_.top() != State::MapKey)
      throw std::runtime_error(
          "canonical Clash YAML map event state is invalid");
    states_.pop();
  }

  size_t convertedStrings() const { return converted_strings_; }

private:
  enum class State { SequenceEntry, MapKey, MapValue };

  static std::string anchorToString(YAML::anchor_t anchor) {
    return std::to_string(anchor);
  }

  void beginNode() {
    if (states_.empty())
      return;
    if (states_.top() == State::MapKey) {
      emitter_ << YAML::Key;
      states_.top() = State::MapValue;
    } else if (states_.top() == State::MapValue) {
      emitter_ << YAML::Value;
      states_.top() = State::MapKey;
    }
  }

  void emitProperties(const std::string &tag, YAML::anchor_t anchor) {
    if (!tag.empty() && tag != "?" && tag != "!") {
      if (tag.front() == '!')
        emitter_ << YAML::LocalTag(tag.substr(1));
      else
        emitter_ << YAML::VerbatimTag(tag);
    }
    if (anchor)
      emitter_ << YAML::Anchor(anchorToString(anchor));
  }

  void applyCollectionStyle(YAML::EmitterStyle::value style) {
    if (style == YAML::EmitterStyle::Block)
      emitter_ << YAML::Block;
    else if (style == YAML::EmitterStyle::Flow)
      emitter_ << YAML::Flow;
  }

  YAML::Emitter &emitter_;
  std::stack<State> states_;
  size_t converted_strings_ = 0;
};

} // namespace

YAML::Node buildCanonicalClashProxy(const Proxy &proxy,
                                    const ClashProxyOverlay &overlay) {
  const nlohmann::json canonical =
      nlohmann::json::parse(proxy.CanonicalProxyJson);
  if (!canonical.is_object())
    throw std::runtime_error("canonical proxy must be a JSON object");

  YAML::Node result(YAML::NodeType::Map);
  result["name"] = stringToYaml(proxy.Remark);
  result["server"] = stringToYaml(proxy.Hostname);
  result["port"] = proxy.Port;

  for (auto item = canonical.begin(); item != canonical.end(); ++item) {
    const std::string &key = item.key();
    if (key == "name" || key == "server" || key == "port")
      continue;
    std::vector<std::string> path{key};
    result[stringToYaml(key)] = jsonToYaml(item.value(), path);
  }

  const std::string protocol = canonical.value("type", std::string());
  applyBooleanOverlay(result, protocol, "udp", overlay.udp);
  applyBooleanOverlay(result, protocol, "skip-cert-verify",
                      overlay.skip_cert_verify);
  applyBooleanOverlay(result, protocol, "tfo", overlay.tfo);
  applyBooleanOverlay(result, protocol, "xudp", overlay.xudp);
  return result;
}

std::string finalizeCanonicalClashYaml(const std::string &yaml) {
  const std::string marker =
      std::string("!<") + kQuotedCanonicalStringTag + ">";
  if (yaml.find(marker) == std::string::npos)
    return yaml;

  std::istringstream input(yaml);
  YAML::Parser parser(input);
  YAML::Emitter emitter;
  CanonicalStringEventHandler handler(emitter);
  if (!parser.HandleNextDocument(handler))
    throw std::runtime_error("canonical Clash YAML document is empty");
  if (parser)
    throw std::runtime_error(
        "canonical Clash YAML unexpectedly contains multiple documents");
  if (!emitter.good())
    throw std::runtime_error("canonical Clash YAML emission failed: " +
                             emitter.GetLastError());

  if (handler.convertedStrings() == 0)
    return yaml;
  return std::string(emitter.c_str(), emitter.size());
}

std::string dumpCanonicalClashYaml(const YAML::Node &node) {
  return finalizeCanonicalClashYaml(YAML::Dump(node));
}
