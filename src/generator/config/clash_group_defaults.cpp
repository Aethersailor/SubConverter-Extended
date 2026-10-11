#include "generator/config/clash_group_defaults.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

#include <rapidjson/encodedstream.h>
#include <rapidjson/memorystream.h>

#include "utils/bounded_output.h"
#include "utils/logger.h"

namespace {

constexpr std::array<const char *, 5> clashHealthKeys = {
    "name", "type", "expected-status", "timeout", "lazy"};

struct ClashHealthFields {
  std::array<YAML::Node, 5> values;
  std::array<bool, 5> present{};
};

struct ClashHealthTraversal {
  std::array<YAML::Node, 32> active;
  size_t visits = 0;
};

// Resolve only the identity and health fields. A local null deliberately
// blocks a merge default; the first mapping in a merge sequence has priority.
bool resolveClashHealthFields(const YAML::Node &mapping,
                             ClashHealthFields &fields,
                             ClashHealthTraversal &traversal,
                             size_t depth = 0) {
  if (!mapping.IsMap() || depth >= traversal.active.size() ||
      ++traversal.visits > 256)
    return false;
  for (size_t index = 0; index < depth; ++index) {
    if (traversal.active[index].is(mapping))
      return false;
  }
  traversal.active[depth].reset(mapping);
  YAML::Node merge;
  bool has_merge = false;
  bool valid = true;
  for (const auto &entry : mapping) {
    if (!entry.first.IsScalar())
      continue;
    const std::string &key = entry.first.Scalar();
    if (key == "<<" &&
        (entry.first.Tag() == "?" ||
         entry.first.Tag() == "tag:yaml.org,2002:merge")) {
      if (has_merge)
        valid = false;
      else {
        merge.reset(entry.second);
        has_merge = true;
      }
      continue;
    }
    for (size_t index = 0; index < clashHealthKeys.size(); ++index) {
      if (key != clashHealthKeys[index])
        continue;
      if (fields.present[index])
        valid = false;
      else {
        fields.values[index].reset(entry.second);
        fields.present[index] = true;
      }
      break;
    }
  }
  if (!valid || !has_merge)
    return valid;
  auto inherit = [&](const YAML::Node &source) {
    ClashHealthFields inherited;
    if (!resolveClashHealthFields(source, inherited, traversal, depth + 1))
      return false;
    for (size_t index = 0; index < clashHealthKeys.size(); ++index) {
      if (!fields.present[index] && inherited.present[index]) {
        fields.values[index].reset(inherited.values[index]);
        fields.present[index] = true;
      }
    }
    return true;
  };
  if (merge.IsMap())
    return inherit(merge);
  if (!merge.IsSequence())
    return false;
  for (const auto &source : merge) {
    if (!inherit(source))
      return false;
  }
  return true;
}

class ClashUtf8SourceCursor {
public:
  explicit ClashUtf8SourceCursor(std::string_view text) : text_(text) {}
  unsigned peek() {
    if (text_.empty())
      return 0;
    const unsigned first = static_cast<unsigned char>(text_.front());
    step_ = 1;
    if (first < 0x80)
      return first;
    rapidjson::MemoryStream bytes(text_.data(), text_.size());
    unsigned point = 0;
    if (!rapidjson::UTF8<unsigned>::Decode(bytes, &point))
      return 0;
    step_ = bytes.Tell();
    return point;
  }
  void take() { if (peek()) text_.remove_prefix(step_); }
private:
  std::string_view text_;
  size_t step_ = 1;
};

class ClashEncodedSourceCursor {
public:
  ClashEncodedSourceCursor(std::string_view source, size_t &remaining)
      : bytes_(source.data(), source.size()), input_(bytes_), remaining_(remaining) { next(); }
  unsigned peek() const { return point_; }
  void take() {
    position_ += point_ <= 0x7f ? 1 : point_ <= 0x7ff ? 2 : point_ <= 0xffff ? 3 : 4;
    next();
  }
  size_t position() const { return position_; }
  bool seek(size_t position) {
    while (point_ && position_ < position)
      take();
    return point_ && position_ == position;
  }
private:
  void next() {
    if (!remaining_ || !input_.Peek()) {
      point_ = 0;
      return;
    }
    --remaining_;
    if (!rapidjson::AutoUTF<unsigned>::Decode(input_, &point_))
      point_ = 0;
  }
  rapidjson::MemoryStream bytes_;
  rapidjson::AutoUTFInputStream<unsigned, rapidjson::MemoryStream> input_;
  size_t &remaining_;
  size_t position_ = 0;
  unsigned point_ = 0;
};

template <class Cursor> bool clashSourceIsString(Cursor &cursor) {
  auto space = [](unsigned c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == 0x85 || c == 0x2028 || c == 0x2029;
  };
  auto delimiter = [&](unsigned c) {
    return !c || space(c) || c == ',' || c == '[' || c == ']' || c == '{' || c == '}';
  };
  for (unsigned properties = 0; properties <= 2;) {
    while (space(cursor.peek()) || cursor.peek() == '#') {
      if (cursor.peek() == '#') {
        while (cursor.peek() && cursor.peek() != '\n' && cursor.peek() != '\r' &&
               cursor.peek() != 0x85 && cursor.peek() != 0x2028 && cursor.peek() != 0x2029)
          cursor.take();
      } else {
        cursor.take();
      }
    }
    const unsigned c = cursor.peek();
    if (!c)
      return true;
    if (c != '&' && c != '!')
      return c == '\'' || c == '"' || c == '|' || c == '>';
    if (++properties > 2)
      return true;
    cursor.take();
    if (c == '!' && cursor.peek() == '<') {
      while (cursor.peek() && cursor.peek() != '>')
        cursor.take();
      if (cursor.peek())
        cursor.take();
    } else {
      while (!delimiter(cursor.peek()))
        cursor.take();
    }
  }
  return true;
}

// Node.Mark refers to the original anchor definition and counts decoded UTF-8
// bytes after the BOM. Only non-specific tags need the source presentation.
class ClashBaseSource {
public:
  explicit ClashBaseSource(std::string_view source) : source_(source) {
    if (source_.size() >= 3 && source_.substr(0, 3) == "\xef\xbb\xbf")
      source_.remove_prefix(3);
    const size_t prefix = std::min(source_.size(), size_t{4});
    encoded_ = source_.substr(0, prefix).find('\0') != std::string_view::npos ||
        (!source_.empty() && (static_cast<unsigned char>(source_.front()) == 0xff ||
                             static_cast<unsigned char>(source_.front()) == 0xfe));
    // Reuse the encoded cursor; bounded restarts cover out-of-order aliases.
    remaining_ = source_.size() > (std::numeric_limits<size_t>::max() - 65536) / 8
        ? std::numeric_limits<size_t>::max() : source_.size() * 8 + 65536;
  }
  bool encoded() const { return encoded_; }
  std::optional<bool> isString(const YAML::Node &value) {
    const int mark = value.Mark().pos;
    if (source_.empty() || mark < 0)
      return true; // Programmatic Tag('!') nodes have no lexical context.
    const size_t position = static_cast<size_t>(mark);
    if (!encoded_) {
      if (position >= source_.size())
        return true;
      const char first = source_[position];
      if (first == '\'' || first == '"' || first == '|' || first == '>')
        return true;
      if (first != '&' && first != '!')
        return false;
    }
    const auto cached = cache_.find(position);
    if (cached != cache_.end())
      return cached->second;
    bool result = true;
    if (!encoded_) {
      ClashUtf8SourceCursor cursor(source_.substr(position));
      result = clashSourceIsString(cursor);
    } else {
      if (!remaining_)
        return std::nullopt;
      if (!cursor_ || position < cursor_->position())
        cursor_.emplace(source_, remaining_);
      if (!cursor_->seek(position))
        return remaining_ ? std::optional<bool>(true) : std::nullopt;
      result = clashSourceIsString(*cursor_);
      if (!remaining_)
        return std::nullopt;
    }
    // Cache every property prefix/encoded Mark so shared anchors and long
    // comments are inspected once. Only up to three fields per requested group
    // can enter here; admission precedes every cache node allocation.
    reserveBoundedOutputBytes(sizeof(std::pair<const size_t, bool>) + 128);
    cache_.emplace(position, result);
    return result;
  }
private:
  std::string_view source_;
  bool encoded_ = false;
  size_t remaining_ = 0;
  std::optional<ClashEncodedSourceCursor> cursor_;
  std::map<size_t, bool> cache_;
};

// Go's implicit YAML numeric resolver removes all underscores for digit/sign
// prefixes. Quoted integers instead enforce strconv's separator placement.
class ClashNumericText {
public:
  explicit ClashNumericText(std::string_view source) {
    const size_t size = source.size() - static_cast<size_t>(std::count(source.begin(), source.end(), '_'));
    char *data = inline_.data();
    if (size > inline_.size()) {
      reserveBoundedOutputBytes(checkedBoundedOutputSize(size, 1, std::numeric_limits<size_t>::max()));
      overflow_.resize(size);
      data = overflow_.data();
    }
    size_t index = 0;
    for (char c : source) if (c != '_') data[index++] = c;
    text_ = std::string_view(data, size);
  }
  std::string_view view() const { return text_; }
private:
  std::array<char, 64> inline_;
  std::string overflow_;
  std::string_view text_;
};

enum class ClashNativeScalar { String, Integer, Float, Boolean, Invalid };

// Common decimal input requires no temporary allocation. Native integer
// separators are accepted; the binary-tag extension remains unsupported.
bool parseClashNativeInteger(std::string_view text, uint64_t &number,
                             bool &negative) {
  negative = !text.empty() && text.front() == '-';
  // Go's unsigned fallback rejects '+' after signed ParseInt overflows.
  const bool positive_sign = !text.empty() && text.front() == '+';
  if (!text.empty() && (text.front() == '-' || text.front() == '+'))
    text.remove_prefix(1);
  if (text.empty())
    return false;
  int base = 10;
  bool explicit_base = false;
  if (text.size() > 1 && text.front() == '0') {
    base = 8;
    const char prefix = text[1];
    if (prefix == 'x' || prefix == 'X' || prefix == 'o' || prefix == 'O' ||
        prefix == 'b' || prefix == 'B') {
      base = prefix == 'x' || prefix == 'X' ? 16 :
             prefix == 'b' || prefix == 'B' ? 2 : 8;
      text.remove_prefix(2);
      explicit_base = true;
    }
  }
  if (text.find('_') != text.npos) {
    number = 0;
    bool digit_before = false;
    for (size_t index = 0; index < text.size(); ++index) {
      const char c = text[index];
      if (c == '_') {
        if (!digit_before && !(index == 0 && explicit_base))
          return false;
        digit_before = false;
        continue;
      }
      const unsigned digit = c >= '0' && c <= '9' ? unsigned(c - '0') :
          c >= 'a' && c <= 'f' ? unsigned(c - 'a' + 10) :
          c >= 'A' && c <= 'F' ? unsigned(c - 'A' + 10) : 16;
      if (digit >= unsigned(base) || number > (UINT64_MAX - digit) / unsigned(base))
        return false;
      number = number * unsigned(base) + digit;
      digit_before = true;
    }
    return digit_before && (!negative || number <= (uint64_t{1} << 63)) &&
           (!positive_sign || number <= static_cast<uint64_t>(INT64_MAX));
  }
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                      number, base);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
         (!negative || number <= (uint64_t{1} << 63)) &&
         (!positive_sign || number <= static_cast<uint64_t>(INT64_MAX));
}

bool parseClashNativeFloat(std::string_view text, double &number) {
  if (!text.empty() && text.front() == '+')
    text.remove_prefix(1);
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                      number, std::chars_format::general);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
         std::isfinite(number);
}

ClashNativeScalar classifyClashNativeText(std::string_view tag, std::string_view text,
    uint64_t &integer, bool &negative, double &floating) {
  if (tag == "tag:yaml.org,2002:str")
    return ClashNativeScalar::String;
  const bool boolean = text == "true" || text == "True" || text == "TRUE" ||
      text == "false" || text == "False" || text == "FALSE";
  if (tag == "tag:yaml.org,2002:bool")
    return boolean ? ClashNativeScalar::Boolean : ClashNativeScalar::Invalid;
  if (tag != "?" && !tag.empty() && tag != "tag:yaml.org,2002:int" &&
      tag != "tag:yaml.org,2002:float") {
    return tag == "tag:yaml.org,2002:binary" || tag == "tag:yaml.org,2002:timestamp" ||
           tag == "tag:yaml.org,2002:null" || tag == "tag:yaml.org,2002:merge" ||
           tag == "tag:yaml.org,2002:map" || tag == "tag:yaml.org,2002:seq"
        ? ClashNativeScalar::Invalid : ClashNativeScalar::String;
  }
  if (!text.empty() && text.find('_') != text.npos &&
      ((text.front() >= '0' && text.front() <= '9') ||
       text.front() == '+' || text.front() == '-')) {
    ClashNumericText normalized(text);
    return classifyClashNativeText(tag, normalized.view(), integer, negative, floating);
  }
  if (boolean)
    return tag == "?" || tag.empty() ? ClashNativeScalar::Boolean :
        ClashNativeScalar::Invalid;
  if (parseClashNativeInteger(text, integer, negative)) {
    if (tag != "tag:yaml.org,2002:float")
      return ClashNativeScalar::Integer;
    // go-yaml's explicit !!float coercion accepts signed int64, not uint64.
    if (!negative && integer > INT64_MAX)
      return ClashNativeScalar::Invalid;
    floating = static_cast<double>(integer) * (negative ? -1.0 : 1.0);
    return ClashNativeScalar::Float;
  }
  if (tag == "tag:yaml.org,2002:int")
    return ClashNativeScalar::Invalid;
  if (!text.empty() && text.front() == '.' && text.find('_') != text.npos) {
    bool valid = true;
    for (size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '_' && (i == 0 || i + 1 == text.size() ||
          text[i - 1] < '0' || text[i - 1] > '9' || text[i + 1] < '0' || text[i + 1] > '9'))
        valid = false;
    }
    if (valid) {
      ClashNumericText normalized(text);
      if (parseClashNativeFloat(normalized.view(), floating))
        return ClashNativeScalar::Float;
    }
  } else if (parseClashNativeFloat(text, floating)) {
    return ClashNativeScalar::Float;
  }
  return tag == "tag:yaml.org,2002:float" ? ClashNativeScalar::Invalid :
      ClashNativeScalar::String;
}


ClashNativeScalar classifyClashNativeScalar(const YAML::Node &value,
    uint64_t &integer, bool &negative, double &floating, ClashBaseSource &source) {
  std::string_view tag = value.Tag();
  if (tag == "!") {
    const std::optional<bool> string = source.isString(value);
    if (!string)
      return ClashNativeScalar::Invalid;
    if (*string)
      return ClashNativeScalar::String;
    tag = "?";
  }
  return classifyClashNativeText(tag, value.Scalar(), integer, negative, floating);
}

// Match Go unicode.IsSpace, used by strings.TrimSpace. The range endpoints
// intentionally continue to use the separate ASCII-only "[ ]" cutset.
bool clashNativeSpace(unsigned point) {
  return point == 0x20 || (point >= 0x09 && point <= 0x0d) ||
      point == 0x85 || point == 0xa0 || point == 0x1680 ||
      (point >= 0x2000 && point <= 0x200a) || point == 0x2028 ||
      point == 0x2029 || point == 0x202f || point == 0x205f || point == 0x3000;
}

std::string_view trimClashNativeSpace(std::string_view text) {
  while (!text.empty()) {
    const unsigned first = static_cast<unsigned char>(text.front());
    if (first < 0x80) {
      if (!clashNativeSpace(first))
        break;
      text.remove_prefix(1);
      continue;
    }
    rapidjson::MemoryStream bytes(text.data(), text.size());
    unsigned point = 0;
    if (!rapidjson::UTF8<unsigned>::Decode(bytes, &point) || !clashNativeSpace(point))
      break;
    text.remove_prefix(bytes.Tell());
  }
  while (!text.empty()) {
    const unsigned last = static_cast<unsigned char>(text.back());
    if (last < 0x80) {
      if (!clashNativeSpace(last))
        break;
      text.remove_suffix(1);
      continue;
    }
    size_t begin = text.size() - 1;
    while (begin != 0 && (static_cast<unsigned char>(text[begin]) & 0xc0) == 0x80)
      --begin;
    rapidjson::MemoryStream bytes(text.data() + begin, text.size() - begin);
    unsigned point = 0;
    if (!rapidjson::UTF8<unsigned>::Decode(bytes, &point) ||
        bytes.Tell() != text.size() - begin || !clashNativeSpace(point))
      break;
    text.remove_suffix(text.size() - begin);
  }
  return text;
}

std::string_view trimClashRange(std::string_view text, std::string_view chars) {
  const size_t first = text.find_first_not_of(chars);
  if (first == text.npos)
    return {};
  const size_t last = text.find_last_not_of(chars);
  return text.substr(first, last - first + 1);
}

bool validClashExpectedStatus(std::string_view text) {
  text = trimClashNativeSpace(text);
  if (text.empty() || text == "*")
    return true;
  size_t terms = 0;
  do {
    if (++terms > 28)
      return false;
    const size_t split = text.find_first_of("/,");
    std::string_view term = trimClashNativeSpace(text.substr(0, split));
    if (!term.empty()) {
      const size_t dash = term.find('-');
      auto endpoint = [](std::string_view digits) {
        digits = trimClashRange(digits, "[ ]");
        if (digits.empty())
          return false;
        uint64_t number = 0;
        const auto parsed = std::from_chars(digits.data(),
            digits.data() + digits.size(), number, 10);
        return parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size();
      };
      if (!endpoint(term.substr(0, dash)) ||
          (dash != term.npos && !endpoint(term.substr(dash + 1))))
        return false;
    }
    if (split == text.npos)
      return true;
    text.remove_prefix(split + 1);
  } while (true);
}

struct PreparedClashHealthScalar {
  std::array<char, 32> digits;
  std::string normalized;
  std::string_view scalar;
  bool present = false;

  void decimal(uint64_t number) {
    const auto encoded = std::to_chars(digits.data(), digits.data() + digits.size(), number);
    scalar = std::string_view(digits.data(), encoded.ptr - digits.data());
  }
};

// Canonicalize decoded values before taking the immutable snapshot. YAML tags
// do not preserve quoting through yaml-cpp emission ("0204" would become octal).
bool prepareClashHealthScalar(size_t index, const YAML::Node &value,
                             PreparedClashHealthScalar &prepared,
                             ClashBaseSource &source) {
  if (!value.IsScalar())
    return false;
  uint64_t integer = 0;
  bool negative = false;
  double floating = 0;
  const ClashNativeScalar kind =
      classifyClashNativeScalar(value, integer, negative, floating, source);
  if (index == 4) {
    if (kind == ClashNativeScalar::Integer)
      prepared.scalar = integer == 0 ? "false" : "true";
    else if (kind == ClashNativeScalar::Boolean)
      prepared.scalar = value.Scalar().front() == 't' || value.Scalar().front() == 'T'
          ? "true" : "false";
    else
      return false;
    return true;
  }
  if (index == 2) {
    if (kind == ClashNativeScalar::Integer) {
      if (negative && integer != 0)
        return false;
      prepared.decimal(integer);
      return true;
    }
    if (kind != ClashNativeScalar::String || !validClashExpectedStatus(value.Scalar()))
      return false;
    const std::string_view text = trimClashNativeSpace(value.Scalar());
    if (!text.empty()) {
      const auto decoded = std::from_chars(text.data(), text.data() + text.size(), integer, 10);
      if (decoded.ec == std::errc{} && decoded.ptr == text.data() + text.size()) {
        prepared.decimal(integer);
        return true;
      }
    }
    // yaml-cpp may emit Unicode line separators as plain scalar bytes. Strip
    // only the whitespace already ignored by the native range parser, keeping
    // every separator and endpoint intact. Ordinary ASCII needs no allocation.
    const std::string &original = value.Scalar();
    if (std::any_of(original.begin(), original.end(), [](unsigned char c) {
          return c < 0x20 || c >= 0x7f;
        })) {
      reserveBoundedOutputBytes(text.size());
      prepared.normalized.reserve(text.size());
      std::string_view remaining = text;
      for (;;) {
        const size_t split = remaining.find_first_of("/,");
        const std::string_view original_term = remaining.substr(0, split);
        const std::string_view term = trimClashNativeSpace(original_term);
        // Native ranges skip a truly empty term but treat a whitespace-only
        // term as zero. Keep that distinction after removing Unicode space.
        if (term.empty() && !original_term.empty())
          prepared.normalized.push_back(' ');
        else
          prepared.normalized.append(term.data(), term.size());
        if (split == remaining.npos)
          break;
        prepared.normalized.push_back(remaining[split]);
        remaining.remove_prefix(split + 1);
      }
      prepared.scalar = prepared.normalized;
    } else {
      prepared.scalar = original;
    }
    return true;
  }
  if (kind == ClashNativeScalar::String &&
      !parseClashNativeInteger(value.Scalar(), integer, negative))
    return false;
  if (kind == ClashNativeScalar::Integer || kind == ClashNativeScalar::String) {
    if ((negative && integer != 0) || integer > INT_MAX)
      return false;
  } else if (kind == ClashNativeScalar::Float) {
    const double truncated = std::trunc(floating);
    if (truncated < 0 || truncated > INT_MAX)
      return false;
    integer = static_cast<uint64_t>(truncated);
  } else {
    return false;
  }
  prepared.decimal(integer);
  return true;
}

} // namespace

ClashHealthDefaultsByName collectClashHealthDefaults(
    const YAML::Node &root, const ProxyGroupConfigs &groups,
    const char *groups_field, std::string_view base_source) {
  ClashHealthDefaultsByName result;
  if (!root.IsMap() || groups.empty())
    return result;
  const YAML::Node base_groups = root[groups_field];
  if (!base_groups.IsDefined() || base_groups.IsNull())
    return result;
  bool ignored = false;
  auto warn = [&]() {
    if (ignored)
      writeLog(LOG_LEVEL_WARNING,
               "CLASH_GROUP_NATIVE_HEALTH_DEFAULT_IGNORED");
  };
  if (!base_groups.IsSequence()) {
    ignored = true;
    warn();
    return result;
  }
  if (base_groups.size() == 0)
    return result;
  ClashBaseSource source(base_source);
  constexpr size_t record_bytes = sizeof(ClashHealthDefaults) +
      2 * sizeof(std::string_view) + 512;
  if (groups.size() > std::numeric_limits<size_t>::max() / record_bytes)
    throw BoundedOutputExceeded();
  reserveBoundedOutputBytes(groups.size() * record_bytes);
  std::unordered_set<std::string_view> requested;
  requested.reserve(groups.size());
  for (const ProxyGroupConfig &group : groups)
    requested.emplace(group.Name);
  result.reserve(requested.size());

  for (const auto &base_group : base_groups) {
    ClashHealthFields fields;
    ClashHealthTraversal traversal;
    const bool valid =
        resolveClashHealthFields(base_group, fields, traversal);
    if (!valid)
      ignored = true;
    if (!fields.present[0] || !fields.values[0].IsScalar())
      continue;
    const std::string &name = fields.values[0].Scalar();
    const auto requested_name = requested.find(name);
    if (requested_name == requested.end())
      continue;
    auto found = result.find(*requested_name);
    if (found != result.end()) {
      found->second.ambiguous = true;
      ignored = true;
      continue;
    }
    const bool valid_identity = valid && fields.present[1] &&
        fields.values[1].IsScalar();
    std::array<PreparedClashHealthScalar, 3> prepared;
    size_t copied_bytes = 0;
    if (valid_identity) {
      copied_bytes = checkedBoundedOutputSize(
          copied_bytes, fields.values[1].Scalar().size(),
          std::numeric_limits<size_t>::max());
      std::array<size_t, 3> order{0, 1, 2};
      if (source.encoded()) {
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
          return fields.values[a + 2].Mark().pos < fields.values[b + 2].Mark().pos;
        });
      }
      for (const size_t index : order) {
        const size_t field = index + 2;
        if (!fields.present[field] || fields.values[field].IsNull())
          continue;
        prepared[index].present =
            prepareClashHealthScalar(field, fields.values[field], prepared[index], source);
        if (!prepared[index].present) {
          ignored = true;
          continue;
        }
        const size_t bytes = prepared[index].scalar.size();
        // Prepay both the immutable snapshot and its generated scalar slot,
        // including the new YAML key/value nodes and their bookkeeping.
        if (bytes > (std::numeric_limits<size_t>::max() - 2048) / 2)
          throw BoundedOutputExceeded();
        copied_bytes = checkedBoundedOutputSize(
            copied_bytes, bytes * 2 + 2048,
            std::numeric_limits<size_t>::max());
      }
    } else {
      ignored = true;
    }
    reserveBoundedOutputBytes(copied_bytes);
    auto inserted = result.emplace(*requested_name, ClashHealthDefaults{}).first;
    ClashHealthDefaults &defaults = inserted->second;
    defaults.ambiguous = !valid_identity;
    if (!valid_identity)
      continue;
    defaults.type = fields.values[1].Scalar();
    for (size_t index = 0; index < prepared.size(); ++index) {
      if (!prepared[index].present)
        continue;
      ClashHealthScalar &snapshot = defaults.values[index];
      snapshot.scalar = prepared[index].scalar;
      snapshot.present = true;
    }
  }
  warn();
  return result;
}
