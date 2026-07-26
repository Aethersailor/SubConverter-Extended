#include "external_rules.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

#include <yaml-cpp/yaml.h>

namespace {

std::string trimAscii(const std::string &value) {
  size_t begin = 0;
  while (begin < value.size() &&
         std::isspace(static_cast<unsigned char>(value[begin])))
    ++begin;
  size_t end = value.size();
  while (end > begin &&
         std::isspace(static_cast<unsigned char>(value[end - 1])))
    --end;
  return value.substr(begin, end - begin);
}

bool isComment(const std::string &line) {
  return startsWith(line, "#") || startsWith(line, ";") ||
         startsWith(line, "//");
}

std::string lowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(ch)));
  });
  return value;
}

struct SplitResult {
  bool ok = true;
  string_array fields;
};

SplitResult splitTopLevelCommas(const std::string &rule) {
  SplitResult result;
  std::string field;
  int round_depth = 0;
  int square_depth = 0;
  int brace_depth = 0;
  char quote = 0;
  bool escaped = false;

  for (char ch : rule) {
    if (quote) {
      field.push_back(ch);
      if (escaped)
        escaped = false;
      else if (ch == '\\')
        escaped = true;
      else if (ch == quote)
        quote = 0;
      continue;
    }

    if (ch == '\'' || ch == '"') {
      quote = ch;
      field.push_back(ch);
      continue;
    }
    if (ch == '(')
      ++round_depth;
    else if (ch == ')')
      --round_depth;
    else if (ch == '[')
      ++square_depth;
    else if (ch == ']')
      --square_depth;
    else if (ch == '{')
      ++brace_depth;
    else if (ch == '}')
      --brace_depth;

    if (round_depth < 0 || square_depth < 0 || brace_depth < 0) {
      result.ok = false;
      return result;
    }

    if (ch == ',' && round_depth == 0 && square_depth == 0 &&
        brace_depth == 0) {
      result.fields.emplace_back(trimAscii(field));
      field.clear();
    } else {
      field.push_back(ch);
    }
  }

  if (quote || round_depth != 0 || square_depth != 0 || brace_depth != 0) {
    result.ok = false;
    return result;
  }
  result.fields.emplace_back(trimAscii(field));
  return result;
}

std::string locationError(const std::string &source_identifier,
                          const std::string &location,
                          const std::string &english,
                          const std::string &chinese) {
  return "Invalid external Clash rule from " + source_identifier + " (" +
         location + "): " + english + ".\n"
         "来自 " +
         source_identifier + "（" + location + "）的外部 Clash 规则无效：" +
         chinese + "。";
}

std::string validateRule(const std::string &rule,
                         const std::string &source_identifier,
                         const std::string &location,
                         const string_array &allowed_rule_types) {
  SplitResult split = splitTopLevelCommas(rule);
  if (!split.ok)
    return locationError(source_identifier, location,
                         "unbalanced brackets or quotes",
                         "括号或引号不匹配");

  const string_array &fields = split.fields;
  const std::string type = fields.empty() ? "" : fields.front();
  if (std::find(allowed_rule_types.begin(), allowed_rule_types.end(), type) ==
      allowed_rule_types.end())
    return locationError(source_identifier, location,
                         "unknown rule type '" + type + "'",
                         "未知规则类型 '" + type + "'");

  if (type == "MATCH" || type == "FINAL")
    return locationError(source_identifier, location,
                         type + " rules are not allowed",
                         "不允许导入 " + type + " 规则");

  if (fields.size() < 2 || fields[1].empty())
    return locationError(source_identifier, location,
                         "matching content is missing", "缺少匹配内容");
  if (fields.size() < 3)
    return locationError(source_identifier, location,
                         "target policy is missing", "缺少目标策略");

  size_t target_index = fields.size() - 1;
  if (fields.size() >= 4 &&
      lowerAscii(fields.back()) == "no-resolve")
    --target_index;
  if (fields[target_index].empty())
    return locationError(source_identifier, location,
                         "target policy is empty", "目标策略为空");
  return "";
}

ExternalRuleParseResult parseRuleList(const string_array &candidates,
                                      const string_array &locations,
                                      const std::string &source_identifier,
                                      const string_array &allowed_rule_types) {
  ExternalRuleParseResult result;
  for (size_t i = 0; i < candidates.size(); ++i) {
    std::string rule = trimAscii(candidates[i]);
    if (rule.empty() || isComment(rule))
      continue;
    std::string error = validateRule(rule, source_identifier, locations[i],
                                     allowed_rule_types);
    if (!error.empty()) {
      result.error = std::move(error);
      return result;
    }
    result.rules.emplace_back(std::move(rule));
  }
  result.ok = true;
  return result;
}

bool isTerminalRule(const std::string &rule) {
  size_t comma = rule.find(',');
  std::string type = trimAscii(rule.substr(0, comma));
  return type == "MATCH" || type == "FINAL";
}

std::pair<string_array, string_array>
splitAtFirstTerminal(const string_array &rules) {
  auto terminal = std::find_if(rules.begin(), rules.end(), isTerminalRule);
  return {string_array(rules.begin(), terminal),
          string_array(terminal, rules.end())};
}

} // namespace

ExternalRuleParseResult
parseExternalClashRules(const std::string &content,
                        const std::string &source_identifier,
                        const string_array &allowed_rule_types) {
  if (trimAscii(content).empty()) {
    ExternalRuleParseResult result;
    result.error = "External rule source " + source_identifier +
                   " returned empty content.\n"
                   "外部规则来源 " +
                   source_identifier + " 返回了空内容。";
    return result;
  }

  try {
    YAML::Node root = YAML::Load(content);
    if (root.IsMap()) {
      if (root["payload"].IsDefined()) {
        ExternalRuleParseResult result;
        result.error =
            "Invalid external rule source " + source_identifier +
            ": YAML payload: format is not supported; use a root rules: "
            "sequence.\n"
            "外部规则来源 " +
            source_identifier +
            " 无效：不支持 YAML payload: 格式，请使用根节点 rules: 数组。";
        return result;
      }
      if (!root["rules"].IsDefined() || !root["rules"].IsSequence()) {
        ExternalRuleParseResult result;
        result.error =
            "Invalid external rule source " + source_identifier +
            ": YAML root must contain a rules: sequence.\n"
            "外部规则来源 " +
            source_identifier + " 无效：YAML 根节点必须包含 rules: 数组。";
        return result;
      }

      string_array rules;
      string_array locations;
      const YAML::Node yaml_rules = root["rules"];
      for (size_t i = 0; i < yaml_rules.size(); ++i) {
        if (!yaml_rules[i].IsScalar()) {
          ExternalRuleParseResult result;
          result.error =
              "Invalid external rule source " + source_identifier +
              ": rules[" + std::to_string(i) + "] must be a string.\n"
              "外部规则来源 " +
              source_identifier + " 无效：rules[" + std::to_string(i) +
              "] 必须是字符串。";
          return result;
        }
        rules.emplace_back(yaml_rules[i].as<std::string>());
        locations.emplace_back("rules[" + std::to_string(i) + "]");
      }
      return parseRuleList(rules, locations, source_identifier,
                           allowed_rule_types);
    }
  } catch (const YAML::Exception &) {
    // A plain-text rule list is not required to be valid YAML.
  }

  string_array lines;
  string_array locations;
  std::stringstream stream(content);
  std::string line;
  size_t line_number = 0;
  while (std::getline(stream, line)) {
    ++line_number;
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    lines.emplace_back(std::move(line));
    locations.emplace_back("line " + std::to_string(line_number));
  }
  return parseRuleList(lines, locations, source_identifier,
                       allowed_rule_types);
}

string_array mergeClashRules(const string_array &prepend,
                             const string_array &original,
                             const string_array &generated,
                             const string_array &append) {
  auto [original_non_terminal, original_terminal] =
      splitAtFirstTerminal(original);
  auto [generated_non_terminal, generated_terminal] =
      splitAtFirstTerminal(generated);

  string_array result;
  result.reserve(prepend.size() + original.size() + generated.size() +
                 append.size());
  result.insert(result.end(), prepend.begin(), prepend.end());
  result.insert(result.end(), original_non_terminal.begin(),
                original_non_terminal.end());
  result.insert(result.end(), generated_non_terminal.begin(),
                generated_non_terminal.end());
  result.insert(result.end(), append.begin(), append.end());
  result.insert(result.end(), original_terminal.begin(),
                original_terminal.end());
  result.insert(result.end(), generated_terminal.begin(),
                generated_terminal.end());
  return result;
}

bool mergeClashRulesWithinLimit(const string_array &prepend,
                                const string_array &original,
                                const string_array &generated,
                                const string_array &append,
                                std::size_t max_rules,
                                string_array &result) {
  result = mergeClashRules(prepend, original, generated, append);
  return !max_rules || result.size() <= max_rules;
}
