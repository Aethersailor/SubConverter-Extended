#include <string>

#include <cctype>
#include <vector>

#include "handler/settings.h"
#include "utils/logger.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/rapidjson_extra.h"
#include "subexport.h"
#ifdef USE_MIHOMO_PARSER
#include "parser/mihomo_bridge.h"
#endif

/// rule type lists
#define basic_types "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL"
// 新增meta路由规则
//string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME"};
string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "DOMAIN-REGEX", "GEOSITE", "IP-SUFFIX", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-PATH-REGEX", "PROCESS-PATH", "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "SUB-RULE", "RULE-SET", "AND", "OR", "NOT"};
string_array Surge2RuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SurgeRuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array QuanXRuleTypes = {basic_types, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"};
string_array SurfRuleTypes = {basic_types, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SingBoxRuleTypes = {basic_types, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"};

static std::string convertRulesetUncached(const std::string &content, int type)
{
    /// Target: Surge type,pattern[,flag]
    /// Source: QuanX type,pattern[,group]
    ///         Clash payload:\n  - 'ipcidr/domain/classic(Surge-like)'

    std::string output, strLine;

    if(type == RULESET_SURGE)
        return content;

    if(regFind(content, "^payload:\\r?\\n")) /// Clash
    {
        output = regReplace(regReplace(content, "payload:\\r?\\n", "", true), R"(\s?^\s*-\s+('|"?)(.*)\1$)", "\n$2", true);
        if(type == RULESET_CLASH_CLASSICAL) /// classical type
            return output;
        std::stringstream ss;
        ss << output;
        char delimiter = getLineBreak(output);
        output.clear();
        string_size pos, lineSize;
        while(getline(ss, strLine, delimiter))
        {
            strLine = trim(strLine);
            lineSize = strLine.size();
            if(lineSize && strLine[lineSize - 1] == '\r') //remove line break
                strLine.erase(--lineSize);

            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            if(!strLine.empty() && (strLine[0] != ';' && strLine[0] != '#' && !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')))
            {
                pos = strLine.find('/');
                if(pos != std::string::npos) /// ipcidr
                {
                    if(isIPv4(strLine.substr(0, pos)))
                        output += "IP-CIDR,";
                    else
                        output += "IP-CIDR6,";
                }
                else
                {
                    if(strLine[0] == '.' || (lineSize >= 2 && strLine[0] == '+' && strLine[1] == '.')) /// suffix
                    {
                        bool keyword_flag = false;
                        while(endsWith(strLine, ".*"))
                        {
                            keyword_flag = true;
                            strLine.erase(strLine.size() - 2);
                        }
                        output += "DOMAIN-";
                        if(keyword_flag)
                            output += "KEYWORD,";
                        else
                            output += "SUFFIX,";
                        strLine.erase(0, 2 - (strLine[0] == '.'));
                    }
                    else
                        output += "DOMAIN,";
                }
            }
            output += strLine;
            output += '\n';
        }
        return output;
    }
    else /// QuanX
    {
        output = regReplace(regReplace(content, "^(?i:host)", "DOMAIN", true), "^(?i:ip6-cidr)", "IP-CIDR6", true); //translate type
        output = regReplace(output, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true); //remove group
        return output;
    }
}

namespace {

constexpr size_t kRulesetConversionCacheEntries = 256;
constexpr size_t kRulesetConversionCacheBytes = 16 * 1024 * 1024;
ConcurrentLruCache<std::string, std::string> ruleset_conversion_cache(
    kRulesetConversionCacheEntries, kRulesetConversionCacheBytes);

} // namespace

std::string convertRuleset(const std::string &content, int type)
{
    if(type == RULESET_SURGE)
        return content;

    const std::string key =
        getMD5(content) + ":" + std::to_string(type);
    return ruleset_conversion_cache.getOrCompute(
        key, true, [&] { return convertRulesetUncached(content, type); },
        [](const std::string &value)
            -> ConcurrentLruCache<std::string, std::string>::CacheSize {
            return value.size();
        });
}

static bool splitRuleFieldsStrict(const std::string &line,
                                  string_array &fields)
{
    fields.clear();
    std::string field;
    int parentheses = 0;
    char quote = '\0';
    bool escaped = false;
    for(char character : line)
    {
        if(quote != '\0')
        {
            field += character;
            if(escaped)
                escaped = false;
            else if(character == '\\')
                escaped = true;
            else if(character == quote)
                quote = '\0';
            continue;
        }
        if(escaped)
        {
            field += character;
            escaped = false;
            continue;
        }
        if(character == '\\')
        {
            field += character;
            escaped = true;
            continue;
        }
        if(character == '\'' || character == '"')
        {
            quote = character;
            field += character;
        }
        else if(character == '(')
        {
            ++parentheses;
            field += character;
        }
        else if(character == ')')
        {
            if(parentheses == 0)
                return false;
            --parentheses;
            field += character;
        }
        else if(character == ',' && parentheses == 0)
        {
            fields.emplace_back(trimWhitespace(field, true, true));
            field.clear();
        }
        else
            field += character;
    }
    if(quote != '\0' || parentheses != 0)
        return false;
    fields.emplace_back(trimWhitespace(field, true, true));
    return !fields.empty();
}

static bool parseRuleInteger(const std::string &value, unsigned int maximum,
                             unsigned int &result)
{
    const std::string normalized = trimWhitespace(value, true, true);
    if(normalized.empty())
        return false;
    unsigned int parsed = 0;
    for(unsigned char character : normalized)
    {
        if(!std::isdigit(character))
            return false;
        const unsigned int digit = character - '0';
        if(parsed > (maximum - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    result = parsed;
    return true;
}

static bool validRuleAddress(const std::string &value, bool ipv6_only,
                             bool ipv4_only)
{
    const std::string normalized = trimWhitespace(value, true, true);
    const std::string::size_type slash = normalized.find('/');
    const std::string address =
        slash == std::string::npos ? normalized : normalized.substr(0, slash);
    const bool ipv4 = isIPv4(address);
    const bool ipv6 = isIPv6(address);
    if((ipv6_only && !ipv6) || (ipv4_only && !ipv4) || (!ipv4 && !ipv6))
        return false;
    if(slash == std::string::npos)
        return true;
    unsigned int prefix = 0;
    const unsigned int maximum = ipv6 ? 128U : 32U;
    return parseRuleInteger(normalized.substr(slash + 1), maximum, prefix);
}

static bool validRuleLine(const std::string &line,
                          const string_array &known_types);

static bool isClashRegexRule(const std::string &rule_type)
{
    return rule_type == "DOMAIN-REGEX" ||
           rule_type == "PROCESS-NAME-REGEX" ||
           rule_type == "PROCESS-PATH-REGEX";
}

static std::string clashRuleType(const std::string &line)
{
    std::string payload = trimWhitespace(line, true, true);
    if(startsWith(payload, "[]"))
        payload = trimWhitespace(payload.substr(2), true, true);
    const std::string::size_type separator = payload.find(',');
    return toUpper(trimWhitespace(
        separator == std::string::npos ? payload : payload.substr(0, separator),
        true, true));
}

static void stripClashInlineComment(std::string &line)
{
    const std::string::size_type comment = line.find("//");
    if(comment != std::string::npos)
        line = trimWhitespace(line.substr(0, comment), true, true);
}

enum class ClashRegexParseMode
{
    SourceRule,
    FinalRule,
};

static bool normalizeClashRegexPattern(const std::string &value,
                                        std::string &pattern)
{
    pattern = trimWhitespace(value, true, true);
    if(pattern.size() >= 2 &&
       ((pattern.front() == '"' && pattern.back() == '"') ||
        (pattern.front() == '\'' && pattern.back() == '\'')))
        pattern = pattern.substr(1, pattern.size() - 2);
    if(pattern.empty())
        return false;
#ifdef USE_MIHOMO_PARSER
    return mihomo::isMihomoRegexValid(pattern);
#else
    return regValid(pattern);
#endif
}

static bool parseClashRegexRule(const std::string &line,
                                string_array &fields,
                                std::string &pattern,
                                ClashRegexParseMode mode)
{
    fields.clear();
    const std::string::size_type type_separator = line.find(',');
    if(type_separator == std::string::npos)
        return false;

    const std::string rule_type = trimWhitespace(
        line.substr(0, type_separator), true, true);
    if(!isClashRegexRule(toUpper(rule_type)))
        return false;

    // Regex payloads are not generic compound-rule fields. Parentheses,
    // quotes, //, and escaped commas are regex syntax and must not be
    // interpreted by splitRuleFieldsStrict(). Only a paired outer quote may
    // introduce an explicit source-side target. In source mode every other
    // comma belongs to the payload; this removes the ambiguity between a
    // native Mihomo payload comma and an old policy delimiter. Final rules
    // retain the Mihomo first-type/last-target convention.
    const std::string body = trimWhitespace(
        line.substr(type_separator + 1), true, true);
    if(body.empty())
        return false;

    size_t outer_quote_end = std::string::npos;
    if(body.front() == '\'' || body.front() == '"')
    {
        const char quote = body.front();
        bool escaped = false;
        bool closed = false;
        for(size_t index = 1; index < body.size(); ++index)
        {
            const char character = body[index];
            if(escaped)
            {
                escaped = false;
                continue;
            }
            if(character == '\\')
            {
                escaped = true;
                continue;
            }
            if(character == quote)
            {
                closed = true;
                const std::string suffix = trimWhitespace(
                    body.substr(index + 1), true, true);
                if(!suffix.empty() && suffix.front() != ',')
                    return false;
                outer_quote_end = index;
                break;
            }
        }
        if(!closed)
            return false;
    }

    std::vector<size_t> separators;
    bool escaped = false;
    for(size_t index = 0; index < body.size(); ++index)
    {
        if(outer_quote_end != std::string::npos && index <= outer_quote_end)
            continue;
        const char character = body[index];
        if(escaped)
        {
            escaped = false;
            continue;
        }
        if(character == '\\')
        {
            escaped = true;
            continue;
        }
        if(character == ',')
            separators.push_back(index);
    }

    std::string raw_pattern = body;
    std::string target;
    if(mode == ClashRegexParseMode::SourceRule)
    {
        if(outer_quote_end != std::string::npos)
        {
            const std::string suffix = trimWhitespace(
                body.substr(outer_quote_end + 1), true, true);
            if(!suffix.empty())
            {
                if(suffix.front() != ',' || separators.size() != 1)
                    return false;
                raw_pattern = body.substr(0, outer_quote_end + 1);
                target = trimWhitespace(suffix.substr(1), true, true);
                if(target.empty())
                    return false;
            }
        }
    }
    else
    {
        if(separators.empty())
            return false;
        const size_t target_separator = separators.back();
        raw_pattern = body.substr(0, target_separator);
        target = trimWhitespace(body.substr(target_separator + 1), true, true);
        if(target.empty())
            return false;
    }
    if(!normalizeClashRegexPattern(raw_pattern, pattern))
        return false;

    fields.emplace_back(rule_type);
    fields.emplace_back(pattern);
    if(!target.empty())
        fields.emplace_back(target);
    return true;
}

static bool unwrapRuleExpression(const std::string &value,
                                 std::string &inner)
{
    const std::string normalized = trimWhitespace(value, true, true);
    if(normalized.size() < 2 || normalized.front() != '(' ||
       normalized.back() != ')')
        return false;

    int parentheses = 0;
    char quote = '\0';
    bool escaped = false;
    for(size_t index = 0; index < normalized.size(); ++index)
    {
        const char character = normalized[index];
        if(quote != '\0')
        {
            if(escaped)
                escaped = false;
            else if(character == '\\')
                escaped = true;
            else if(character == quote)
                quote = '\0';
            continue;
        }
        if(character == '\'' || character == '"')
        {
            quote = character;
            continue;
        }
        if(character == '(')
            ++parentheses;
        else if(character == ')')
        {
            if(parentheses == 0)
                return false;
            --parentheses;
            if(parentheses == 0 && index + 1 != normalized.size())
                return false;
        }
    }
    if(quote != '\0' || parentheses != 0)
        return false;
    inner = normalized.substr(1, normalized.size() - 2);
    return !trimWhitespace(inner, true, true).empty();
}

static bool validCompoundExpression(const std::string &expression,
                                    const string_array &known_types,
                                    size_t minimum_components,
                                    bool exact_component_count)
{
    std::string inner;
    if(!unwrapRuleExpression(expression, inner))
        return false;
    string_array components;
    if(!splitRuleFieldsStrict(inner, components) ||
       components.size() < minimum_components ||
       (exact_component_count && components.size() != minimum_components))
        return false;
    for(const std::string &component : components)
    {
        const std::string normalized = trimWhitespace(component, true, true);
        if(normalized.empty())
            return false;
        if(normalized.front() == '(')
        {
            std::string nested_rule;
            if(!unwrapRuleExpression(normalized, nested_rule) ||
               !validRuleLine(nested_rule, known_types))
                return false;
        }
        else if(!validRuleLine(normalized, known_types))
            return false;
    }
    return true;
}

static bool validRuleLine(const std::string &line,
                          const string_array &known_types)
{
    const std::string type = clashRuleType(line);
    if(isClashRegexRule(type))
    {
        if(std::none_of(known_types.begin(), known_types.end(),
                        [&](const std::string &known) { return type == known; }))
            return false;
        string_array fields;
        std::string pattern;
        return parseClashRegexRule(line, fields, pattern,
                                   ClashRegexParseMode::SourceRule);
    }

    string_array fields;
    if(!splitRuleFieldsStrict(line, fields) || fields.size() < 2)
        return false;
    const std::string parsed_type = toUpper(fields.front());
    if(std::none_of(known_types.begin(), known_types.end(),
                    [&](const std::string &known) { return parsed_type == known; }))
        return false;
    if(parsed_type == "SUB-RULE")
        // RulesetConfig supplies a proxy policy as the third field. A
        // SUB-RULE third field is a sub-rule name instead, and its sub-rules
        // cannot travel with a server-side ruleset, so reject it here rather
        // than silently rewriting its meaning.
        return false;
    for(size_t index = 1; index < fields.size(); ++index)
    {
        if(fields[index].empty())
            return false;
    }
    if(parsed_type == "IP-CIDR" &&
       !validRuleAddress(fields[1], false, true))
        return false;
    if(parsed_type == "IP-CIDR6" &&
       !validRuleAddress(fields[1], true, false))
        return false;
    if(parsed_type == "SRC-IP-CIDR" &&
       !validRuleAddress(fields[1], false, false))
        return false;
    if(parsed_type == "AND" || parsed_type == "OR" || parsed_type == "NOT")
    {
        if(fields.size() != 2 && fields.size() != 3)
            return false;
        const size_t minimum_components = parsed_type == "NOT" ? 1 : 2;
        if(!validCompoundExpression(fields[1], known_types,
                                     minimum_components, parsed_type == "NOT"))
            return false;
    }
    return true;
}

static bool validInlineRuleLine(const std::string &line,
                                const string_array &known_types)
{
    const std::string payload = trimWhitespace(line.substr(2), true, true);
    if(payload.empty())
        return false;
    if(isClashRegexRule(clashRuleType(payload)))
    {
        string_array fields;
        std::string pattern;
        return parseClashRegexRule(payload, fields, pattern,
                                   ClashRegexParseMode::SourceRule);
    }
    string_array fields;
    if(!splitRuleFieldsStrict(payload, fields))
        return false;
    if(fields.size() == 1)
    {
        const std::string type = toUpper(fields.front());
        return type == "FINAL" || type == "MATCH";
    }
    return validRuleLine(payload, known_types);
}

RulesetValidationResult validateRulesetEntries(const std::string &content,
                                               ruleset_type type)
{
    RulesetValidationResult result;
    const std::string trimmed = trimWhitespace(content, true, true);
    if (trimmed.empty())
    {
        result.failure_reason = "empty";
        return result;
    }

    const string_array *known_types = &SurgeRuleTypes;
    switch (type)
    {
    case RULESET_QUANX:
        known_types = &QuanXRuleTypes;
        break;
    case RULESET_CLASH_DOMAIN:
    case RULESET_CLASH_IPCIDR:
    case RULESET_CLASH_CLASSICAL:
        known_types = &ClashRuleTypes;
        break;
    case RULESET_SURGE:
        known_types = &SurgeRuleTypes;
        break;
    }

    const std::string converted = convertRuleset(content, type);
    std::stringstream stream(converted);
    const char delimiter = getLineBreak(converted);
    std::string line;
    while (std::getline(stream, line, delimiter))
    {
        line = trimWhitespace(line, true, true);
        if (line.empty() || line[0] == ';' || line[0] == '#' ||
            (line.size() >= 2 && line[0] == '/' && line[1] == '/'))
            continue;
        if(!isClashRegexRule(clashRuleType(line)))
            stripClashInlineComment(line);
        if (line.empty())
            continue;
        const bool valid = startsWith(line, "[]")
                               ? validInlineRuleLine(line, *known_types)
                               : validRuleLine(line, *known_types);
        if (valid)
            ++result.valid_count;
        else
        {
            ++result.invalid_count;
            if (result.failure_reason.empty())
                result.failure_reason = "invalid_rule";
        }
    }
    if (result.valid_count == 0 && result.invalid_count == 0)
        result.failure_reason = "no_rules";
    return result;
}

size_t countValidRulesetEntries(const std::string &content,
                                ruleset_type type)
{
    return validateRulesetEntries(content, type).valid_count;
}

size_t rulesetConversionCacheMaxEntries()
{
    return kRulesetConversionCacheEntries;
}

size_t rulesetConversionCacheMaxBytes()
{
    return kRulesetConversionCacheBytes;
}

static bool isClashCompoundRule(const std::string &rule_type)
{
    return rule_type == "AND" || rule_type == "OR" || rule_type == "NOT";
}

static bool isClashStructuredPayloadRule(const std::string &rule_type)
{
    return isClashRegexRule(rule_type);
}

static bool isNoResolveOption(const std::string &value)
{
    return toUpper(trimWhitespace(value, true, true)) == "NO-RESOLVE";
}

std::string appendClashRuleTarget(const std::string &rule, const std::string &target, bool no_resolve_only)
{
    std::string strLine = trimWhitespace(rule, true, true);
    std::string::size_type pos = strLine.find(',');
    std::string rule_type = toUpper(trimWhitespace(pos == std::string::npos ? strLine : strLine.substr(0, pos), true, true));

    if(rule_type == "FINAL" || rule_type == "MATCH")
        return "MATCH," + target;

    if(isClashCompoundRule(rule_type))
    {
        string_array fields;
        if(!splitRuleFieldsStrict(strLine, fields) || fields.size() < 2)
            return strLine + "," + target;

        std::string output = fields[0] + "," + fields[1] + "," + target;
        for(size_t index = 3; index < fields.size(); ++index)
            output += "," + fields[index];
        return output;
    }

    if(rule_type == "SUB-RULE")
    {
        string_array fields;
        std::string expression;
        if(!splitRuleFieldsStrict(strLine, fields) || fields.size() != 3 ||
           !unwrapRuleExpression(fields[1], expression) ||
           !validRuleLine(expression, ClashRuleTypes))
            return {};
        // The third field is a sub-rule name, not a proxy policy. Preserve
        // the complete valid base rule instead of injecting RulesetConfig's
        // proxy group into it.
        return strLine;
    }

    if(isClashStructuredPayloadRule(rule_type))
    {
        string_array fields;
        std::string pattern;
        if(!parseClashRegexRule(strLine, fields, pattern,
                                ClashRegexParseMode::SourceRule))
            return {};
        // The normalized pattern is also the value validated above. Outer
        // quotes are input-side disambiguation only and must not reach
        // Mihomo's regexp2 parser.
        return fields[0] + "," + pattern + "," + target;
    }

    if(pos == std::string::npos)
        return strLine + "," + target;

    string_array fields;
    if(!splitRuleFieldsStrict(strLine, fields) || fields.size() < 2)
        return strLine + "," + target;

    std::string output = fields[0] + "," + fields[1] + "," + target;
    size_t option_start = 2;
    if(fields.size() > 2 && !isNoResolveOption(fields[2]))
        option_start = 3;
    for(size_t index = option_start; index < fields.size(); ++index)
    {
        const std::string &option = fields[index];
        if(!no_resolve_only || isNoResolveOption(option))
            output += "," + option;
    }
    return output;
}

static std::string transformRuleToCommon(string_view_array &temp, const std::string &input, const std::string &group, bool no_resolve_only = false)
{
    temp.clear();
    std::string strLine;
    split(temp, input, ',');
    if(temp.size() < 2)
    {
        strLine = temp[0];
        strLine += ",";
        strLine += group;
    }
    else
    {
        strLine = temp[0];
        strLine += ",";
        strLine += temp[1];
        strLine += ",";
        strLine += group;
        if(temp.size() > 2 && (!no_resolve_only || temp[2] == "no-resolve"))
        {
            strLine += ",";
            strLine += temp[2];
        }
    }
    return strLine;
}

static void warnNoResolveIgnoredForTarget(
    const std::vector<RulesetContent> &ruleset_content_array,
    const std::string &target)
{
    for(const RulesetContent &ruleset : ruleset_content_array)
    {
        if(!ruleset.options.no_resolve)
            continue;
        writeLog(0,
                 "规则集选项 no-resolve 不支持 " + target +
                     " 输出，已对策略组 '" + ruleset.rule_group +
                     "' 安全忽略。",
                 LOG_LEVEL_WARNING);
    }
}

void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    string_array allRules;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    YAML::Node rules;
    size_t total_rules = 0;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
        rules = base_rule[field_name];

    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "获取规则集失败或规则集为空：'" + x.rule_path + "'。", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            strLine = appendClashRuleTarget(strLine, rule_group);
            if(strLine.empty())
                continue;
            allRules.emplace_back(strLine);
            total_rules++;
            local_stats.add();
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                continue;
            if(!isClashRegexRule(clashRuleType(strLine)))
                stripClashInlineComment(strLine);
            strLine = appendClashRuleTarget(strLine, rule_group);
            if(strLine.empty())
                continue;
            strLine =
                appendClashIpCidrNoResolve(strLine, x.rule_type, x.options);
            allRules.emplace_back(strLine);
            total_rules++;
            local_stats.add();
        }
    }

    for(std::string &x : allRules)
    {
        rules.push_back(x);
    }

    base_rule[field_name] = rules;
    if(stats)
        stats->add(local_stats.rules);
}

std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    std::string output_content = "\n" + field_name + ":\n";
    size_t total_rules = 0;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        for(size_t i = 0; i < base_rule[field_name].size(); i++)
            output_content += "  - " + safe_as<std::string>(base_rule[field_name][i]) + "\n";
    }
    base_rule.remove(field_name);

    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "获取规则集失败或规则集为空：'" + x.rule_path + "'。", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            strLine = appendClashRuleTarget(strLine, rule_group);
            if(strLine.empty())
                continue;
            output_content += "  - " + strLine + "\n";
            total_rules++;
            local_stats.add();
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){ return startsWith(strLine, type); }))
                continue;
            if(!isClashRegexRule(clashRuleType(strLine)))
                stripClashInlineComment(strLine);

            strLine = appendClashRuleTarget(strLine, rule_group);
            if(strLine.empty())
                continue;
            strLine =
                appendClashIpCidrNoResolve(strLine, x.rule_type, x.options);
            output_content += "  - " + strLine + "\n";
            total_rules++;
            local_stats.add();
        }
    }
    if(stats)
        stats->add(local_stats.rules);
    return output_content;
}

void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string &remote_path_prefix, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    warnNoResolveIgnoredForTarget(ruleset_content_array, "非 Clash");
    string_array allRules;
    std::string rule_group, rule_path, rule_path_typed, retrieved_rules, strLine;
    std::stringstream strStrm;
    size_t total_rules = 0;

    switch(surge_ver) //other version: -3 for Surfboard, -4 for Loon
    {
    case 0:
        base_rule.set_current_section("RoutingRule"); //Mellow
        break;
    case -1:
        base_rule.set_current_section("filter_local"); //Quantumult X
        break;
    case -2:
        base_rule.set_current_section("TCP"); //Quantumult
        break;
    default:
        base_rule.set_current_section("Rule");
    }

    if(overwrite_original_rules)
    {
        base_rule.erase_section();
        switch(surge_ver)
        {
        case -1:
            base_rule.erase_section("filter_remote");
            break;
        case -4:
            base_rule.erase_section("Remote Rule");
            break;
        default:
            break;
        }
    }

    const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = x.rule_content.get().substr(2);
            if(strLine == "MATCH")
                strLine = "FINAL";
            if(surge_ver == -1 || surge_ver == -2)
            {
                strLine = transformRuleToCommon(temp, strLine, rule_group, true);
            }
            else
            {
                if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                    strLine = transformRuleToCommon(temp, strLine, rule_group);
            }
            strLine = replaceAllDistinct(strLine, ",,", ",");
            allRules.emplace_back(strLine);
            total_rules++;
            local_stats.add();
            continue;
        }
        else
        {
            if(surge_ver == -1 && x.rule_type == RULESET_QUANX && isLink(rule_path))
            {
                strLine = rule_path + ", tag=" + rule_group + ", force-policy=" + rule_group + ", enabled=true";
                base_rule.set("filter_remote", "{NONAME}", strLine);
                local_stats.add();
                continue;
            }
            if(fileExist(rule_path))
            {
                if(surge_ver > 2 && !remote_path_prefix.empty())
                {
                    strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);
                    allRules.emplace_back(strLine);
                    local_stats.add();
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    local_stats.add();
                    continue;
                }
                else if(surge_ver == -4 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    local_stats.add();
                    continue;
                }
            }
            else if(isLink(rule_path))
            {
                if(surge_ver > 2)
                {
                    if(x.rule_type != RULESET_SURGE)
                    {
                        if(!remote_path_prefix.empty())
                            strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                        else
                            continue;
                    }
                    else
                        strLine = "RULE-SET," + rule_path + "," + rule_group;

                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);

                    allRules.emplace_back(strLine);
                    local_stats.add();
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    local_stats.add();
                    continue;
                }
                else if(surge_ver == -4)
                {
                    strLine = rule_path + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    local_stats.add();
                    continue;
                }
            }
            else
                continue;
            retrieved_rules = x.rule_content.get();
            if(retrieved_rules.empty())
            {
                writeLog(0, "获取规则集失败或规则集为空：'" + x.rule_path + "'。", LOG_LEVEL_WARNING);
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            while(getline(strStrm, strLine, delimiter))
            {
                if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                    break;
                strLine = trimWhitespace(strLine, true, true);
                lineSize = strLine.size();
                if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                    continue;

                /// remove unsupported types
                switch(surge_ver)
                {
                case -2:
                    if(startsWith(strLine, "IP-CIDR6"))
                        continue;
                    [[fallthrough]];
                case -1:
                    if(!std::any_of(QuanXRuleTypes.begin(), QuanXRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                case -3:
                    if(!std::any_of(SurfRuleTypes.begin(), SurfRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                default:
                    if(surge_ver > 2)
                    {
                        if(!std::any_of(SurgeRuleTypes.begin(), SurgeRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                    else
                    {
                        if(!std::any_of(Surge2RuleTypes.begin(), Surge2RuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                }

                if(strFind(strLine, "//"))
                {
                    strLine.erase(strLine.find("//"));
                    strLine = trimWhitespace(strLine);
                }

                if(surge_ver == -1 || surge_ver == -2)
                {
                    if(startsWith(strLine, "IP-CIDR6"))
                        strLine.replace(0, 8, "IP6-CIDR");
                    strLine = transformRuleToCommon(temp, strLine, rule_group, true);
                }
                else
                {
                    if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                        strLine = transformRuleToCommon(temp, strLine, rule_group);
                }
                allRules.emplace_back(strLine);
                total_rules++;
                local_stats.add();
            }
        }
    }

    for(std::string &x : allRules)
    {
        base_rule.set("{NONAME}", x);
    }
    if(stats)
        stats->add(local_stats.rules);
}

static rapidjson::Value transformRuleToSingBox(std::vector<std::string_view> &args, const std::string& rule, const std::string &group, rapidjson::MemoryPoolAllocator<>& allocator)
{
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return rapidjson::Value(rapidjson::kObjectType);
    auto type = toLower(std::string(args[0]));
    auto value = toLower(std::string(args[1]));
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    rapidjson::Value rule_obj(rapidjson::kObjectType);
    type = replaceAllDistinct(type, "-", "_");
    type = replaceAllDistinct(type, "ip_cidr6", "ip_cidr");
    type = replaceAllDistinct(type, "src_", "source_");
    if (type == "match" || type == "final")
    {
        rule_obj.AddMember("outbound", rapidjson::Value(value.data(), value.size(), allocator), allocator);
    }
    else
    {
        rule_obj.AddMember(rapidjson::Value(type.c_str(), allocator), rapidjson::Value(value.data(), value.size(), allocator), allocator);
        rule_obj.AddMember("outbound", rapidjson::Value(group.c_str(), allocator), allocator);
    }
    return rule_obj;
}

static bool appendSingBoxRule(std::vector<std::string_view> &args, rapidjson::Value &rules, const std::string& rule, rapidjson::MemoryPoolAllocator<>& allocator)
{
    using namespace rapidjson_ext;
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return false;
    auto type = args[0];
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    if (none_of(SingBoxRuleTypes, [&](const std::string& t){ return type == t; }))
        return false;

    auto realType = toLower(std::string(type));
    auto value = toLower(std::string(args[1]));
    realType = replaceAllDistinct(realType, "-", "_");
    realType = replaceAllDistinct(realType, "ip_cidr6", "ip_cidr");

    rules | AppendToArray(realType.c_str(), rapidjson::Value(value.c_str(), value.size(), allocator), allocator);
    return true;
}

void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    warnNoResolveIgnoredForTarget(ruleset_content_array, "sing-box");
    using namespace rapidjson_ext;
    std::string rule_group, retrieved_rules, strLine, final;
    std::stringstream strStrm;
    size_t total_rules = 0;
    auto &allocator = base_rule.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    if (!overwrite_original_rules)
    {
        if (base_rule.HasMember("route") && base_rule["route"].HasMember("rules") && base_rule["route"]["rules"].IsArray())
            rules.Swap(base_rule["route"]["rules"]);
    }

    if (global.singBoxAddClashModes)
    {
        auto global_object = buildObject(allocator, "clash_mode", "Global", "outbound", "GLOBAL");
        auto direct_object = buildObject(allocator, "clash_mode", "Direct", "outbound", "DIRECT");
        rules.PushBack(global_object, allocator);
        rules.PushBack(direct_object, allocator);
    }

    // auto dns_object = buildObject(allocator, "protocol", "dns", "outbound", "dns-out");
    // rules.PushBack(dns_object, allocator);

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "获取规则集失败或规则集为空：'" + x.rule_path + "'。", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL") || startsWith(strLine, "MATCH"))
            {
                final = rule_group;
                continue;
            }
            rules.PushBack(transformRuleToSingBox(temp, strLine, rule_group, allocator), allocator);
            total_rules++;
            local_stats.add();
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;

        std::string::size_type lineSize;
        rapidjson::Value rule(rapidjson::kObjectType);

        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            if (appendSingBoxRule(temp, rule, strLine, allocator))
            {
                total_rules++;
                local_stats.add();
            }
        }
        if (rule.ObjectEmpty()) continue;
        rule.AddMember("outbound", rapidjson::Value(rule_group.c_str(), allocator), allocator);
        rules.PushBack(rule, allocator);
    }

    if (!base_rule.HasMember("route"))
        base_rule.AddMember("route", rapidjson::Value(rapidjson::kObjectType), allocator);

    auto finalValue = rapidjson::Value(final.c_str(), allocator);
    base_rule["route"]
    | AddMemberOrReplace("rules", rules, allocator)
    | AddMemberOrReplace("final", finalValue, allocator);
    if(stats)
        stats->add(local_stats.rules);
}
