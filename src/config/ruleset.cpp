#include "ruleset.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string_view>
#include <utility>

namespace {

std::string trimAscii(std::string_view value)
{
    const auto first = std::find_if_not(
        value.begin(), value.end(),
        [](unsigned char c) { return std::isspace(c) != 0; });
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(),
        [](unsigned char c) { return std::isspace(c) != 0; }).base();
    if(first >= last)
        return "";
    return std::string(first, last);
}

std::string lowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return value;
}

std::string upperAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::toupper(c));
                   });
    return value;
}

StrArray splitOptions(std::string_view value)
{
    StrArray result;
    size_t begin = 0;
    while(begin <= value.size())
    {
        const size_t end = value.find('|', begin);
        result.emplace_back(value.substr(
            begin, end == std::string_view::npos ? value.size() - begin
                                                 : end - begin));
        if(end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    return result;
}

bool hasNoResolveOption(const std::string &rule)
{
    size_t begin = 0;
    while(begin <= rule.size())
    {
        const size_t end = rule.find(',', begin);
        const std::string token = lowerAscii(trimAscii(std::string_view(rule).substr(
            begin, end == std::string::npos ? rule.size() - begin
                                            : end - begin)));
        if(token == "no-resolve")
            return true;
        if(end == std::string::npos)
            break;
        begin = end + 1;
    }
    return false;
}

} // namespace

RulesetOptions parseRulesetOptions(const StrArray &raw_options,
                                   StrArray *unknown_options)
{
    RulesetOptions result;
    for(const std::string &raw_option : raw_options)
    {
        const std::string option = lowerAscii(trimAscii(raw_option));
        if(option.empty())
            continue;
        if(option == "no-resolve")
        {
            result.no_resolve = true;
            continue;
        }
        if(unknown_options != nullptr &&
           std::find(unknown_options->begin(), unknown_options->end(), option) ==
               unknown_options->end())
            unknown_options->emplace_back(option);
    }
    return result;
}

ParsedRulesetInterval parseRulesetInterval(const String &raw_interval)
{
    ParsedRulesetInterval result;
    StrArray tokens = splitOptions(raw_interval);
    if(tokens.empty())
        return result;

    // Keep the historical std::atoi-compatible interval behavior.
    result.interval = std::atoi(tokens.front().c_str());
    if(tokens.size() > 1)
    {
        StrArray raw_options(tokens.begin() + 1, tokens.end());
        result.options =
            parseRulesetOptions(raw_options, &result.unknown_options);
    }
    return result;
}

bool parseRulesetConfigLine(const String &line, RulesetConfig &config,
                            StrArray *unknown_options)
{
    const String::size_type first_separator = line.find(',');
    if(first_separator == String::npos)
        return false;

    RulesetConfig parsed;
    parsed.Group = line.substr(0, first_separator);
    if(line.substr(first_separator + 1, 2) == "[]")
    {
        parsed.Url = line.substr(first_separator + 1);
        config = std::move(parsed);
        return true;
    }

    const String::size_type last_separator = line.rfind(',');
    if(first_separator != last_separator)
    {
        ParsedRulesetInterval interval =
            parseRulesetInterval(line.substr(last_separator + 1));
        parsed.Interval = interval.interval;
        parsed.Options = interval.options;
        parsed.Url =
            line.substr(first_separator + 1,
                        last_separator - first_separator - 1);
        if(unknown_options != nullptr)
            *unknown_options = std::move(interval.unknown_options);
    }
    else
        parsed.Url = line.substr(first_separator + 1);

    config = std::move(parsed);
    return true;
}

std::string buildClashRuleSetReference(const std::string &provider_name,
                                       const std::string &group,
                                       ruleset_type type,
                                       const RulesetOptions &options)
{
    std::string result = "RULE-SET," + provider_name + "," + group;
    if(type == RULESET_CLASH_IPCIDR && options.no_resolve)
        result += ",no-resolve";
    return result;
}

std::string appendClashIpCidrNoResolve(const std::string &rule,
                                      ruleset_type type,
                                      const RulesetOptions &options)
{
    if(type != RULESET_CLASH_IPCIDR || !options.no_resolve)
        return rule;

    const size_t separator = rule.find(',');
    const std::string rule_type =
        upperAscii(trimAscii(rule.substr(0, separator)));
    if(rule_type != "IP-CIDR" && rule_type != "IP-CIDR6")
        return rule;
    if(hasNoResolveOption(rule))
        return rule;
    return rule + ",no-resolve";
}
