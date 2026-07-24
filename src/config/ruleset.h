#ifndef RULESET_H_INCLUDED
#define RULESET_H_INCLUDED

#include "def.h"

enum ruleset_type
{
    RULESET_SURGE,
    RULESET_QUANX,
    RULESET_CLASH_DOMAIN,
    RULESET_CLASH_IPCIDR,
    RULESET_CLASH_CLASSICAL
};

struct RulesetOptions
{
    bool no_resolve = false;

    bool operator==(const RulesetOptions &r) const
    {
        return no_resolve == r.no_resolve;
    }
};

struct ParsedRulesetInterval
{
    Integer interval = 0;
    RulesetOptions options;
    StrArray unknown_options;
};

struct RulesetConfig
{
    String Group;
    String Url;
    Integer Interval = 86400;
    RulesetOptions Options;
    bool operator==(const RulesetConfig &r) const
    {
        return Group == r.Group && Url == r.Url && Interval == r.Interval &&
               Options == r.Options;
    }
};

using RulesetConfigs = std::vector<RulesetConfig>;

RulesetOptions parseRulesetOptions(const StrArray &raw_options,
                                   StrArray *unknown_options = nullptr);
ParsedRulesetInterval parseRulesetInterval(const String &raw_interval);
bool parseRulesetConfigLine(const String &line, RulesetConfig &config,
                            StrArray *unknown_options = nullptr);

std::string buildClashRuleSetReference(const std::string &provider_name,
                                       const std::string &group,
                                       ruleset_type type,
                                       const RulesetOptions &options);
std::string appendClashIpCidrNoResolve(const std::string &rule,
                                      ruleset_type type,
                                      const RulesetOptions &options);

#endif // RULESET_H_INCLUDED
