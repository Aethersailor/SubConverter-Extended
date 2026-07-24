#include <algorithm>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdlib>
#include <string>

#include "config/ruleset.h"

namespace {

size_t countOccurrences(const std::string &value, const std::string &needle)
{
    size_t count = 0;
    size_t position = 0;
    while((position = value.find(needle, position)) != std::string::npos)
    {
        ++count;
        position += needle.size();
    }
    return count;
}

RulesetOptions noResolve()
{
    RulesetOptions options;
    options.no_resolve = true;
    return options;
}

} // namespace

int main()
{
    RulesetConfig config;
    StrArray unknown;
    assert(parseRulesetConfigLine(
        "DIRECT,clash-ipcidr:https://example.com/ip.yaml,28800|no-resolve",
        config, &unknown));
    assert(config.Group == "DIRECT");
    assert(config.Url == "clash-ipcidr:https://example.com/ip.yaml");
    assert(config.Interval == 28800);
    assert(config.Options.no_resolve);
    assert(unknown.empty());

    for(const std::string spelling :
        {"NO-RESOLVE", "No-Resolve", " no-resolve "})
    {
        ParsedRulesetInterval parsed =
            parseRulesetInterval("28800|" + spelling);
        assert(parsed.interval == 28800);
        assert(parsed.options.no_resolve);
        assert(parsed.unknown_options.empty());
    }

    ParsedRulesetInterval duplicate =
        parseRulesetInterval("28800|no-resolve||NO-RESOLVE|");
    assert(duplicate.interval == 28800);
    assert(duplicate.options.no_resolve);
    assert(duplicate.unknown_options.empty());

    ParsedRulesetInterval unknown_option =
        parseRulesetInterval("28800|future-option|FUTURE-OPTION");
    assert(unknown_option.interval == 28800);
    assert(!unknown_option.options.no_resolve);
    assert(unknown_option.unknown_options ==
           StrArray({"future-option"}));

    ParsedRulesetInterval mixed =
        parseRulesetInterval("28800|no-resolve|unknown-option");
    assert(mixed.interval == 28800);
    assert(mixed.options.no_resolve);
    assert(mixed.unknown_options == StrArray({"unknown-option"}));

    assert(parseRulesetInterval("abc|no-resolve").interval == 0);
    assert(parseRulesetInterval("|no-resolve").interval == 0);
    assert(parseRulesetInterval("0|no-resolve").interval == 0);
    assert(parseRulesetInterval("28800|").interval == 28800);

    RulesetConfig default_interval;
    assert(parseRulesetConfigLine(
        "DIRECT,clash-ipcidr:https://example.com/ip.yaml",
        default_interval));
    assert(default_interval.Interval == 86400);
    assert(!default_interval.Options.no_resolve);

    RulesetConfig inline_geoip;
    assert(parseRulesetConfigLine("DIRECT,[]GEOIP,CN", inline_geoip));
    assert(inline_geoip.Url == "[]GEOIP,CN");
    assert(inline_geoip.Interval == 86400);
    assert(!inline_geoip.Options.no_resolve);

    RulesetConfig inline_final;
    assert(parseRulesetConfigLine("FINAL,[]FINAL", inline_final));
    assert(inline_final.Url == "[]FINAL");
    assert(inline_final.Interval == 86400);

    const RulesetOptions enabled = noResolve();
    const RulesetOptions disabled;

    const std::string provider = buildClashRuleSetReference(
        "ip", "DIRECT", RULESET_CLASH_IPCIDR, enabled);
    assert(provider == "RULE-SET,ip,DIRECT,no-resolve");
    assert(countOccurrences(provider, "no-resolve") == 1);
    assert(buildClashRuleSetReference(
               "ip", "DIRECT", RULESET_CLASH_IPCIDR, disabled) ==
           "RULE-SET,ip,DIRECT");
    assert(buildClashRuleSetReference(
               "domain", "DIRECT", RULESET_CLASH_DOMAIN, enabled) ==
           "RULE-SET,domain,DIRECT");
    assert(buildClashRuleSetReference(
               "classic", "DIRECT", RULESET_CLASH_CLASSICAL, enabled) ==
           "RULE-SET,classic,DIRECT");
    assert(buildClashRuleSetReference(
               "surge", "DIRECT", RULESET_SURGE, enabled) ==
           "RULE-SET,surge,DIRECT");
    assert(buildClashRuleSetReference(
               "ip", "DIRECT", RULESET_CLASH_IPCIDR,
               mixed.options) ==
           "RULE-SET,ip,DIRECT,no-resolve");

    const std::string ipv4 = appendClashIpCidrNoResolve(
        "IP-CIDR,1.1.1.0/24,DIRECT", RULESET_CLASH_IPCIDR, enabled);
    const std::string ipv6 = appendClashIpCidrNoResolve(
        "IP-CIDR6,2001:db8::/32,DIRECT", RULESET_CLASH_IPCIDR, enabled);
    assert(ipv4 == "IP-CIDR,1.1.1.0/24,DIRECT,no-resolve");
    assert(ipv6 ==
           "IP-CIDR6,2001:db8::/32,DIRECT,no-resolve");
    assert(countOccurrences(ipv4, "no-resolve") == 1);
    assert(countOccurrences(ipv6, "no-resolve") == 1);

    const std::string existing =
        "IP-CIDR,1.1.1.0/24,DIRECT,no-resolve";
    assert(appendClashIpCidrNoResolve(
               existing, RULESET_CLASH_IPCIDR, enabled) == existing);
    assert(appendClashIpCidrNoResolve(
               "IP-CIDR6,2001:db8::/32,DIRECT,NO-RESOLVE",
               RULESET_CLASH_IPCIDR, enabled) ==
           "IP-CIDR6,2001:db8::/32,DIRECT,NO-RESOLVE");

    assert(appendClashIpCidrNoResolve(
               "DOMAIN-SUFFIX,example.com,DIRECT",
               RULESET_CLASH_IPCIDR, enabled) ==
           "DOMAIN-SUFFIX,example.com,DIRECT");
    assert(appendClashIpCidrNoResolve(
               "IP-CIDR,1.1.1.0/24,DIRECT",
               RULESET_CLASH_DOMAIN, enabled) ==
           "IP-CIDR,1.1.1.0/24,DIRECT");
    assert(appendClashIpCidrNoResolve(
               "IP-CIDR,1.1.1.0/24,DIRECT",
               RULESET_CLASH_CLASSICAL, enabled) ==
           "IP-CIDR,1.1.1.0/24,DIRECT");
    assert(appendClashIpCidrNoResolve(
               "IP-CIDR,1.1.1.0/24,DIRECT",
               RULESET_CLASH_IPCIDR, disabled) ==
           "IP-CIDR,1.1.1.0/24,DIRECT");

    const std::string provider_payload =
        "payload:\n  - 1.1.1.0/24\n  - 2001:db8::/32\n";
    assert(appendClashIpCidrNoResolve(
               provider_payload, RULESET_CLASH_IPCIDR, enabled) ==
           provider_payload);
    assert(provider_payload.find("no-resolve") == std::string::npos);

    // Traditional subconverter parses the suffix with std::atoi.
    assert(std::atoi("28800|no-resolve") == 28800);

    // The YAML adapter normalizes options to the same INI tail, while TOML
    // feeds its options array directly into the same option parser.
    RulesetConfig yaml_normalized;
    assert(parseRulesetConfigLine(
        "DIRECT,clash-ipcidr:https://example.com/ip.yaml,"
        "86400|no-resolve",
        yaml_normalized));
    assert(yaml_normalized.Interval == 86400);
    assert(yaml_normalized.Options.no_resolve);
    assert(parseRulesetOptions({"no-resolve"}).no_resolve);

    return 0;
}
