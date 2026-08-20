#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "utils/logger.h"
#include "utils/concurrent_lru_cache.h"
#include "utils/cooperative_cpu.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/rapidjson_extra.h"
#include "subexport.h"

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

size_t rulesetConversionCacheMaxEntries()
{
    return kRulesetConversionCacheEntries;
}

size_t rulesetConversionCacheMaxBytes()
{
    return kRulesetConversionCacheBytes;
}

static bool isClashCommaPayloadRule(const std::string &rule_type)
{
    return rule_type == "AND" || rule_type == "OR" || rule_type == "NOT" ||
           rule_type == "SUB-RULE" || rule_type == "DOMAIN-REGEX" ||
           rule_type == "PROCESS-NAME-REGEX" || rule_type == "PROCESS-PATH-REGEX";
}

std::string appendClashRuleTarget(const std::string &rule, const std::string &target, bool no_resolve_only)
{
    std::string strLine = trimWhitespace(rule, true, true);
    std::string::size_type pos = strLine.find(',');
    std::string rule_type = toUpper(trimWhitespace(pos == std::string::npos ? strLine : strLine.substr(0, pos), true, true));

    if(rule_type == "FINAL" || rule_type == "MATCH")
        return "MATCH," + target;

    if(pos == std::string::npos || isClashCommaPayloadRule(rule_type))
        return strLine + "," + target;

    string_view_array temp;
    split(temp, strLine, ',');
    if(temp.size() < 2)
        return strLine + "," + target;

    std::string output = std::string(temp[0]) + "," + std::string(temp[1]) + "," + target;
    if(temp.size() > 2)
    {
        std::string option = trimWhitespace(std::string(temp[2]), true, true);
        if(!no_resolve_only || option == "no-resolve")
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
        writeLog(LOG_LEVEL_WARNING,
                 "规则集选项 no-resolve 不支持 " + target +
                     " 输出，已对策略组 '" + ruleset.rule_group +
                     "' 安全忽略。");
    }
}

namespace {

struct StashNativeRulesetContract
{
    std::string behavior;
    std::string format;
    std::string extension;
};

bool inferStashNativeRulesetContract(const RulesetContent &ruleset,
                                     StashNativeRulesetContract &contract)
{
    if(ruleset.delivery != RulesetDelivery::NativeStashProvider ||
       (!startsWith(ruleset.rule_path, "https://") &&
        !startsWith(ruleset.rule_path, "http://")))
        return false;

    switch(ruleset.rule_type)
    {
    case RULESET_CLASH_DOMAIN:
        contract.behavior = "domain";
        break;
    case RULESET_CLASH_IPCIDR:
        contract.behavior = "ipcidr";
        break;
    case RULESET_CLASH_CLASSICAL:
        contract.behavior = "classical";
        break;
    default:
        return false;
    }

    std::string path = ruleset.rule_path;
    const size_t query = path.find_first_of("?#");
    if(query != std::string::npos)
        path.erase(query);
    const std::string explicit_format = ruleset.options.stash_format;
    const size_t slash = path.find_last_of('/');
    const size_t dot = path.find_last_of('.');
    const std::string extension =
        dot == std::string::npos ||
                (slash != std::string::npos && dot < slash + 1)
            ? ""
            : toLower(path.substr(dot));
    if(explicit_format.empty() && extension.empty())
        return false;
    if(explicit_format == "mrs" ||
       (explicit_format.empty() && extension == ".mrs"))
    {
        if(contract.behavior == "classical")
            return false;
        contract.format = "mrs";
        contract.extension = ".mrs";
    }
    else if(explicit_format == "yaml" ||
            (explicit_format.empty() &&
             (extension == ".yaml" || extension == ".yml")))
    {
        contract.format = "yaml";
        contract.extension = ".yaml";
    }
    else if(explicit_format == "text")
    {
        contract.format = "text";
        contract.extension = ".txt";
    }
    else
        return false;
    return true;
}

std::string stashRulesetStem(const std::string &url)
{
    std::string path = url;
    const size_t query = path.find_first_of("?#");
    if(query != std::string::npos)
        path.erase(query);
    const size_t slash = path.find_last_of('/');
    std::string name = path.substr(slash == std::string::npos ? 0 : slash + 1);
    const size_t dot = name.find_last_of('.');
    if(dot != std::string::npos)
        name.erase(dot);

    std::string safe;
    safe.reserve(std::min<size_t>(name.size(), 48));
    bool last_separator = false;
    for(unsigned char ch : name)
    {
        if(safe.size() >= 48)
            break;
        if(std::isalnum(ch) || ch == '-' || ch == '_')
        {
            safe.push_back(static_cast<char>(ch));
            last_separator = false;
        }
        else if(!safe.empty() && !last_separator)
        {
            safe.push_back('_');
            last_separator = true;
        }
    }
    while(!safe.empty() && safe.back() == '_')
        safe.pop_back();
    return safe.empty() ? "SubConverter_Rule" : safe;
}

bool stashRulesetScalarIsSafe(const std::string &value)
{
    if(value.empty() || value != trimWhitespace(value, true, true))
        return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 0x20 || ch == 0x7f;
    });
}

bool stashRulesetGroupIsSafe(const std::string &value)
{
    return stashRulesetScalarIsSafe(value) &&
           value.find(',') == std::string::npos;
}

bool normalizeStashRule(std::string rule, const std::string &group,
                        const RulesetOptions &options, std::string &output)
{
    rule = trimWhitespace(rule, true, true);
    if(rule.empty())
        return false;
    string_array fields = split(rule, ",");
    for(std::string &field : fields)
    {
        field = trimWhitespace(field, true, true);
        if(!stashRulesetScalarIsSafe(field))
            return false;
    }
    if(fields.empty())
        return false;
    const std::string type = toUpper(fields[0]);
    static const std::unordered_set<std::string> allowed_types = {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
        "DOMAIN-REGEX", "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-ASN",
        "GEOIP", "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT",
        "URL-REGEX", "NETWORK", "PROTOCOL", "DST-PORT", "MATCH",
        "FINAL"};
    if(allowed_types.find(type) == allowed_types.end())
        return false;

    const bool terminal_rule = type == "MATCH" || type == "FINAL";
    if((terminal_rule && fields.size() != 1) ||
       (!terminal_rule && (fields.size() < 2 || fields[1].empty())))
        return false;

    const bool supports_no_resolve =
        type == "GEOIP" || type == "IP-CIDR" || type == "IP-CIDR6" ||
        type == "IP-ASN";
    bool no_resolve = options.no_resolve && supports_no_resolve;
    bool explicit_no_resolve = false;
    bool no_track = false;
    for(size_t index = 2; index < fields.size(); ++index)
    {
        const std::string option = toLower(fields[index]);
        if(option == "no-resolve" && supports_no_resolve &&
           !explicit_no_resolve)
        {
            no_resolve = true;
            explicit_no_resolve = true;
        }
        else if(option == "no-track" && !no_track)
            no_track = true;
        else
            return false;
    }

    if(type == "GEOIP")
    {
        const std::string &country = fields[1];
        if(country.size() != 2 ||
           !std::all_of(country.begin(), country.end(), [](unsigned char ch) {
               return std::isalpha(ch) != 0;
           }))
            return false;
    }

    output = terminal_rule ? "MATCH," + group
                           : type + "," + fields[1] + "," + group;
    if(no_resolve)
        output += ",no-resolve";
    if(no_track)
        output += ",no-track";
    return true;
}

} // namespace

bool rulesetToStash(YAML::Node &base_rule,
                    const std::vector<RulesetContent> &ruleset_content_array,
                    bool overwrite_original_rules,
                    StashRuleConversionStats &stash_stats,
                    RuleConversionStats *stats,
                    std::string &error)
{
    stash_stats = StashRuleConversionStats{};
    stash_stats.input_sources = ruleset_content_array.size();
    error.clear();
    const size_t max_allowed_rules = effectiveSettings().maxAllowedRules;

    auto fail = [&](const std::string &english, const std::string &chinese) {
        stash_stats.unsupported_sources++;
        error = "Invalid request: " + english + ".\n无效请求：" + chinese + "。";
        return false;
    };

    YAML::Node rules(YAML::NodeType::Sequence);
    YAML::Node terminal_rules(YAML::NodeType::Sequence);
    if(!overwrite_original_rules && base_rule["rules"].IsSequence())
    {
        bool terminal_seen = false;
        for(const YAML::Node &entry : base_rule["rules"])
        {
            if(!entry.IsScalar())
                return fail("the selected Stash base contains a non-scalar rule",
                            "所选 Stash 基础模板包含非标量规则");
            const std::string value = trimWhitespace(
                entry.as<std::string>(), true, true);
            const size_t separator = value.find(',');
            const std::string type = toUpper(trimWhitespace(
                separator == std::string::npos ? value
                                               : value.substr(0, separator),
                true, true));
            if(type == "MATCH" || type == "FINAL")
                terminal_seen = true;
            (terminal_seen ? terminal_rules : rules).push_back(entry);
        }
    }
    YAML::Node providers = base_rule["rule-providers"].IsMap()
                               ? YAML::Clone(base_rule["rule-providers"])
                               : YAML::Node(YAML::NodeType::Map);
    rules.SetStyle(YAML::EmitterStyle::Block);
    providers.SetStyle(YAML::EmitterStyle::Block);
    if(max_allowed_rules &&
       rules.size() + terminal_rules.size() > max_allowed_rules)
        return fail("the selected Stash base exceeds max_allowed_rules",
                    "所选 Stash 基础模板超过 max_allowed_rules 限制");

    std::unordered_set<std::string> provider_names;
    std::unordered_set<std::string> provider_paths;
    if(base_rule["rule-providers"].IsDefined() &&
       !base_rule["rule-providers"].IsNull() &&
       !base_rule["rule-providers"].IsMap())
        return fail("the selected Stash base has an invalid rule-providers field",
                    "所选 Stash 基础模板的 rule-providers 字段无效");
    for(const auto &entry : providers)
    {
        if(!entry.first.IsScalar() || !entry.second.IsMap())
            return fail("the selected Stash base contains an invalid rule-provider",
                        "所选 Stash 基础模板包含无效的 rule-provider");
        const std::string name = entry.first.as<std::string>();
        if(!provider_names.insert(toLower(name)).second)
            return fail("the selected Stash base contains duplicate rule-provider names",
                        "所选 Stash 基础模板包含重复的 rule-provider 名称");
        const YAML::Node path = entry.second["path"];
        if(path.IsDefined() && !path.IsNull())
        {
            if(!path.IsScalar() ||
               !provider_paths.insert(toLower(path.as<std::string>())).second)
                return fail("the selected Stash base contains conflicting rule-provider paths",
                            "所选 Stash 基础模板包含冲突的 rule-provider 路径");
        }
    }

    RuleConversionStats local_stats;
    for(const RulesetContent &source : ruleset_content_array)
    {
        if(max_allowed_rules &&
           rules.size() + terminal_rules.size() >= max_allowed_rules)
            return fail("the final Stash rule count exceeds max_allowed_rules",
                        "最终 Stash 规则数量超过 max_allowed_rules 限制");

        if(source.delivery == RulesetDelivery::NativeStashProvider)
        {
            StashNativeRulesetContract contract;
            if(!inferStashNativeRulesetContract(source, contract) ||
               !stashRulesetScalarIsSafe(source.rule_path) ||
               !stashRulesetGroupIsSafe(source.rule_group))
                return fail("a Stash rule-provider source has an unsupported format or unsafe value",
                            "Stash rule-provider 来源的格式不受支持或包含不安全值");

            const std::string stem = stashRulesetStem(source.rule_path);
            std::string name = stem;
            size_t suffix = 2;
            while(provider_names.find(toLower(name)) != provider_names.end())
                name = stem + "_" + std::to_string(suffix++);
            const std::string path = "./rules/" + name + contract.extension;
            if(!provider_paths.insert(toLower(path)).second)
                return fail("generated Stash rule-provider paths conflict",
                            "生成的 Stash rule-provider 路径发生冲突");
            provider_names.insert(toLower(name));

            YAML::Node item;
            item.SetStyle(YAML::EmitterStyle::Block);
            item["behavior"] = contract.behavior;
            item["format"] = contract.format;
            item["url"] = source.rule_path;
            item["path"] = path;
            if(source.update_interval > 0)
                item["interval"] = source.update_interval;
            providers[name] = item;
            rules.push_back(buildClashRuleSetReference(
                name, source.rule_group, source.rule_type, source.options));
            stash_stats.providerized_sources++;
            stash_stats.provider_references++;
            stash_stats.emitted_rules++;
            local_stats.add();
            continue;
        }

        std::string retrieved = waitWithoutCpuPermit(
            [&] { return source.rule_content.get(); });
        if(!stashRulesetGroupIsSafe(source.rule_group))
            return fail("a Stash ruleset policy name contains an unsafe value",
                        "Stash 规则集的策略名称包含不安全值");
        if(retrieved.empty())
            return fail("a Stash ruleset could not be fetched or was empty",
                        "Stash 规则集获取失败或内容为空");
        if(source.rule_path.empty())
            stash_stats.inline_sources++;
        else
        {
            stash_stats.expanded_sources++;
        }
        if(startsWith(retrieved, "[]"))
            retrieved.erase(0, 2);
        else
            retrieved = convertRuleset(retrieved, source.rule_type);

        std::stringstream stream(retrieved);
        std::string line;
        const char delimiter = getLineBreak(retrieved);
        bool emitted_source_rule = false;
        while(getline(stream, line, delimiter))
        {
            line = trimWhitespace(line, true, true);
            if(line.empty() || line[0] == ';' || line[0] == '#' ||
               (line.size() >= 2 && line[0] == '/' && line[1] == '/'))
                continue;
            std::string normalized;
            if(!normalizeStashRule(line, source.rule_group, source.options,
                                   normalized))
                return fail("a Stash ruleset contains an unsupported or invalid rule",
                            "Stash 规则集包含不受支持或无效的规则");
            if(max_allowed_rules &&
               rules.size() + terminal_rules.size() >= max_allowed_rules)
                return fail("the final Stash rule count exceeds max_allowed_rules",
                            "最终 Stash 规则数量超过 max_allowed_rules 限制");
            rules.push_back(normalized);
            stash_stats.emitted_rules++;
            local_stats.add();
            emitted_source_rule = true;
        }
        if(!emitted_source_rule)
            return fail("a Stash ruleset did not contain any supported rules",
                        "Stash 规则集不包含任何受支持的规则");
    }

    for(const YAML::Node &entry : terminal_rules)
        rules.push_back(entry);
    stash_stats.final_provider_count = providers.size();
    base_rule["rules"] = rules;
    base_rule["rule-providers"] = providers;
    if(stats)
        stats->add(local_stats.rules);
    return true;
}

void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    string_array allRules;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    const size_t max_allowed_rules = effectiveSettings().maxAllowedRules;
    YAML::Node rules;
    size_t total_rules = 0;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
        rules = base_rule[field_name];

    for(RulesetContent &x : ruleset_content_array)
    {
        if(max_allowed_rules && total_rules > max_allowed_rules)
            break;
        rule_group = x.rule_group;
        retrieved_rules =
            waitWithoutCpuPermit([&] { return x.rule_content.get(); });
        if(retrieved_rules.empty())
        {
            writeLog(LOG_LEVEL_WARNING, "获取规则集失败或规则集为空：'" + x.rule_path + "'。");
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            strLine = appendClashRuleTarget(strLine, rule_group);
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
            if(max_allowed_rules && total_rules > max_allowed_rules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            strLine = appendClashRuleTarget(strLine, rule_group);
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
    const size_t max_allowed_rules = effectiveSettings().maxAllowedRules;
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
        if(max_allowed_rules && total_rules > max_allowed_rules)
            break;
        rule_group = x.rule_group;
        retrieved_rules =
            waitWithoutCpuPermit([&] { return x.rule_content.get(); });
        if(retrieved_rules.empty())
        {
            writeLog(LOG_LEVEL_WARNING, "获取规则集失败或规则集为空：'" + x.rule_path + "'。");
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            strLine = appendClashRuleTarget(strLine, rule_group);
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
            if(max_allowed_rules && total_rules > max_allowed_rules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){ return startsWith(strLine, type); }))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            strLine = appendClashRuleTarget(strLine, rule_group);
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
    const size_t max_allowed_rules = effectiveSettings().maxAllowedRules;
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
        if(max_allowed_rules && total_rules > max_allowed_rules)
            break;
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = waitWithoutCpuPermit(
                          [&] { return x.rule_content.get(); })
                          .substr(2);
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
            retrieved_rules =
                waitWithoutCpuPermit([&] { return x.rule_content.get(); });
            if(retrieved_rules.empty())
            {
                writeLog(LOG_LEVEL_WARNING, "获取规则集失败或规则集为空：'" + x.rule_path + "'。");
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            while(getline(strStrm, strLine, delimiter))
            {
                if(max_allowed_rules && total_rules > max_allowed_rules)
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

namespace {

enum class SingBoxRuleValueKind { String, Integer, Boolean };

struct SingBoxRuleBucket {
    std::string field;
    SingBoxRuleValueKind kind = SingBoxRuleValueKind::String;
    bool match_rule_set_source = false;
    std::vector<std::string> values;
};

bool singBoxRuleSetCodeSafe(const std::string &value) {
    return !value.empty() &&
           regMatch(value, R"(^[a-z0-9][a-z0-9._@!+-]*$)");
}

std::string singBoxRuleSetTag(const std::string &family,
                              const std::string &value) {
    return family + "-" + value;
}

bool parseSingBoxRuleInteger(const std::string &value, uint32_t maximum,
                             uint32_t &parsed) {
    if (value.empty())
        return false;
    const char *begin = value.data();
    const char *end = begin + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    return result.ec == std::errc{} && result.ptr == end &&
           parsed <= maximum;
}

bool appendSingBoxRule(std::vector<std::string_view> &args,
                       std::map<std::string, SingBoxRuleBucket> &buckets,
                       std::set<std::string> &geosite_codes,
                       std::set<std::string> &geoip_codes,
                       const std::string &rule, std::string &final,
                       const std::string &rule_group) {
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2)
        return false;

    const std::string type = toUpper(trimWhitespace(std::string(args[0])));
    std::string value = toLower(trimWhitespace(std::string(args[1])));
    if (none_of(SingBoxRuleTypes, [&](const std::string &candidate) {
          return type == candidate;
        }))
        return false;

    if (type == "MATCH" || type == "FINAL") {
        final = rule_group;
        return true;
    }

    std::string field;
    SingBoxRuleValueKind kind = SingBoxRuleValueKind::String;
    bool match_rule_set_source = false;
    if (type == "DOMAIN")
        field = "domain";
    else if (type == "DOMAIN-SUFFIX")
        field = "domain_suffix";
    else if (type == "DOMAIN-KEYWORD")
        field = "domain_keyword";
    else if (type == "DOMAIN-REGEX")
        field = "domain_regex";
    else if (type == "IP-CIDR" || type == "IP-CIDR6")
        field = "ip_cidr";
    else if (type == "SRC-IP-CIDR")
        field = "source_ip_cidr";
    else if (type == "IP-VERSION") {
        uint32_t parsed = 0;
        if ((value != "4" && value != "6") ||
            !parseSingBoxRuleInteger(value, 6, parsed) ||
            (parsed != 4 && parsed != 6))
            return false;
        field = "ip_version";
        kind = SingBoxRuleValueKind::Integer;
    } else if (type == "INBOUND")
        field = "inbound";
    else if (type == "PROTOCOL")
        field = "protocol";
    else if (type == "NETWORK")
        field = "network";
    else if (type == "PROCESS-NAME")
        field = "process_name";
    else if (type == "PROCESS-PATH")
        field = "process_path";
    else if (type == "PACKAGE-NAME")
        field = "package_name";
    else if (type == "PORT" || type == "SRC-PORT" || type == "USER-ID") {
        const uint32_t maximum = type == "USER-ID"
            ? std::numeric_limits<uint32_t>::max()
            : 65535U;
        uint32_t parsed = 0;
        if (!parseSingBoxRuleInteger(value, maximum, parsed))
            return false;
        field = type == "PORT" ? "port"
                 : type == "SRC-PORT" ? "source_port"
                                        : "user_id";
        kind = SingBoxRuleValueKind::Integer;
    } else if (type == "PORT-RANGE")
        field = "port_range";
    else if (type == "SRC-PORT-RANGE")
        field = "source_port_range";
    else if (type == "USER")
        field = "auth_user";
    else if (type == "GEOSITE") {
        if (!singBoxRuleSetCodeSafe(value))
            return false;
        field = "rule_set";
        value = singBoxRuleSetTag("geosite", value);
        geosite_codes.emplace(value.substr(std::string("geosite-").size()));
    } else if (type == "GEOIP" || type == "SRC-GEOIP") {
        const bool source = type == "SRC-GEOIP";
        if (value == "private") {
            field = source ? "source_ip_is_private" : "ip_is_private";
            value = "true";
            kind = SingBoxRuleValueKind::Boolean;
        } else {
            if (!singBoxRuleSetCodeSafe(value))
                return false;
            field = "rule_set";
            match_rule_set_source = source;
            value = singBoxRuleSetTag("geoip", value);
            geoip_codes.emplace(value.substr(std::string("geoip-").size()));
        }
    } else {
        return false;
    }

    const std::string bucket_key = field +
        (match_rule_set_source ? ":source" : ":destination");
    auto &bucket = buckets[bucket_key];
    bucket.field = field;
    bucket.kind = kind;
    bucket.match_rule_set_source = match_rule_set_source;
    if (std::find(bucket.values.begin(), bucket.values.end(), value) ==
        bucket.values.end())
        bucket.values.emplace_back(std::move(value));
    return true;
}

void emitSingBoxRuleBuckets(
    const std::map<std::string, SingBoxRuleBucket> &buckets,
    const std::string &outbound, rapidjson::Value &rules,
    rapidjson::MemoryPoolAllocator<> &allocator) {
    for (const auto &[key, bucket] : buckets) {
        (void)key;
        rapidjson::Value rule(rapidjson::kObjectType);
        rapidjson::Value field_name(bucket.field.c_str(), allocator);
        if (bucket.kind == SingBoxRuleValueKind::Boolean) {
            rule.AddMember(field_name, true, allocator);
        } else if (bucket.kind == SingBoxRuleValueKind::Integer &&
                   bucket.values.size() == 1) {
            uint32_t parsed = 0;
            parseSingBoxRuleInteger(bucket.values.front(),
                                    std::numeric_limits<uint32_t>::max(),
                                    parsed);
            rule.AddMember(field_name, parsed, allocator);
        } else {
            rapidjson::Value values(rapidjson::kArrayType);
            for (const std::string &value : bucket.values) {
                if (bucket.kind == SingBoxRuleValueKind::Integer) {
                    uint32_t parsed = 0;
                    parseSingBoxRuleInteger(
                        value, std::numeric_limits<uint32_t>::max(), parsed);
                    values.PushBack(parsed, allocator);
                } else {
                    values.PushBack(rapidjson::Value(value.c_str(), allocator),
                                    allocator);
                }
            }
            rule.AddMember(field_name, values, allocator);
        }
        if (bucket.match_rule_set_source)
            rule.AddMember("rule_set_ip_cidr_match_source", true, allocator);
        rule.AddMember("action", "route", allocator);
        rule.AddMember("outbound",
                       rapidjson::Value(outbound.c_str(), allocator), allocator);
        rules.PushBack(rule, allocator);
    }
}

void appendSingBoxRemoteRuleSet(
    rapidjson::Value &rule_sets, std::set<std::string> &existing_tags,
    const std::string &family, const std::string &code,
    rapidjson::MemoryPoolAllocator<> &allocator) {
    const std::string tag = singBoxRuleSetTag(family, code);
    if (!existing_tags.emplace(tag).second)
        return;
    rapidjson::Value rule_set(rapidjson::kObjectType);
    rule_set.AddMember("type", "remote", allocator);
    rule_set.AddMember("tag", rapidjson::Value(tag.c_str(), allocator),
                       allocator);
    rule_set.AddMember("format", "binary", allocator);
    const std::string url =
        "https://raw.githubusercontent.com/SagerNet/sing-" + family +
        "/rule-set/" + tag + ".srs";
    rule_set.AddMember("url", rapidjson::Value(url.c_str(), allocator),
                       allocator);
    rule_set.AddMember("download_detour", "DIRECT", allocator);
    rule_sets.PushBack(rule_set, allocator);
}

bool preserveSingBoxBaseActionRule(const rapidjson::Value &rule) {
    if (!rule.IsObject() || !rule.HasMember("action") ||
        !rule["action"].IsString())
        return false;
    const std::string action = rule["action"].GetString();
    return action == "sniff" || action == "hijack-dns" ||
           action == "resolve" || action == "route-options";
}

} // namespace

void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, RuleConversionStats *stats)
{
    RuleConversionStats local_stats;
    warnNoResolveIgnoredForTarget(ruleset_content_array, "sing-box");
    using namespace rapidjson_ext;
    std::string rule_group, retrieved_rules, strLine, final;
    std::stringstream strStrm;
    const Settings &settings = effectiveSettings();
    size_t total_rules = 0;
    auto &allocator = base_rule.GetAllocator();

    if (base_rule.HasMember("route") && !base_rule["route"].IsObject())
        base_rule.RemoveMember("route");
    if (!base_rule.HasMember("route"))
        base_rule.AddMember("route", rapidjson::Value(rapidjson::kObjectType),
                            allocator);

    rapidjson::Value rules(rapidjson::kArrayType);
    if (base_rule["route"].HasMember("rules") &&
        base_rule["route"]["rules"].IsArray()) {
        if (!overwrite_original_rules) {
            rules.Swap(base_rule["route"]["rules"]);
        } else {
            for (const rapidjson::Value &base_item :
                 base_rule["route"]["rules"].GetArray()) {
                if (!preserveSingBoxBaseActionRule(base_item))
                    continue;
                rapidjson::Value copy(rapidjson::kObjectType);
                copy.CopyFrom(base_item, allocator);
                rules.PushBack(copy, allocator);
            }
        }
    }

    if (settings.singBoxAddClashModes)
    {
        auto global_object = buildObject(allocator, "clash_mode", "Global",
                                         "action", "route", "outbound", "GLOBAL");
        auto direct_object = buildObject(allocator, "clash_mode", "Direct",
                                         "action", "route", "outbound", "DIRECT");
        rules.PushBack(global_object, allocator);
        rules.PushBack(direct_object, allocator);
    }

    // auto dns_object = buildObject(allocator, "protocol", "dns", "outbound", "dns-out");
    // rules.PushBack(dns_object, allocator);

    std::vector<std::string_view> temp(4);
    std::set<std::string> geosite_codes, geoip_codes;
    for(RulesetContent &x : ruleset_content_array)
    {
        if(settings.maxAllowedRules && total_rules > settings.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules =
            waitWithoutCpuPermit([&] { return x.rule_content.get(); });
        if(retrieved_rules.empty())
        {
            writeLog(LOG_LEVEL_WARNING, "获取规则集失败或规则集为空：'" + x.rule_path + "'。");
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            std::map<std::string, SingBoxRuleBucket> buckets;
            if (appendSingBoxRule(temp, buckets, geosite_codes, geoip_codes,
                                  strLine, final, rule_group)) {
                emitSingBoxRuleBuckets(buckets, rule_group, rules, allocator);
                total_rules++;
                local_stats.add();
            }
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;

        std::string::size_type lineSize;
        std::map<std::string, SingBoxRuleBucket> buckets;

        while(getline(strStrm, strLine, delimiter))
        {
            if(settings.maxAllowedRules && total_rules > settings.maxAllowedRules)
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
            if (appendSingBoxRule(temp, buckets, geosite_codes, geoip_codes,
                                  strLine, final, rule_group))
            {
                total_rules++;
                local_stats.add();
            }
        }
        emitSingBoxRuleBuckets(buckets, rule_group, rules, allocator);
    }

    rapidjson::Value rule_sets(rapidjson::kArrayType);
    std::set<std::string> existing_tags;
    if (base_rule["route"].HasMember("rule_set") &&
        base_rule["route"]["rule_set"].IsArray()) {
        rule_sets.Swap(base_rule["route"]["rule_set"]);
        for (const rapidjson::Value &rule_set : rule_sets.GetArray()) {
            if (rule_set.IsObject() && rule_set.HasMember("tag") &&
                rule_set["tag"].IsString())
                existing_tags.emplace(rule_set["tag"].GetString());
        }
    }
    for (const std::string &code : geosite_codes)
        appendSingBoxRemoteRuleSet(rule_sets, existing_tags, "geosite", code,
                                   allocator);
    for (const std::string &code : geoip_codes)
        appendSingBoxRemoteRuleSet(rule_sets, existing_tags, "geoip", code,
                                   allocator);

    auto finalValue = rapidjson::Value(final.c_str(), allocator);
    base_rule["route"]
    | AddMemberOrReplace("rules", rules, allocator)
    | AddMemberOrReplace("rule_set", rule_sets, allocator)
    | AddMemberOrReplace("final", finalValue, allocator);
    if(stats)
        stats->add(local_stats.rules);
}
