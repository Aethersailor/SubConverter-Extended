#include <string>
#include <algorithm>
#include <map>
#include <sstream>
#include <filesystem>
#include <unordered_set>
#include <inja.hpp>
#include <nlohmann/json.hpp>

#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/settings_view.h"
#include "handler/webget.h"
#include "server/request_context.h"
#include "utils/logger.h"
#include "utils/cooperative_cpu.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/regexp.h"
#include "utils/string_hash.h"
#include "utils/time_compat.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "templates.h"

// 在 ruleconvert.cpp 中定义的全局规则类型白名单
extern string_array ClashRuleTypes;

static thread_local FetchContext current_template_fetch_context =
    FetchContext::TrustedConfig;
static thread_local bool *current_template_fetch_failed = nullptr;
static constexpr std::size_t rule_provider_file_name_max_length = 64;
static constexpr std::size_t rule_provider_url_hash_hex_length = 16;

static std::string ruleProviderUrlFingerprint(const std::string &source_url)
{
    static constexpr char hex[] = "0123456789abcdef";
    hash_t value = hash_(source_url);
    std::string result(rule_provider_url_hash_hex_length, '0');
    for(std::size_t index = result.size(); index > 0; --index)
    {
        result[index - 1] = hex[value & 0x0f];
        value >>= 4;
    }
    return result;
}

static bool hasExtension(const std::string &path_or_url,
                         const std::string &extension)
{
    size_t path_end = path_or_url.find_first_of("?#");
    std::string path = path_or_url.substr(0, path_end);
    size_t slash = path.rfind('/');
    size_t dot = path.rfind('.');
    return dot != std::string::npos &&
           (slash == std::string::npos || dot > slash) &&
           toLower(path.substr(dot)) == extension;
}

static bool isRuleProviderFileNameCharacter(unsigned char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

static std::string sanitizeRuleProviderFileName(const std::string &name)
{
    std::string result;
    result.reserve(std::min(name.size(), rule_provider_file_name_max_length));
    bool pending_separator = false;
    for(unsigned char c : name)
    {
        if(isRuleProviderFileNameCharacter(c))
        {
            if(pending_separator && !result.empty())
                result += '_';
            result += static_cast<char>(c);
            pending_separator = false;
        }
        else
            pending_separator = true;
    }

    const std::string trim_characters = "._-";
    const std::size_t first = result.find_first_not_of(trim_characters);
    if(first == std::string::npos)
        return "provider";
    result.erase(0, first);
    const std::size_t last = result.find_last_not_of(trim_characters);
    result.erase(last + 1);
    if(result.size() > rule_provider_file_name_max_length)
    {
        result.resize(rule_provider_file_name_max_length);
        const std::size_t truncated_last =
            result.find_last_not_of(trim_characters);
        if(truncated_last == std::string::npos)
            return "provider";
        result.erase(truncated_last + 1);
    }
    return result.empty() ? "provider" : result;
}

static std::string normalizeRuleProviderPathKey(std::string path)
{
    std::replace(path.begin(), path.end(), '\\', '/');
    while(startsWith(path, "./"))
        path.erase(0, 2);
    for(char &c : path)
    {
        if(c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return path;
}

static std::unordered_set<std::string>
collectRuleProviderPaths(const YAML::Node &base_rule)
{
    std::unordered_set<std::string> paths;
    YAML::Node providers;
    if(base_rule.IsMap())
    {
        for(const auto &entry : base_rule)
        {
            if(entry.first.IsScalar() &&
               entry.first.as<std::string>() == "rule-providers")
            {
                providers = entry.second;
                break;
            }
        }
    }
    if(!providers.IsMap())
        return paths;
    for(const auto &provider : providers)
    {
        if(!provider.second.IsMap())
            continue;
        const YAML::Node path = provider.second["path"];
        if(path.IsScalar())
            paths.emplace(normalizeRuleProviderPathKey(path.as<std::string>()));
    }
    return paths;
}

static std::string reserveRuleProviderPath(
    const std::string &provider_name, const std::string &behavior,
    const std::string &source_url, const std::string &extension,
    std::unordered_set<std::string> &used_paths)
{
    const std::string safe_name =
        sanitizeRuleProviderFileName(provider_name);
    const std::string url_hash =
        ruleProviderUrlFingerprint(source_url);
    for(std::size_t index = 1;; ++index)
    {
        std::string unique_name = safe_name;
        if(index > 1)
            unique_name += "-" + std::to_string(index);
        const std::string path =
            "./providers/" + unique_name + "-" + behavior + "-" +
            url_hash + "." + extension;
        if(used_paths.emplace(normalizeRuleProviderPathKey(path)).second)
            return path;
    }
}

namespace inja
{
    void convert_dot_to_json_pointer(std::string_view dot, std::string& out)
    {
        out = DataNode::convert_dot_to_ptr(dot);
    }
}

static inline void parse_json_pointer(nlohmann::json &json, const std::string &path, const std::string &value)
{
    std::string pointer;
    inja::convert_dot_to_json_pointer(path, pointer);
    try
    {
        json[nlohmann::json::json_pointer(pointer)] = value;
    }
    catch (std::exception&)
    {
        //ignore broken pointer
    }
}

static bool path_is_inside_scope(const std::filesystem::path &path,
                                 const std::filesystem::path &scope)
{
    try
    {
        std::filesystem::path relative = std::filesystem::relative(path, scope);
        std::string rel = relative.generic_string();
        return rel == "." ||
               (!relative.is_absolute() && rel != ".." &&
                !startsWith(rel, "../"));
    }
    catch(std::exception &)
    {
        return false;
    }
}

static std::string python_string_escape(const std::string &value)
{
    static const char hex[] = "0123456789abcdef";
    std::string escaped;
    escaped.reserve(value.size());
    for(unsigned char c : value)
    {
        switch(c)
        {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\'':
            escaped += "\\'";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if(c < 0x20)
            {
                escaped += "\\x";
                escaped += hex[c >> 4];
                escaped += hex[c & 0x0f];
            }
            else
                escaped += static_cast<char>(c);
        }
    }
    return escaped;
}

static std::string python_string_literal(const std::string &value)
{
    return "\"" + python_string_escape(value) + "\"";
}

/*
std::string parseHostname(inja::Arguments &args)
{
    std::string data = args.at(0)->get<std::string>(), hostname;
    const std::string matcher = R"(^(?i:hostname\s*?=\s*?)(.*?)\s$)";
    string_array urls = split(data, ",");
    if(!urls.size())
        return std::string();

    std::string input_content, output_content;
    const Settings &settings = effectiveSettings();
    ProxyPolicy proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
    for(std::string &x : urls)
    {
        input_content = webGet(x, proxy, settings.cacheConfig);
        regGetMatch(input_content, matcher, 2, 0, &hostname);
        if(hostname.size())
        {
            output_content += hostname + ",";
            hostname.clear();
        }
    }
    string_array vArray = split(output_content, ",");
    std::set<std::string> hostnames;
    for(std::string &x : vArray)
        hostnames.emplace(trim(x));
    output_content = std::accumulate(hostnames.begin(), hostnames.end(), std::string(), [](std::string a, std::string b)
    {
        return std::move(a) + "," + std::move(b);
    });
    return output_content;
}*/

#ifndef NO_WEBGET
std::string template_webGet(inja::Arguments &args)
{
    std::string data = args.at(0)->get<std::string>();
    const Settings &settings = effectiveSettings();
    ProxyPolicy proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
    writeLog(LOG_LEVEL_INFO, "模板调用 fetch：" + summarizeUrlForLog(data) + "。");
    std::string content =
        webGet(data, proxy, settings.cacheConfig, nullptr, nullptr,
               current_template_fetch_context);
    if(content.empty() && current_template_fetch_failed)
        *current_template_fetch_failed = true;
    return content;
}
#endif // NO_WEBGET

int render_template(const std::string &content, const template_args &vars,
                    std::string &output, const std::string &include_scope,
                    FetchContext context, bool *fetch_failed)
{
    RequestStageTimer template_timer(RequestStage::Template);
    struct TemplateFetchContextGuard
    {
        FetchContext previous;
        bool *previous_fetch_failed;
        TemplateFetchContextGuard(FetchContext context, bool *fetch_failed)
            : previous(current_template_fetch_context),
              previous_fetch_failed(current_template_fetch_failed)
        {
            current_template_fetch_context = context;
            current_template_fetch_failed = fetch_failed;
        }
        ~TemplateFetchContextGuard()
        {
            current_template_fetch_context = previous;
            current_template_fetch_failed = previous_fetch_failed;
        }
    } guard(context, fetch_failed);

    if(fetch_failed)
        *fetch_failed = false;

    std::string absolute_scope;
    try
    {
        if(!include_scope.empty())
            absolute_scope = std::filesystem::canonical(include_scope).string();
    }
    catch(std::exception &e)
    {
        writeLog(LOG_LEVEL_ERROR,
                 "TEMPLATE_SCOPE_RESOLUTION_FAILED detail=" +
                     summarizeSensitiveTextForLog(e.what()));
    }
    nlohmann::json data;
    for(auto &x : vars.global_vars)
        parse_json_pointer(data["global"], x.first, x.second);
    std::string all_args;
    for(auto &x : vars.request_params)
    {
        all_args += x.first;
        if(!x.second.empty())
        {
            parse_json_pointer(data["request"], x.first, x.second);
            all_args += "=" + x.second;
        }
        all_args += "&";
    }
    all_args.erase(all_args.size() - 1);
    parse_json_pointer(data["request"], "_args", all_args);
    for(auto &x : vars.local_vars)
        parse_json_pointer(data["local"], x.first, x.second);

    inja::Environment env;

    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);
    env.set_line_statement("#~#");
    env.add_callback("UrlEncode", 1, [](inja::Arguments &args)
    {
        std::string data = args.at(0)->get<std::string>();
        return urlEncode(data);
    });
    env.add_callback("UrlDecode", 1, [](inja::Arguments &args)
    {
        std::string data = args.at(0)->get<std::string>();
        return urlDecode(data);
    });
    env.add_callback("trim_of", 2, [](inja::Arguments &args)
    {
        std::string data = args.at(0)->get<std::string>(), target = args.at(1)->get<std::string>();
        if(target.empty())
            return data;
        return trimOf(data, target[0]);
    });
    env.add_callback("trim", 1, [](inja::Arguments &args)
    {
        std::string data = args.at(0)->get<std::string>();
        return trim(data);
    });
    env.add_callback("find", 2, [](inja::Arguments &args)
    {
        std::string src = args.at(0)->get<std::string>(), target = args.at(1)->get<std::string>();
        return regFind(src, target);
    });
    env.add_callback("replace", 3, [](inja::Arguments &args)
    {
        std::string src = args.at(0)->get<std::string>(), target = args.at(1)->get<std::string>(), rep = args.at(2)->get<std::string>();
        if(target.empty() || src.empty())
            return src;
        return regReplace(src, target, rep);
    });
    env.add_callback("set", 2, [&data](inja::Arguments &args)
    {
        std::string key = args.at(0)->get<std::string>(), value = args.at(1)->get<std::string>();
        parse_json_pointer(data, key, value);
        return "";
    });
    env.add_callback("split", 3, [&data](inja::Arguments &args)
    {
        std::string content = args.at(0)->get<std::string>(), delim = args.at(1)->get<std::string>(), dest = args.at(2)->get<std::string>();
        string_array vArray = split(content, delim);
        for(size_t index = 0; index < vArray.size(); index++)
            parse_json_pointer(data, dest + "." + std::to_string(index), vArray[index]);
        return "";
    });
    env.add_callback("append", 2, [&data](inja::Arguments &args)
    {
        std::string path = args.at(0)->get<std::string>(), value = args.at(1)->get<std::string>(), pointer, output_content;
        inja::convert_dot_to_json_pointer(path, pointer);
        try
        {
            output_content = data[nlohmann::json::json_pointer(pointer)].get<std::string>();
        }
        catch (std::exception &e)
        {
            // non-exist path, ignore
        }
        output_content.append(value);
        data[nlohmann::json::json_pointer(pointer)] = output_content;
        return "";
    });
    env.add_callback("getLink", 1, [](inja::Arguments &args)
    {
        return effectiveSettings().managedConfigPrefix +
               args.at(0)->get<std::string>();
    });
    env.add_callback("startsWith", 2, [](inja::Arguments &args)
    {
        return startsWith(args.at(0)->get<std::string>(), args.at(1)->get<std::string>());
    });
    env.add_callback("endsWith", 2, [](inja::Arguments &args)
    {
        return endsWith(args.at(0)->get<std::string>(), args.at(1)->get<std::string>());
    });
    env.add_callback("or", -1, [](inja::Arguments &args)
    {
        for(auto iter = args.begin(); iter != args.end(); iter++)
            if((*iter)->get<int>())
                return true;
        return false;
    });
    env.add_callback("and", -1, [](inja::Arguments &args)
    {
        for(auto iter = args.begin(); iter != args.end(); iter++)
            if(!(*iter)->get<int>())
                return false;
        return true;
    });
    env.add_callback("bool", 1, [](inja::Arguments &args)
    {
        std::string value = args.at(0)->get<std::string>();
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
        switch(hash_(value))
        {
        case "true"_hash:
        case "1"_hash:
            return 1;
        default:
            return 0;
        }
    });
    env.add_callback("string", 1, [](inja::Arguments &args)
    {
        return std::to_string(args.at(0)->get<int>());
    });
#ifndef NO_WEBGET
    env.add_callback("fetch", 1, template_webGet);
#endif // NO_WEBGET
    //env.add_callback("parseHostname", 1, parseHostname);

    env.set_include_callback([&](const std::filesystem::path &path, const std::string &template_name)
    {
        const std::string include_path = path.string();
        std::string absolute_path;
        try
        {
            absolute_path = std::filesystem::canonical(path).string();
        }
        catch(std::exception &e)
        {
            throw inja::FileError(e.what());
        }
        if(!absolute_scope.empty() &&
           !path_is_inside_scope(absolute_path, absolute_scope))
            throw inja::FileError("access denied when trying to include '" + template_name + "': out of scope");
        return env.parse(fileGet(include_path, true));
    });
    env.set_search_included_templates_in_files(false);

    try
    {
        std::stringstream out;
        env.render_to(out, env.parse(content), data);
        output = out.str();
        return 0;
    }
    catch (std::exception &e)
    {
        output = "Invalid template: rendering failed.\n"
                 "无效模板：模板渲染失败。\n"
                 "Please check the template syntax and configured resources.\n"
                 "请检查模板语法和已配置资源。";
        writeLog(LOG_LEVEL_ERROR,
                 "TEMPLATE_RENDER_FAILED detail=" +
                     summarizeSensitiveTextForLog(e.what()));
        return -1;
    }
    return -2;
}

const std::string clash_script_template = R"(def main(ctx, md):
  host = md["host"]
{% for rule in rules %}
{% if rule.set == "true" %}{% include "group_template" %}{% endif %}
{% endfor %}

{% if exists("geoips") %}  geoips = { {{ geoips }} }
  ip = md["dst_ip"]
  if ip == "":
    ip = ctx.resolve_ip(host)
    if ip == "":
      ctx.log('[Script] dns lookup error use {{ match_group }}')
      return "{{ match_group }}"
  for key in geoips:
    if ctx.geoip(ip) == key:
      return geoips[key]{% endif %}
  return "{{ match_group }}")";

const std::string clash_script_group_template = R"({% if (rule.has_domain == "false" and rule.has_ipcidr == "false") or rule.original == "true" %}  if ctx.rule_providers["{{ rule.name }}"].match(md):
    ctx.log('[Script] matched {{ rule.group }} rule')
    return "{{ rule.group }}"{% else %}{% if rule.has_domain == "true" %}  if ctx.rule_providers["{{ rule.name }}_domain"].match(md):
    ctx.log('[Script] matched {{ rule.group }} DOMAIN rule')
    return "{{ rule.group }}"{% endif %}
{% if not rule.keyword == "" %}{% include "keyword_template" %}{% endif %}
{% if rule.has_ipcidr == "true" %}  if ctx.rule_providers["{{ rule.name }}_ipcidr"].match(md):
    ctx.log('[Script] matched {{ rule.group }} IP rule')
    return "{{ rule.group }}"{% endif %}{% endif %})";

const std::string clash_script_keyword_template = R"(  keywords = [{{ rule.keyword }}]
  for keyword in keywords:
    if keyword in host:
      ctx.log('[Script] matched {{ rule.group }} DOMAIN-KEYWORD rule')
      return "{{ rule.group }}")";

std::string findFileName(const std::string &path)
{
    string_size pos = path.rfind('/');
    if(pos == std::string::npos)
    {
        pos = path.rfind('\\');
        if(pos == std::string::npos)
            pos = 0;
    }
    string_size pos2 = path.rfind('.');
    if(pos2 < pos || pos2 == std::string::npos)
        pos2 = path.size();
    return path.substr(pos + 1, pos2 - pos - 1);
}

int renderClashScript(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, const std::string &remote_path_prefix, bool script, bool overwrite_original_rules, bool clash_classical_ruleset, RuleConversionStats *stats)
{
    RequestStageTimer rules_timer(RequestStage::Rules);
    RuleConversionStats local_stats;
    nlohmann::json data;
    std::string match_group, geoips, retrieved_rules;
    std::string strLine, rule_group, rule_path, rule_path_typed, rule_name, old_rule_name;
    std::stringstream strStrm;
    string_array vArray, groups;
    string_map keywords, urls, source_urls, names;
    std::map<std::string, bool> has_domain, has_ipcidr;
    std::map<std::string, int> ruleset_interval, rule_type;
    string_array rules;
    int index = 0;

    if(!overwrite_original_rules && base_rule["rules"].IsDefined())
        rules = safe_as<string_array>(base_rule["rules"]);

    for(RulesetContent &x : ruleset_content_array)
    {
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = waitWithoutCpuPermit(
                          [&] { return x.rule_content.get(); })
                          .substr(2);
            if(script)
            {
                if(startsWith(strLine, "MATCH") || startsWith(strLine, "FINAL"))
                    match_group = rule_group;
                else if(startsWith(strLine, "GEOIP"))
                {
                    vArray = split(strLine, ",");
                    if(vArray.size() < 2)
                        continue;
                    geoips += python_string_literal(vArray[1]) + ": " +
                              python_string_literal(rule_group) + ",";
                }
                continue;
            }
            if(startsWith(strLine, "FINAL"))
                strLine = "MATCH";
            strLine = appendClashRuleTarget(strLine, rule_group);
            rules.emplace_back(std::move(strLine));
            local_stats.add();
            continue;
        }
        else
        {
            if(x.rule_type == RULESET_CLASH_IPCIDR || x.rule_type == RULESET_CLASH_DOMAIN || x.rule_type == RULESET_CLASH_CLASSICAL)
            {
                //rule_name = std::to_string(hash_(rule_group + rule_path));
                rule_name = old_rule_name = urlDecode(findFileName(rule_path));
                int idx = 2;
                while(std::find(groups.begin(), groups.end(), rule_name) != groups.end())
                    rule_name = old_rule_name + " " + std::to_string(idx++);
                names[rule_name] = rule_group;
                urls[rule_name] = "*" + rule_path;
                source_urls[rule_name] = rule_path;
                rule_type[rule_name] = x.rule_type;
                ruleset_interval[rule_name] = x.update_interval;
                switch(x.rule_type)
                {
                case RULESET_CLASH_IPCIDR:
                    has_ipcidr[rule_name] = true;
                    break;
                case RULESET_CLASH_DOMAIN:
                    has_domain[rule_name] = true;
                    break;
                case RULESET_CLASH_CLASSICAL:
                    break;
                default:
                    break;
                }
                if(script && x.rule_type == RULESET_CLASH_IPCIDR &&
                   x.options.no_resolve)
                    writeLog(LOG_LEVEL_WARNING,
                             "Clash Script 模式不支持规则集选项 "
                             "no-resolve，已对策略组 '" +
                                 rule_group + "' 安全忽略。");
                if(!script)
                {
                    rules.emplace_back(buildClashRuleSetReference(
                        rule_name, rule_group, x.rule_type, x.options));
                    local_stats.add();
                }
                groups.emplace_back(rule_name);
                continue;
            }
            if(!remote_path_prefix.empty())
            {
                if(fileExist(rule_path, true) || isLink(rule_path))
                {
                    //rule_name = std::to_string(hash_(rule_group + rule_path));
                    rule_name = old_rule_name = urlDecode(findFileName(rule_path));
                    int idx = 2;
                    while(std::find(groups.begin(), groups.end(), rule_name) != groups.end())
                        rule_name = old_rule_name + " " + std::to_string(idx++);
                    names[rule_name] = rule_group;
                    urls[rule_name] = rule_path_typed;
                    source_urls[rule_name] = rule_path;
                    rule_type[rule_name] = x.rule_type;
                    ruleset_interval[rule_name] = x.update_interval;
                    if(clash_classical_ruleset)
                    {
                        if(!script)
                        {
                            rules.emplace_back("RULE-SET," + rule_name + "," + rule_group);
                            local_stats.add();
                        }
                        groups.emplace_back(rule_name);
                        continue;
                    }
                }
                else
                    continue;
            }

            retrieved_rules =
                waitWithoutCpuPermit([&] { return x.rule_content.get(); });
            if(retrieved_rules.empty())
            {
                writeLog(LOG_LEVEL_WARNING, "获取规则集失败或规则集为空：" +
                                summarizeUrlForLog(x.rule_path) + "。");
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            bool has_no_resolve = false;
            while(getline(strStrm, strLine, delimiter))
            {
                lineSize = strLine.size();
                if(lineSize && strLine[lineSize - 1] == '\r') //remove line break
                    strLine.erase(--lineSize);
                if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                    continue;

                if(startsWith(strLine, "DOMAIN-KEYWORD,"))
                {
                    if(script)
                    {
                        vArray = split(strLine, ",");
                        if(vArray.size() < 2)
                            continue;
                        if(keywords.find(rule_name) == keywords.end())
                            keywords[rule_name] =
                                python_string_literal(trim(vArray[1]));
                        else
                            keywords[rule_name] += "," +
                                                   python_string_literal(trim(vArray[1]));
                    }
                    else
                    {
                        vArray = split(strLine, ",");
                        if(vArray.size() < 2)
                        {
                            strLine = vArray[0] + "," + rule_group;
                        }
                        else
                        {
                            strLine = vArray[0] + "," + trim(vArray[1]) + "," + rule_group;
                            if(vArray.size() > 2)
                                strLine += "," + vArray[2];
                        }
                        rules.emplace_back(strLine);
                        local_stats.add();
                    }
                }
                else if(!has_domain[rule_name] && (startsWith(strLine, "DOMAIN,") || startsWith(strLine, "DOMAIN-SUFFIX,")))
                    has_domain[rule_name] = true;
                else if(!has_ipcidr[rule_name] && (startsWith(strLine, "IP-CIDR,") || startsWith(strLine, "IP-CIDR6,")))
                {
                    has_ipcidr[rule_name] = true;
                    if(strLine.find(",no-resolve") != std::string::npos)
                        has_no_resolve = true;
                }
            }
            if(has_domain[rule_name] && !script)
            {
                rules.emplace_back("RULE-SET," + rule_name + " (Domain)," + rule_group);
                local_stats.add();
            }
            if(has_ipcidr[rule_name] && !script)
            {
                if(has_no_resolve)
                    rules.emplace_back("RULE-SET," + rule_name + " (IP-CIDR)," + rule_group + ",no-resolve");
                else
                    rules.emplace_back("RULE-SET," + rule_name + " (IP-CIDR)," + rule_group);
                local_stats.add();
            }
            if(!has_domain[rule_name] && !has_ipcidr[rule_name] && !script)
            {
                rules.emplace_back("RULE-SET," + rule_name + "," + rule_group);
                local_stats.add();
            }
            if(std::find(groups.begin(), groups.end(), rule_name) == groups.end())
                groups.emplace_back(rule_name);
        }
    }
    std::unordered_set<std::string> used_provider_paths =
        collectRuleProviderPaths(base_rule);
    for(std::string &x : groups)
    {
        std::string url = urls[x], keyword = keywords[x], name = names[x];
        std::string direct_url =
            !url.empty() && url[0] == '*' ? url.substr(1) : "";
        bool direct_mrs =
            !direct_url.empty() && hasExtension(direct_url, ".mrs");
        bool direct_txt =
            !direct_url.empty() && hasExtension(direct_url, ".txt");
        bool direct_yaml =
            !direct_url.empty() &&
            (hasExtension(direct_url, ".yaml") ||
             hasExtension(direct_url, ".yml"));
        std::string provider_format =
            direct_mrs ? "mrs" :
            direct_txt ? "text" :
            (direct_url.empty() || direct_yaml) ? "yaml" : "";
        const std::string provider_extension =
            direct_mrs ? "mrs" : direct_txt ? "txt" : "yaml";
        bool group_has_domain = has_domain[x], group_has_ipcidr = has_ipcidr[x];
        int interval = ruleset_interval[x];

        auto emit_provider = [&](const std::string &yaml_key,
                                 const std::string &behavior,
                                 int conversion_type)
        {
            YAML::Node provider = base_rule["rule-providers"][yaml_key];
            provider["type"] = "http";
            provider["behavior"] = behavior;
            if(url[0] == '*')
                provider["url"] = url.substr(1);
            else
                provider["url"] =
                    remote_path_prefix + "/getruleset?type=" +
                    std::to_string(conversion_type) + "&url=" +
                    urlSafeBase64Encode(url);
            provider["path"] = reserveRuleProviderPath(
                x, behavior, source_urls[x], provider_extension,
                used_provider_paths);
            if(!provider_format.empty())
                provider["format"] = provider_format;
            if(interval)
                provider["interval"] = interval;
        };

        if(group_has_domain)
        {
            std::string yaml_key = x;
            if(rule_type[x] != RULESET_CLASH_DOMAIN)
                yaml_key += " (Domain)";
            emit_provider(yaml_key, "domain", 3);
        }
        if(group_has_ipcidr)
        {
            std::string yaml_key = x;
            if(rule_type[x] != RULESET_CLASH_IPCIDR)
                yaml_key += " (IP-CIDR)";
            emit_provider(yaml_key, "ipcidr", 4);
        }
        if(!group_has_domain && !group_has_ipcidr)
        {
            std::string yaml_key = x;
            emit_provider(yaml_key, "classical", 6);
        }
        if(script)
        {
            local_stats.add();
            std::string json_path = "rules." + std::to_string(index) + ".";
            parse_json_pointer(data, json_path + "has_domain", group_has_domain ? "true" : "false");
            parse_json_pointer(data, json_path + "has_ipcidr", group_has_ipcidr ? "true" : "false");
            parse_json_pointer(data, json_path + "name", python_string_escape(x));
            parse_json_pointer(data, json_path + "group", python_string_escape(name));
            parse_json_pointer(data, json_path + "set", "true");
            parse_json_pointer(data, json_path + "keyword", keyword);
            parse_json_pointer(data, json_path + "original", (rule_type[x] == RULESET_CLASH_DOMAIN || rule_type[x] == RULESET_CLASH_IPCIDR) ? "true" : "false");
        }
        index++;
    }
    if(script)
    {
        if(!geoips.empty())
            parse_json_pointer(data, "geoips", geoips.erase(geoips.size() - 1));

        parse_json_pointer(data, "match_group",
                           python_string_escape(match_group));

        inja::Environment env;
        env.include_template("keyword_template", env.parse(clash_script_keyword_template));
        env.include_template("group_template", env.parse(clash_script_group_template));
        inja::Template tmpl = env.parse(clash_script_template);

        try
        {
            std::string output_content = env.render(tmpl, data);
            base_rule["script"]["code"] = output_content;
        }
        catch (std::exception &e)
        {
            writeLog(LOG_LEVEL_ERROR,
                     "CLASH_SCRIPT_RENDER_FAILED detail=" +
                         summarizeSensitiveTextForLog(e.what()));
            if(stats)
                stats->add(local_stats.rules);
            return -1;
        }
    }
    else
        base_rule["rules"] = rules;
    if(stats)
        stats->add(local_stats.rules);
    return 0;
}
