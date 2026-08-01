#ifndef RULECONVERT_H_INCLUDED
#define RULECONVERT_H_INCLUDED

#include <string>
#include <vector>
#include <future>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <memory>
#include <mutex>

#include <yaml-cpp/yaml.h>
#include <rapidjson/document.h>

#include "config/ruleset.h"
#include "utils/ini_reader/ini_reader.h"

struct FetchOutcome;

struct RulesetFetchState {
    std::atomic<int> status_code{0};
    std::atomic<bool> request_rejected{false};
    mutable std::mutex pending_mutex;
    std::shared_ptr<FetchOutcome> pending_fetch;
};

struct RulesetContent
{
    std::string rule_group;
    std::string rule_path;
    std::string rule_path_typed;
    ruleset_type rule_type = RULESET_SURGE;
    std::shared_future<std::string> rule_content;
    int update_interval = 0;
    RulesetOptions options;
    bool request_rejected = false;
    std::shared_ptr<RulesetFetchState> fetch_state;
};

struct RuleConversionStats
{
    uint64_t rules = 0;
    void add(uint64_t count = 1)
    {
        rules = count > UINT64_MAX - rules ? UINT64_MAX : rules + count;
    }
};

std::string convertRuleset(const std::string &content, int type);
size_t countValidRulesetEntries(const std::string &content,
                                ruleset_type type);
size_t rulesetConversionCacheMaxEntries();
size_t rulesetConversionCacheMaxBytes();
std::string appendClashRuleTarget(const std::string &rule, const std::string &target, bool no_resolve_only = false);
void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, RuleConversionStats *stats = nullptr);
std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, RuleConversionStats *stats = nullptr);
void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string& remote_path_prefix, RuleConversionStats *stats = nullptr);
void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, RuleConversionStats *stats = nullptr);

#endif // RULECONVERT_H_INCLUDED
