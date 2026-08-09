#ifndef RULESET_OUTPUT_H_INCLUDED
#define RULESET_OUTPUT_H_INCLUDED

#include <string>
#include <vector>

struct RulesetTypeCatalogs {
  const std::vector<std::string> &clash;
  const std::vector<std::string> &surge;
  const std::vector<std::string> &quanx;
};

std::string formatRulesetOutput(std::string converted_content, int type,
                                const std::string &group,
                                const RulesetTypeCatalogs &catalogs);

#endif // RULESET_OUTPUT_H_INCLUDED
