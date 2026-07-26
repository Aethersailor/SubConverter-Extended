#include <algorithm>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>

#include "generator/config/external_rules.h"

namespace {

const string_array kRuleTypes = {
    "DOMAIN",        "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
    "SRC-IP-CIDR",   "GEOIP",         "MATCH",          "FINAL",
    "IP-CIDR6",      "SRC-PORT",      "DST-PORT",       "PROCESS-NAME",
    "DOMAIN-REGEX",  "GEOSITE",       "IP-SUFFIX",      "IP-ASN",
    "SRC-GEOIP",     "SRC-IP-ASN",    "SRC-IP-SUFFIX",  "IN-PORT",
    "IN-TYPE",       "IN-USER",       "IN-NAME",        "PROCESS-PATH-REGEX",
    "PROCESS-PATH",  "PROCESS-NAME-REGEX", "UID",       "NETWORK",
    "DSCP",          "SUB-RULE",      "RULE-SET",       "AND",
    "OR",            "NOT"};

ExternalRuleParseResult parse(const std::string &content) {
  return parseExternalClashRules(content, "test source", kRuleTypes);
}

void assertErrorContains(const std::string &content,
                         const std::string &needle) {
  ExternalRuleParseResult result = parse(content);
  assert(!result.ok);
  assert(result.error.find("test source") != std::string::npos);
  assert(result.error.find(needle) != std::string::npos);
}

} // namespace

int main() {
  ExternalRuleParseResult text = parse(
      "# comment\n"
      "; comment\n"
      "// comment\n"
      "\n"
      " DOMAIN-SUFFIX,example.com,DIRECT \n"
      "IP-CIDR,192.0.2.0/24,Proxy,no-resolve\r\n"
      "SRC-IP-CIDR,192.168.1.10/32,DIRECT\n");
  assert(text.ok);
  assert(text.rules ==
         string_array({"DOMAIN-SUFFIX,example.com,DIRECT",
                       "IP-CIDR,192.0.2.0/24,Proxy,no-resolve",
                       "SRC-IP-CIDR,192.168.1.10/32,DIRECT"}));

  ExternalRuleParseResult yaml = parse(
      "rules:\n"
      "  - DOMAIN-SUFFIX,example.org,DIRECT\n"
      "  - IP-CIDR,198.51.100.0/24,Proxy,no-resolve\n");
  assert(yaml.ok);
  assert(yaml.rules.size() == 2);
  assert(yaml.rules[0] == "DOMAIN-SUFFIX,example.org,DIRECT");

  assertErrorContains("payload:\n  - DOMAIN-SUFFIX,example.com\n",
                      "payload:");
  assertErrorContains("DOMAIN-UNKNOWN,example.com,DIRECT\n",
                      "unknown rule type");
  assertErrorContains("DOMAIN-SUFFIX,,DIRECT\n",
                      "matching content is missing");
  assertErrorContains("DOMAIN-SUFFIX,example.com\n",
                      "target policy is missing");
  assertErrorContains("DOMAIN-SUFFIX,example.com,\n",
                      "target policy is empty");
  assertErrorContains("MATCH,DIRECT\n", "MATCH rules are not allowed");
  assertErrorContains("FINAL,DIRECT\n", "FINAL rules are not allowed");

  for (const std::string compound :
       {"AND,((DOMAIN-SUFFIX,example.com),(NETWORK,TCP)),DIRECT",
        "OR,((DOMAIN,one.example),(DOMAIN,two.example)),Proxy",
        "NOT,((DOMAIN-SUFFIX,example.net)),REJECT"}) {
    ExternalRuleParseResult result = parse(compound + "\n");
    assert(result.ok);
    assert(result.rules == string_array({compound}));
  }

  ExternalRuleParseResult indexed =
      parse("rules:\n  - DOMAIN-SUFFIX,ok.example,DIRECT\n  - MATCH,DIRECT\n");
  assert(!indexed.ok);
  assert(indexed.error.find("rules[1]") != std::string::npos);

  const string_array prepend = {
      "DOMAIN,prepend-1.example,DIRECT",
      "DOMAIN,prepend-2.example,DIRECT"};
  const string_array original = {
      "DOMAIN,base.example,DIRECT", "MATCH,Base",
      "DOMAIN,base-after-match.example,DIRECT"};
  const string_array generated = {
      "RULE-SET,generated,Proxy", "FINAL,Generated",
      "DOMAIN,generated-after-final.example,DIRECT"};
  const string_array append = {
      "DOMAIN,append-1.example,DIRECT",
      "DOMAIN,append-2.example,DIRECT"};

  assert(mergeClashRules(prepend, original, generated, append) ==
         string_array({"DOMAIN,prepend-1.example,DIRECT",
                       "DOMAIN,prepend-2.example,DIRECT",
                       "DOMAIN,base.example,DIRECT",
                       "RULE-SET,generated,Proxy",
                       "DOMAIN,append-1.example,DIRECT",
                       "DOMAIN,append-2.example,DIRECT",
                       "MATCH,Base",
                       "DOMAIN,base-after-match.example,DIRECT",
                       "FINAL,Generated",
                       "DOMAIN,generated-after-final.example,DIRECT"}));

  assert(mergeClashRules(prepend, {}, generated, append) ==
         string_array({"DOMAIN,prepend-1.example,DIRECT",
                       "DOMAIN,prepend-2.example,DIRECT",
                       "RULE-SET,generated,Proxy",
                       "DOMAIN,append-1.example,DIRECT",
                       "DOMAIN,append-2.example,DIRECT",
                       "FINAL,Generated",
                       "DOMAIN,generated-after-final.example,DIRECT"}));

  assert(mergeClashRules(prepend,
                        {"DOMAIN,base.example,DIRECT", "MATCH,Base"},
                        {}, append) ==
         string_array({"DOMAIN,prepend-1.example,DIRECT",
                       "DOMAIN,prepend-2.example,DIRECT",
                       "DOMAIN,base.example,DIRECT",
                       "DOMAIN,append-1.example,DIRECT",
                       "DOMAIN,append-2.example,DIRECT",
                       "MATCH,Base"}));

  // Source order and duplicates are intentionally preserved.
  assert(mergeClashRules(
             {"DOMAIN,duplicate.example,DIRECT",
              "DOMAIN,duplicate.example,DIRECT"},
             {}, {}, {}) ==
         string_array({"DOMAIN,duplicate.example,DIRECT",
                       "DOMAIN,duplicate.example,DIRECT"}));

  string_array limited;
  assert(mergeClashRulesWithinLimit(
      {"DOMAIN,one.example,DIRECT"}, {}, {},
      {"DOMAIN,two.example,DIRECT"}, 2, limited));
  assert(limited.size() == 2);
  assert(!mergeClashRulesWithinLimit(
      {"DOMAIN,one.example,DIRECT"}, {}, {},
      {"DOMAIN,two.example,DIRECT"}, 1, limited));
  assert(limited.size() == 2);

  return 0;
}
