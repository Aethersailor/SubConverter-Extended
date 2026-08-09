#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

#include "handler/ruleset_output.h"

int main() {
  const std::vector<std::string> clash = {
      "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6", "GEOIP"};
  const std::vector<std::string> surge = clash;
  const std::vector<std::string> quanx = {
      "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "GEOIP"};
  const RulesetTypeCatalogs catalogs{clash, surge, quanx};
  const std::string converted =
      "// ignored\r\n"
      "DOMAIN-SUFFIX,example.com,Old // trailing\r\n"
      "DOMAIN,full.example,Old\r\n"
      "IP-CIDR,198.51.100.0/24,no-resolve\r\n"
      "IP-CIDR6,2001:db8::/32,no-resolve\r\n"
      "GEOIP,CN,Old\r\n"
      "UNSUPPORTED,value,Old\r\n";

  assert(formatRulesetOutput(converted, 1, "Converted", catalogs) ==
         "DOMAIN-SUFFIX,example.com,Old\n"
         "DOMAIN,full.example,Old\n"
         "IP-CIDR,198.51.100.0/24,no-resolve\n"
         "IP-CIDR6,2001:db8::/32,no-resolve\n"
         "GEOIP,CN,Old\n");
  assert(formatRulesetOutput(converted, 2, "Converted", catalogs) ==
         "DOMAIN-SUFFIX,example.com,Converted\n"
         "DOMAIN,full.example,Converted\n"
         "IP-CIDR,198.51.100.0/24,Converted,no-resolve\n"
         "IP6-CIDR,2001:db8::/32,Converted,no-resolve\n"
         "GEOIP,CN,Converted\n");
  assert(formatRulesetOutput(converted, 3, "Converted", catalogs) ==
         "payload:\n"
         "  - '+.example.com'\n"
         "  - 'full.example'\n");
  assert(formatRulesetOutput(converted, 4, "Converted", catalogs) ==
         "payload:\n"
         "  - '198.51.100.0/24'\n"
         "  - '2001:db8::/32'\n");
  assert(formatRulesetOutput(converted, 5, "Converted", catalogs) ==
         ".example.com\n"
         "full.example\n");
  assert(formatRulesetOutput(converted, 6, "Converted", catalogs) ==
         "payload:\n"
         "  - DOMAIN-SUFFIX,example.com,Old\n"
         "  - DOMAIN,full.example,Old\n"
         "  - IP-CIDR,198.51.100.0/24,no-resolve\n"
         "  - IP-CIDR6,2001:db8::/32,no-resolve\n"
         "  - GEOIP,CN,Old\n");

  const std::string unsupported = "USER-AGENT,fixture\n";
  assert(formatRulesetOutput(unsupported, 3, "Converted", catalogs) ==
         "payload:\n  - '--placeholder--'");
  assert(formatRulesetOutput(unsupported, 4, "Converted", catalogs) ==
         "payload:\n  - '0.0.0.0/32'");
  assert(formatRulesetOutput(unsupported, 6, "Converted", catalogs) ==
         "payload:\n  - 'DOMAIN,--placeholder--'");

  assert(formatRulesetOutput(
             "DOMAIN,cr.example,Old\rDOMAIN-SUFFIX,cr-suffix.example,Old\r",
             5, "Converted", catalogs) ==
         "cr.example\n.cr-suffix.example\n");
  return 0;
}
