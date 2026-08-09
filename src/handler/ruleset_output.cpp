#include "ruleset_output.h"

#include <algorithm>
#include <sstream>

#include "utils/regexp.h"
#include "utils/string.h"

std::string formatRulesetOutput(std::string converted_content, int type,
                                const std::string &group,
                                const RulesetTypeCatalogs &catalogs) {
  std::string output_content;
  std::string strLine;
  std::stringstream ss;
  const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

  ss << converted_content;
  char delimiter = getLineBreak(converted_content);
  std::string::size_type lineSize, posb, pose;
  auto filterLine = [&]() {
    posb = 0;
    pose = strLine.find(',');
    if (pose == std::string::npos)
      return 1;
    posb = pose + 1;
    pose = strLine.find(',', posb);
    if (pose == std::string::npos) {
      pose = strLine.size();
      if (strLine[pose - 1] == '\r')
        pose--;
    }
    pose -= posb;
    return 0;
  };

  lineSize = converted_content.size();
  output_content.reserve(lineSize);

  if (type == 3 || type == 4 || type == 6)
    output_content = "payload:\n";

  while (getline(ss, strLine, delimiter)) {
    if (strFind(strLine, "//")) {
      strLine.erase(strLine.find("//"));
      strLine = trimWhitespace(strLine);
    }
    switch (type) {
    case 2:
      if (!std::any_of(catalogs.quanx.begin(), catalogs.quanx.end(),
                       [&strLine](const std::string &rule_type) {
                         return startsWith(strLine, rule_type);
                       }))
        continue;
      break;
    case 1:
      if (!std::any_of(catalogs.surge.begin(), catalogs.surge.end(),
                       [&strLine](const std::string &rule_type) {
                         return startsWith(strLine, rule_type);
                       }))
        continue;
      break;
    case 3:
      if (!startsWith(strLine, "DOMAIN-SUFFIX,") &&
          !startsWith(strLine, "DOMAIN,"))
        continue;
      if (filterLine())
        continue;
      output_content += "  - '";
      if (strLine[posb - 2] == 'X')
        output_content += "+.";
      output_content += strLine.substr(posb, pose);
      output_content += "'\n";
      continue;
    case 4:
      if (!startsWith(strLine, "IP-CIDR,") &&
          !startsWith(strLine, "IP-CIDR6,"))
        continue;
      if (filterLine())
        continue;
      output_content += "  - '";
      output_content += strLine.substr(posb, pose);
      output_content += "'\n";
      continue;
    case 5:
      if (!startsWith(strLine, "DOMAIN-SUFFIX,") &&
          !startsWith(strLine, "DOMAIN,"))
        continue;
      if (filterLine())
        continue;
      if (strLine[posb - 2] == 'X')
        output_content += '.';
      output_content += strLine.substr(posb, pose);
      output_content += '\n';
      continue;
    case 6:
      if (!std::any_of(catalogs.clash.begin(), catalogs.clash.end(),
                       [&strLine](const std::string &rule_type) {
                         return startsWith(strLine, rule_type);
                       }))
        continue;
      output_content += "  - ";
    default:
      break;
    }

    lineSize = strLine.size();
    if (lineSize && strLine[lineSize - 1] == '\r')
      strLine.erase(--lineSize);

    if (!strLine.empty() &&
        (strLine[0] != ';' && strLine[0] != '#' &&
         !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/'))) {
      if (type == 2) {
        if (startsWith(strLine, "IP-CIDR6"))
          strLine.replace(0, 8, "IP6-CIDR");
        strLine += "," + group;
        if (count_least(strLine, ',', 3) &&
            regReplace(strLine, rule_match_regex, "$2") == ",no-resolve")
          strLine = regReplace(strLine, rule_match_regex, "$1$3$2");
        else
          strLine = regReplace(strLine, rule_match_regex, "$1$3");
      }
    }
    output_content += strLine;
    output_content += '\n';
  }

  if (output_content == "payload:\n") {
    switch (type) {
    case 3:
      output_content += "  - '--placeholder--'";
      break;
    case 4:
      output_content += "  - '0.0.0.0/32'";
      break;
    case 6:
      output_content += "  - 'DOMAIN,--placeholder--'";
      break;
    }
  }
  return output_content;
}
