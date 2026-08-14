#include "handler/user_agent.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "utils/regexp.h"

namespace {

struct UAProfile {
  std::string head;
  std::string version_match;
  std::string version_target;
  std::string target;
  tribool clash_new_name = tribool();
  int surge_ver = -1;
  const char *family = nullptr;
};

// Heads are lower-case and ordered from the most specific family to the most
// general one. Keep ClashR markers ahead of the generic Clash rules.
const std::vector<UAProfile> kUserAgentProfiles = {
    {"clashforandroid", "\\/([0-9.]+)[Rr][0-9]*(?:$|[^A-Za-z0-9])", "",
     "clashr", false, -1, "clash-for-android-r"},
    {"clashforandroid", "\\/([0-9.]+)", "2.0", "clash", true, -1,
     "clash-for-android"},
    {"clashforandroid", "", "", "clash", false, -1,
     "clash-for-android"},
    {"clashr", "", "", "clashr", false, -1, "clashr"},
    {"clashforwindows", "\\/([0-9.]+)", "0.11", "clash", true, -1,
     "clash-for-windows"},
    {"clashforwindows", "", "", "clash", false, -1,
     "clash-for-windows"},
    {"clash-verge", "", "", "clash", true, -1, "clash-verge"},
    {"flclash", "", "", "clash", true, -1, "flclash"},
    {"mihomo", "", "", "clash", true, -1, "mihomo"},
    {"openclash", "", "", "clash", true, -1, "openclash"},
    {"clashx pro", "", "", "clash", true, -1, "clashx-pro"},
    {"clashx", "\\/([0-9.]+)", "0.13", "clash", true, -1,
     "clashx"},
    {"clashx", "", "", "clash", false, -1, "clashx"},
    {"clash", "", "", "clash", true, -1, "clash"},
    {"kitsunebi", "", "", "v2ray", tribool(), -1, "kitsunebi"},
    {"loon", "", "", "loon", tribool(), -1, "loon"},
    {"pharos", "", "", "mixed", tribool(), -1, "pharos"},
    {"potatso", "", "", "mixed", tribool(), -1, "potatso"},
    {"quantumult%20x", "", "", "quanx", tribool(), -1,
     "quantumult-x"},
    {"quantumult", "", "", "quan", tribool(), -1, "quantumult"},
    {"qv2ray", "", "", "v2ray", tribool(), -1, "qv2ray"},
    {"shadowrocket", "", "", "shadowrocket", tribool(), -1,
     "shadowrocket"},
    {"surfboard", "", "", "surfboard", tribool(), -1, "surfboard"},
    {"surge", "\\/([0-9.]+).*x86", "906", "surge", false, 4,
     "surge"},
    {"surge", "\\/([0-9.]+).*x86", "368", "surge", false, 3,
     "surge"},
    {"surge", "\\/([0-9.]+)", "1419", "surge", false, 4, "surge"},
    {"surge", "\\/([0-9.]+)", "900", "surge", false, 3, "surge"},
    {"surge", "", "", "surge", false, 2, "surge"},
    {"trojan-qt5", "", "", "trojan", tribool(), -1, "trojan-qt5"},
    {"v2rayng", "", "", "v2rayng", tribool(), -1, "v2rayng"},
    {"v2rayn", "", "", "v2rayn", tribool(), -1, "v2rayn"},
    {"v2rayu", "", "", "v2ray", tribool(), -1, "v2rayu"},
    {"v2rayx", "", "", "v2ray", tribool(), -1, "v2rayx"},
};

std::string lowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
}

bool hasPrefix(const std::string &value, const std::string &prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

bool verGreaterEqual(const std::string &src_ver,
                     const std::string &target_ver) {
  std::istringstream src_stream(src_ver), target_stream(target_ver);
  int src_part, target_part;
  char dot;
  while (src_stream >> src_part) {
    if (target_stream >> target_part) {
      if (src_part < target_part)
        return false;
      if (src_part > target_part)
        return true;
      src_stream >> dot;
      target_stream >> dot;
    } else {
      return true;
    }
  }
  return !bool(target_stream >> target_part);
}

} // namespace

UserAgentMatch matchUserAgent(const std::string &user_agent,
                              std::string &target,
                              tribool &clash_new_name,
                              int &surge_ver) {
  if (user_agent.empty())
    return {};

  const std::string normalized_user_agent = lowerAscii(user_agent);
  for (const UAProfile &profile : kUserAgentProfiles) {
    if (!hasPrefix(normalized_user_agent, profile.head))
      continue;

    if (!profile.version_match.empty()) {
      std::string version;
      if (regGetMatch(normalized_user_agent, profile.version_match, 2,
                      static_cast<std::string *>(nullptr), &version))
        continue;
      if (!profile.version_target.empty() &&
          !verGreaterEqual(version, profile.version_target))
        continue;
    }

    target = profile.target;
    clash_new_name = profile.clash_new_name;
    if (profile.surge_ver != -1)
      surge_ver = profile.surge_ver;
    return {true, profile.family ? profile.family : profile.head};
  }
  return {};
}
