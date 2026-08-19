#include "utils/regexp.h"

#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "handler/user_agent.h"

namespace {

struct Case {
  const char *user_agent;
  const char *target;
  const char *family;
  int clash_new_name;
  int surge_version;
};

int triboolValue(const tribool &value) {
  if (value.is_undef())
    return -1;
  return value ? 1 : 0;
}

bool checkCase(const Case &test) {
  std::string target = "auto";
  tribool clash_new_name;
  int surge_version = 3;
  UserAgentMatch match =
      matchUserAgent(test.user_agent, target, clash_new_name, surge_version);
  if (!match.matched || target != test.target || match.family != test.family ||
      triboolValue(clash_new_name) != test.clash_new_name ||
      surge_version != test.surge_version) {
    std::cerr << "UA mismatch: " << test.user_agent << " => matched="
              << match.matched << " target=" << target
              << " family=" << match.family
              << " clash_new_name=" << triboolValue(clash_new_name)
              << " surge_version=" << surge_version << "\n";
    return false;
  }
  return true;
}

} // namespace

int main() {
  const std::vector<Case> cases = {
      {"clash.meta/1.19.29", "clash", "clash", 1, 3},
      {"ClashMetaForAndroid/2.11.32.Meta", "clash", "clash", 1, 3},
      {"clash-verge/v2.5.3", "clash", "clash-verge", 1, 3},
      {"mihomo.party/v2.0.0 (clash.meta)", "clash", "mihomo", 1, 3},
      {"OpenClash/0.46.075", "clash", "openclash", 1, 3},
      {"FlClash/v0.8.94", "clash", "flclash", 1, 3},
      {"clash-nyanpasu/v2.0.0", "clash", "clash", 1, 3},
      {"ClashMi/1.0.6 platform/android", "clash", "clash", 1, 3},
      {"ClashForAndroid/2.5.12", "clash", "clash-for-android", 1, 3},
      {"ClashForAndroid/2.0", "clash", "clash-for-android", 1, 3},
      {"CLASHFORANDROID/1.9.0", "clash", "clash-for-android", 0, 3},
      {"ClashForAndroid/1.3.4R", "clashr", "clash-for-android-r", 0, 3},
      {"ClashForAndroid/1.3.3R2", "clashr", "clash-for-android-r", 0, 3},
      {"CLASHFORANDROID/1.1.10r3", "clashr", "clash-for-android-r", 0, 3},
      {"ClashR/1.0", "clashr", "clashr", 0, 3},
      {"ClashforWindows/0.20.39", "clash", "clash-for-windows", 1, 3},
      {"ClashforWindows/0.11", "clash", "clash-for-windows", 1, 3},
      {"CLASHFORWINDOWS/0.10.0", "clash", "clash-for-windows", 0, 3},
      {"ClashX Pro/1.0", "clash", "clashx-pro", 1, 3},
      {"ClashX/0.13", "clash", "clashx", 1, 3},
      {"ClashX/0.12", "clash", "clashx", 0, 3},
      {"ClashX/1.91.1 (com.west2online.ClashX) Alamofire/5.5.0",
       "clash", "clashx", 1, 3},
      {"Kitsunebi/1.8.0", "v2ray", "kitsunebi", -1, 3},
      {"Loon/3.2.1", "loon", "loon", -1, 3},
      {"Pharos/1.0", "mixed", "pharos", -1, 3},
      {"Potatso/2.0", "mixed", "potatso", -1, 3},
      {"Quantumult%20X/1.4", "quanx", "quantumult-x", -1, 3},
      {"Quantumult/2.0", "quan", "quantumult", -1, 3},
      {"Qv2ray/2.7", "v2ray", "qv2ray", -1, 3},
      {"Shadowrocket/2.2.60", "shadowrocket", "shadowrocket", -1, 3},
      {"Surfboard/2.24", "surfboard", "surfboard", -1, 3},
      {"SURGE/367 X86", "surge", "surge", 0, 2},
      {"SURGE/368 X86", "surge", "surge", 0, 3},
      {"Surge/905 x86", "surge", "surge", 0, 3},
      {"SURGE/906 X86", "surge", "surge", 0, 4},
      {"Surge/899", "surge", "surge", 0, 2},
      {"Surge/900", "surge", "surge", 0, 3},
      {"Surge/1418", "surge", "surge", 0, 3},
      {"Surge/1419", "surge", "surge", 0, 4},
      {"Trojan-Qt5/1.4", "trojan", "trojan-qt5", -1, 3},
      {"v2rayNG/1.10.29", "v2rayng", "v2rayng", -1, 3},
      {"V2RayN/7.14.3", "v2rayn", "v2rayn", -1, 3},
      {"V2rayU/3.8", "v2ray", "v2rayu", -1, 3},
      {"V2RayX/1.5", "v2ray", "v2rayx", -1, 3},
  };

  for (const Case &test : cases) {
    if (!checkCase(test))
      return 1;
  }

  std::string target = "auto";
  tribool clash_new_name;
  int surge_version = 3;
  UserAgentMatch unmatched = matchUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", target,
      clash_new_name, surge_version);
  if (unmatched.matched || target != "auto" || !clash_new_name.is_undef() ||
      surge_version != 3) {
    std::cerr << "unrecognized UA changed auto-target state\n";
    return 1;
  }

  CompiledRegex search("^(US|HK)-[0-9]+$", CompiledRegexMode::Search);
  if (!search.valid() || !search.matches("US-1") ||
      !search.matches("HK-200") || search.matches("JP-1")) {
    std::cerr << "compiled search regex changed repeated-match semantics\n";
    return 1;
  }
  CompiledRegex moved(std::move(search));
  if (!moved.valid() || !moved.matches("US-3")) {
    std::cerr << "compiled search regex did not preserve move ownership\n";
    return 1;
  }

  CompiledRegex full("SS", CompiledRegexMode::FullMatch);
  if (!full.valid() || !full.matches("SS") || full.matches("SSR")) {
    std::cerr << "compiled full-match regex changed anchored semantics\n";
    return 1;
  }

  CompiledRegex invalid("[", CompiledRegexMode::Search);
  if (invalid.valid() || invalid.matches("anything")) {
    std::cerr << "invalid compiled regex did not fail closed\n";
    return 1;
  }
  return 0;
}
