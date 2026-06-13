#include <iostream>
#include <string>
#include <vector>

#include "handler/external_config_fallback.h"

struct TestCase {
  std::string url;
  std::string expected;
};

int main() {
  const std::vector<TestCase> cases = {
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini",
       "Custom_Clash.ini"},
      {"https://raw.githubusercontent.com/aethersailor/"
       "custom_openclash_rules/refs/heads/main/cfg/Custom_Clash_Full.ini",
       "Custom_Clash_Full.ini"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/raw/main/cfg/"
       "Custom_Clash_GFW.ini",
       "Custom_Clash_GFW.ini"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/refs/"
       "heads/main/cfg/Custom_Clash_Lite.ini?raw=1",
       "Custom_Clash_Lite.ini"},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/cfg/Custom_Clash_Mainland.ini",
       "Custom_Clash_Mainland.ini"},
      {"https://testingcf.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@refs/heads/main/cfg/Custom_Clash.ini",
       "Custom_Clash.ini"},
      {"HTTPS://GCORE.JSDELIVR.NET/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/cfg/Custom_Clash_Full.ini#fragment",
       "Custom_Clash_Full.ini"},
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/dev/cfg/Custom_Clash.ini",
       ""},
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/cfg/test/Custom_Clash.ini",
       ""},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/cfg/archived/Custom_Clash.ini",
       ""},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/cfg/Unknown.ini",
       ""},
      {"https://cdn.jsdelivr.net/gh/Other/Custom_OpenClash_Rules@main/cfg/"
       "Custom_Clash.ini",
       ""},
      {"https://cdn.jsdelivr.net.evil.example/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/cfg/Custom_Clash.ini",
       ""},
      {"file:///base/config/Custom_Clash.ini", ""},
  };

  for (const TestCase &test : cases) {
    std::string actual =
        external_config_fallback::bundledCustomClashConfigName(test.url);
    if (actual != test.expected) {
      std::cerr << "URL: " << test.url << "\nExpected: " << test.expected
                << "\nActual: " << actual << '\n';
      return 1;
    }
  }

  std::cout << "external config fallback URL tests passed\n";
  return 0;
}
