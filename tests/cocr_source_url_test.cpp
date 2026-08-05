#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

#include "handler/cocr_source_url.h"

struct RewriteCase {
  std::string input;
  std::string expected;
};

int main() {
  const std::vector<RewriteCase> rewrites = {
      {"https://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/main/rule/a.yaml",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml"},
      {"http://raw.githubusercontent.com/Aethersailor/"
       "Custom_OpenClash_Rules/refs/heads/main/cfg/a.ini?x=1#part",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/cfg/a.ini?x=1#part"},
      {"https://github.com/Aethersailor/Custom_OpenClash_Rules/raw/main/"
       "game_rule/a.mrs",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/game_rule/a.mrs"},
      {"https://github.com/aethersailor/custom_openclash_rules/blob/refs/"
       "heads/main/overwrite/a.yaml",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/overwrite/a.yaml"},
      {"https://cdn.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@main/rule/a.list",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.list"},
      {"https://testingcf.jsdelivr.net/gh/Aethersailor/"
       "Custom_OpenClash_Rules@refs/heads/main/new/path/a.txt",
       "https://git.asailor.org/Custom_OpenClash_Rules/main/new/path/a.txt"},
  };

  for (const RewriteCase &test : rewrites) {
    CocrSourceResolution disabled = resolveCocrSourceUrl(test.input, false);
    assert(!disabled.rewritten);
    assert(disabled.effective_url == test.input);

    CocrSourceResolution enabled = resolveCocrSourceUrl(test.input, true);
    assert(enabled.rewritten);
    assert(enabled.effective_url == test.expected);
  }

  const std::vector<std::string> unchanged = {
      "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml",
      "https://raw.githubusercontent.com/other/Custom_OpenClash_Rules/main/"
      "rule/a.yaml",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/dev/rule/a.yaml",
      "https://user@raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/rule/a.yaml",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/rule/%61.yaml",
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/rule/../a.yaml",
      "file:///base/Custom_OpenClash_Rules/main/rule/a.yaml",
      "data:text/plain,Custom_OpenClash_Rules",
  };

  for (const std::string &url : unchanged) {
    CocrSourceResolution resolved = resolveCocrSourceUrl(url, true);
    assert(!resolved.rewritten);
    assert(resolved.effective_url == url);
  }
  return 0;
}
