#ifndef CLASH_GROUP_DEFAULTS_H_INCLUDED
#define CLASH_GROUP_DEFAULTS_H_INCLUDED

#include <array>
#include <string>
#include <string_view>
#include <unordered_map>

#include <yaml-cpp/yaml.h>
#include "config/proxygroup.h"

// Owned canonical health values, collected before the base graph is changed.
struct ClashHealthScalar {
  std::string scalar;
  bool present = false;
};

struct ClashHealthDefaults {
  std::string type;
  std::array<ClashHealthScalar, 3> values;
  bool ambiguous = false;
};

// Keys borrow groups[*].Name passed to collectClashHealthDefaults. Keep that
// config storage and its names unchanged until the returned defaults die.
// Type and canonical health values remain owned, independent of the base graph.
using ClashHealthDefaultsByName =
    std::unordered_map<std::string_view, ClashHealthDefaults>;

ClashHealthDefaultsByName collectClashHealthDefaults(
    const YAML::Node &root, const ProxyGroupConfigs &groups,
    const char *groups_field, std::string_view base_source);

inline void applyClashHealthDefaults(YAML::Node &group,
                             const ClashHealthDefaultsByName &defaults,
                             const ProxyGroupConfig &config) {
  const auto found = defaults.find(config.Name);
  if (found == defaults.end() || found->second.ambiguous)
    return;
  const std::string type = config.Type == ProxyGroupType::Smart
      ? "url-test" : config.TypeStr();
  if (found->second.type != type)
    return;
  constexpr std::array<const char *, 3> keys{"expected-status", "timeout", "lazy"};
  const YAML::Node &existing = group;
  for (size_t index = 0; index < found->second.values.size(); ++index) {
    const ClashHealthScalar &snapshot = found->second.values[index];
    const char *key = keys[index];
    if (!snapshot.present || existing[key].IsDefined())
      continue;
    YAML::Node slot = group[key];
    slot = snapshot.scalar;
  }
}

#endif // CLASH_GROUP_DEFAULTS_H_INCLUDED
