#ifndef MIHOMO_BRIDGE_H
#define MIHOMO_BRIDGE_H

#include <map>
#include <string>
#include <vector>


namespace mihomo {

/**
 * @brief Proxy node structure parsed from subscription links
 */
struct ProxyNode {
  std::string name;
  std::string type;
  std::string server;
  int port;
  std::map<std::string, std::string> params; // Additional parameters
  std::map<std::string, std::string> param_json; // Type-preserving JSON values

  // For easier access
  std::string toYAML() const;
};

/**
 * @brief Parse subscription content using mihomo's parser
 *
 * @param subscription Base64-encoded or plain-text subscription data
 * @return Vector of parsed proxy nodes
 * @throws std::runtime_error if parsing fails
 */
std::vector<ProxyNode> parseSubscription(const std::string &subscription);

/**
 * @brief Check if mihomo parser is available
 * @return true if the Go library is properly linked
 */
bool isMihomoParserAvailable();

} // namespace mihomo

#endif // MIHOMO_BRIDGE_H
