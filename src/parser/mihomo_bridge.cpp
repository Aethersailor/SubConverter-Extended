#include "mihomo_bridge.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

// Go library functions (generated from libconvert.h)
extern "C" {
char *ConvertSubscription(char *data);
void FreeString(char *s);
}

namespace mihomo {

std::string ProxyNode::toYAML() const {
  std::stringstream ss;
  ss << "  - name: \"" << name << "\"\n";
  ss << "    type: " << type << "\n";
  ss << "    server: " << server << "\n";
  ss << "    port: " << port << "\n";

  // Add other parameters
  for (const auto &[key, value] : params) {
    ss << "    " << key << ": " << value << "\n";
  }

  return ss.str();
}

std::vector<ProxyNode> parseSubscription(const std::string &subscription) {
  std::vector<ProxyNode> nodes;

  // Call Go function
  char *result = ConvertSubscription(const_cast<char *>(subscription.c_str()));
  if (!result) {
    throw std::runtime_error("Failed to call Go ConvertSubscription function");
  }

  // Parse JSON result
  try {
    auto json_result = nlohmann::json::parse(result);

    // Check for error
    if (json_result.contains("error")) {
      std::string error = json_result["error"];
      FreeString(result);
      throw std::runtime_error("Mihomo parser error: " + error);
    }

    // Parse proxy array
    for (const auto &item : json_result) {
      ProxyNode node;
      node.name = item.value("name", "");
      node.type = item.value("type", "");
      node.server = item.value("server", "");

      // Port: handle both number and string
      if (item.contains("port")) {
        if (item["port"].is_number()) {
          node.port = item["port"].get<int>();
        } else if (item["port"].is_string()) {
          try {
            node.port = std::stoi(item["port"].get<std::string>());
          } catch (...) {
            node.port = 0;
          }
        } else {
          node.port = 0;
        }
      } else {
        node.port = 0;
      }

      // Store all other fields in params
      for (auto it = item.begin(); it != item.end(); ++it) {
        const std::string &key = it.key();
        if (key != "name" && key != "type" && key != "server" &&
            key != "port") {
          std::string value;
          if (it->is_string()) {
            value = it->get<std::string>();
          } else if (it->is_number_integer()) {
            value = std::to_string(it->get<int>());
          } else if (it->is_number_float()) {
            value = std::to_string(it->get<double>());
          } else if (it->is_boolean()) {
            value = it->get<bool>() ? "true" : "false";
          } else {
            value = it->dump(); // For complex types, serialize to JSON
          }
          node.params[key] = value;
        }
      }

      nodes.push_back(node);
    }

  } catch (const nlohmann::json::exception &e) {
    FreeString(result);
    throw std::runtime_error(std::string("JSON parse error: ") + e.what());
  }

  // Free Go-allocated memory
  FreeString(result);

  return nodes;
}

bool isMihomoParserAvailable() {
  // Simple check: try to call the function with empty input
  try {
    char empty[] = "";
    char *result = ConvertSubscription(empty);
    if (result) {
      FreeString(result);
      return true;
    }
  } catch (...) {
    return false;
  }
  return false;
}

} // namespace mihomo
