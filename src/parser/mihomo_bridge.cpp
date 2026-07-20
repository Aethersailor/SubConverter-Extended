#include "mihomo_bridge.h"
#include <nlohmann/json.hpp>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>

// Go library functions (generated from libconvert.h)
extern "C" {
char *ConvertSubscription(char *data);
char *ResolveAgeRecipient(char *key);
char *EncryptAgeArmored(char *data, char *recipient);
void ReleaseUnusedMemory();
void FreeString(char *s);
}

namespace {

constexpr size_t kLargeSubscriptionThreshold = 256 * 1024;

struct GoParseMemoryState {
  std::mutex mutex;
  size_t active_parses = 0;
  size_t pending_bytes = 0;
};

GoParseMemoryState &goParseMemoryState() {
  static GoParseMemoryState state;
  return state;
}

class GoParseMemoryGuard {
public:
  explicit GoParseMemoryGuard(size_t subscription_size) {
    GoParseMemoryState &state = goParseMemoryState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.active_parses++;

    // Saturating accumulation prevents many concurrent medium subscriptions
    // from bypassing the same reclamation boundary as one large subscription.
    if (subscription_size >=
        kLargeSubscriptionThreshold - state.pending_bytes) {
      state.pending_bytes = kLargeSubscriptionThreshold;
    } else {
      state.pending_bytes += subscription_size;
    }
  }

  ~GoParseMemoryGuard() {
    GoParseMemoryState &state = goParseMemoryState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.active_parses--;
    if (state.active_parses != 0 ||
        state.pending_bytes < kLargeSubscriptionThreshold)
      return;

    state.pending_bytes = 0;
    try {
      // Holding the guard mutex keeps a newly starting parse from racing the
      // reclamation pass after the previous batch has fully drained.
      ReleaseUnusedMemory();
    } catch (...) {
      // Memory reclamation is opportunistic and must never fail a conversion.
    }
  }
};

} // namespace

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
  GoParseMemoryGuard memory_guard(subscription.size());

  // Call Go function
  char *raw_result =
      ConvertSubscription(const_cast<char *>(subscription.c_str()));
  if (!raw_result) {
    throw std::runtime_error("调用 Go ConvertSubscription 函数失败");
  }
  std::unique_ptr<char, decltype(&FreeString)> result(raw_result, &FreeString);

  // Parse JSON result
  try {
    auto json_result = nlohmann::json::parse(result.get());

    // Check for error
    if (json_result.contains("error")) {
      std::string error = json_result["error"];
      throw std::runtime_error("Mihomo 解析器错误：" + error);
    }

    // Parse proxy array
    nodes.reserve(json_result.size());
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
          node.param_json[key] = it->dump();
        }
      }

      nodes.emplace_back(std::move(node));
    }

  } catch (const nlohmann::json::exception &e) {
    throw std::runtime_error(std::string("JSON 解析错误：") + e.what());
  }

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

AgeRecipient resolveAgeRecipient(const std::string &key) {
  char *result =
      ResolveAgeRecipient(const_cast<char *>(key.c_str()));
  if (!result)
    throw std::runtime_error("Age 密钥解析失败");

  std::string payload(result);
  FreeString(result);
  auto parsed = nlohmann::json::parse(payload);
  if (parsed.contains("error"))
    throw std::runtime_error(parsed.value("error", "invalid age key"));

  AgeRecipient resolved;
  resolved.recipient = parsed.value("recipient", "");
  resolved.fingerprint = parsed.value("fingerprint", "");
  resolved.source = parsed.value("source", "");
  if (resolved.recipient.empty() || resolved.fingerprint.size() != 64)
    throw std::runtime_error("Age 密钥解析结果无效");
  return resolved;
}

std::string encryptAgeArmored(const std::string &data,
                              const std::string &recipient) {
  char *result = EncryptAgeArmored(const_cast<char *>(data.c_str()),
                                   const_cast<char *>(recipient.c_str()));
  if (!result)
    throw std::runtime_error("Age 加密失败");

  std::string payload(result);
  FreeString(result);
  if (payload.rfind("OK\n", 0) != 0)
    throw std::runtime_error("Age 加密失败");
  return payload.substr(3);
}

} // namespace mihomo
