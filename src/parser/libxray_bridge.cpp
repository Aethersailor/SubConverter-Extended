#include "libxray_bridge.h"

#include <nlohmann/json.hpp>

#include <memory>
#include <stdexcept>

extern "C" {
char *ConvertXraySubscription(char *data);
char *XrayParserInfo();
void FreeString(char *s);
}

namespace {

using GoString = std::unique_ptr<char, decltype(&FreeString)>;

nlohmann::json consumeGoJson(char *raw_result, const char *function_name) {
  if (!raw_result)
    throw std::runtime_error(std::string("Go bridge call failed: ") +
                             function_name);
  GoString result(raw_result, &FreeString);
  try {
    return nlohmann::json::parse(result.get());
  } catch (const nlohmann::json::exception &) {
    throw std::runtime_error(std::string("Invalid Go bridge JSON: ") +
                             function_name);
  }
}

std::string requiredString(const nlohmann::json &object, const char *field) {
  if (!object.contains(field) || !object[field].is_string())
    throw std::runtime_error(std::string("Invalid libXray bridge field: ") +
                             field);
  auto value = object[field].get<std::string>();
  if (value.empty())
    throw std::runtime_error(std::string("Empty libXray bridge field: ") +
                             field);
  return value;
}

} // namespace

namespace libxray {

std::vector<ProxyNode> parseSubscription(const std::string &subscription) {
  auto response = consumeGoJson(
      ConvertXraySubscription(const_cast<char *>(subscription.c_str())),
      "ConvertXraySubscription");
  if (!response.is_object())
    throw std::runtime_error("Invalid libXray parser response");
  if (response.contains("error"))
    throw std::runtime_error("libXray parser error: " +
                             response.value("error", "unknown error"));
  if (!response.contains("nodes") || !response["nodes"].is_array())
    throw std::runtime_error("libXray parser returned no node array");

  std::vector<ProxyNode> nodes;
  nodes.reserve(response["nodes"].size());
  for (const auto &item : response["nodes"]) {
    if (!item.is_object() || !item.contains("port") ||
        !(item["port"].is_number_integer() ||
          item["port"].is_number_unsigned()) ||
        !item.contains("xray_outbound") ||
        !item["xray_outbound"].is_object()) {
      throw std::runtime_error("Invalid libXray node projection");
    }

    const int port = item["port"].get<int>();
    if (port < 1 || port > 65535)
      throw std::runtime_error("Invalid libXray node port");

    ProxyNode node;
    node.name = requiredString(item, "name");
    node.protocol = requiredString(item, "protocol");
    node.server = requiredString(item, "server");
    node.port = port;
    node.xray_outbound_json = item["xray_outbound"].dump();
    nodes.emplace_back(std::move(node));
  }
  if (nodes.empty())
    throw std::runtime_error("libXray parser returned no supported node");
  return nodes;
}

ParserInfo parserInfo() {
  auto response = consumeGoJson(XrayParserInfo(), "XrayParserInfo");
  if (!response.is_object())
    throw std::runtime_error("Invalid libXray parser info response");

  ParserInfo info;
  info.available = response.value("available", false);
  info.library = requiredString(response, "library");
  info.release = requiredString(response, "release");
  info.module_version = requiredString(response, "module_version");
  info.source_revision = requiredString(response, "source_revision");
  info.routed_targets = response.value("routed_targets", -1);
  if (!info.available || info.routed_targets != 0 ||
      info.source_revision.size() != 40) {
    throw std::runtime_error("Invalid libXray parser capability state");
  }
  return info;
}

} // namespace libxray
