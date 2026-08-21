#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/settings_snapshot.h"
#include "handler/webget.h"
#include "parser/mihomo_bridge.h"
#include "server/webserver.h"
#include "utils/logger.h"

WebServer webServer;

namespace mihomo {

std::vector<ProxyNode> parseSubscription(const std::string &) {
  throw std::runtime_error(
      "Mihomo parsing is unavailable in the settings snapshot helper");
}

bool isMihomoParserAvailable() { return false; }

AgeRecipient resolveAgeRecipient(const std::string &) {
  throw std::runtime_error(
      "Age recipient resolution is unavailable in the settings snapshot helper");
}

std::string encryptAgeArmored(const std::string &, const std::string &) {
  throw std::runtime_error(
      "Age encryption is unavailable in the settings snapshot helper");
}

} // namespace mihomo

int main(int argc, char *argv[]) {
  const bool webget_probe =
      argc == 6 && std::string(argv[1]) == "--webget-probe";
  const bool expect_reload_failure =
      argc == 4 && std::string(argv[3]) == "--expect-reload-failure";
  if ((!webget_probe && argc != 2 && argc != 3 && argc != 4) ||
      (argc == 4 && !expect_reload_failure)) {
    std::cerr << "usage: settings_snapshot_test_helper <config> "
                 "[reload-config [--expect-reload-failure]]\n"
                 "       settings_snapshot_test_helper --webget-probe "
                 "<config> <url> <cache-ttl> <delay-ms>\n";
    return 2;
  }

  const std::filesystem::path config =
      std::filesystem::absolute(argv[webget_probe ? 2 : 1]).lexically_normal();
  if (!config.has_filename()) {
    std::cerr << "configuration path has no filename\n";
    return 2;
  }

  std::filesystem::current_path(config.parent_path());
  global.prefPath = config.filename().string();
  if (!readConf())
    return 1;

  if (webget_probe) {
    int cache_ttl = 0;
    int delay_ms = 0;
    try {
      cache_ttl = std::max(0, std::stoi(argv[4]));
      delay_ms = std::max(0, std::stoi(argv[5]));
    } catch (...) {
      std::cerr << "webget probe cache-ttl and delay-ms must be integers\n";
      return 2;
    }
    auto fetch = [&]() {
      OwnedWebGetRequest request;
      request.url = argv[3];
      request.proxy = ProxyPolicy::direct();
      request.cache_ttl = static_cast<unsigned int>(cache_ttl);
      request.capture_response_headers = true;
      request.context = FetchContext::TrustedConfig;
      request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
      return webGetOwned(std::move(request));
    };
    const OwnedWebGetResult first = fetch();
    if (delay_ms > 0)
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    const OwnedWebGetResult second = fetch();
    const std::string payload_url =
        std::string(argv[3]) + "?payload-singleflight=1";
    auto fetch_payload = [&]() {
      OwnedWebGetRequest request;
      request.url = payload_url;
      request.proxy = ProxyPolicy::direct();
      request.cache_ttl = static_cast<unsigned int>(cache_ttl);
      request.capture_response_headers = true;
      request.context = FetchContext::TrustedConfig;
      request.retention = OwnedWebGetRequest::RetentionPolicy::Result;
      return webGetOwned(std::move(request));
    };
    std::future<OwnedWebGetResult> payload_owner =
        std::async(std::launch::async, fetch_payload);
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    std::future<OwnedWebGetResult> payload_follower =
        std::async(std::launch::async, fetch_payload);
    const OwnedWebGetResult payload_owner_result = payload_owner.get();
    const OwnedWebGetResult payload_follower_result = payload_follower.get();
    const CacheFetchPayloadSnapshot payload_snapshot =
        cacheFetchPayloadSnapshot();
    std::string early_headers = "sentinel-header-state";
    const std::string early_body = webGet(
        "data:,owned-webget-early", ProxyPolicy::direct(), 0,
        &early_headers, nullptr, FetchContext::TrustedConfig);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("first_status");
    writer.Int(first.status_code);
    writer.Key("first_body");
    writer.String(first.content.c_str(),
                  static_cast<rapidjson::SizeType>(first.content.size()));
    writer.Key("first_headers");
    writer.String(
        first.response_headers.c_str(),
        static_cast<rapidjson::SizeType>(first.response_headers.size()));
    writer.Key("first_retained_bytes");
    writer.Uint64(first.retained_bytes.bytes());
    writer.Key("second_status");
    writer.Int(second.status_code);
    writer.Key("second_body");
    writer.String(second.content.c_str(),
                  static_cast<rapidjson::SizeType>(second.content.size()));
    writer.Key("second_headers");
    writer.String(
        second.response_headers.c_str(),
        static_cast<rapidjson::SizeType>(second.response_headers.size()));
    writer.Key("second_retained_bytes");
    writer.Uint64(second.retained_bytes.bytes());
    writer.Key("payload_bodies_equal");
    writer.Bool(!payload_owner_result.content.empty() &&
                payload_owner_result.content == payload_follower_result.content);
    writer.Key("payload_retained_bytes");
    writer.Uint64(payload_snapshot.retained_bytes);
    writer.Key("payload_peak_retained_bytes");
    writer.Uint64(payload_snapshot.peak_retained_bytes);
    writer.Key("early_header_preserved");
    writer.Bool(early_body == "owned-webget-early" &&
                early_headers == "sentinel-header-state");
    writer.EndObject();
    std::cout << buffer.GetString();
    return 0;
  }

  if (argc >= 3) {
    const std::filesystem::path reload_config =
        std::filesystem::absolute(argv[2]).lexically_normal();
    if (!reload_config.has_filename()) {
      std::cerr << "reload configuration path has no filename\n";
      return 2;
    }
    std::filesystem::current_path(reload_config.parent_path());
    global.prefPath = reload_config.filename().string();
    const bool reloaded = readConf();
    if (expect_reload_failure ? reloaded : !reloaded) {
      std::cerr << (expect_reload_failure
                        ? "reload unexpectedly succeeded\n"
                        : "reload failed\n");
      return 1;
    }
    if (expect_reload_failure)
      writeLog(LOG_LEVEL_VERBOSE, "SETTINGS_RELOAD_LEVEL_PROBE");
  }

  std::cout << sanitizedSettingsSnapshot(global);
  return 0;
}
