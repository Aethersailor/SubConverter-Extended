#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <string>

#include <yaml-cpp/yaml.h>

#include "generator/config/clash_proxy.h"

int main() {
  Proxy proxy;
  proxy.Remark = "Renamed Reality";
  proxy.Hostname = "rewritten.example.test";
  proxy.Port = 8443;
  proxy.CanonicalProxyJson = R"json({
    "name":"Original Reality",
    "server":"original.example.test",
    "port":443,
    "type":"vless",
    "uuid":"11111111-1111-1111-1111-111111111111",
    "reality-opts":{"public-key":"fixture-key","short-id":""},
    "alpn":["h2","http/1.1"],
    "udp":true,
    "x-extra":{
      "enabled":true,
      "count":2,
      "numeric-string":"00112233",
      "boolean-string":"true",
      "timestamp-string":"2026-08-09",
      "safe-string":"3proxy"
    }
  })json";

  ClashProxyOverlay overlay;
  overlay.udp = false;
  overlay.skip_cert_verify = true;
  overlay.tfo = false;
  overlay.xudp = true;

  YAML::Node result = buildCanonicalClashProxy(proxy, overlay);
  assert(result["name"].as<std::string>() == "Renamed Reality");
  assert(result["server"].as<std::string>() == "rewritten.example.test");
  assert(result["port"].as<int>() == 8443);
  assert(result["type"].as<std::string>() == "vless");
  assert(result["reality-opts"]["short-id"].as<std::string>().empty());
  assert(result["alpn"].IsSequence() && result["alpn"].size() == 2);
  assert(result["x-extra"]["enabled"].as<bool>());
  assert(result["x-extra"]["count"].as<int>() == 2);
  assert(result["x-extra"]["numeric-string"].as<std::string>() ==
         "00112233");
  assert(result["x-extra"]["boolean-string"].as<std::string>() == "true");
  assert(!result["udp"].as<bool>());
  assert(result["skip-cert-verify"].as<bool>());
  assert(!result["tfo"].as<bool>());
  assert(result["xudp"].as<bool>());

  result.SetStyle(YAML::EmitterStyle::Flow);
  const std::string dumped = dumpCanonicalClashYaml(result);
  assert(dumped.find("short-id: \"\"") != std::string::npos);
  assert(dumped.find("short-id: \"\"\"\"") == std::string::npos);
  assert(dumped.find("numeric-string: \"00112233\"") !=
         std::string::npos);
  assert(dumped.find("boolean-string: \"true\"") != std::string::npos);
  assert(dumped.find("timestamp-string: \"2026-08-09\"") !=
         std::string::npos);
  assert(dumped.find("safe-string: 3proxy") != std::string::npos);
  assert(dumped.find("canonical-string") == std::string::npos);

  Proxy numeric_sid = proxy;
  numeric_sid.CanonicalProxyJson = R"json({
    "name":"Original Reality",
    "server":"original.example.test",
    "port":443,
    "type":"vless",
    "uuid":"11111111-1111-1111-1111-111111111111",
    "reality-opts":{"public-key":"fixture-key","short-id":"00112233"}
  })json";
  YAML::Node numeric_sid_result =
      buildCanonicalClashProxy(numeric_sid, overlay);
  numeric_sid_result.SetStyle(YAML::EmitterStyle::Flow);
  const std::string numeric_sid_dumped =
      dumpCanonicalClashYaml(numeric_sid_result);
  assert(numeric_sid_dumped.find("short-id: \"00112233\"") !=
         std::string::npos);
  assert(numeric_sid_dumped.find("short-id: 00112233") ==
         std::string::npos);
  assert(numeric_sid_dumped.find("canonical-string") == std::string::npos);

  YAML::Node anchored = YAML::Load(
      "defaults: &defaults\n"
      "  mode: rule\n"
      "copy: *defaults\n");
  anchored["proxy"] = numeric_sid_result;
  const std::string anchored_dumped = dumpCanonicalClashYaml(anchored);
  YAML::Node anchored_roundtrip = YAML::Load(anchored_dumped);
  assert(anchored_roundtrip["defaults"].is(anchored_roundtrip["copy"]));
  assert(anchored_dumped.find("short-id: \"00112233\"") !=
         std::string::npos);

  Proxy marker_text = numeric_sid;
  marker_text.Remark =
      "!<tag:aethersailor.github.io,2026:canonical-string>";
  YAML::Node marker_text_result =
      buildCanonicalClashProxy(marker_text, overlay);
  marker_text_result.SetStyle(YAML::EmitterStyle::Flow);
  const std::string marker_text_dumped =
      dumpCanonicalClashYaml(marker_text_result);
  assert(marker_text_dumped.find(marker_text.Remark) != std::string::npos);
  assert(marker_text_dumped.find("short-id: \"00112233\"") !=
         std::string::npos);
  const std::string marker_only =
      "name: \"!<tag:aethersailor.github.io,2026:canonical-string>\"\n";
  assert(finalizeCanonicalClashYaml(marker_only) == marker_only);

  YAML::Node local_tagged = YAML::Load("custom: !fixture value\n");
  local_tagged["proxy"] = numeric_sid_result;
  const std::string local_tagged_dumped =
      dumpCanonicalClashYaml(local_tagged);
  assert(local_tagged_dumped.find("!fixture value") != std::string::npos);
  assert(local_tagged_dumped.find("!<!fixture>") == std::string::npos);

  Proxy future;
  future.Remark = "Future";
  future.Hostname = "future.example.test";
  future.Port = 443;
  future.CanonicalProxyJson =
      R"json({"name":"Future","server":"future.example.test","port":443,"type":"future-protocol","future-list":[1,true,"three"]})json";
  YAML::Node future_result = buildCanonicalClashProxy(future, overlay);
  assert(future_result["type"].as<std::string>() == "future-protocol");
  assert(future_result["future-list"].IsSequence());
  assert(future_result["future-list"][0].as<int>() == 1);
  assert(future_result["future-list"][1].as<bool>());
  assert(future_result["future-list"][2].as<std::string>() == "three");
  assert(!future_result["udp"]);
  assert(!future_result["skip-cert-verify"]);

  // OpenVPN has no legacy ProxyType branch in SubConverter-Extended. Its
  // mapping and eligible overlays therefore prove that generated Mihomo
  // capabilities are sufficient for newly supported canonical proxy types.
  Proxy generated_only;
  generated_only.Remark = "Generated only";
  generated_only.Hostname = "openvpn.example.test";
  generated_only.Port = 1194;
  generated_only.CanonicalProxyJson =
      R"json({"name":"Generated only","server":"openvpn.example.test","port":1194,"type":"openvpn","proto":"tcp","udp":true})json";
  YAML::Node generated_result =
      buildCanonicalClashProxy(generated_only, overlay);
  assert(generated_result["type"].as<std::string>() == "openvpn");
  assert(generated_result["proto"].as<std::string>() == "tcp");
  assert(!generated_result["udp"].as<bool>());
  assert(!generated_result["tfo"].as<bool>());

  Proxy computed_type;
  computed_type.Remark = "HTTPS URI";
  computed_type.Hostname = "https.example.test";
  computed_type.Port = 443;
  computed_type.CanonicalProxyJson =
      R"json({"name":"HTTPS URI","server":"https.example.test","port":443,"type":"http","tls":true,"skip-cert-verify":true})json";
  ClashProxyOverlay reject_insecure;
  reject_insecure.skip_cert_verify = false;
  YAML::Node computed_result =
      buildCanonicalClashProxy(computed_type, reject_insecure);
  assert(computed_result["skip-cert-verify"].as<bool>());

  return 0;
}
