#include "handler/remote_source.h"

#include <cassert>
#include <iostream>

using remote_source::Kind;

int main() {
  {
    const auto parsed = remote_source::parse(
        "https://raw.githubusercontent.com/Aethersailor/"
        "Custom_OpenClash_Rules/refs/heads/main/rule/a.yaml?token=secret#x");
    assert(parsed.valid);
    assert(parsed.kind == Kind::GithubRaw);
    assert(parsed.isCocr());
    assert(parsed.resource.ref == "main");
    assert(parsed.resource.path == "rule/a.yaml");
    assert(parsed.canonical_jsdelivr_url ==
           "https://cdn.jsdelivr.net/gh/Aethersailor/"
           "Custom_OpenClash_Rules@main/rule/a.yaml");
    assert(remote_source::buildCocrRewrite(parsed.resource) ==
           "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
  }

  {
    const auto parsed = remote_source::parse(
        "https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/main/"
        "cfg/Custom_Clash.ini");
    assert(parsed.valid);
    assert(parsed.kind == Kind::GithubFile);
    assert(parsed.canonical_raw_url ==
           "https://raw.githubusercontent.com/Aethersailor/"
           "Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini");
  }

  {
    const auto parsed = remote_source::parse(
        "https://testingcf.jsdelivr.net/gh/Aethersailor/"
        "Custom_OpenClash_Rules@refs/heads/main/rule/a.yaml");
    assert(parsed.valid);
    assert(parsed.kind == Kind::JsDelivr);
    assert(parsed.resource.key() ==
           "aethersailor/custom_openclash_rules\nmain\nrule/a.yaml");
  }

  {
    const auto parsed = remote_source::parse(
        "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
    assert(parsed.valid);
    assert(parsed.kind == Kind::GitAsailor);
    assert(parsed.isCocr());
    assert(parsed.rewritten_url ==
           "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
  }

  for (const std::string url : {
           "https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/main/"
           "rule/../secret.yaml",
           "https://raw.githubusercontent.com/Aethersailor/"
           "Custom_OpenClash_Rules/main/rule/%2e%2e/secret.yaml",
           "https://github.com/Aethersailor/Custom_OpenClash_Rules"}) {
    const auto parsed = remote_source::parse(url);
    assert(!parsed.valid);
    assert(parsed.recognized_host);
  }

  const auto evil = remote_source::parse(
      "https://cdn.jsdelivr.net.evil.example/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/a.yaml");
  assert(evil.valid && !evil.recognized_host && !evil.isCocr());

  assert(remote_source::parse("https://example.com/config.ini").valid);
  assert(remote_source::redactForLog(
             "https://user:secret@example.com/config?token=abc#fragment") ==
         "https://example.com/config");

  std::cout << "remote source policy tests passed\n";
  return 0;
}
