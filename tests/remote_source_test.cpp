#include "handler/remote_source.h"

#include <cassert>
#include <iostream>
#include <map>

using remote_source::Kind;

static void assert_rewritten_plan(const std::string &url) {
  const auto parsed = remote_source::parse(url);
  const auto plan = remote_source::buildFetchPlan(url, parsed, true, true);
  assert(!plan.cocr_rewrite_failed);
  assert(plan.cocr_rewrite_used);
  assert(plan.candidates.size() == 1);
  assert(plan.candidates[0].source_kind == "git_asailor");
  assert(plan.candidates[0].url ==
         "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
}

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
    assert(parsed.rewritten_url ==
           "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
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
    assert(parsed.rewritten_url ==
           "https://git.asailor.org/Custom_OpenClash_Rules/main/rule/a.yaml");
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

  assert_rewritten_plan(
      "https://raw.githubusercontent.com/Aethersailor/"
      "Custom_OpenClash_Rules/main/rule/a.yaml");
  assert_rewritten_plan(
      "https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/main/"
      "rule/a.yaml");
  assert_rewritten_plan(
      "https://cdn.jsdelivr.net/gh/Aethersailor/"
      "Custom_OpenClash_Rules@main/rule/a.yaml");

  {
    const std::string url =
        "https://raw.githubusercontent.com/Aethersailor/"
        "Custom_OpenClash_Rules/main/rule/a.yaml";
    const auto plan = remote_source::buildFetchPlan(
        url, remote_source::parse(url), false, true);
    assert(!plan.cocr_rewrite_used);
    assert(plan.candidates.size() == 2);
    assert(plan.candidates[0].source_kind == "github_raw");
    assert(plan.candidates[1].source_kind == "jsdelivr");
    assert(plan.candidates[0].url.find("raw.githubusercontent.com") !=
           std::string::npos);
    assert(plan.candidates[1].url.find("cdn.jsdelivr.net") !=
           std::string::npos);
  }

  {
    const std::string url =
        "https://cdn.jsdelivr.net/gh/Aethersailor/"
        "Custom_OpenClash_Rules@main/rule/a.yaml";
    const auto plan = remote_source::buildFetchPlan(
        url, remote_source::parse(url), false, true);
    assert(plan.candidates.size() == 1);
    assert(plan.candidates[0].source_kind == "jsdelivr");
    assert(plan.candidates[0].url == url);
  }

  {
    const std::string url =
        "https://raw.githubusercontent.com/Aethersailor/"
        "Custom_OpenClash_Rules/main/rule/a.yaml";
    const auto plan = remote_source::buildFetchPlan(
        url, remote_source::parse(url), true, true);
    std::map<std::string, int> calls;
    for (const auto &candidate : plan.candidates)
      ++calls[candidate.source_kind];
    assert(calls["git_asailor"] == 1);
    assert(calls["github_raw"] == 0);
    assert(calls["jsdelivr"] == 0);
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
