#!/usr/bin/env python3
"""Verify clash-ipcidr no-resolve behavior against a running service."""

from __future__ import annotations

import argparse
import base64
import urllib.error
import urllib.parse
import urllib.request


SAMPLE_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#NoResolveSmoke"
)


def data_uri(content: str) -> str:
    encoded = base64.urlsafe_b64encode(content.encode("utf-8")).decode("ascii")
    return "data:text/plain;base64," + encoded


def fetch(base_url: str, params: dict[str, str], timeout: int) -> str:
    url = base_url.rstrip("/") + "/sub?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": "no-resolve-smoke"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            if response.status < 200 or response.status >= 300:
                raise AssertionError(f"{url} returned HTTP {response.status}\n{body}")
            return body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{url} returned HTTP {exc.code}\n{body}") from exc
    except urllib.error.URLError as exc:
        raise AssertionError(f"{url} failed: {exc}") from exc


def ini_config(ruleset: str) -> str:
    return "\n".join(
        (
            "[custom]",
            "enable_rule_generator=true",
            "overwrite_original_rules=true",
            f"ruleset={ruleset}",
            "clash_rule_base=base/simple_base.yml",
            "surge_rule_base=base/surge.conf",
            "",
        )
    )


def toml_config(url: str) -> str:
    return "\n".join(
        (
            "version = 1",
            "[custom]",
            "enable_rule_generator = true",
            "overwrite_original_rules = true",
            'clash_rule_base = "base/simple_base.yml"',
            "",
            "[[rulesets]]",
            'group = "DIRECT"',
            'type = "clash-ipcidr"',
            f'ruleset = "{url}"',
            "interval = 28800",
            'options = ["no-resolve"]',
            "",
        )
    )


def yaml_config(url: str) -> str:
    return "\n".join(
        (
            "custom:",
            "  enable_rule_generator: true",
            "  overwrite_original_rules: true",
            "  clash_rule_base: base/simple_base.yml",
            "  rulesets:",
            "    - group: DIRECT",
            f"      ruleset: clash-ipcidr:{url}",
            "      interval: 28800",
            "      options:",
            "        - no-resolve",
            "",
        )
    )


def convert(
    base_url: str,
    config: str,
    timeout: int,
    *,
    target: str = "clash",
    expand: bool = False,
    script: bool = False,
) -> str:
    return fetch(
        base_url,
        {
            "target": target,
            "url": SAMPLE_SS_LINK,
            "config": data_uri(config),
            "expand": "true" if expand else "false",
            "script": "true" if script else "false",
        },
        timeout,
    )


def assert_once(body: str, expected: str) -> None:
    count = body.count(expected)
    if count != 1:
        raise AssertionError(
            f"expected exactly one {expected!r}, found {count}\n"
            + relevant_output(body)
        )


def assert_absent(body: str, unexpected: str) -> None:
    if unexpected in body:
        raise AssertionError(
            f"unexpected {unexpected!r}\n" + relevant_output(body)
        )


def relevant_output(body: str) -> str:
    markers = (
        "RULE-SET",
        "IP-CIDR",
        "behavior:",
        "interval:",
        "no-resolve",
        "payload:",
        "url:",
    )
    lines = [line for line in body.splitlines() if any(x in line for x in markers)]
    return "\n".join(lines[:80])


def run(base_url: str, fixture_base_url: str, timeout: int) -> None:
    fixture_base_url = fixture_base_url.rstrip("/")
    ip_fixture = fixture_base_url + "/no_resolve_ipcidr.yaml"
    domain_fixture = fixture_base_url + "/no_resolve_domain.yaml"

    no_option = convert(
        base_url,
        ini_config(
            "DIRECT,clash-ipcidr:https://example.com/ip.yaml,28800"
        ),
        timeout,
    )
    assert_once(no_option, "RULE-SET,ip,DIRECT")
    assert_absent(no_option, "RULE-SET,ip,DIRECT,no-resolve")

    provider = convert(
        base_url,
        ini_config(
            "DIRECT,clash-ipcidr:https://example.com/ip.yaml,"
            "28800|no-resolve"
        ),
        timeout,
    )
    assert_once(provider, "RULE-SET,ip,DIRECT,no-resolve")
    assert_once(provider, "url: https://example.com/ip.yaml")
    assert_once(provider, "behavior: ipcidr")
    assert_absent(provider, "payload:")

    for option_tail in (
        "28800|NO-RESOLVE",
        "28800|No-Resolve",
        "28800| no-resolve ",
        "28800|no-resolve|NO-RESOLVE",
        "28800||no-resolve|",
        "28800|no-resolve|future-option",
        "abc|no-resolve",
    ):
        body = convert(
            base_url,
            ini_config(
                "DIRECT,clash-ipcidr:https://example.com/ip.yaml,"
                + option_tail
            ),
            timeout,
        )
        assert_once(body, "RULE-SET,ip,DIRECT,no-resolve")

    domain = convert(
        base_url,
        ini_config(
            f"DIRECT,clash-domain:{domain_fixture},28800|no-resolve"
        ),
        timeout,
    )
    assert_absent(domain, "RULE-SET,no_resolve_domain,DIRECT,no-resolve")
    assert_absent(domain, "no_resolve_domain,DIRECT,no-resolve")

    classic = convert(
        base_url,
        ini_config(
            f"DIRECT,clash-classic:{domain_fixture},28800|no-resolve"
        ),
        timeout,
    )
    assert_absent(classic, "RULE-SET,no_resolve_domain,DIRECT,no-resolve")

    expanded = convert(
        base_url,
        ini_config(
            f"DIRECT,clash-ipcidr:{ip_fixture},28800|no-resolve"
        ),
        timeout,
        expand=True,
    )
    assert_once(expanded, "IP-CIDR,1.1.1.0/24,DIRECT,no-resolve")
    assert_once(expanded, "IP-CIDR6,2001:db8::/32,DIRECT,no-resolve")
    assert_absent(expanded, "no-resolve,no-resolve")

    scripted = convert(
        base_url,
        ini_config(
            f"DIRECT,clash-ipcidr:{ip_fixture},28800|no-resolve"
        ),
        timeout,
        script=True,
    )
    assert_absent(scripted, "RULE-SET,no_resolve_ipcidr,DIRECT,no-resolve")

    surge = convert(
        base_url,
        ini_config(
            f"DIRECT,clash-ipcidr:{ip_fixture},28800|no-resolve"
        ),
        timeout,
        target="surge",
        expand=True,
    )
    assert_absent(surge, ",no-resolve")

    toml = convert(base_url, toml_config("https://example.com/ip.yaml"), timeout)
    assert_once(toml, "RULE-SET,ip,DIRECT,no-resolve")

    yaml = convert(base_url, yaml_config("https://example.com/ip.yaml"), timeout)
    assert_once(yaml, "RULE-SET,ip,DIRECT,no-resolve")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--fixture-base-url", required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    run(args.base_url, args.fixture_base_url, args.timeout)
    print("no-resolve HTTP smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
