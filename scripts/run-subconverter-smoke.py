#!/usr/bin/env python3
"""Run HTTP smoke checks against a running SubConverter-Extended instance.

The script does not build the project. Point --base-url at a local or remote
test server and it will verify health, normal conversion, and explain output.
Snapshots are optional; pass --snapshot-dir and --update-snapshots to create or
refresh them.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SAMPLE_SS_LINK = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke"
DIRECT_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@direct.example.com:8389#DirectSmoke"
)
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"
PROVIDER_FILTER_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"\n".join(
        (
            b"enable_rule_generator=false",
            b"include_remarks=HK",
            b"include_remarks=JP",
            b"exclude_remarks=Expired",
            b"exclude_remarks=Traffic",
        )
    )
).decode("ascii")
AGE_PUBLIC_KEY = (
    "age1xh86kh9v23vattr58yedspm3f57sxvnswu9krr6ns438amekx5gsd09uma"
)


def build_url(base_url: str, path: str, params: dict[str, str] | None = None) -> str:
    base = base_url.rstrip("/")
    query = urllib.parse.urlencode(params or {})
    return f"{base}{path}" + (f"?{query}" if query else "")


def fetch_response(
    base_url: str,
    path: str,
    params: dict[str, str] | None,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    url = build_url(base_url, path, params)
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{url} returned HTTP {exc.code}\n{body}") from exc
    except urllib.error.URLError as exc:
        raise AssertionError(f"{url} failed: {exc}") from exc

    if status < 200 or status >= 300:
        raise AssertionError(f"{url} returned HTTP {status}\n{body}")
    return body, response_headers


def fetch(
    base_url: str,
    path: str,
    params: dict[str, str] | None,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> str:
    body, _ = fetch_response(base_url, path, params, timeout, headers)
    return body


def assert_rejected(
    base_url: str,
    path: str,
    params: dict[str, str],
    timeout: int,
    label: str,
    headers: dict[str, str] | None = None,
) -> None:
    try:
        fetch(base_url, path, params, timeout, headers)
    except AssertionError as exc:
        if "returned HTTP 400" not in str(exc):
            raise AssertionError(f"{label} failed unexpectedly: {exc}") from exc
        return
    raise AssertionError(f"{label} was unexpectedly accepted")


def assert_snapshot(name: str, content: str, snapshot_dir: Path | None, update: bool) -> None:
    if snapshot_dir is None:
        return

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    path = snapshot_dir / name
    normalized = content.replace("\r\n", "\n")
    if update or not path.exists():
        path.write_text(normalized, encoding="utf-8")
        return

    expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if expected != normalized:
        diff = "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                normalized.splitlines(),
                fromfile=str(path),
                tofile=f"current:{name}",
                lineterm="",
            )
        )
        raise AssertionError(f"Snapshot mismatch for {name}\n{diff}")


def run_checks(
    base_url: str,
    timeout: int,
    snapshot_dir: Path | None,
    update: bool,
    remote_subscription_url: str | None,
    mihomo_yaml_subscription_url: str | None,
    legacy_subscription_url: str | None,
    verify_non_clash: bool,
) -> None:
    health = fetch(base_url, "/healthz", None, timeout)
    if health.strip() != "ok":
        raise AssertionError(f"/healthz returned unexpected body: {health!r}")

    version_page, version_headers = fetch_response(
        base_url, "/version", None, timeout
    )
    if (
        "<!DOCTYPE html>" not in version_page
        or "SubConverter-Extended" not in version_page
    ):
        raise AssertionError("/version did not return the HTML version page")
    if not version_headers.get("content-type", "").lower().startswith("text/html"):
        raise AssertionError("/version HTML response has an unexpected content type")

    navigation_page, navigation_headers = fetch_response(
        base_url,
        "/version",
        None,
        timeout,
        {
            "Origin": "https://edgetunnel.example",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )
    if "<!DOCTYPE html>" not in navigation_page:
        raise AssertionError("/version navigation request did not return HTML")
    if not navigation_headers.get("content-type", "").lower().startswith(
        "text/html"
    ):
        raise AssertionError("/version navigation response has an unexpected content type")

    probe_headers = {
        "Origin": "https://edgetunnel.example",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    version_probe, version_probe_headers = fetch_response(
        base_url, "/version", None, timeout, probe_headers
    )
    version_probe_line = version_probe.strip()
    if not re.fullmatch(
        r"SubConverter-Extended \S+ backend", version_probe_line
    ):
        raise AssertionError(
            f"/version probe returned an unexpected body: {version_probe!r}"
        )
    if "subconverter" not in version_probe_line.lower() or "<" in version_probe_line:
        raise AssertionError("/version probe is not compatible with backend detection")
    if not version_probe_headers.get("content-type", "").lower().startswith(
        "text/plain"
    ):
        raise AssertionError("/version probe response has an unexpected content type")
    if version_probe_headers.get("access-control-allow-origin") != "*":
        raise AssertionError("/version probe response is missing the CORS header")
    if "no-store" not in version_probe_headers.get("cache-control", "").lower():
        raise AssertionError("/version probe response is missing no-store caching")
    vary = version_probe_headers.get("vary", "").lower()
    for header in ("sec-fetch-mode", "sec-fetch-dest", "origin"):
        if header not in vary:
            raise AssertionError(f"/version probe Vary header is missing {header}")

    legacy_probe, _ = fetch_response(
        base_url,
        "/version",
        None,
        timeout,
        {"Origin": "https://edgetunnel.example"},
    )
    if legacy_probe != version_probe:
        raise AssertionError("/version legacy browser probe response is inconsistent")

    inspect_page = fetch(base_url, "/inspect", None, timeout)
    if (
        "Request Inspector" not in inspect_page
        or "request-input" not in inspect_page
        or "request-preview" not in inspect_page
        or "parameter-section" not in inspect_page
    ):
        raise AssertionError("/inspect did not return the inspector page")
    localized_labels = [
        "代理提供者",
        "请求值",
        "生效值",
        "说明",
        "项目",
        "详情",
        "来源哈希",
        "包含过滤",
        "排除过滤",
    ]
    missing_labels = [label for label in localized_labels if label not in inspect_page]
    if missing_labels:
        raise AssertionError(
            "/inspect page is missing localized labels: " + ", ".join(missing_labels)
        )

    common_params = {
        "target": "clash",
        "url": SAMPLE_SS_LINK,
        "config": DISABLE_RULEGEN_CONFIG,
    }

    direct_config = fetch(base_url, "/sub", common_params, timeout)
    if "Smoke" not in direct_config or "proxies:" not in direct_config:
        raise AssertionError("direct Clash conversion did not include expected node output")
    assert_snapshot("direct-clash.yaml", direct_config, snapshot_dir, update)

    _, plaintext_headers = fetch_response(
        base_url, "/sub", common_params, timeout
    )
    plaintext_vary = {
        value.strip().lower()
        for value in plaintext_headers.get("vary", "").split(",")
        if value.strip()
    }
    if "x-age-public-key" not in plaintext_vary:
        raise AssertionError("plaintext /sub response is missing Vary: X-Age-Public-Key")

    age_config, age_headers = fetch_response(
        base_url,
        "/sub",
        common_params,
        timeout,
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )
    if not age_config.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
        raise AssertionError("Age response is not official ASCII armor")
    if age_headers.get("x-sce-age") != "encrypted":
        raise AssertionError("Age response is missing its encrypted diagnostic header")
    if len(age_headers.get("x-sce-age-recipient", "")) != 64:
        raise AssertionError("Age response is missing its recipient fingerprint")
    if "no-store" not in age_headers.get("cache-control", "").lower():
        raise AssertionError("Age response is not marked no-store")
    age_vary = {
        value.strip().lower()
        for value in age_headers.get("vary", "").split(",")
        if value.strip()
    }
    if "x-age-public-key" not in age_vary:
        raise AssertionError("Age response is missing Vary: X-Age-Public-Key")

    plaintext_after_age = fetch(base_url, "/sub", common_params, timeout)
    if plaintext_after_age.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
        raise AssertionError("Age response leaked into the plaintext cache variant")
    if plaintext_after_age != direct_config:
        raise AssertionError("plaintext response changed after an Age request")

    assert_rejected(
        base_url,
        "/sub",
        common_params,
        timeout,
        "invalid Age key",
        {"X-Age-Public-Key": "not-an-age-key"},
    )
    assert_rejected(
        base_url,
        "/sub",
        {**common_params, "target": "clashr"},
        timeout,
        "Age encryption for non-Clash target",
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )

    direct_explain = fetch(
        base_url,
        "/sub",
        {**common_params, "explain": "true"},
        timeout,
    )
    direct_report = json.loads(direct_explain)
    if direct_report.get("target") != "clash":
        raise AssertionError(f"unexpected explain target: {direct_report.get('target')!r}")
    if direct_report.get("nodes", {}).get("total", 0) < 1:
        raise AssertionError("direct explain report did not count the parsed node")
    direct_params = direct_report.get("parameters", {})
    direct_recognized = {
        item.get("name"): item for item in direct_params.get("recognized", [])
    }
    if "target" not in direct_recognized or "url" not in direct_recognized:
        raise AssertionError("direct explain report did not include recognized request parameters")
    if "effective_config" not in direct_report:
        raise AssertionError("direct explain report did not include effective config diagnostics")
    assert_snapshot("direct-explain.json", direct_explain, snapshot_dir, update)

    age_explain, age_explain_headers = fetch_response(
        base_url,
        "/sub",
        {**common_params, "explain": "true"},
        timeout,
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )
    json.loads(age_explain)
    if age_explain_headers.get("x-sce-age") != "diagnostic-not-encrypted":
        raise AssertionError("Age explain response did not remain diagnostic JSON")

    provider_explain = fetch(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "https://example.com/sub",
            "config": PROVIDER_FILTER_CONFIG,
            "explain": "true",
        },
        timeout,
    )
    provider_report = json.loads(provider_explain)
    if not provider_report.get("mode", {}).get("proxy_provider"):
        raise AssertionError("provider explain report did not enter proxy-provider mode")
    if provider_report.get("output", {}).get("provider_count") != 1:
        raise AssertionError("provider explain report did not count one provider")
    provider = provider_report.get("providers", [{}])[0]
    if provider.get("filter") != "(HK)|(JP)":
        raise AssertionError("provider did not inherit configured include filters")
    if provider.get("exclude_filter") != "(Expired)|(Traffic)":
        raise AssertionError("provider did not inherit configured exclude filters")
    provider_params = provider_report.get("parameters", {})
    provider_recognized = {
        item.get("name"): item for item in provider_params.get("recognized", [])
    }
    if provider_recognized.get("config", {}).get("status") not in {"applied", "ignored"}:
        raise AssertionError("provider explain report did not diagnose the config parameter")
    assert_snapshot("provider-explain.json", provider_explain, snapshot_dir, update)

    if remote_subscription_url:
        mixed_url = f"{remote_subscription_url}|{DIRECT_SS_LINK}"
        clash_cases = (
            (
                "remote/list=false",
                remote_subscription_url,
                False,
                ("proxy-providers:", remote_subscription_url),
                ("name: Smoke", "DirectSmoke"),
            ),
            (
                "uri/list=false",
                DIRECT_SS_LINK,
                False,
                ("DirectSmoke", "direct.example.com"),
                ("proxy-providers:", "name: Smoke"),
            ),
            (
                "mixed/list=false",
                mixed_url,
                False,
                ("proxy-providers:", remote_subscription_url, "DirectSmoke"),
                ("name: Smoke",),
            ),
            (
                "remote/list=true",
                remote_subscription_url,
                True,
                ("Smoke", "example.com"),
                ("proxy-providers:", "DirectSmoke"),
            ),
            (
                "uri/list=true",
                DIRECT_SS_LINK,
                True,
                ("DirectSmoke", "direct.example.com"),
                ("proxy-providers:", "name: Smoke"),
            ),
            (
                "mixed/list=true",
                mixed_url,
                True,
                ("Smoke", "DirectSmoke", "example.com", "direct.example.com"),
                ("proxy-providers:",),
            ),
        )
        for case_name, source_url, list_mode, expected, forbidden in clash_cases:
            params = {
                "target": "clash",
                "url": source_url,
                "config": DISABLE_RULEGEN_CONFIG,
            }
            if list_mode:
                params["list"] = "true"
            output = fetch(base_url, "/sub", params, timeout)
            missing = [value for value in expected if value not in output]
            unexpected = [value for value in forbidden if value in output]
            if missing or unexpected:
                raise AssertionError(
                    f"{case_name} failed: missing={missing}, unexpected={unexpected}\n"
                    f"{output}"
                )

        def assert_provider_ua_present(label: str, output: str, user_agent: str) -> None:
            required = ("proxy-providers:", "header:", "User-Agent:", user_agent)
            missing = [value for value in required if value not in output]
            if missing:
                raise AssertionError(
                    f"{label} did not include provider User-Agent: missing={missing}\n"
                    f"{output}"
                )

        def assert_provider_ua_absent(label: str, output: str) -> None:
            if "User-Agent:" in output:
                raise AssertionError(
                    f"{label} unexpectedly included provider User-Agent\n{output}"
                )

        provider_params = {
            "target": "clash",
            "url": remote_subscription_url,
            "config": DISABLE_RULEGEN_CONFIG,
        }
        client_ua = "clash.meta/1.19.20"
        client_output, client_headers = fetch_response(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_present("client UA provider", client_output, client_ua)
        vary_values = {
            value.strip().lower()
            for value in client_headers.get("vary", "").split(",")
            if value.strip()
        }
        if "user-agent" not in vary_values:
            raise AssertionError(
                "client UA provider response did not emit Vary: User-Agent"
            )

        custom_ua = "AirportRequired-UA/2026.07"
        custom_output = fetch(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": custom_ua},
        )
        assert_provider_ua_present("custom UA provider", custom_output, custom_ua)
        if client_ua in custom_output:
            raise AssertionError("custom UA provider output reused the sample UA")

        selected_header_output, selected_header_response_headers = fetch_response(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "x-hwid,Authorization"},
            timeout,
            {
                "User-Agent": client_ua,
                "x-hwid": "smoke-device-2026",
                "Authorization": "Bearer provider-smoke-token",
                "X-Unselected-Smoke": "must-not-leak",
            },
        )
        selected_header_output_lower = selected_header_output.lower()
        for expected in ("x-hwid:", "authorization:"):
            if expected not in selected_header_output_lower:
                raise AssertionError(
                    f"selected provider header output is missing {expected!r}"
                )
        for expected in ("smoke-device-2026", "Bearer provider-smoke-token"):
            if expected not in selected_header_output:
                raise AssertionError(
                    f"selected provider header output is missing {expected!r}"
                )
        if "must-not-leak" in selected_header_output:
            raise AssertionError("unselected request header leaked into proxy-provider")
        selected_vary = {
            value.strip().lower()
            for value in selected_header_response_headers.get("vary", "").split(",")
            if value.strip()
        }
        for expected in ("x-hwid", "authorization", "x-age-public-key"):
            if expected not in selected_vary:
                raise AssertionError(
                    f"selected provider response Vary is missing {expected}"
                )

        expanded_with_headers = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "list": "true",
                "provider_headers": "x-hwid,Authorization",
            },
            timeout,
            {
                "User-Agent": client_ua,
                "x-hwid": "smoke-device-2026",
                "Authorization": "Bearer provider-smoke-token",
            },
        )
        if (
            "Smoke" not in expanded_with_headers
            or "proxy-providers:" in expanded_with_headers
        ):
            raise AssertionError("list=true provider header fetch did not expand nodes")

        assert_rejected(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "x-missing-smoke"},
            timeout,
            "missing selected provider header",
        )
        assert_rejected(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "X-Age-Public-Key"},
            timeout,
            "reserved selected provider header",
            {"X-Age-Public-Key": AGE_PUBLIC_KEY},
        )
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": DIRECT_SS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
                "provider_headers": "x-hwid",
            },
            timeout,
            "selected provider header without a generated provider",
            {"x-hwid": "smoke-device-2026"},
        )

        browser_output, browser_headers = fetch_response(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                )
            },
        )
        if "proxy-providers:" not in browser_output:
            raise AssertionError("browser UA provider request did not stay in provider mode")
        assert_provider_ua_absent("browser UA provider", browser_output)
        browser_vary_values = {
            value.strip().lower()
            for value in browser_headers.get("vary", "").split(",")
            if value.strip()
        }
        if "user-agent" not in browser_vary_values:
            raise AssertionError(
                "browser UA provider response did not emit Vary: User-Agent"
            )

        tool_output = fetch(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": "curl/8.5.0"},
        )
        assert_provider_ua_absent("inspection-tool UA provider", tool_output)

        uri_with_client_ua = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": DIRECT_SS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            timeout,
            {"User-Agent": client_ua},
        )
        if "proxy-providers:" in uri_with_client_ua:
            raise AssertionError("URI-only request unexpectedly entered provider mode")
        assert_provider_ua_absent("URI-only client UA", uri_with_client_ua)

        list_true_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "list": "true"},
            timeout,
            {"User-Agent": client_ua},
        )
        if "proxy-providers:" in list_true_with_client_ua:
            raise AssertionError("list=true request unexpectedly emitted proxy-providers")
        assert_provider_ua_absent("list=true client UA", list_true_with_client_ua)

        mixed_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "url": mixed_url},
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_present("mixed client UA provider", mixed_with_client_ua, client_ua)
        if "DirectSmoke" not in mixed_with_client_ua:
            raise AssertionError("mixed client UA provider lost direct URI nodes")

        clashr_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "target": "clashr"},
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_absent("clashr client UA provider", clashr_with_client_ua)

        duplicate_uri_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": f"{DIRECT_SS_LINK}|{DIRECT_SS_LINK}",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "DirectSmoke 2" not in duplicate_uri_nodes:
            raise AssertionError("duplicate URI node names were not made unique")

        duplicate_remote_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": f"{remote_subscription_url}|{remote_subscription_url}",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "Smoke 2" not in duplicate_remote_nodes:
            raise AssertionError("duplicate subscription node names were not made unique")

        if verify_non_clash:
            singbox_config = fetch(
                base_url,
                "/sub",
                {
                    "target": "singbox",
                    "url": remote_subscription_url,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                timeout,
            )
            singbox_json = json.loads(singbox_config)
            outbounds = singbox_json.get("outbounds", [])
            if not any(outbound.get("tag") == "Smoke" for outbound in outbounds):
                raise AssertionError(
                    "remote sing-box conversion did not expand the subscription"
                )

            surge_config = fetch(
                base_url,
                "/sub",
                {
                    "target": "surge",
                    "url": remote_subscription_url,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                timeout,
            )
            if "Smoke" not in surge_config or "example.com" not in surge_config:
                raise AssertionError(
                    "remote Surge conversion did not expand the subscription"
                )

    if mihomo_yaml_subscription_url:
        mihomo_yaml_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": mihomo_yaml_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if (
            "NativeYAML" not in mihomo_yaml_nodes
            or "yaml.example.com" not in mihomo_yaml_nodes
            or "udp: true" not in mihomo_yaml_nodes
            or "smux:" not in mihomo_yaml_nodes
            or "enabled: true" not in mihomo_yaml_nodes
            or "NativeVLESS" not in mihomo_yaml_nodes
            or "alpn:" not in mihomo_yaml_nodes
            or "h2" not in mihomo_yaml_nodes
            or "ws-opts:" not in mihomo_yaml_nodes
            or "path: /ws" not in mihomo_yaml_nodes
            or "proxy-providers:" in mihomo_yaml_nodes
        ):
            raise AssertionError(
                "Mihomo native YAML was not expanded with scalar types preserved"
            )

    if legacy_subscription_url:
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": legacy_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
            "Clash Mihomo-only mode",
        )

    if legacy_subscription_url and verify_non_clash:
        legacy_singbox = fetch(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": legacy_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            timeout,
        )
        legacy_json = json.loads(legacy_singbox)
        legacy_outbounds = legacy_json.get("outbounds", [])
        if not any(
            outbound.get("tag") == "LegacyFallback" for outbound in legacy_outbounds
        ):
            raise AssertionError(
                "legacy parser fallback did not expand the Surge subscription"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:25500")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--update-snapshots", action="store_true")
    parser.add_argument(
        "--remote-subscription-url",
        help="Optional HTTP(S) subscription used to verify provider vs expanded output.",
    )
    parser.add_argument(
        "--mihomo-yaml-subscription-url",
        help="Optional native Mihomo YAML subscription used to verify list expansion.",
    )
    parser.add_argument(
        "--legacy-subscription-url",
        help="Optional legacy subscription used to verify non-Clash fallback.",
    )
    parser.add_argument(
        "--verify-non-clash",
        action="store_true",
        help="Also verify sing-box, Surge, and legacy-parser compatibility.",
    )
    args = parser.parse_args()

    try:
        run_checks(
            args.base_url,
            args.timeout,
            args.snapshot_dir,
            args.update_snapshots,
            args.remote_subscription_url,
            args.mihomo_yaml_subscription_url,
            args.legacy_subscription_url,
            args.verify_non_clash,
        )
    except Exception as exc:
        print(f"smoke checks failed: {exc}", file=sys.stderr)
        return 1

    print("smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
