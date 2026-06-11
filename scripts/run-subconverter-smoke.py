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


def fetch(base_url: str, path: str, params: dict[str, str] | None, timeout: int) -> str:
    body, _ = fetch_response(base_url, path, params, timeout)
    return body


def assert_rejected(
    base_url: str, path: str, params: dict[str, str], timeout: int, label: str
) -> None:
    try:
        fetch(base_url, path, params, timeout)
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
