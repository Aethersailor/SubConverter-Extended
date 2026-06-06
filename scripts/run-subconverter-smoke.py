#!/usr/bin/env python3
"""Run HTTP smoke checks against a running SubConverter-Extended instance.

The script does not build the project. Point --base-url at a local or remote
test server and it will verify health, normal conversion, and explain output.
Snapshots are optional; pass --snapshot-dir and --update-snapshots to create or
refresh them.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SAMPLE_SS_LINK = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke"
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"


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


def run_checks(base_url: str, timeout: int, snapshot_dir: Path | None, update: bool) -> None:
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
            "config": DISABLE_RULEGEN_CONFIG,
            "explain": "true",
        },
        timeout,
    )
    provider_report = json.loads(provider_explain)
    if not provider_report.get("mode", {}).get("proxy_provider"):
        raise AssertionError("provider explain report did not enter proxy-provider mode")
    if provider_report.get("output", {}).get("provider_count") != 1:
        raise AssertionError("provider explain report did not count one provider")
    provider_params = provider_report.get("parameters", {})
    provider_recognized = {
        item.get("name"): item for item in provider_params.get("recognized", [])
    }
    if provider_recognized.get("config", {}).get("status") not in {"applied", "ignored"}:
        raise AssertionError("provider explain report did not diagnose the config parameter")
    assert_snapshot("provider-explain.json", provider_explain, snapshot_dir, update)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:25500")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--update-snapshots", action="store_true")
    args = parser.parse_args()

    try:
        run_checks(args.base_url, args.timeout, args.snapshot_dir, args.update_snapshots)
    except Exception as exc:
        print(f"smoke checks failed: {exc}", file=sys.stderr)
        return 1

    print("smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
