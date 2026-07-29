#!/usr/bin/env python3
"""Offline compatibility and security baselines for the built service."""

from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
FIXTURES = REPOSITORY / "tests" / "fixtures"
COMPAT_FIXTURES = FIXTURES / "compat"
GOLDEN_ROOT = REPOSITORY / "tests" / "snapshots" / "compatibility"
SUBSCRIPTION = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke\n"
)
RULESET = "DOMAIN-SUFFIX,example.com,Proxy\nIP-CIDR,198.51.100.0/24,Proxy\n"
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/subscription.txt":
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path == "/rules.list":
            body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextlib.contextmanager
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def direct_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(
    base_url: str,
    path: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    query = urllib.parse.urlencode(params or {})
    url = base_url + path + (f"?{query}" if query else "")
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with direct_opener().open(req, timeout=20) as response:
            return (
                response.status,
                response.read(),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            error.read(),
            {key.lower(): value for key, value in error.headers.items()},
        )


def wait_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(
                f"service exited before readiness with {process.returncode}"
            )
        try:
            status, body, _ = request(base_url, "/healthz")
            if status == 200 and body.strip() == b"ok":
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("service did not become ready")


@contextlib.contextmanager
def running_service(
    binary: Path,
    *,
    statistics: bool = False,
    security_profile: str = "lan",
    extra_args: tuple[str, ...] = (),
):
    port = unused_port()
    baseline = (COMPAT_FIXTURES / "legacy-pref.toml").read_text(
        encoding="utf-8"
    )
    base_path = (REPOSITORY / "base" / "base").as_posix()
    baseline = baseline.replace('base_path = "base"', f'base_path = "{base_path}"')
    baseline = baseline.replace(
        '"base/all_base.tpl"', f'"{base_path}/all_base.tpl"'
    )
    baseline = baseline.replace(
        'template_path = "template"', f'template_path = "{base_path}/templates"'
    )
    baseline = baseline.replace(
        'proxy_config = "socks5h://fixture-user:fixture-secret@proxy.example.test:1080"',
        'proxy_config = "NONE"',
    )
    baseline = baseline.replace('proxy_subscription = "SYSTEM"', 'proxy_subscription = "NONE"')
    baseline = baseline.replace('enabled = true\n', f"enabled = {str(statistics).lower()}\n", 1)
    baseline = baseline.replace('profile = "lan"', f'profile = "{security_profile}"')
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        stats_path = (temporary_path / "stats").as_posix()
        baseline = baseline.replace('data_dir = "stats"', f'data_dir = "{stats_path}"')
        pref = temporary_path / "pref.toml"
        pref.write_text(baseline, encoding="utf-8", newline="\n")
        stdout = (temporary_path / "stdout.log").open("wb")
        stderr = (temporary_path / "stderr.log").open("wb")
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = "127.0.0.1,localhost"
        process = subprocess.Popen(
            [str(binary), *extra_args, "-f", str(pref)],
            cwd=REPOSITORY,
            env=env,
            stdout=stdout,
            stderr=stderr,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            wait_ready(base_url, process)
            yield base_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout.close()
            stderr.close()


def load_settings_snapshot(helper: Path, fixture: Path) -> dict[str, object]:
    completed = subprocess.run(
        [str(helper), str(fixture)],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if "fixture-secret" in completed.stdout or "fixture-dashboard-secret" in completed.stdout:
        raise AssertionError("SettingsSnapshot leaked a fixture secret")
    return json.loads(completed.stdout)


def runtime_cli_isolation_baseline(binary: Path) -> None:
    marker = b"--settings-snapshot"
    if marker in binary.read_bytes():
        raise AssertionError(
            "formal subconverter binary still contains --settings-snapshot"
        )
    with running_service(binary, extra_args=(marker.decode(),)) as base_url:
        status, body, _ = request(base_url, "/healthz")
        if status != 200 or body.strip() != b"ok":
            raise AssertionError(
                "formal subconverter binary still handles --settings-snapshot "
                "instead of preserving legacy unknown-argument behavior"
            )


def normalize_output(content: bytes, fixture_base: str) -> str:
    normalized = (
        content.decode("utf-8")
        .replace("\r\n", "\n")
        .replace(fixture_base, "http://fixture.test")
    )
    normalized = re.sub(r"Provider_[0-9A-F]{6}", "Provider_FIXTURE", normalized)
    return normalized.strip() + "\n"


def canonical_golden(name: str, content: str) -> str:
    """Keep generated semantics while excluding platform base-template boilerplate."""
    lines = content.splitlines()
    if name == "clash-provider.yaml":
        start = lines.index("proxy-providers:")
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index] in {"proxy-groups: ~", "rules: ~"}
            ),
            len(lines),
        )
        return "\n".join(lines[start:end]) + "\n"
    if name == "surge.conf":
        return next(line for line in lines if line.startswith("Smoke = ")) + "\n"
    if name == "quanx.conf":
        return next(
            line
            for line in lines
            if line.startswith("shadowsocks = ") and "tag=Smoke" in line
        ) + "\n"
    if name == "singbox.json":
        document = json.loads(content)
        smoke = next(
            item
            for item in document.get("outbounds", [])
            if item.get("tag") == "Smoke"
        )
        return (
            json.dumps(
                {"outbounds": [smoke]},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
    return content


def assert_golden(name: str, content: str, update: bool) -> None:
    path = GOLDEN_ROOT / name
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        return
    expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if content != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"{name}.expected",
                tofile=f"{name}.actual",
            )
        )
        raise AssertionError(f"golden output changed: {path}\n{diff}")


def conversion_baselines(
    base_url: str, fixture_base: str, update_golden: bool
) -> None:
    subscription_url = fixture_base + "/subscription.txt"
    common = {
        "url": subscription_url,
        "config": DISABLE_RULEGEN_CONFIG,
    }
    cases = {
        "clash-provider.yaml": {"target": "clash", **common},
        "clash-list.yaml": {"target": "clash", "list": "true", **common},
        "surge.conf": {"target": "surge", "list": "true", **common},
        "singbox.json": {"target": "singbox", "list": "true", **common},
        "quanx.conf": {"target": "quanx", "list": "true", **common},
        "simple-subscription.txt": {
            "target": "mixed",
            "list": "true",
            **common,
        },
    }
    outputs: dict[str, str] = {}
    for name, params in cases.items():
        status, body, _ = request(base_url, "/sub", params)
        if status != 200:
            raise AssertionError(f"{name} conversion returned HTTP {status}: {body!r}")
        outputs[name] = normalize_output(body, fixture_base)
        assert_golden(
            name, canonical_golden(name, outputs[name]), update_golden
        )

    if "proxy-providers:" not in outputs["clash-provider.yaml"]:
        raise AssertionError("Clash provider baseline lost provider mode")
    if "Smoke" not in outputs["clash-list.yaml"] or "proxy-providers:" in outputs[
        "clash-list.yaml"
    ]:
        raise AssertionError("Clash list baseline lost expanded node mode")
    if "Smoke = ss, " not in outputs["surge.conf"]:
        raise AssertionError("Surge semantic baseline failed")
    singbox = json.loads(outputs["singbox.json"])
    if not any(item.get("tag") == "Smoke" for item in singbox.get("outbounds", [])):
        raise AssertionError("sing-box semantic baseline lost the fixture outbound")
    if "Smoke" not in outputs["quanx.conf"]:
        raise AssertionError("Quantumult X semantic baseline failed")
    if not outputs["simple-subscription.txt"].startswith("ss://"):
        raise AssertionError("simple subscription baseline is not an ss:// URI")

    encoded_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules.list").encode()
    ).decode()
    status, body, _ = request(
        base_url, "/getruleset", {"url": encoded_ruleset, "type": "6"}
    )
    if status != 200:
        raise AssertionError(f"/getruleset returned HTTP {status}: {body!r}")
    ruleset_output = normalize_output(body, fixture_base)
    assert_golden("getruleset.yaml", ruleset_output, update_golden)
    if "payload:" not in ruleset_output or "example.com" not in ruleset_output:
        raise AssertionError("/getruleset semantic baseline failed")


def dashboard_baseline(binary: Path) -> None:
    with running_service(binary, statistics=True) as base_url:
        status, _, headers = request(base_url, "/dashboard")
        if status != 401 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("Dashboard missing-auth baseline failed")
        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, _ = request(
            base_url, "/dashboard", headers={"Authorization": "Basic " + token}
        )
        if status != 200 or b"SubConverter-Extended Dashboard" not in body:
            raise AssertionError("Dashboard valid-auth baseline failed")
        for expected in (401, 401, 429):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={"Authorization": "Basic invalid"},
            )
            if status != expected:
                raise AssertionError(
                    f"Dashboard lockout expected HTTP {expected}, got {status}"
                )


def public_request_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(binary, security_profile="public") as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 400:
            raise AssertionError(
                f"PublicRequest accepted loopback HTTP source with status {status}"
            )
        for path in ("/get", "/getlocal"):
            status, _, _ = request(base_url, path, {"path": "../secret"})
            if status != 404:
                raise AssertionError(f"API-mode file tool {path} became reachable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--settings-snapshot-helper", type=Path, required=True
    )
    parser.add_argument("--update-golden", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    settings_snapshot_helper = args.settings_snapshot_helper.resolve()
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    if not settings_snapshot_helper.is_file():
        parser.error(
            "settings snapshot helper does not exist: "
            f"{settings_snapshot_helper}"
        )
    if settings_snapshot_helper == binary:
        parser.error(
            "settings snapshot helper must be separate from the runtime binary"
        )

    runtime_cli_isolation_baseline(binary)

    snapshots = [
        load_settings_snapshot(settings_snapshot_helper, COMPAT_FIXTURES / name)
        for name in ("legacy-pref.ini", "legacy-pref.yml", "legacy-pref.toml")
    ]
    if snapshots[1:] != snapshots[:1] * 2:
        raise AssertionError("INI/YAML/TOML SettingsSnapshot values differ")
    if snapshots[0]["custom_openclash_rules"]["publish_enabled"]:
        raise AssertionError("historical publish default changed from false")
    if snapshots[0]["security"]["profile"] != "lan":
        raise AssertionError("historical security profile default changed")

    with fixture_server() as fixture_base:
        with running_service(binary) as base_url:
            conversion_baselines(base_url, fixture_base, args.update_golden)
        dashboard_baseline(binary)
        public_request_baseline(binary, fixture_base)

    print("compatibility and security baselines passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"compatibility/security baseline failed: {error}", file=sys.stderr)
        raise
