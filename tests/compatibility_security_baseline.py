#!/usr/bin/env python3
"""Offline compatibility and security baselines for the built service."""

from __future__ import annotations

import argparse
import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor
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
STRICT_VALID_RULESET = (
    "AND,((DOMAIN-SUFFIX,example.com),(DOMAIN,network.example))\n"
    "OR,((DOMAIN,one.example),(DOMAIN,two.example))\n"
    "NOT,((DOMAIN-SUFFIX,example.net))\n"
    "AND,((OR,((DOMAIN-SUFFIX,nested.example),(DOMAIN,inner.example))),"
    "(DOMAIN,network.example))\n"
    "DOMAIN-SUFFIX,existing.example,OldPolicy\n"
    "IP-CIDR,203.0.113.0/24,OldPolicy,no-resolve\n"
    "AND,((DOMAIN,already.example),(DOMAIN,also.example)),OldPolicy\n"
    "OR,((DOMAIN,old-one.example),(DOMAIN,old-two.example)),OldPolicy\n"
    "NOT,((DOMAIN,old-not.example)),OldPolicy\n"
    "DOMAIN-REGEX,\"^example\\.com$\",OldPolicy\n"
    "PROCESS-NAME-REGEX,\"^chrome,helper$\",OldPolicy\n"
    "PROCESS-PATH-REGEX,\"^/usr/bin/example$\",OldPolicy\n"
    "DOMAIN-REGEX,\"^example\\,comma$\",OldPolicy\n"
    "PROCESS-NAME-REGEX,\"^\\($\",OldPolicy\n"
    "PROCESS-NAME-REGEX,\"^foo\\\"bar$\",OldPolicy\n"
    "PROCESS-PATH-REGEX,\"^//server/share$\",OldPolicy\n"
)
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"


class FixtureHandler(BaseHTTPRequestHandler):
    request_counts: dict[str, int] = {}
    cross_semantic_condition = threading.Condition()
    cross_semantic_waiters = 0
    cross_semantic_released = False
    cross_semantic_deliveries: list[int] = []

    @classmethod
    def reset_counters(cls) -> None:
        cls.request_counts = {}
        with cls.cross_semantic_condition:
            cls.cross_semantic_waiters = 0
            cls.cross_semantic_released = False
            cls.cross_semantic_deliveries = []

    @classmethod
    def record_request(cls, path: str) -> int:
        key = path.split("?", 1)[0]
        cls.request_counts[key] = cls.request_counts.get(key, 0) + 1
        return cls.request_counts[key]

    def do_GET(self) -> None:  # noqa: N802
        request_number = self.record_request(self.path)
        response_status = 200
        if self.path == "/subscription.txt":
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path == "/external-valid.ini":
            body = b"[custom]\nenable_rule_generator=false\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path == "/external-invalid.ini":
            body = b"<!doctype html><html><body>not a config</body></html>"
            content_type = "text/html; charset=utf-8"
        elif self.path == "/external-forbidden.ini":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"forbidden")
            return
        elif self.path == "/rules.list":
            body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/import-cache-probe"):
            if request_number == 1:
                body = b"<!doctype html><html><body>transient error</body></html>"
                content_type = "text/html; charset=utf-8"
            else:
                body = b"Proxy`select`[]DIRECT\n"
                content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/import-semantic-probe"):
            if request_number == 1:
                body = b"invalid imported object\n"
            else:
                body = b"Proxy`select`[]DIRECT\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ruleset-semantic-probe"):
            if request_number == 1:
                body = b"this is not a ruleset\n"
            else:
                body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/template-cache-probe"):
            if request_number == 1:
                body = b"<!doctype html><html><body>transient template error</body></html>"
                content_type = "text/html; charset=utf-8"
            else:
                body = b"[custom]\nenable_rule_generator=false\n"
                content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/template-static-failure-probe"):
            if request_number == 1:
                self.send_response(503)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"transient template failure")
                return
            body = b"[custom]\nenable_rule_generator=false\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ruleset-structure-probe"):
            if request_number == 1:
                body = b"DOMAIN-SUFFIX,\n"
            elif request_number == 2:
                body = b"IP-CIDR,not-a-cidr,Proxy\n"
            else:
                body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ruleset-strict-probe"):
            if request_number == 1:
                body = (
                    b"DOMAIN-SUFFIX,example.com,Proxy\n"
                    b"IP-CIDR,not-a-cidr,Proxy\n"
                    b"PROCESS-NAME-REGEX,^chrome,helper$,Proxy\n"
                    b"DOMAIN-REGEX,[a-z,Proxy\n"
                    b"SUB-RULE,(NETWORK,tcp),sub-rule-name\n"
                    b"[]garbage\n"
                )
            elif request_number == 2:
                body = (
                    b"AND,((DOMAIN-SUFFIX,example.com),"
                    b"(IP-CIDR,not-a-cidr)),Proxy\n"
                )
            else:
                body = STRICT_VALID_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ruleset-regex-probe"):
            if request_number == 1:
                body = (
                    b"DOMAIN-REGEX,[a-z,Proxy\n"
                    b"PROCESS-NAME-REGEX,\"(chrome\",Proxy\n"
                )
            else:
                body = (
                    b"DOMAIN-REGEX,\"^example\\.com$\",OldPolicy\n"
                    b"PROCESS-NAME-REGEX,\"^chrome,helper$\",OldPolicy\n"
                    b"PROCESS-PATH-REGEX,\"^/usr/bin/example$\",OldPolicy\n"
                    b"DOMAIN-REGEX,\"^example\\,comma$\",OldPolicy\n"
                    b"DOMAIN-REGEX,^foo,bar,baz$\n"
                    b"PROCESS-NAME-REGEX,\"^\\($\",OldPolicy\n"
                    b"PROCESS-NAME-REGEX,\"^foo\\\"bar$\",OldPolicy\n"
                    b"PROCESS-PATH-REGEX,\"^//server/share$\",OldPolicy\n"
                )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ruleset-sub-rule-probe"):
            if request_number == 1:
                body = b"SUB-RULE,(NETWORK,tcp),sub-rule-name\n"
            else:
                body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/http-get-204-probe"):
            if request_number == 1:
                self.send_response(204)
                self.end_headers()
                return
            body = (
                b"mixed-port: 7890\n"
                b"proxies: []\n"
                b"proxy-groups: []\n"
                b"rules:\n  - MATCH,DIRECT\n"
            )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/http-get-206-probe"):
            response_status = 206 if request_number == 1 else 200
            body = (
                b"mixed-port: 7890\n"
                b"proxies: []\n"
                b"proxy-groups: []\n"
                b"rules:\n  - MATCH,DIRECT\n"
            )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/sssub-base-object"):
            body = b'{"base":"kept"}'
            content_type = "application/json"
        elif self.path.startswith("/sssub-base-array"):
            body = b"[]"
            content_type = "application/json"
        elif self.path.startswith("/sssub-base-scalar"):
            body = b"true"
            content_type = "application/json"
        elif self.path.startswith("/singbox-base-object"):
            body = b'{"route":{"rules":[]}}'
            content_type = "application/json"
        elif self.path.startswith("/singbox-base-array"):
            body = b"[]"
            content_type = "application/json"
        elif self.path.startswith("/singbox-base-scalar"):
            body = b"true"
            content_type = "application/json"
        elif self.path.startswith("/clash-base-sub-rule-probe"):
            body = (
                b"mixed-port: 7890\n"
                b"proxies: []\n"
                b"proxy-groups:\n"
                b"  - name: Proxy\n"
                b"    type: select\n"
                b"    proxies: [DIRECT]\n"
                b"rules:\n"
                b"  - SUB-RULE,(NETWORK,TCP),sub-rule-name\n"
                b"sub-rules:\n"
                b"  sub-rule-name:\n"
                b"    - DOMAIN-SUFFIX,example.com,DIRECT\n"
                b"    - MATCH,DIRECT\n"
            )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/clash-base-transaction-probe"):
            if request_number == 1:
                body = b"mixed-port: [\n"
            else:
                body = (
                    b"mixed-port: 7890\n"
                    b"proxies: []\n"
                    b"proxy-groups: []\n"
                    b"rules:\n  - MATCH,DIRECT\n"
                )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/ini-base-transaction-probe"):
            if request_number == 1:
                body = b"[General]\nfoo=bar\n[General]\nbaz=qux\n"
            else:
                body = b"[General]\nfoo=bar\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/base-template-transaction-probe"):
            dependency = (
                f"http://127.0.0.1:{self.server.server_port}"
                "/base-template-dependency"
            )
            if request_number == 1:
                body = f'{{{{ fetch("{dependency}") }}}}\nnot: [\n'.encode()
            else:
                body = (
                    f'{{{{ fetch("{dependency}") }}}}\n'
                    "mixed-port: 7890\n"
                    "proxies: []\n"
                    "proxy-groups: []\n"
                    "rules:\n  - MATCH,DIRECT\n"
                ).encode()
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/base-template-dependency"):
            body = b"# dependency fetched during base rendering\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/cross-semantic-probe"):
            with FixtureHandler.cross_semantic_condition:
                FixtureHandler.cross_semantic_waiters += 1
                if FixtureHandler.cross_semantic_waiters >= 2:
                    FixtureHandler.cross_semantic_released = True
                    FixtureHandler.cross_semantic_condition.notify_all()
                else:
                    FixtureHandler.cross_semantic_condition.wait_for(
                        lambda: FixtureHandler.cross_semantic_released, timeout=10
                    )
                if not FixtureHandler.cross_semantic_released:
                    self.send_error(504)
                    return
                FixtureHandler.cross_semantic_deliveries.append(request_number)
            body = (
                SUBSCRIPTION.encode() if request_number <= 2 else RULESET.encode()
            )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/regex-ini-probe") or self.path.startswith(
            "/regex-yaml-probe"
        ):
            if request_number == 1:
                body = b"([@replacement\n"
            else:
                body = b".*@Renamed\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/toml-empty-groups-probe"):
            if request_number == 1:
                body = b"custom_groups = []\n"
            else:
                body = (
                    b'custom_groups = [{ name = "Proxy", type = "select", '
                    b'rule = ["DIRECT"] }]\n'
                )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/toml-invalid-groups-probe"):
            if request_number == 1:
                body = (
                    b'custom_groups = [{ name = "Proxy", type = "invalid", '
                    b'rule = ["DIRECT"] }]\n'
                )
            else:
                body = (
                    b'custom_groups = [{ name = "Proxy", type = "select", '
                    b'rule = ["DIRECT"] }]\n'
                )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/toml-invalid-rulesets-probe"):
            if request_number == 1:
                body = (
                    b'rulesets = [{ group = "Proxy", type = "invalid", '
                    b'ruleset = "https://rules.example.test/list" }]\n'
                )
            else:
                body = (
                    b'rulesets = [{ group = "Proxy", type = "surge-ruleset", '
                    b'ruleset = "https://rules.example.test/list" }]\n'
                )
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/toml-invalid-regex-probe"):
            if request_number == 1:
                body = b'rename_node = [{ match = "([", replace = "x" }]\n'
            else:
                body = b'rename_node = [{ match = ".*", replace = "x" }]\n'
            content_type = "text/plain; charset=utf-8"
        elif self.path == "/fallback-default.ini":
            missing = (
                f"http://127.0.0.1:{self.server.server_port}"
                "/fallback-default-missing"
            )
            body = (
                "[custom]\n"
                f"custom_proxy_group=!!import:{missing}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(response_status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextlib.contextmanager
def fixture_server():
    FixtureHandler.reset_counters()
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
    runtime_details: bool = False,
    legacy_statistics: bool = False,
    invalid_statistics_path: bool = False,
    default_external_config: str | None = None,
    fallback_to_default_external_config: bool = False,
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
    if default_external_config is not None:
        baseline = re.sub(
            r'default_external_config = "[^"]*"',
            f'default_external_config = "{default_external_config}"',
            baseline,
        )
    baseline = baseline.replace(
        "fallback_to_default_external_config = false",
        "fallback_to_default_external_config = "
        + str(fallback_to_default_external_config).lower(),
    )
    if fallback_to_default_external_config and "fallback_to_default_external_config" not in baseline:
        baseline = baseline.replace(
            "[common]\n", "[common]\nfallback_to_default_external_config = true\n", 1
        )
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        statistics_path = temporary_path / "stats"
        stats_path = statistics_path.as_posix()
        baseline = baseline.replace('data_dir = "stats"', f'data_dir = "{stats_path}"')
        if legacy_statistics:
            statistics_path.mkdir(parents=True, exist_ok=True)
            (statistics_path / "statistics.json").write_text(
                '{"schema":4,"legacy":true}',
                encoding="utf-8",
            )
        elif invalid_statistics_path:
            statistics_path.write_text("not a directory", encoding="utf-8")
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
            yield (
                (base_url, statistics_path)
                if runtime_details
                else base_url
            )
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


def dashboard_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(
        binary,
        statistics=True,
        runtime_details=True,
        legacy_statistics=True,
    ) as runtime:
        base_url, statistics_path = runtime
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
        auth_headers = {"Authorization": "Basic " + token}
        status, first_body, first_headers = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        if status != 200 or "no-store" not in first_headers.get("cache-control", ""):
            raise AssertionError("Dashboard data cache-control baseline failed")
        data = json.loads(first_body)
        required_top_level = {
            "enabled",
            "generated_at",
            "started_at",
            "runtime",
            "windows",
            "country_windows",
            "countries",
            "china_region_windows",
            "china_regions",
            "series",
        }
        if not required_top_level.issubset(data):
            raise AssertionError(
                f"Dashboard data fields changed: {required_top_level - set(data)}"
            )
        window_names = {
            "startup",
            "hour",
            "day",
            "seven_days",
            "thirty_days",
            "half_year",
            "year",
            "lifetime",
        }
        if set(data["windows"]) != window_names:
            raise AssertionError("Dashboard window names changed")
        for window in data["windows"].values():
            if (
                not isinstance(window.get("subscription_requests"), int)
                or not isinstance(window.get("rule_conversions"), int)
            ):
                raise AssertionError("Dashboard counter types changed")
        if len(data["series"]) != 24 or not isinstance(data.get("revision"), int):
            raise AssertionError("Dashboard series/revision compatibility failed")
        status, second_body, _ = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        if status != 200 or second_body != first_body:
            raise AssertionError("Dashboard clients did not share the one-second snapshot")

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
        if status != 200:
            raise AssertionError("statistics-enabled /sub compatibility failed")
        time.sleep(1.1)
        status, updated_body, _ = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        updated = json.loads(updated_body)
        if (
            status != 200
            or updated["revision"] <= data["revision"]
            or updated["windows"]["lifetime"]["subscription_requests"] != 1
        ):
            raise AssertionError("Dashboard revision/request accounting failed")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            checkpoints = list(
                statistics_path.glob("statistics-v2-*.bin")
            )
            wal = statistics_path / "statistics-v2.wal"
            if (
                checkpoints
                and wal.is_file()
                and wal.stat().st_size > 0
                and not (statistics_path / "statistics.json").exists()
            ):
                break
            time.sleep(0.1)
        else:
            raise AssertionError(
                "Statistics v2 checkpoint/WAL creation or legacy cleanup failed"
            )
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


def persistence_degradation_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(
        binary,
        statistics=True,
        invalid_statistics_path=True,
    ) as base_url:
        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, _ = request(
            base_url,
            "/dashboard/data",
            headers={"Authorization": "Basic " + token},
        )
        if status != 200 or not json.loads(body).get("enabled"):
            raise AssertionError(
                "Dashboard failed after persistence degradation"
            )
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
        if status != 200:
            raise AssertionError(
                "/sub failed after persistence degradation"
            )

    with running_service(
        binary,
        statistics=False,
        runtime_details=True,
    ) as runtime:
        base_url, statistics_path = runtime
        status, body, _ = request(base_url, "/healthz")
        if status != 200 or body.strip() != b"ok":
            raise AssertionError("statistics-disabled service failed")
        if statistics_path.exists():
            raise AssertionError(
                "statistics-disabled service touched the data directory"
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


def external_config_policy_baseline(binary: Path, fixture_base: str) -> None:
    invalid = fixture_base + "/external-invalid.ini"
    forbidden = fixture_base + "/external-forbidden.ini"
    valid = fixture_base + "/external-valid.ini"
    common = {"target": "clash", "url": fixture_base + "/subscription.txt", "list": "true"}
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": invalid})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("invalid user external config was not fail-closed")
        status, body, _ = request(base_url, "/sub", {**common, "config": valid})
        if status != 200 or b"Smoke" not in body:
            raise AssertionError("valid user external config did not apply")

    with running_service(
        binary,
        default_external_config=valid,
        fallback_to_default_external_config=True,
    ) as base_url:
        status, body, _ = request(base_url, "/sub", {**common, "config": invalid})
        if status != 200 or b"Smoke" not in body:
            raise AssertionError("explicit default external fallback did not apply")

        status, _, headers = request(base_url, "/sub", {**common, "config": forbidden})
        if status != 403 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("permission-denied user config incorrectly used default fallback")

        status, body, _ = request(
            base_url,
            "/sub",
            {**common, "config": invalid, "explain": "true"},
        )
        if status != 200:
            raise AssertionError("explain fallback request failed")
        report = json.loads(body)
        external = report.get("external_config", {})
        if not external.get("fallback_used") or not external.get("attempts"):
            raise AssertionError("explain response omitted external source attempts")
        if external.get("effective_source") != "generic":
            raise AssertionError("explain response omitted the effective source")

        broken_base_content = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"clash_rule_base={fixture_base}/missing-base.yml\n"
        )
        broken_base = "data:text/plain;base64," + base64.urlsafe_b64encode(
            broken_base_content.encode()
        ).decode()
        conversion_common = {key: value for key, value in common.items() if key != "list"}
        status, body, _ = request(
            base_url, "/sub", {**conversion_common, "config": broken_base}
        )
        if status != 200 or b"proxy-providers:" not in body:
            raise AssertionError(
                "default fallback did not recover an external base failure"
            )
        status, body, _ = request(
            base_url,
            "/sub",
            {**conversion_common, "config": broken_base, "explain": "true"},
        )
        if status != 200 or not json.loads(body).get("external_config", {}).get(
            "fallback_used"
        ):
            raise AssertionError(
                "external base fallback was not recorded in explain output"
            )

        broken_import_content = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"custom_proxy_group=!!import:{fixture_base}/missing-import.ini\n"
        )
        broken_import = "data:text/plain;base64," + base64.urlsafe_b64encode(
            broken_import_content.encode()
        ).decode()
        status, body, _ = request(
            base_url, "/sub", {**conversion_common, "config": broken_import}
        )
        if status != 200 or b"proxy-providers:" not in body:
            raise AssertionError(
                "default fallback did not recover an external import failure"
            )
        rejected_import_content = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"custom_proxy_group=!!import:{fixture_base}/external-forbidden.ini\n"
        )
        rejected_import = "data:text/plain;base64," + base64.urlsafe_b64encode(
            rejected_import_content.encode()
        ).decode()
        status, _, headers = request(
            base_url, "/sub", {**conversion_common, "config": rejected_import}
        )
        if status != 403 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(
                "request-rejected external import incorrectly used default fallback"
            )

        rejected_base_content = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"clash_rule_base={fixture_base}/external-forbidden.ini\n"
        )
        rejected_base = "data:text/plain;base64," + base64.urlsafe_b64encode(
            rejected_base_content.encode()
        ).decode()
        status, _, headers = request(
            base_url, "/sub", {**conversion_common, "config": rejected_base}
        )
        if status != 403 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(
                "request-rejected external base incorrectly used default fallback"
            )

        broken_ruleset_content = (
            "[custom]\n"
            "enable_rule_generator=true\n"
            "overwrite_original_rules=true\n"
            f"ruleset=Proxy,clash-domain:{fixture_base}/missing-rules.yml\n"
        )
        broken_ruleset = "data:text/plain;base64," + base64.urlsafe_b64encode(
            broken_ruleset_content.encode()
        ).decode()
        status, body, _ = request(
            base_url,
            "/sub",
            {**conversion_common, "config": broken_ruleset, "expand": "true"},
        )
        if status != 200 or b"proxy-providers:" not in body:
            raise AssertionError(
                "default fallback did not recover an external ruleset failure"
            )
        status, body, _ = request(
            base_url,
            "/sub",
            {
                **conversion_common,
                "config": broken_ruleset,
                "expand": "true",
                "explain": "true",
            },
        )
        if status != 200 or not json.loads(body).get("external_config", {}).get(
            "fallback_used"
        ):
            raise AssertionError(
                "external ruleset fallback was not recorded in explain output"
            )

        rejected_ruleset_content = (
            "[custom]\n"
            "enable_rule_generator=true\n"
            "overwrite_original_rules=true\n"
            f"ruleset=Proxy,clash-domain:{fixture_base}/external-forbidden.ini\n"
        )
        rejected_ruleset = "data:text/plain;base64," + base64.urlsafe_b64encode(
            rejected_ruleset_content.encode()
        ).decode()
        status, _, headers = request(
            base_url,
            "/sub",
            {
                **conversion_common,
                "config": rejected_ruleset,
                "expand": "true",
            },
        )
        if status != 403 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(
                "request-rejected external ruleset incorrectly used default fallback"
            )


def external_import_cache_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/import-cache-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        f"custom_proxy_group=!!import:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {"target": "clash", "url": fixture_base + "/subscription.txt", "list": "true"}

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502:
            raise AssertionError("invalid imported HTML did not fail closed")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError(
                "valid imported content was not fetched after rejection: "
                f"status={status}, body={body[:500]!r}"
            )

    if FixtureHandler.request_counts.get("/import-cache-probe") != 2:
        raise AssertionError(
            "invalid imported HTML was cached or the valid retry did not reach the fixture"
        )


def external_import_semantic_cache_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/import-semantic-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=false\n"
        f"custom_proxy_group=!!import:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("semantically invalid imported content was not rejected")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid imported content did not recover after semantic rejection")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid imported content did not remain usable from cache")

    if FixtureHandler.request_counts.get("/import-semantic-probe") != 2:
        raise AssertionError(
            "semantically invalid imported content was cached or valid retry was not cached"
        )


def external_ruleset_semantic_cache_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/ruleset-semantic-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,surge:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {"target": "clash", "url": fixture_base + "/subscription.txt"}

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("semantically invalid ruleset was not fail-closed")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid ruleset did not recover after semantic rejection")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid ruleset did not remain usable from cache")

    if FixtureHandler.request_counts.get("/ruleset-semantic-probe") != 2:
        raise AssertionError(
            "semantically invalid ruleset was cached or valid retry was not cached"
        )


def template_dependency_cache_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/template-cache-probe?nonce=" + str(time.time_ns())
    config = '{{ fetch("' + probe_url + '") }}'
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("invalid template dependency was not fail-closed")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid template dependency did not recover")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid template dependency did not remain usable from cache")

    if FixtureHandler.request_counts.get("/template-cache-probe") != 2:
        raise AssertionError(
            "invalid template dependency was cached or valid retry was not cached"
        )


def template_static_dependency_failure_baseline(
    binary: Path, fixture_base: str
) -> None:
    probe_url = fixture_base + "/template-static-failure-probe?nonce=" + str(
        time.time_ns()
    )
    config = '[custom]\nenable_rule_generator=false\n{{ fetch("' + probe_url + '") }}\n'
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(
                "static template content masked a failed fetch dependency"
            )
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid static template dependency did not recover")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid static template dependency did not remain cached")

    if FixtureHandler.request_counts.get("/template-static-failure-probe") != 2:
        raise AssertionError(
            "failed static template dependency was cached or valid retry missed the fixture"
        )


def external_ruleset_structure_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/ruleset-structure-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,surge:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {"target": "clash", "url": fixture_base + "/subscription.txt"}

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        for invalid_description in ("empty field", "invalid CIDR"):
            status, _, headers = request(
                base_url, "/sub", {**common, "config": config_url}
            )
            if status != 502 or "no-store" not in headers.get("cache-control", ""):
                raise AssertionError(
                    f"ruleset with {invalid_description} was not rejected"
                )
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid structurally checked ruleset did not recover")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid structurally checked ruleset did not remain cached")

    if FixtureHandler.request_counts.get("/ruleset-structure-probe") != 3:
        raise AssertionError(
            "invalid ruleset content was cached or valid ruleset cache was not reused"
        )


def external_ruleset_strict_validation_baseline(
    binary: Path, fixture_base: str
) -> None:
    probe_url = fixture_base + "/ruleset-strict-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,clash-classic:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "expand": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(
                "mixed valid/invalid or malformed inline rules were not rejected"
            )
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("invalid nested compound rules were not rejected")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("fully valid ruleset did not recover")
        for expected_rule in (
            b"AND,((DOMAIN-SUFFIX,example.com),(DOMAIN,network.example)),Proxy",
            b"OR,((DOMAIN,one.example),(DOMAIN,two.example)),Proxy",
            b"NOT,((DOMAIN-SUFFIX,example.net)),Proxy",
            b"AND,((OR,((DOMAIN-SUFFIX,nested.example),(DOMAIN,inner.example))),"
            b"(DOMAIN,network.example)),Proxy",
            b"DOMAIN-SUFFIX,existing.example,Proxy",
            b"IP-CIDR,203.0.113.0/24,Proxy,no-resolve",
            b"AND,((DOMAIN,already.example),(DOMAIN,also.example)),Proxy",
            b"OR,((DOMAIN,old-one.example),(DOMAIN,old-two.example)),Proxy",
            b"NOT,((DOMAIN,old-not.example)),Proxy",
            b"DOMAIN-REGEX,^example\\.com$,Proxy",
            b"PROCESS-NAME-REGEX,^chrome,helper$,Proxy",
            b"PROCESS-PATH-REGEX,^/usr/bin/example$,Proxy",
            b"DOMAIN-REGEX,^example\\,comma$,Proxy",
            b"PROCESS-NAME-REGEX,^\\($,Proxy",
            b"PROCESS-NAME-REGEX,^foo\\\"bar$,Proxy",
            b"PROCESS-PATH-REGEX,^//server/share$,Proxy",
        ):
            if expected_rule not in body:
                raise AssertionError(
                    "valid server-side compound rule was not preserved: "
                    + expected_rule.decode()
                )
        if b"OldPolicy" in body:
            raise AssertionError("existing rule policy was duplicated instead of replaced")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("fully valid ruleset did not remain cached")

    if FixtureHandler.request_counts.get("/ruleset-strict-probe") != 3:
        raise AssertionError(
            "strict ruleset validation cached an invalid mixed or nested response"
        )


def assert_mihomo_config(validator: Path, body: bytes, description: str) -> None:
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as handle:
        handle.write(body)
        config_path = Path(handle.name)
    try:
        completed = subprocess.run(
            [str(validator), str(config_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        config_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"Mihomo rejected {description}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )


def assert_mihomo_regex_rule(
    validator: Path,
    rule: str,
    expected_type: str,
    expected_payload: str,
    expected_target: str,
) -> None:
    completed = subprocess.run(
        [str(validator), "--regex", rule],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Mihomo rejected final regex rule {rule!r}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Mihomo regex helper returned invalid JSON for {rule!r}: "
            f"{completed.stdout!r}"
        ) from exc
    expected = {
        "type": expected_type,
        "payload": expected_payload,
        "target": expected_target,
    }
    if parsed != expected:
        raise AssertionError(
            f"Mihomo parsed {rule!r} as {parsed!r}, expected {expected!r}"
        )


def external_ruleset_regex_validation_baseline(
    binary: Path, fixture_base: str, mihomo_config_validator: Path
) -> None:
    probe_url = fixture_base + "/ruleset-regex-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,clash-classic:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "expand": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("invalid regex ruleset was not rejected")
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid regex ruleset did not recover")
        for expected_rule in (
            b"DOMAIN-REGEX,^example\\.com$,Proxy",
            b"PROCESS-NAME-REGEX,^chrome,helper$,Proxy",
            b"PROCESS-PATH-REGEX,^/usr/bin/example$,Proxy",
            b"DOMAIN-REGEX,^example\\,comma$,Proxy",
            b"DOMAIN-REGEX,^foo,bar,baz$,Proxy",
        ):
            if expected_rule not in body:
                raise AssertionError(
                    "valid regex rule was not preserved: " + expected_rule.decode()
                )
        if b'PROCESS-NAME-REGEX,"' in body:
            raise AssertionError("regex input quotes leaked into Mihomo output")
        for rule, payload in (
            ("DOMAIN-REGEX,^example\\.com$,Proxy", r"^example\.com$"),
            ("PROCESS-NAME-REGEX,^chrome,helper$,Proxy", "^chrome,helper$"),
            ("PROCESS-PATH-REGEX,^/usr/bin/example$,Proxy", r"^/usr/bin/example$"),
            ("DOMAIN-REGEX,^example\\,comma$,Proxy", r"^example\,comma$"),
            (r"DOMAIN-REGEX,^foo,bar,baz$,Proxy", r"^foo,bar,baz$"),
            (r"PROCESS-NAME-REGEX,^\($,Proxy", r"^\($"),
            (r'PROCESS-NAME-REGEX,^foo\"bar$,Proxy', r'^foo\"bar$'),
            (r"PROCESS-PATH-REGEX,^//server/share$,Proxy", r"^//server/share$"),
        ):
            assert_mihomo_regex_rule(
                mihomo_config_validator,
                rule,
                rule.split(",", 1)[0],
                payload,
                "Proxy",
            )
        if b"OldPolicy" in body:
            raise AssertionError("regex rule policy was duplicated instead of replaced")
        assert_mihomo_config(
            mihomo_config_validator, body, "the generated regex ruleset configuration"
        )
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid regex ruleset did not remain cached")

    if FixtureHandler.request_counts.get("/ruleset-regex-probe") != 2:
        raise AssertionError("invalid regex ruleset was cached")


def external_ruleset_sub_rule_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/ruleset-sub-rule-probe?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,clash-classic:{probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "expand": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("server-side SUB-RULE was not rejected")
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid ruleset did not recover after SUB-RULE rejection")
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("valid ruleset did not remain cached after recovery")

    if FixtureHandler.request_counts.get("/ruleset-sub-rule-probe") != 2:
        raise AssertionError("rejected SUB-RULE ruleset was cached")


def json_base_shape_baseline(binary: Path, fixture_base: str) -> None:
    subscription_url = fixture_base + "/subscription.txt"

    def config_url(key: str, endpoint: str) -> str:
        config = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"{key}={fixture_base}{endpoint}?nonce={time.time_ns()}\n"
        )
        return "data:text/plain;base64," + base64.urlsafe_b64encode(
            config.encode()
        ).decode()

    def request_target(
        base_url: str, target: str, config: str
    ) -> tuple[int, bytes, dict[str, str]]:
        return request(
            base_url,
            "/sub",
            {"target": target, "url": subscription_url, "config": config},
        )

    with running_service(binary) as base_url:
        status, body, _ = request_target(
            base_url, "sssub", config_url("sssub_rule_base", "/sssub-base-object")
        )
        if status != 200 or not isinstance(json.loads(body), list):
            raise AssertionError("valid SSSUB object base did not produce a JSON array")

        status, body, _ = request_target(
            base_url,
            "singbox",
            config_url("singbox_rule_base", "/singbox-base-object"),
        )
        if status != 200 or not isinstance(json.loads(body), dict):
            raise AssertionError("valid sing-box object base did not produce a JSON object")

        for target, key, endpoint in (
            ("sssub", "sssub_rule_base", "/sssub-base-array"),
            ("sssub", "sssub_rule_base", "/sssub-base-scalar"),
            ("singbox", "singbox_rule_base", "/singbox-base-array"),
            ("singbox", "singbox_rule_base", "/singbox-base-scalar"),
        ):
            status, _, headers = request_target(
                base_url, target, config_url(key, endpoint)
            )
            if status != 502 or "no-store" not in headers.get("cache-control", ""):
                raise AssertionError(
                    f"non-object {target} base was not rejected with no-store: {status}"
                )
        status, body, _ = request(base_url, "/healthz")
        if status != 200 or body.strip() != b"ok":
            raise AssertionError("non-object JSON base caused the service to stop")


def clash_base_sub_rule_baseline(
    binary: Path, fixture_base: str, mihomo_config_validator: Path
) -> None:
    config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        f"ruleset=Proxy,clash-classic:{fixture_base}/rules.list\n"
        f"clash_rule_base={fixture_base}/clash-base-sub-rule-probe?nonce={time.time_ns()}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "expand": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"SUB-RULE,(NETWORK,TCP),sub-rule-name" not in body:
            raise AssertionError("valid base SUB-RULE was rewritten or rejected")
        if b"sub-rules:" not in body:
            raise AssertionError("base SUB-RULE definition was not preserved")
        if (
            b"rules:\n  - SUB-RULE,(NETWORK,TCP),sub-rule-name\n"
            b"  - DOMAIN-SUFFIX,example.com,Proxy" not in body
        ):
            raise AssertionError("rule generation did not append after base SUB-RULE")
        assert_mihomo_config(
            mihomo_config_validator, body, "the generated base SUB-RULE configuration"
        )
        status, body, _ = request(
            base_url, "/sub", {**common, "config": config_url}
        )
        if status != 200 or b"SUB-RULE,(NETWORK,TCP),sub-rule-name" not in body:
            raise AssertionError("valid base SUB-RULE did not remain cached")

    if FixtureHandler.request_counts.get("/clash-base-sub-rule-probe") != 1:
        raise AssertionError("valid base SUB-RULE was not cached")


def external_get_status_baseline(binary: Path, fixture_base: str) -> None:
    subscription_url = fixture_base + "/subscription.txt"

    def config_url(endpoint: str) -> str:
        config = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"clash_rule_base={fixture_base}{endpoint}?nonce={time.time_ns()}\n"
        )
        return "data:text/plain;base64," + base64.urlsafe_b64encode(
            config.encode()
        ).decode()

    common = {"target": "clash", "url": subscription_url}
    with running_service(binary) as base_url:
        for endpoint in ("/http-get-204-probe", "/http-get-206-probe"):
            FixtureHandler.reset_counters()
            params = {**common, "config": config_url(endpoint)}
            status, _, headers = request(base_url, "/sub", params)
            if status != 502 or "no-store" not in headers.get(
                "cache-control", ""
            ):
                raise AssertionError(
                    f"GET {endpoint} non-200 2xx response was accepted or cached"
                )
            status, body, _ = request(base_url, "/sub", params)
            if status != 200 or b"proxy-groups:" not in body:
                raise AssertionError(
                    f"GET {endpoint} did not recover on a later 200 response"
                )
            status, body, _ = request(base_url, "/sub", params)
            if status != 200 or b"proxy-groups:" not in body:
                raise AssertionError(
                    f"GET {endpoint} valid 200 response was not cached"
                )
            if FixtureHandler.request_counts.get(endpoint) != 2:
                raise AssertionError(
                    f"GET {endpoint} non-200 2xx response was cached"
                )


def external_base_cache_transaction_baseline(
    binary: Path,
    fixture_base: str,
    *,
    target: str,
    config_key: str,
    endpoint: str,
    marker: bytes,
) -> None:
    probe_url = fixture_base + endpoint + "?nonce=" + str(time.time_ns())
    config = (
        "[custom]\n"
        "enable_rule_generator=false\n"
        f"{config_key}={probe_url}\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {"target": target, "url": fixture_base + "/subscription.txt"}

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError(f"invalid {target} base was not fail-closed")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or marker not in body:
            raise AssertionError(f"valid {target} base did not recover")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or marker not in body:
            raise AssertionError(f"valid {target} base did not remain cached")

    if FixtureHandler.request_counts.get(endpoint) != 2:
        raise AssertionError(
            f"invalid {target} base was cached or valid retry missed the fixture"
        )


def external_base_template_transaction_baseline(
    binary: Path, fixture_base: str
) -> None:
    external_base_cache_transaction_baseline(
        binary,
        fixture_base,
        target="clash",
        config_key="clash_rule_base",
        endpoint="/base-template-transaction-probe",
        marker=b"proxy-groups:",
    )
    if FixtureHandler.request_counts.get("/base-template-dependency") != 2:
        raise AssertionError(
            "template dependency was committed before the final base format validated"
        )


def semantic_cache_concurrency_baseline(binary: Path, fixture_base: str) -> None:
    probe_url = fixture_base + "/cross-semantic-probe?nonce=" + str(time.time_ns())
    strict_config = (
        "[custom]\n"
        "enable_rule_generator=true\n"
        "overwrite_original_rules=true\n"
        f"ruleset=Proxy,surge:{probe_url}\n"
    )
    strict_config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        strict_config.encode()
    ).decode()
    immediate_params = {
        "target": "clash",
        "url": probe_url,
        "list": "true",
        "config": DISABLE_RULEGEN_CONFIG,
    }
    strict_params = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "config": strict_config_url,
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        with ThreadPoolExecutor(max_workers=2) as executor:
            immediate_future = executor.submit(
                request, base_url, "/sub", immediate_params
            )
            strict_future = executor.submit(request, base_url, "/sub", strict_params)
            immediate_status, immediate_body, _ = immediate_future.result(timeout=30)
            strict_status, strict_body, strict_headers = strict_future.result(timeout=30)
        if immediate_status != 200:
            raise AssertionError(
                "immediate semantic consumer failed during concurrency test: "
                f"{immediate_status}, body={immediate_body[:500]!r}, "
                f"deliveries={FixtureHandler.cross_semantic_deliveries!r}, "
                f"counts={FixtureHandler.request_counts!r}"
            )
        if strict_status != 502 or "no-store" not in strict_headers.get(
            "cache-control", ""
        ):
            raise AssertionError(
                "strict semantic consumer did not reject the concurrently returned invalid ruleset: "
                f"status={strict_status}, body={strict_body[:500]!r}"
            )
        status, body, _ = request(base_url, "/sub", strict_params)
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError(
                "strict consumer reused the immediate consumer cache instead of refetching"
            )
        status, body, _ = request(base_url, "/sub", strict_params)
        if status != 200 or b"proxy-groups:" not in body:
            raise AssertionError("strict semantic cache was not reusable after validation")

    if FixtureHandler.request_counts.get("/cross-semantic-probe") != 3:
        raise AssertionError(
            "semantic cache isolation concurrency count did not show two invalid/one valid network fetches"
        )
    if sorted(FixtureHandler.cross_semantic_deliveries[:2]) != [1, 2]:
        raise AssertionError(
            "semantic cache isolation fixture did not release two concurrent first fetches: "
            f"deliveries={FixtureHandler.cross_semantic_deliveries!r}"
        )


def external_regex_import_baseline(
    binary: Path, fixture_base: str, *, yaml: bool
) -> None:
    endpoint = "/regex-yaml-probe" if yaml else "/regex-ini-probe"
    probe_url = fixture_base + endpoint + "?nonce=" + str(time.time_ns())
    if yaml:
        config = (
            "custom:\n"
            "  enable_rule_generator: false\n"
            "  rename_node:\n"
            f'    - import: "{probe_url}"\n'
        )
    else:
        config = (
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"rename=!!import:{probe_url}\n"
        )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            kind = "YAML" if yaml else "INI"
            raise AssertionError(f"invalid {kind} imported regex was not rejected")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid imported regex did not recover")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError("valid imported regex did not remain cached")

    if FixtureHandler.request_counts.get(endpoint) != 2:
        raise AssertionError("invalid imported regex was cached")


def toml_import_semantic_baseline(
    binary: Path, fixture_base: str, endpoint: str, key: str, *, empty: bool = False
) -> None:
    probe_url = fixture_base + endpoint + "?nonce=" + str(time.time_ns())
    config = (
        "version=1\n"
        f'{key}=[{{ import = "{probe_url}" }}]\n'
        "[custom]\n"
        "enable_rule_generator=false\n"
    )
    config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        config.encode()
    ).decode()
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }

    FixtureHandler.reset_counters()
    with running_service(binary) as base_url:
        status, _, headers = request(base_url, "/sub", {**common, "config": config_url})
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            kind = "empty" if empty else "malformed"
            raise AssertionError(f"TOML {kind} import was not rejected for {key}")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError(f"valid TOML import did not recover for {key}")
        status, body, _ = request(base_url, "/sub", {**common, "config": config_url})
        if status != 200 or b"proxies:" not in body:
            raise AssertionError(f"valid TOML import did not remain cached for {key}")

    if FixtureHandler.request_counts.get(endpoint) != 2:
        raise AssertionError(f"invalid TOML import was cached for {key}")


def default_dependency_single_execution_baseline(
    binary: Path, fixture_base: str
) -> None:
    user_missing = fixture_base + "/fallback-user-missing"
    user_config = (
        "[custom]\n"
        f"custom_proxy_group=!!import:{user_missing}\n"
    )
    user_config_url = "data:text/plain;base64," + base64.urlsafe_b64encode(
        user_config.encode()
    ).decode()
    common = {"target": "clash", "url": fixture_base + "/subscription.txt", "list": "true"}

    FixtureHandler.reset_counters()
    with running_service(
        binary,
        default_external_config=fixture_base + "/fallback-default.ini",
        fallback_to_default_external_config=True,
    ) as base_url:
        status, _, headers = request(
            base_url, "/sub", {**common, "config": user_config_url}
        )
        if status != 502 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("failed default dependency chain was not fail-closed")

    if FixtureHandler.request_counts.get("/fallback-default.ini") != 1:
        raise AssertionError(
            "default external config was executed more than once: "
            f"counts={FixtureHandler.request_counts!r}"
        )
    if FixtureHandler.request_counts.get("/fallback-default-missing") != 1:
        raise AssertionError("default external dependency was retried more than once")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--settings-snapshot-helper", type=Path, required=True
    )
    parser.add_argument("--mihomo-config-validator", type=Path, required=True)
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
    mihomo_config_validator = args.mihomo_config_validator.resolve()
    if not mihomo_config_validator.is_file():
        parser.error(
            "Mihomo config validator does not exist: "
            f"{mihomo_config_validator}"
        )

    runtime_cli_isolation_baseline(binary)

    snapshots = [
        load_settings_snapshot(settings_snapshot_helper, COMPAT_FIXTURES / name)
        for name in ("legacy-pref.ini", "legacy-pref.yml", "legacy-pref.toml")
    ]
    if snapshots[1:] != snapshots[:1] * 2:
        raise AssertionError("INI/YAML/TOML SettingsSnapshot values differ")
    if "publish_enabled" in snapshots[0]["custom_openclash_rules"]:
        raise AssertionError("removed publish_enabled leaked into SettingsSnapshot")
    if snapshots[0]["common"]["fallback_to_default_external_config"]:
        raise AssertionError("fallback_to_default_external_config default changed")
    if snapshots[0]["security"]["profile"] != "lan":
        raise AssertionError("historical security profile default changed")

    with fixture_server() as fixture_base:
        with running_service(binary) as base_url:
            conversion_baselines(base_url, fixture_base, args.update_golden)
        dashboard_baseline(binary, fixture_base)
        persistence_degradation_baseline(binary, fixture_base)
        public_request_baseline(binary, fixture_base)
        external_config_policy_baseline(binary, fixture_base)
        external_import_cache_baseline(binary, fixture_base)
        external_import_semantic_cache_baseline(binary, fixture_base)
        external_ruleset_semantic_cache_baseline(binary, fixture_base)
        external_ruleset_structure_baseline(binary, fixture_base)
        external_ruleset_strict_validation_baseline(binary, fixture_base)
        external_ruleset_regex_validation_baseline(
            binary, fixture_base, mihomo_config_validator
        )
        external_ruleset_sub_rule_baseline(binary, fixture_base)
        json_base_shape_baseline(binary, fixture_base)
        clash_base_sub_rule_baseline(
            binary, fixture_base, mihomo_config_validator
        )
        external_get_status_baseline(binary, fixture_base)
        semantic_cache_concurrency_baseline(binary, fixture_base)
        template_dependency_cache_baseline(binary, fixture_base)
        template_static_dependency_failure_baseline(binary, fixture_base)
        external_base_cache_transaction_baseline(
            binary,
            fixture_base,
            target="clash",
            config_key="clash_rule_base",
            endpoint="/clash-base-transaction-probe",
            marker=b"proxy-groups:",
        )
        external_base_cache_transaction_baseline(
            binary,
            fixture_base,
            target="surge",
            config_key="surge_rule_base",
            endpoint="/ini-base-transaction-probe",
            marker=b"[Proxy]",
        )
        external_base_template_transaction_baseline(binary, fixture_base)
        external_regex_import_baseline(binary, fixture_base, yaml=False)
        external_regex_import_baseline(binary, fixture_base, yaml=True)
        toml_import_semantic_baseline(
            binary, fixture_base, "/toml-empty-groups-probe", "custom_groups", empty=True
        )
        toml_import_semantic_baseline(
            binary, fixture_base, "/toml-invalid-groups-probe", "custom_groups"
        )
        toml_import_semantic_baseline(
            binary, fixture_base, "/toml-invalid-rulesets-probe", "rulesets"
        )
        toml_import_semantic_baseline(
            binary, fixture_base, "/toml-invalid-regex-probe", "rename_node"
        )
        default_dependency_single_execution_baseline(binary, fixture_base)

    print("compatibility and security baselines passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"compatibility/security baseline failed: {error}", file=sys.stderr)
        raise
