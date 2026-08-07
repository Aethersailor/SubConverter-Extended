#!/usr/bin/env python3
"""Offline compatibility and security baselines for the built service."""

from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
import hashlib
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
VLESS_URI = (
    "vless://11111111-1111-1111-1111-111111111111@vless.example.test:443"
    "?security=tls&type=ws&host=vless.example.test&path=%2Fws#VLESSFixture"
)
HYSTERIA2_URI = (
    "hysteria2://hy-password@hy2.example.test:8443/?insecure=1"
    "&obfs=salamander&obfs-password=real-obfs-password"
    "&sni=hy2.example.test#Hy2Fixture"
)
MIXED_PROTOCOL_SUBSCRIPTION = SUBSCRIPTION + VLESS_URI + "\n" + HYSTERIA2_URI + "\n"
RULESET = (
    "DOMAIN-SUFFIX,example.com,Proxy\n"
    "IP-CIDR,198.51.100.0/24,Proxy\n"
)
RULESET_WITH_INVALID_LINE = (
    "DOMAIN-SUFFIX,valid-before.example,SourcePolicy\n"
    "NOT-A-SUPPORTED-RULE,this-entry-must-be-skipped\n"
    "IP-CIDR,203.0.113.0/24,SourcePolicy\n"
)
GENERATION_RULESET = (
    "DOMAIN-SUFFIX,first.snapshot.test,Proxy\n"
    "DOMAIN-SUFFIX,second.snapshot.test,Proxy\n"
    "DOMAIN-SUFFIX,third.snapshot.test,Proxy\n"
)
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"


class FixtureHandler(BaseHTTPRequestHandler):
    gist_request_count = 0
    slow_subscription_started = threading.Event()
    slow_subscription_release = threading.Event()
    slow_ruleset_started = threading.Event()
    slow_ruleset_release = threading.Event()

    def do_GET(self) -> None:  # noqa: N802
        request_path = urllib.parse.urlsplit(self.path).path
        if request_path == "/subscription.txt":
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/slow-subscription.txt":
            type(self).slow_subscription_started.set()
            if not type(self).slow_subscription_release.wait(timeout=15):
                self.send_error(504)
                return
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/mixed-protocol-subscription.txt":
            body = MIXED_PROTOCOL_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/rules.list":
            body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/rules-with-invalid.list":
            body = RULESET_WITH_INVALID_LINE.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/generation-rules.list":
            body = GENERATION_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/slow-generation-rules.list":
            type(self).slow_ruleset_started.set()
            if not type(self).slow_ruleset_release.wait(timeout=15):
                self.send_error(504)
                return
            body = GENERATION_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-valid.ini":
            body = b"[custom]\nenable_rule_generator=false\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-empty.ini":
            body = b""
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-template-failure.ini":
            body = b"[custom]\nenable_rule_generator={{ invalid\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-template-fetch-failure.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"unused={{{{ fetch(\"http://{host}/missing-template-input\") }}}}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-malicious-base.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"clash_rule_base=http://{host}/malicious-base.yaml\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/malicious-base.yaml":
            body = b'{% include "template-exception-cookie-secret.tpl" %}\n'
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-no-effective.ini":
            body = b"[custom]\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-import-failure.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"ruleset=!!import:http://{host}/missing-import.list\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path in (
            "/external-generation.ini",
            "/external-generation-slow.ini",
        ):
            host = self.headers.get("Host", "127.0.0.1")
            rules_path = (
                "/slow-generation-rules.list"
                if request_path.endswith("-slow.ini")
                else "/generation-rules.list"
            )
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                f"singbox_rule_base=http://{host}/snapshot-singbox.json\n"
                f"ruleset=Proxy,http://{host}{rules_path}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/snapshot-singbox.json":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "{\n"
                '  "snapshot_link": "{{ getLink("/snapshot") }}",\n'
                f'  "template_fetch": "{{{{ fetch("http://{host}/template-marker") }}}}",\n'
                '  "outbounds": [],\n'
                '  "route": {"rules": []}\n'
                "}\n"
            ).encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/template-marker":
            body = b"template-ok"
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_gist_response(self) -> None:
        type(self).gist_request_count += 1
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            self.rfile.read(content_length)
        body = b'{"id":"fixture-gist","owner":{"login":"fixture-user"}}'
        self.send_response(201 if self.command == "POST" else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/gists":
            self.send_error(404)
            return
        self._write_gist_response()

    def do_PATCH(self) -> None:  # noqa: N802
        if not self.path.startswith("/gists/"):
            self.send_error(404)
            return
        self._write_gist_response()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextlib.contextmanager
def fixture_server():
    FixtureHandler.gist_request_count = 0
    FixtureHandler.slow_subscription_started.clear()
    FixtureHandler.slow_subscription_release.set()
    FixtureHandler.slow_ruleset_started.clear()
    FixtureHandler.slow_ruleset_release.set()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        FixtureHandler.slow_subscription_release.set()
        FixtureHandler.slow_ruleset_release.set()
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
    method: str = "GET",
) -> tuple[int, bytes, dict[str, str]]:
    query = urllib.parse.urlencode(params or {})
    url = base_url + path + (f"?{query}" if query else "")
    req = urllib.request.Request(url, headers=headers or {}, method=method)
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


def request_with_raw_headers(
    base_url: str, path: str, headers: list[tuple[str, str]]
) -> int:
    parsed = urllib.parse.urlsplit(base_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=20) as sock:
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {parsed.hostname}:{parsed.port}",
            "Connection: close",
        ]
        request_lines.extend(f"{name}: {value}" for name, value in headers)
        sock.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii"))
        response = b""
        while b"\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    try:
        return int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError) as error:
        raise AssertionError(f"invalid raw HTTP response: {status_line!r}") from error


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
    allow_public_upload: bool = False,
    listen_address: str = "127.0.0.1",
    extra_args: tuple[str, ...] = (),
    runtime_details: bool = False,
    legacy_statistics: bool = False,
    invalid_statistics_path: bool = False,
    fallback_to_default_external_config: bool = False,
    default_external_config: str | None = None,
    legacy_publish_enabled: bool = False,
    proxy_provider_interval: int | None = None,
    proxy_provider_direct: bool | None = None,
    dashboard_client_ip_header: str | None = None,
    dashboard_trusted_proxy_cidrs: tuple[str, ...] = (),
    gist_api_base: str | None = None,
    gist_config_hardlink_failure: bool = False,
    log_capture: list[str] | None = None,
    log_level: str = "info",
    config_replacements: tuple[tuple[str, str], ...] = (),
    pref_path_capture: list[Path] | None = None,
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
    if legacy_publish_enabled:
        baseline = baseline.replace(
            "publish_enabled = false", "publish_enabled = true"
        )
    if proxy_provider_interval is not None or proxy_provider_direct is not None:
        provider_settings = ["[proxy_provider]"]
        if proxy_provider_interval is not None:
            provider_settings.append(f"interval = {proxy_provider_interval}")
        if proxy_provider_direct is not None:
            provider_settings.append(
                f"proxy_direct = {str(proxy_provider_direct).lower()}"
            )
        baseline = baseline.replace(
            "[custom_openclash_rules]",
            "\n".join(provider_settings)
            + "\n\n"
            "[custom_openclash_rules]",
            1,
        )
    if default_external_config is not None:
        baseline = baseline.replace(
            'default_external_config = "data:,enable_rule_generator=false"',
            "default_external_config = "
            + json.dumps(default_external_config),
        )
    if fallback_to_default_external_config:
        baseline = baseline.replace(
            "append_proxy_type = false",
            "fallback_to_default_external_config = true\n"
            "append_proxy_type = false",
            1,
        )
    if dashboard_client_ip_header is not None or dashboard_trusted_proxy_cidrs:
        header = dashboard_client_ip_header or "none"
        client_ip_section = (
            "lock_seconds = 60\n\n"
            "[statistics.dashboard_auth.client_ip]\n"
            f"header = {json.dumps(header)}\n"
            "trusted_proxy_cidrs = "
            f"{json.dumps(list(dashboard_trusted_proxy_cidrs))}"
        )
        baseline = baseline.replace("lock_seconds = 60", client_ip_section, 1)
    baseline = baseline.replace('proxy_subscription = "SYSTEM"', 'proxy_subscription = "NONE"')
    baseline = baseline.replace('log_level = "info"', f'log_level = "{log_level}"')
    baseline = baseline.replace('enabled = true\n', f"enabled = {str(statistics).lower()}\n", 1)
    baseline = baseline.replace('profile = "lan"', f'profile = "{security_profile}"')
    baseline = baseline.replace(
        "allow_public_upload = false",
        f"allow_public_upload = {str(allow_public_upload).lower()}",
    )
    baseline = baseline.replace(
        'listen = "127.0.0.1"', f'listen = "{listen_address}"'
    )
    for original, replacement in config_replacements:
        if original not in baseline:
            raise AssertionError(
                f"runtime configuration replacement source is missing: {original!r}"
            )
        baseline = baseline.replace(original, replacement, 1)
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
        if pref_path_capture is not None:
            pref_path_capture.append(pref)
        stdout_path = temporary_path / "stdout.log"
        stderr_path = temporary_path / "stderr.log"
        stdout = stdout_path.open("wb")
        stderr = stderr_path.open("wb")
        if gist_api_base is not None:
            gist_config = temporary_path / "gistconf.ini"
            gist_config.write_text(
                "[common]\n"
                "token=fixture-token\n"
                "username=fixture-user\n",
                encoding="utf-8",
                newline="\n",
            )
            if gist_config_hardlink_failure:
                os.link(gist_config, temporary_path / "gistconf-hardlink.ini")
        env = os.environ.copy()
        env.pop("SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER", None)
        env.pop("SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS", None)
        env.pop("SUBCONVERTER_SECURITY_PROFILE", None)
        env.pop("SUBCONVERTER_ALLOW_PUBLIC_UPLOAD", None)
        env.pop("SUBCONVERTER_GIST_API_BASE", None)
        if gist_api_base is not None:
            env["SUBCONVERTER_GIST_API_BASE"] = gist_api_base
        env["PORT"] = str(port)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = "127.0.0.1,localhost"
        process = subprocess.Popen(
            [str(binary), *extra_args, "-f", str(pref)],
            cwd=temporary_path if gist_api_base is not None else REPOSITORY,
            env=env,
            stdout=stdout,
            stderr=stderr,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            try:
                wait_ready(base_url, process)
            except Exception as error:
                stderr.flush()
                diagnostics = stderr_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                raise AssertionError(
                    f"{error}; service stderr tail: {diagnostics[-8000:]!r}"
                ) from error
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
            if log_capture is not None:
                log_capture.append(
                    stderr_path.read_text(encoding="utf-8", errors="replace")
                )


def run_settings_snapshot(
    helper: Path,
    fixture: Path,
    environment: dict[str, str] | None = None,
) -> tuple[dict[str, object], str]:
    env = os.environ.copy() if environment is None else environment.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        if environment is None:
            env.pop(name, None)
    completed = subprocess.run(
        [str(helper), str(fixture)],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "settings snapshot helper failed with "
            f"exit {completed.returncode}; stderr tail: "
            f"{completed.stderr[-8000:]!r}"
        )
    if "fixture-secret" in completed.stdout or "fixture-dashboard-secret" in completed.stdout:
        raise AssertionError("SettingsSnapshot leaked a fixture secret")
    return json.loads(completed.stdout), completed.stderr


def load_settings_snapshot(
    helper: Path,
    fixture: Path,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    snapshot, _ = run_settings_snapshot(helper, fixture, environment)
    return snapshot


def reload_settings_snapshot(
    helper: Path,
    first: Path,
    second: Path,
    *,
    expect_failure: bool = False,
) -> dict[str, object]:
    command = [str(helper), str(first), str(second)]
    if expect_failure:
        command.append("--expect-reload-failure")
    env = os.environ.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        env.pop(name, None)
    completed = subprocess.run(
        command,
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "settings reload helper failed with "
            f"exit {completed.returncode}; stderr tail: "
            f"{completed.stderr[-8000:]!r}"
        )
    return json.loads(completed.stdout)


def security_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        env.pop(name, None)
    return env


def replace_security_profile(
    content: str, suffix: str, value: str | None
) -> str:
    patterns = {
        ".ini": r"(?m)^profile=.*\n?",
        ".yml": r"(?m)^  profile:.*\n?",
        ".toml": r'(?m)^profile\s*=.*\n?',
    }
    replacements = {
        ".ini": "" if value is None else f"profile={value}\n",
        ".yml": "" if value is None else f"  profile: {value}\n",
        ".toml": "" if value is None else f'profile = "{value}"\n',
    }
    pattern = patterns.get(suffix)
    if pattern is None:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    updated, count = re.subn(pattern, replacements[suffix], content, count=1)
    if count != 1:
        raise AssertionError(f"security profile line missing: {suffix}")
    return updated


def security_configuration_matrix_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        fixtures = (
            COMPAT_FIXTURES / "legacy-pref.ini",
            COMPAT_FIXTURES / "legacy-pref.yml",
            COMPAT_FIXTURES / "legacy-pref.toml",
        )
        for original in fixtures:
            original_content = original.read_text(encoding="utf-8")
            source = "file:yaml" if original.suffix == ".yml" else (
                "file:" + original.suffix.removeprefix(".")
            )
            for configured, expected in (
                (None, "lan"),
                ("lan", "lan"),
                ("public", "public"),
                ("strict", "strict"),
                ("publci", "lan"),
            ):
                label = "missing" if configured is None else configured
                candidate = temporary_path / f"{original.stem}-{label}{original.suffix}"
                candidate.write_text(
                    replace_security_profile(
                        original_content, original.suffix, configured
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                snapshot, logs = run_settings_snapshot(helper, candidate)
                actual = snapshot["security"]["profile"]
                if actual != expected:
                    raise AssertionError(
                        f"{original.suffix} profile={label} became {actual}, "
                        f"expected {expected}"
                    )
                expected_source = "builtin-default" if configured is None else source
                event = (
                    f"SECURITY_PROFILE_EFFECTIVE profile={expected} "
                    f"source={expected_source}"
                )
                if event not in logs:
                    raise AssertionError(
                        f"{original.suffix} profile={label} source log missing: "
                        f"{logs!r}"
                    )
                invalid_event = "SECURITY_PROFILE_INVALID_FALLBACK"
                if configured == "publci":
                    if (
                        f"{invalid_event} source={source}" not in logs
                        or "effective=lan compatibility_fallback=true" not in logs
                    ):
                        raise AssertionError(
                            f"{original.suffix} invalid profile fallback was not "
                            f"observable: {logs!r}"
                        )
                elif invalid_event in logs:
                    raise AssertionError(
                        f"{original.suffix} valid profile emitted invalid warning"
                    )

            public_file = temporary_path / f"{original.stem}-env{original.suffix}"
            public_file.write_text(
                replace_security_profile(
                    original_content, original.suffix, "public"
                ),
                encoding="utf-8",
                newline="\n",
            )
            env = security_environment()
            env["SUBCONVERTER_SECURITY_PROFILE"] = "strict"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["profile"] != "strict" or (
                "SECURITY_PROFILE_EFFECTIVE profile=strict source=environment "
                f"file_candidate={source}"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} environment profile did not override file"
                )

            env["SUBCONVERTER_SECURITY_PROFILE"] = "publci'\nforged-event\\tail"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["profile"] != "lan" or (
                "SECURITY_PROFILE_INVALID_FALLBACK source=environment "
                "input='publci\\x27\\x0Aforged-event\\x5Ctail'"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} invalid environment profile fallback or "
                    "log escaping changed"
                )

            env = security_environment()
            env["SUBCONVERTER_SECURITY_PROFILE"] = "public"
            env["SUBCONVERTER_ALLOW_PUBLIC_UPLOAD"] = "true"
            snapshot, _ = run_settings_snapshot(helper, public_file, env)
            if not snapshot["security"]["allow_public_upload"]:
                raise AssertionError(
                    f"{original.suffix} upload environment override was ignored"
                )

            env["SUBCONVERTER_ALLOW_PUBLIC_UPLOAD"] = "truthy"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["allow_public_upload"] or (
                "SECURITY_UPLOAD_VALUE_INVALID source=environment "
                "input='truthy' effective=false"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} invalid upload environment behavior changed"
                )

            missing_file = temporary_path / f"{original.stem}-reload{original.suffix}"
            missing_file.write_text(
                replace_security_profile(original_content, original.suffix, None),
                encoding="utf-8",
                newline="\n",
            )
            reloaded = reload_settings_snapshot(helper, public_file, missing_file)
            if reloaded["security"]["profile"] != "public":
                raise AssertionError(
                    f"{original.suffix} reload no longer retains a removed profile"
                )


def deployment_security_defaults_baseline() -> None:
    expected_profile_lines = {
        REPOSITORY / "base" / "pref.example.ini": "profile=lan",
        REPOSITORY / "base" / "pref.example.yml": "  profile: lan",
        REPOSITORY / "base" / "pref.example.toml": 'profile = "lan"',
    }
    expected_upload_lines = {
        ".ini": "allow_public_upload=false",
        ".yml": "  allow_public_upload: false",
        ".toml": "allow_public_upload = false",
    }
    for path, profile_line in expected_profile_lines.items():
        lines = path.read_text(encoding="utf-8").splitlines()
        if profile_line not in lines or expected_upload_lines[path.suffix] not in lines:
            raise AssertionError(
                f"deployment example defaults changed in {path.name}"
            )

    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    if (
        "COPY --from=builder /src/base /base/" not in dockerfile
        or "cp /base/pref.example.toml \"$CONF\"" not in dockerfile
    ):
        raise AssertionError(
            "Docker image no longer bootstraps pref.toml from the TOML example"
        )

    compose = (REPOSITORY / "docker-compose.yml").read_text(encoding="utf-8")
    active_compose = "\n".join(
        line for line in compose.splitlines() if not line.lstrip().startswith("#")
    )
    if '- "25500:25500/tcp"' not in active_compose:
        raise AssertionError("Compose default port publication changed")
    if re.search(
        r"(?m)^\s*SUBCONVERTER_SECURITY_PROFILE\s*:", active_compose
    ):
        raise AssertionError("Compose started forcing a security profile")


def add_proxy_provider_interval(
    content: str, suffix: str, value: str
) -> str:
    if suffix == ".ini":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\ninterval={value}\n"
    elif suffix == ".yml":
        marker = "\ncustom_openclash_rules:"
        section = f"\nproxy_provider:\n  interval: {value}\n"
    elif suffix == ".toml":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\ninterval = {value}\n"
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"provider interval insertion marker missing: {suffix}")
    return content.replace(marker, section + marker, 1)


def add_dashboard_client_ip(
    content: str, suffix: str, header: str, cidrs: list[str]
) -> str:
    if suffix == ".ini":
        marker = "\n[security]"
        section = (
            f"dashboard_auth_client_ip_header={header}\n"
            "dashboard_auth_trusted_proxy_cidrs=" + ",".join(cidrs) + "\n\n"
        )
    elif suffix == ".yml":
        marker = "\nsecurity:"
        cidr_lines = "\n".join(f"        - {json.dumps(cidr)}" for cidr in cidrs)
        section = (
            "    client_ip:\n"
            f"      header: {json.dumps(header)}\n"
            "      trusted_proxy_cidrs:\n"
            f"{cidr_lines}\n"
        )
    elif suffix == ".toml":
        marker = "\n[security]"
        section = (
            "[statistics.dashboard_auth.client_ip]\n"
            f"header = {json.dumps(header)}\n"
            f"trusted_proxy_cidrs = {json.dumps(cidrs)}\n\n"
        )
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"dashboard client IP insertion marker missing: {suffix}")
    return content.replace(marker, "\n" + section + marker.lstrip("\n"), 1)


def settings_dashboard_client_ip_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            configured = temporary_path / ("client-ip-" + fixture_name)
            configured.write_text(
                add_dashboard_client_ip(
                    content,
                    original.suffix,
                    "X-FoRwArDeD-FoR",
                    ["127.0.0.1/32", "2001:db8::/32"],
                ),
                encoding="utf-8",
                newline="\n",
            )
            snapshot = load_settings_snapshot(helper, configured)
            configured_snapshots.append(snapshot)
            statistics = snapshot["statistics"]
            if (
                statistics["dashboard_client_ip_header"] != "x-forwarded-for"
                or statistics["dashboard_trusted_proxy_count"] != 2
            ):
                raise AssertionError(
                    f"{original.suffix} did not load dashboard client-IP policy"
                )

            reloaded = reload_settings_snapshot(helper, configured, original)
            if (
                reloaded["statistics"]["dashboard_client_ip_header"] != "none"
                or reloaded["statistics"]["dashboard_trusted_proxy_count"] != 0
            ):
                raise AssertionError(
                    f"{original.suffix} reload retained removed client-IP settings"
                )

            for label, invalid_header, invalid_cidrs in (
                ("header", "x-client-ip", ["127.0.0.1/32"]),
                ("cidr", "x-forwarded-for", ["0.0.0.0/0"]),
            ):
                invalid = temporary_path / (f"invalid-{label}-" + fixture_name)
                invalid.write_text(
                    add_dashboard_client_ip(
                        content, original.suffix, invalid_header, invalid_cidrs
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                startup = subprocess.run(
                    [str(helper), str(invalid)],
                    cwd=REPOSITORY,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if key
                        not in {
                            "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
                            "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
                        }
                    },
                )
                if startup.returncode == 0:
                    raise AssertionError(
                        f"{original.suffix} accepted invalid client-IP {label}"
                    )
                retained = reload_settings_snapshot(
                    helper, configured, invalid, expect_failure=True
                )
                if (
                    retained["statistics"]["dashboard_client_ip_header"]
                    != "x-forwarded-for"
                    or retained["statistics"]["dashboard_trusted_proxy_count"] != 2
                ):
                    raise AssertionError(
                        f"{original.suffix} invalid reload replaced valid policy"
                    )

        if configured_snapshots[1:] != configured_snapshots[:1] * 2:
            raise AssertionError("INI/YAML/TOML dashboard client-IP snapshots differ")

        env = os.environ.copy()
        env["SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER"] = "cf-connecting-ip"
        env["SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS"] = (
            "127.0.0.1/32, 2001:db8::/32"
        )
        snapshot = load_settings_snapshot(
            helper, COMPAT_FIXTURES / "legacy-pref.toml", env
        )
        if (
            snapshot["statistics"]["dashboard_client_ip_header"]
            != "cf-connecting-ip"
            or snapshot["statistics"]["dashboard_trusted_proxy_count"] != 2
        ):
            raise AssertionError("dashboard client-IP environment overrides failed")


def settings_provider_interval_compatibility_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: dict[int, list[dict[str, object]]] = {
        0: [],
        7200: [],
    }
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            for expected in configured_snapshots:
                configured = temporary_path / (
                    f"configured-{expected}-" + fixture_name
                )
                configured.write_text(
                    add_proxy_provider_interval(
                        content, original.suffix, str(expected)
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                configured_snapshot = load_settings_snapshot(helper, configured)
                configured_snapshots[expected].append(configured_snapshot)
                if configured_snapshot["proxy_provider"]["interval"] != expected:
                    raise AssertionError(
                        f"{original.suffix} did not load "
                        f"proxy_provider.interval={expected}"
                    )

                reloaded = reload_settings_snapshot(helper, configured, original)
                if reloaded["proxy_provider"]["interval"] != 3600:
                    raise AssertionError(
                        f"{original.suffix} hot reload retained a removed "
                        "provider interval"
                    )

            invalid = temporary_path / ("invalid-" + fixture_name)
            invalid_value = '"none"' if original.suffix == ".toml" else "none"
            invalid.write_text(
                add_proxy_provider_interval(
                    content, original.suffix, invalid_value
                ),
                encoding="utf-8",
                newline="\n",
            )
            startup = subprocess.run(
                [str(helper), str(invalid)],
                cwd=REPOSITORY,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=security_environment(),
            )
            if startup.returncode == 0:
                raise AssertionError(
                    f"{original.suffix} accepted an invalid provider interval"
                )
            retained = reload_settings_snapshot(
                helper, original, invalid, expect_failure=True
            )
            if retained["proxy_provider"]["interval"] != 3600:
                raise AssertionError(
                    f"{original.suffix} invalid reload replaced valid settings"
                )

    for expected, snapshots in configured_snapshots.items():
        if snapshots[1:] != snapshots[:1] * 2:
            raise AssertionError(
                "INI/YAML/TOML provider interval snapshots differ for "
                f"interval={expected}"
            )


def add_proxy_provider_direct(content: str, suffix: str, value: str) -> str:
    if suffix == ".ini":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\nproxy_direct={value}\n"
    elif suffix == ".yml":
        marker = "\ncustom_openclash_rules:"
        section = f"\nproxy_provider:\n  proxy_direct: {value}\n"
    elif suffix == ".toml":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\nproxy_direct = {value}\n"
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"provider direct insertion marker missing: {suffix}")
    return content.replace(marker, section + marker, 1)


def settings_provider_direct_compatibility_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: dict[bool, list[dict[str, object]]] = {
        True: [],
        False: [],
    }
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            configured_paths: dict[bool, Path] = {}
            for expected in configured_snapshots:
                configured = temporary_path / (
                    f"configured-direct-{str(expected).lower()}-" + fixture_name
                )
                configured_paths[expected] = configured
                configured.write_text(
                    add_proxy_provider_direct(
                        content, original.suffix, str(expected).lower()
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                configured_snapshot = load_settings_snapshot(helper, configured)
                configured_snapshots[expected].append(configured_snapshot)
                if (
                    configured_snapshot["proxy_provider"]["proxy_direct"]
                    is not expected
                ):
                    raise AssertionError(
                        f"{original.suffix} did not load "
                        f"proxy_provider.proxy_direct={expected}"
                    )

                reloaded = reload_settings_snapshot(helper, configured, original)
                if reloaded["proxy_provider"]["proxy_direct"] is not True:
                    raise AssertionError(
                        f"{original.suffix} hot reload retained a removed "
                        "provider proxy_direct value"
                    )

            invalid = temporary_path / ("invalid-direct-" + fixture_name)
            invalid_value = '"none"' if original.suffix == ".toml" else "none"
            invalid.write_text(
                add_proxy_provider_direct(content, original.suffix, invalid_value),
                encoding="utf-8",
                newline="\n",
            )
            startup = subprocess.run(
                [str(helper), str(invalid)],
                cwd=REPOSITORY,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if startup.returncode == 0:
                raise AssertionError(
                    f"{original.suffix} accepted an invalid provider proxy_direct"
                )
            retained = reload_settings_snapshot(
                helper, configured_paths[False], invalid, expect_failure=True
            )
            if retained["proxy_provider"]["proxy_direct"] is not False:
                raise AssertionError(
                    f"{original.suffix} invalid reload did not retain false"
                )

    for expected, snapshots in configured_snapshots.items():
        if snapshots[1:] != snapshots[:1] * 2:
            raise AssertionError(
                "INI/YAML/TOML provider direct snapshots differ for "
                f"proxy_direct={expected}"
            )


def runtime_cli_isolation_baseline(binary: Path) -> None:
    binary_content = binary.read_bytes()
    for marker in (
        b"--settings-snapshot",
        b"--inject-invariant-failure",
    ):
        if marker in binary_content:
            raise AssertionError(
                "formal subconverter binary contains test-only marker "
                f"{marker.decode()}"
            )
        with running_service(binary, extra_args=(marker.decode(),)) as base_url:
            status, body, _ = request(base_url, "/healthz")
            if status != 200 or body.strip() != b"ok":
                raise AssertionError(
                    "formal subconverter binary handles test-only marker "
                    f"{marker.decode()} instead of preserving legacy "
                    "unknown-argument behavior"
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
    encoded_group = base64.urlsafe_b64encode(b"Converted").decode()
    expected_ruleset_outputs = {
        "1": RULESET,
        "2": (
            "DOMAIN-SUFFIX,example.com,Converted\n"
            "IP-CIDR,198.51.100.0/24,Converted\n"
        ),
        "3": "payload:\n  - '+.example.com'\n",
        "4": "payload:\n  - '198.51.100.0/24'\n",
        "5": ".example.com\n",
        "6": (
            "payload:\n"
            "  - DOMAIN-SUFFIX,example.com,Proxy\n"
            "  - IP-CIDR,198.51.100.0/24,Proxy\n"
        ),
    }
    for ruleset_type, expected in expected_ruleset_outputs.items():
        params = {"url": encoded_ruleset, "type": ruleset_type}
        if ruleset_type == "2":
            params["group"] = encoded_group
        status, body, _ = request(base_url, "/getruleset", params)
        if status != 200:
            raise AssertionError(
                f"/getruleset type={ruleset_type} returned "
                f"HTTP {status}: {body!r}"
            )
        ruleset_output = normalize_output(body, fixture_base)
        if ruleset_output != expected:
            diff = "".join(
                difflib.unified_diff(
                    expected.splitlines(keepends=True),
                    ruleset_output.splitlines(keepends=True),
                    fromfile=f"getruleset-type-{ruleset_type}.expected",
                    tofile=f"getruleset-type-{ruleset_type}.actual",
                )
            )
            raise AssertionError(
                f"/getruleset type={ruleset_type} output changed:\n{diff}"
            )
        if ruleset_type == "6":
            assert_golden("getruleset.yaml", ruleset_output, update_golden)

    encoded_mixed_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules-with-invalid.list").encode()
    ).decode()
    for ruleset_type, expected_rule in (
        ("3", "valid-before.example"),
        ("4", "203.0.113.0/24"),
    ):
        status, body, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_mixed_ruleset, "type": ruleset_type},
        )
        converted = body.decode("utf-8", errors="replace")
        if (
            status != 200
            or expected_rule not in converted
            or "NOT-A-SUPPORTED-RULE" in converted
        ):
            raise AssertionError(
                "a single unsupported ruleset line was not skipped "
                f"independently for type={ruleset_type}: {converted!r}"
            )


def provider_block_from_output(output: str, provider_name: str) -> str:
    marker = f"  {provider_name}:\n"
    start = output.find(marker)
    if start < 0:
        raise AssertionError(f"provider block is missing: {provider_name}")
    following = output[start + len(marker) :]
    next_provider = re.search(r"(?m)^  [^ ].*:\s*$", following)
    end = len(following) if next_provider is None else next_provider.start()
    return marker + following[:end]


def provider_interval_from_output(output: str, provider_name: str) -> int:
    block = provider_block_from_output(output, provider_name)
    interval = re.search(r"(?m)^    interval: ([0-9]+)\s*$", block)
    if interval is None:
        raise AssertionError(
            f"provider interval is missing or non-numeric: {provider_name}\n{block}"
        )
    return int(interval.group(1))


def provider_proxy_direct_from_output(output: str, provider_name: str) -> bool:
    block = provider_block_from_output(output, provider_name)
    return re.search(r"(?m)^    proxy: DIRECT\s*$", block) is not None


def provider_direct_default_output_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/subscription.txt"

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:DefaultDirect,{source}?case=default-direct",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200 or not provider_proxy_direct_from_output(
        output, "DefaultDirect"
    ):
        raise AssertionError(
            "the compatibility default no longer emits proxy: DIRECT"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:RequestFalse,{source}?case=request-false",
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "false",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200 or provider_proxy_direct_from_output(output, "RequestFalse"):
        raise AssertionError(
            "the existing provider_proxy_direct=false request parameter regressed"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "|".join(
                (
                    f"provider:LinkFalse,proxy_direct:false,{source}?case=link-false",
                    f"provider:LinkTrue,proxy_direct:true,{source}?case=link-true",
                    f"provider:RequestFallback,{source}?case=request-fallback",
                )
            ),
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "false",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"mixed provider direct request returned HTTP {status}: {output!r}"
        )
    expected_direct = {
        "LinkFalse": False,
        "LinkTrue": True,
        "RequestFallback": False,
    }
    for provider_name, expected in expected_direct.items():
        actual = provider_proxy_direct_from_output(output, provider_name)
        if actual is not expected:
            raise AssertionError(
                f"{provider_name} proxy_direct mismatch: {actual} != {expected}"
            )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:ExplainDirect,proxy_direct:false,{source}?case=explain",
            "config": DISABLE_RULEGEN_CONFIG,
            "explain": "true",
        },
    )
    if status != 200:
        raise AssertionError(f"proxy_direct explain returned HTTP {status}: {body!r}")
    report = json.loads(body)
    providers = report.get("providers", [])
    if len(providers) != 1:
        raise AssertionError(f"proxy_direct explain provider mismatch: {providers!r}")
    if (
        providers[0].get("proxy_direct") is not False
        or providers[0].get("proxy_field_emitted") is not False
    ):
        raise AssertionError(
            f"proxy_direct explain did not report field omission: {providers[0]!r}"
        )


def provider_interval_output_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/subscription.txt"
    multi_url = "|".join(
        (
            f"provider:Zero,interval:0,proxy_direct:false,{source}?case=zero",
            f"proxy_direct:true,interval:21600,provider:Slow,{source}?case=slow",
            f"tag:Tagged,proxy_direct:0,interval:1800,provider:Ordered,{source}?case=ordered",
            f"provider:Default,{source}?case=default",
        )
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": multi_url,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"multi-provider interval request returned HTTP {status}: {output!r}"
        )
    for provider_name, expected in {
        "Zero": 0,
        "Slow": 21600,
        "Ordered": 1800,
        "Default": 7200,
    }.items():
        actual = provider_interval_from_output(output, provider_name)
        if actual != expected:
            raise AssertionError(
                f"{provider_name} interval mismatch: {actual} != {expected}"
            )
    for provider_name, expected in {
        "Zero": False,
        "Slow": True,
        "Ordered": False,
        "Default": False,
    }.items():
        actual = provider_proxy_direct_from_output(output, provider_name)
        if actual is not expected:
            raise AssertionError(
                f"{provider_name} proxy_direct mismatch: {actual} != {expected}"
            )
    if output.count("      interval: 300") != 4:
        raise AssertionError("provider health-check intervals changed")

    encoded_value = urllib.parse.quote(
        f"provider:Encoded,interval:0,proxy_direct:false,{source}?case=encoded",
        safe="",
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": encoded_value,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    encoded_output = body.decode("utf-8", errors="replace")
    if (
        status != 200
        or provider_interval_from_output(encoded_output, "Encoded") != 0
        or provider_proxy_direct_from_output(encoded_output, "Encoded")
    ):
        raise AssertionError(
            f"encoded interval prefix failed: status={status}, body={encoded_output!r}"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:Managed,{source}?case=managed",
            "config": DISABLE_RULEGEN_CONFIG,
            "interval": "17",
        },
    )
    managed_output = body.decode("utf-8", errors="replace")
    if status != 200 or provider_interval_from_output(
        managed_output, "Managed"
    ) != 7200:
        raise AssertionError(
            "the existing request-level interval parameter changed provider interval"
        )
    if provider_proxy_direct_from_output(managed_output, "Managed"):
        raise AssertionError(
            "configured proxy_provider.proxy_direct=false was not applied"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:RequestTrue,{source}?case=request-true",
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "true",
        },
    )
    request_true_output = body.decode("utf-8", errors="replace")
    if status != 200 or not provider_proxy_direct_from_output(
        request_true_output, "RequestTrue"
    ):
        raise AssertionError(
            "provider_proxy_direct=true did not override configured false"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clashr",
            "url": f"provider:ClashR,interval:0,proxy_direct:false,{source}?case=clashr",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    clashr_output = body.decode("utf-8", errors="replace")
    if (
        status != 200
        or provider_interval_from_output(clashr_output, "ClashR") != 0
        or provider_proxy_direct_from_output(clashr_output, "ClashR")
    ):
        raise AssertionError(
            f"ClashR provider interval failed: status={status}, body={clashr_output!r}"
        )

    secret = "private-token-issue-90"
    rejected_cases = (
        ("none", f"interval:none,https://example.invalid/sub?token={secret}"),
        ("negative", f"interval:-1,https://example.invalid/sub?token={secret}"),
        ("empty", f"interval:,https://example.invalid/sub?token={secret}"),
        ("overflow", f"interval:2147483648,https://example.invalid/sub?token={secret}"),
        ("duplicate", f"interval:0,interval:1,https://example.invalid/sub?token={secret}"),
        ("missing delimiter", f"interval:0https://example.invalid/sub?token={secret}"),
    )
    for label, source_value in rejected_cases:
        status, body, _ = request(
            base_url, "/sub", {"target": "clash", "url": source_value}
        )
        response = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"{label} interval returned HTTP {status}: {response!r}"
            )
        if secret in response:
            raise AssertionError(f"{label} interval leaked the subscription token")

    direct_rejected_cases = (
        ("none", f"proxy_direct:none,https://example.invalid/sub?token={secret}"),
        ("empty", f"proxy_direct:,https://example.invalid/sub?token={secret}"),
        (
            "duplicate",
            f"proxy_direct:true,proxy_direct:false,https://example.invalid/sub?token={secret}",
        ),
        (
            "missing delimiter",
            f"proxy_direct:falsehttps://example.invalid/sub?token={secret}",
        ),
    )
    for label, source_value in direct_rejected_cases:
        status, body, _ = request(
            base_url, "/sub", {"target": "clash", "url": source_value}
        )
        response = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"{label} proxy_direct returned HTTP {status}: {response!r}"
            )
        if secret in response:
            raise AssertionError(
                f"{label} proxy_direct leaked the subscription token"
            )

    scope_cases = (
        (
            "direct node",
            {"target": "clash", "url": f"interval:0,{SUBSCRIPTION.strip()}"},
        ),
        (
            "list=true",
            {"target": "clash", "url": f"interval:0,{source}", "list": "true"},
        ),
        (
            "non-Clash target",
            {"target": "surge", "url": f"interval:0,{source}", "list": "true"},
        ),
    )
    for label, params in scope_cases:
        status, body, _ = request(base_url, "/sub", params)
        if status != 400:
            raise AssertionError(
                f"interval on {label} returned HTTP {status}: {body!r}"
            )

    direct_scope_cases = (
        (
            "direct node",
            {
                "target": "clash",
                "url": f"proxy_direct:false,{SUBSCRIPTION.strip()}",
            },
        ),
        (
            "list=true",
            {
                "target": "clash",
                "url": f"proxy_direct:false,{source}",
                "list": "true",
            },
        ),
        (
            "non-Clash target",
            {
                "target": "surge",
                "url": f"proxy_direct:false,{source}",
            },
        ),
    )
    for label, params in direct_scope_cases:
        status, body, _ = request(base_url, "/sub", params)
        if status != 400:
            raise AssertionError(
                f"proxy_direct on {label} returned HTTP {status}: {body!r}"
            )


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
        status, body, page_headers = request(
            base_url, "/dashboard", headers={"Authorization": "Basic " + token}
        )
        if status != 200 or b"SubConverter-Extended Dashboard" not in body:
            raise AssertionError("Dashboard valid-auth baseline failed")
        if (
            len(body) != 100487
            or hashlib.sha256(body).hexdigest()
            != "265cbce59394ec1e966bdd137bd79e993768eaf7f95260700ee287957b503908"
        ):
            raise AssertionError("Dashboard HTTP response bytes changed")
        expected_page_headers = {
            "cache-control": (
                "no-store, no-cache, must-revalidate, proxy-revalidate, "
                "max-age=0, s-maxage=0"
            ),
            "pragma": "no-cache",
            "expires": "0",
            "surrogate-control": "no-store",
            "x-accel-expires": "0",
            "x-robots-tag": (
                "noindex, nofollow, noarchive, nosnippet, noimageindex"
            ),
            "content-type": "text/html; charset=utf-8",
        }
        for header, expected in expected_page_headers.items():
            if page_headers.get(header) != expected:
                raise AssertionError(
                    f"Dashboard {header} changed: {page_headers.get(header)!r}"
                )
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


def dashboard_client_ip_security_baseline(binary: Path, fixture_base: str) -> None:
    spoof_headers = (
        ("CF-Connecting-IP", "198.51.100.1"),
        ("True-Client-IP", "198.51.100.2"),
        ("X-Real-IP", "198.51.100.3"),
        ("X-Forwarded-For", "198.51.100.4"),
        ("X-Client-IP", "198.51.100.5"),
    )
    with running_service(
        binary,
        statistics=True,
        dashboard_client_ip_header="x-forwarded-for",
        dashboard_trusted_proxy_cidrs=("10.0.0.0/8",),
    ) as base_url:
        for expected, rotated in zip((401, 401, 429), spoof_headers):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={
                    "Authorization": "Basic invalid",
                    rotated[0]: rotated[1],
                },
            )
            if status != expected:
                raise AssertionError(
                    "direct client bypassed peer bucket by rotating proxy "
                    f"headers: expected {expected}, got {status}"
                )

    with running_service(
        binary,
        statistics=True,
        dashboard_client_ip_header="x-forwarded-for",
        dashboard_trusted_proxy_cidrs=("127.0.0.1/32",),
    ) as base_url:
        client_a = "192.0.2.10, 127.0.0.1"
        client_b = "192.0.2.11, 127.0.0.1"
        for value in (client_a, client_b, client_a, client_b):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={
                    "Authorization": "Basic invalid",
                    "X-Forwarded-For": value,
                },
            )
            if status != 401:
                raise AssertionError(
                    "trusted-proxy clients did not receive independent buckets"
                )

        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic " + token,
                "X-Forwarded-For": client_a,
            },
        )
        if status != 200:
            raise AssertionError("successful auth did not clear the client bucket")
        status, _, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic invalid",
                "X-Forwarded-For": client_a,
            },
        )
        if status != 401:
            raise AssertionError("client bucket was not reset after successful auth")
        status, _, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic invalid",
                "X-Forwarded-For": client_b,
            },
        )
        if status != 429:
            raise AssertionError("third failure did not lock the second proxy client")

        duplicate_status = request_with_raw_headers(
            base_url,
            "/dashboard",
            [
                ("Authorization", "Basic invalid"),
                ("X-Forwarded-For", "192.0.2.20"),
                ("x-forwarded-for", "192.0.2.21"),
            ],
        )
        if duplicate_status != 401:
            raise AssertionError(
                "duplicate selected client-IP headers did not fail closed to peer"
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
            raise AssertionError("client-IP policy changed /sub behavior")


def simple_target_protocol_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/mixed-protocol-subscription.txt"

    def convert(target: str, url: str, list_mode: bool) -> str:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": target,
                "url": url,
                "list": "true" if list_mode else "false",
            },
        )
        if status != 200:
            raise AssertionError(
                f"target={target} list={list_mode} returned HTTP {status}: {body!r}"
            )
        if not list_mode:
            try:
                body = base64.b64decode(body)
            except ValueError as error:
                raise AssertionError(
                    f"target={target} did not return valid Base64"
                ) from error
        return body.decode("utf-8").replace("\r\n", "\n")

    vless = convert("vless", source, True)
    vless_lines = [line for line in vless.splitlines() if line]
    if not vless_lines or any(
        not line.startswith("vless://") for line in vless_lines
    ):
        raise AssertionError(f"VLESS target filtering is incorrect: {vless!r}")
    if "11111111-1111-1111-1111-111111111111" not in vless:
        raise AssertionError("VLESS target lost the fixture UUID")
    for expected in (
        "security=tls",
        "type=ws",
        "host=vless.example.test",
        "path=%2Fws",
    ):
        if expected not in vless:
            raise AssertionError(
                f"VLESS target lost {expected!r}: {vless!r}"
            )

    hysteria2 = convert("hysteria2", source, True)
    hysteria2_lines = [line for line in hysteria2.splitlines() if line]
    if not hysteria2_lines or any(
        not line.startswith("hysteria2://") for line in hysteria2_lines
    ):
        raise AssertionError(
            f"Hysteria2 target filtering is incorrect: {hysteria2!r}"
        )
    if "obfs=salamander" not in hysteria2:
        raise AssertionError(f"Hysteria2 output lost the obfs type: {hysteria2!r}")
    if "insecure=1" not in hysteria2:
        raise AssertionError("Hysteria2 output lost skip-cert-verify semantics")
    if "obfs-password=real-obfs-password" not in hysteria2:
        raise AssertionError(
            "Hysteria2 output did not preserve the real obfs password"
        )
    if "obfs-password=salamander" in hysteria2:
        raise AssertionError("Hysteria2 output reused the obfs type as its password")

    mixed = convert("mixed", source, True)
    mixed_lines = [line for line in mixed.splitlines() if line]
    if len(mixed_lines) != 3 or not all(
        any(line.startswith(prefix) for line in mixed_lines)
        for prefix in ("ss://", "vless://", "hysteria2://")
    ):
        raise AssertionError(f"mixed target lost a protocol: {mixed!r}")
    if "obfs-password=real-obfs-password" not in mixed:
        raise AssertionError("mixed output did not preserve Hysteria2 obfs password")

    for target, uri, prefix in (
        ("vless", VLESS_URI, "vless://"),
        ("hysteria2", HYSTERIA2_URI, "hysteria2://"),
    ):
        direct = convert(target, uri, True)
        encoded = convert(target, source, False)
        if not direct.startswith(prefix):
            raise AssertionError(f"single-link {target} input failed: {direct!r}")
        if not encoded.startswith(prefix):
            raise AssertionError(
                f"Base64 {target} output decoded incorrectly: {encoded!r}"
            )

    status, body, _ = request(
        base_url, "/sub", {"target": "unsupported-fixture", "url": source}
    )
    error = body.decode("utf-8", errors="replace")
    if status != 400 or "vless" not in error or "hysteria2" not in error:
        raise AssertionError(
            "unsupported target response did not retain 400 with the current list"
        )


def sensitive_log_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    secrets = (
        "11111111-1111-1111-1111-111111111111",
        "request-token-secret",
        "request-userinfo-secret",
        "provider-header-secret",
        "provider-source-secret",
        "private-config-secret",
    )
    with running_service(
        binary,
        log_capture=logs,
        log_level="verbose",
    ) as base_url:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "mixed",
                "url": (
                    fixture_base
                    + "/mixed-protocol-subscription.txt?token="
                    + "provider-source-secret"
                ),
                "list": "true",
                "token": "request-token-secret",
                "userinfo": "request-userinfo-secret",
                "config": (
                    "data:text/plain;private-config-secret,"
                    "enable_rule_generator=false"
                ),
            },
            headers={"X-Provider-Secret": "provider-header-secret"},
        )
        if status != 200:
            raise AssertionError(
                "verbose-log fixture conversion returned "
                f"HTTP {status}: {body!r}"
            )
    if not logs:
        raise AssertionError("verbose-log fixture did not capture service logs")
    for secret in secrets:
        if secret in logs[0]:
            raise AssertionError(f"verbose service log leaked fixture secret: {secret}")
    if "parameter_count=" not in logs[0] or "X-Provider-Secret" not in logs[0]:
        raise AssertionError("safe request diagnostics disappeared from verbose logs")


def template_error_redaction_baseline(binary: Path, fixture_base: str) -> None:
    secret = "template-exception-cookie-secret"
    logs: list[str] = []
    with running_service(
        binary,
        log_capture=logs,
        log_level="verbose",
    ) as base_url:
        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": fixture_base + "/external-malicious-base.ini",
                "token": "query-secret",
            },
            headers={
                "Authorization": "Bearer authorization-secret",
                "Cookie": "session=cookie-secret",
            },
        )
        error = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"template render failure changed status: {status}, body={error!r}"
            )
        if "Invalid template" not in error or "模板渲染失败" not in error:
            raise AssertionError("template render failure lost stable bilingual guidance")
        for leaked in (
            secret,
            "query-secret",
            "authorization-secret",
            "cookie-secret",
        ):
            if leaked in error:
                raise AssertionError(f"template error response leaked secret: {leaked}")
        if "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("template render failure lost no-store policy")

        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": fixture_base + "/external-valid.ini",
            },
        )
        if status != 200 or not body:
            raise AssertionError("successful template render behavior changed")

    if not logs:
        raise AssertionError("template error fixture did not capture logs")
    for leaked in (
        secret,
        "query-secret",
        "authorization-secret",
        "cookie-secret",
    ):
        if leaked in logs[0]:
            raise AssertionError(f"template error log leaked secret: {leaked}")
    if "TEMPLATE_RENDER_FAILED" not in logs[0]:
        raise AssertionError("template error log lost its stable event identifier")


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
        legacy_routes = (
            ("GET", "/get"),
            ("GET", "/getlocal"),
            ("GET", "/refreshrules"),
            ("GET", "/readconf"),
            ("POST", "/updateconf"),
            ("GET", "/flushcache"),
            ("GET", "/sub2clashr"),
            ("GET", "/surge2clash"),
            ("GET", "/getprofile"),
            ("GET", "/render"),
            ("POST", "/create-profile"),
            ("GET", "/list-profiles"),
        )
        for method, path in legacy_routes:
            status, _, _ = request(
                base_url, path, {"path": "../secret"}, method=method
            )
            if status != 404:
                raise AssertionError(
                    f"legacy route {method} {path} became reachable"
                )


def security_endpoint_matrix_baseline(binary: Path, fixture_base: str) -> None:
    sub_params = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
    }
    encoded_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules.list").encode()
    ).decode()

    with running_service(binary, security_profile="lan") as base_url:
        status, baseline_body, _ = request(base_url, "/sub", sub_params)
        if status != 200:
            raise AssertionError(
                f"lan profile changed loopback /sub behavior: HTTP {status}"
            )
        request_script_params = dict(sub_params)
        request_script_params["filter_script"] = (
            "function filter(node) { return false; }"
        )
        status, scripted_body, _ = request(
            base_url, "/sub", request_script_params
        )
        if status != 200 or scripted_body != baseline_body:
            raise AssertionError(
                "public /sub request regained executable filter authorization"
            )
        status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_ruleset, "type": "6"},
        )
        if status != 200:
            raise AssertionError(
                f"lan profile changed loopback /getruleset behavior: HTTP {status}"
            )

    for profile in ("public", "strict"):
        with running_service(binary, security_profile=profile) as base_url:
            status, _, _ = request(base_url, "/sub", sub_params)
            if status != 400:
                raise AssertionError(
                    f"{profile} profile accepted loopback /sub source: HTTP {status}"
                )
            status, _, _ = request(
                base_url,
                "/getruleset",
                {"url": encoded_ruleset, "type": "6"},
            )
            if status != 400:
                raise AssertionError(
                    f"{profile} profile accepted loopback /getruleset source: "
                    f"HTTP {status}"
                )

    upload_params = {
        "target": "clash",
        "url": SUBSCRIPTION.strip(),
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
        "upload": "true",
    }
    cases = (
        ("lan", False, 200, 1, "reason=lan-compatibility"),
        ("public", False, 403, 0, "reason=public-upload-setting"),
        ("public", True, 200, 1, "reason=public-upload-setting"),
        ("strict", True, 403, 0, "reason=strict-policy"),
    )
    for profile, configured_allow, expected_status, gist_delta, reason in cases:
        logs: list[str] = []
        before = FixtureHandler.gist_request_count
        with running_service(
            binary,
            security_profile=profile,
            allow_public_upload=configured_allow,
            listen_address="0.0.0.0" if profile == "lan" else "127.0.0.1",
            gist_api_base=fixture_base,
            log_capture=logs,
        ) as base_url:
            status, _, _ = request(base_url, "/sub", upload_params)
        actual_delta = FixtureHandler.gist_request_count - before
        if status != expected_status or actual_delta != gist_delta:
            raise AssertionError(
                f"upload policy changed for profile={profile}, "
                f"allow_public_upload={configured_allow}: HTTP {status}, "
                f"gist requests {actual_delta}"
            )
        effective = "allowed" if gist_delta else "blocked"
        expected_log = (
            f"SECURITY_UPLOAD_EFFECTIVE profile={profile} "
            "configured_allow_public_upload="
            f"{str(configured_allow).lower()} source=file:toml "
            f"effective={effective} {reason}"
        )
        if not logs or expected_log not in logs[0]:
            raise AssertionError(
                f"effective upload policy log missing for {profile}: {logs!r}"
            )
        if gist_delta and "GIST_UPLOAD_COMPLETE" not in logs[0]:
            raise AssertionError(
                f"successful Gist upload lacks completion evidence: {logs!r}"
            )
        if logs and "fixture-token" in logs[0]:
            raise AssertionError("Gist upload logs leaked the configured token")
        if profile == "lan" and (
            "SECURITY_EXPOSURE_POSSIBLE profile=lan bind=0.0.0.0:" not in logs[0]
            or "public_reachability=unknown" not in logs[0]
        ):
            raise AssertionError(
                "wildcard LAN binding did not emit reachability-unknown warning"
            )

    logs = []
    before = FixtureHandler.gist_request_count
    with running_service(
        binary,
        security_profile="lan",
        gist_api_base=fixture_base,
        gist_config_hardlink_failure=True,
        log_capture=logs,
    ) as base_url:
        status, body, _ = request(base_url, "/sub", upload_params)
    if status != 500 or FixtureHandler.gist_request_count - before != 1:
        raise AssertionError(
            "local Gist persistence failure was reported as complete success: "
            f"HTTP {status}, gist requests "
            f"{FixtureHandler.gist_request_count - before}"
        )
    if not logs or (
        "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED" not in logs[0]
        or "GIST_UPLOAD_COMPLETE" in logs[0]
        or b"did not complete locally" not in body
    ):
        raise AssertionError(
            f"partial Gist upload diagnostics are ambiguous: logs={logs!r}, "
            f"body={body!r}"
        )


def settings_reload_compatibility_baseline(helper: Path) -> None:
    insertions = {
        ".ini": (
            "append_proxy_type=false",
            "fallback_to_default_external_config=true\nappend_proxy_type=false",
        ),
        ".yml": (
            "  append_proxy_type: false",
            "  fallback_to_default_external_config: true\n"
            "  append_proxy_type: false",
        ),
        ".toml": (
            "append_proxy_type = false",
            "fallback_to_default_external_config = true\n"
            "append_proxy_type = false",
        ),
    }
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            marker, replacement = insertions[original.suffix]
            enabled = temporary_path / fixture_name
            enabled.write_text(
                original.read_text(encoding="utf-8").replace(
                    marker, replacement, 1
                ),
                encoding="utf-8",
                newline="\n",
            )
            enabled_snapshot = load_settings_snapshot(helper, enabled)
            if not enabled_snapshot["common"][
                "fallback_to_default_external_config"
            ]:
                raise AssertionError(
                    f"{original.suffix} did not load the new fallback switch"
                )
            reloaded = reload_settings_snapshot(helper, enabled, original)
            if reloaded["common"]["fallback_to_default_external_config"]:
                raise AssertionError(
                    f"{original.suffix} hot reload retained a removed switch"
                )


def common_scalar_binding_compatibility_baseline(helper: Path) -> None:
    configured_values: dict[str, str | bool] = {
        "prepend_insert_url": False,
        "base_path": "stage-c-base",
        "clash_rule_base": "stage-c/clash.tpl",
        "surge_rule_base": "stage-c/surge.tpl",
        "surfboard_rule_base": "stage-c/surfboard.tpl",
        "mellow_rule_base": "stage-c/mellow.tpl",
        "quan_rule_base": "stage-c/quan.tpl",
        "quanx_rule_base": "stage-c/quanx.tpl",
        "loon_rule_base": "stage-c/loon.tpl",
        "sssub_rule_base": "stage-c/sssub.tpl",
        "singbox_rule_base": "stage-c/singbox.tpl",
        "default_external_config": "data:,enable_rule_generator=false",
        "fallback_to_default_external_config": True,
        "append_proxy_type": True,
        "proxy_config": "NONE",
        "proxy_ruleset": "SYSTEM",
        "proxy_subscription": "http://127.0.0.1:8080",
        "reload_conf_on_request": True,
    }

    def render_value(suffix: str, value: str | bool) -> str:
        if isinstance(value, bool):
            return str(value).lower()
        if suffix == ".ini":
            return value
        return json.dumps(value)

    def field_pattern(suffix: str, key: str) -> str:
        if suffix == ".ini":
            return rf"(?m)^{re.escape(key)}=.*$"
        if suffix == ".yml":
            return rf"(?m)^  {re.escape(key)}:.*$"
        if suffix == ".toml":
            return rf"(?m)^{re.escape(key)}\s*=.*$"
        raise AssertionError(f"unsupported config suffix: {suffix}")

    def field_line(suffix: str, key: str, value: str | bool) -> str:
        rendered = render_value(suffix, value)
        if suffix == ".ini":
            return f"{key}={rendered}"
        if suffix == ".yml":
            return f"  {key}: {rendered}"
        return f"{key} = {rendered}"

    def configure(content: str, suffix: str) -> str:
        for key, value in configured_values.items():
            replacement = field_line(suffix, key, value)
            content, count = re.subn(
                field_pattern(suffix, key), replacement, content, count=1
            )
            if count == 0:
                marker = field_pattern(suffix, "append_proxy_type")
                match = re.search(marker, content)
                if match is None:
                    raise AssertionError(
                        f"common scalar insertion marker missing: {suffix}"
                    )
                content = (
                    content[: match.start()]
                    + replacement
                    + "\n"
                    + content[match.start() :]
                )
        return content

    def empty_default_external_config(content: str, suffix: str) -> str:
        replacement = field_line(suffix, "default_external_config", "")
        content, count = re.subn(
            field_pattern(suffix, "default_external_config"),
            replacement,
            content,
            count=1,
        )
        if count != 1:
            raise AssertionError(
                f"default external config field missing: {suffix}"
            )
        return content

    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        configured_snapshots: list[dict[str, object]] = []
        configured_paths: dict[str, Path] = {}
        empty_snapshots: list[dict[str, object]] = []
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            configured = temporary_path / ("common-scalars-" + fixture_name)
            configured.write_text(
                configure(content, original.suffix),
                encoding="utf-8",
                newline="\n",
            )
            configured_paths[original.suffix] = configured
            configured_snapshots.append(load_settings_snapshot(helper, configured))

            empty = temporary_path / ("empty-default-" + fixture_name)
            empty.write_text(
                empty_default_external_config(content, original.suffix),
                encoding="utf-8",
                newline="\n",
            )
            empty_snapshots.append(load_settings_snapshot(helper, empty))

        if configured_snapshots[1:] != configured_snapshots[:1] * 2:
            raise AssertionError("INI/YAML/TOML common scalar bindings differ")
        common = configured_snapshots[0]["common"]
        expected_rule_bases = {
            name: f"stage-c/{name}.tpl"
            for name in (
                "clash",
                "surge",
                "surfboard",
                "mellow",
                "quan",
                "quanx",
                "loon",
                "sssub",
                "singbox",
            )
        }
        if (
            common["base_path"] != "stage-c-base"
            or common["rule_bases"] != expected_rule_bases
            or common["prepend_insert"] is not False
            or common["append_proxy_type"] is not True
            or common["reload_conf_on_request"] is not True
            or common["fallback_to_default_external_config"] is not True
        ):
            raise AssertionError(f"common scalar values were misbound: {common!r}")

        if empty_snapshots[1:] != empty_snapshots[:1] * 2 or any(
            snapshot["common"]["default_external_config"]["configured"] is not True
            for snapshot in empty_snapshots
        ):
            raise AssertionError(
                "empty default external config no longer uses the common fallback"
            )

        invalid_ini = temporary_path / "invalid-bool-pref.ini"
        invalid_ini.write_text(
            re.sub(
                field_pattern(".ini", "prepend_insert_url"),
                "prepend_insert_url=not-a-bool",
                (COMPAT_FIXTURES / "legacy-pref.ini").read_text(encoding="utf-8"),
                count=1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        if load_settings_snapshot(helper, invalid_ini)["common"]["prepend_insert"]:
            raise AssertionError("legacy INI invalid boolean handling changed")

        for suffix, invalid_value in (
            (".yml", "not-a-bool"),
            (".toml", '"not-a-bool"'),
        ):
            original = COMPAT_FIXTURES / ("legacy-pref" + suffix)
            invalid = temporary_path / ("invalid-bool-pref" + suffix)
            invalid.write_text(
                re.sub(
                    field_pattern(suffix, "prepend_insert_url"),
                    field_line(suffix, "prepend_insert_url", False).replace(
                        "false", invalid_value
                    ),
                    original.read_text(encoding="utf-8"),
                    count=1,
                ),
                encoding="utf-8",
                newline="\n",
            )
            retained = reload_settings_snapshot(
                helper,
                configured_paths[suffix],
                invalid,
                expect_failure=True,
            )
            expected_index = {".ini": 0, ".yml": 1, ".toml": 2}[suffix]
            if retained != configured_snapshots[expected_index]:
                raise AssertionError(
                    f"{suffix} invalid common scalar replaced previous settings"
                )


def settings_parser_diagnostic_redaction_baseline(helper: Path) -> None:
    secret = "yaml-parser-diagnostic-secret"
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        malformed = Path(temporary) / "malformed-secret.yml"
        malformed.write_text(
            "common:\n"
            f"  token: {secret}\n"
            "  malformed: [\n",
            encoding="utf-8",
            newline="\n",
        )
        completed = subprocess.run(
            [
                str(helper),
                str(COMPAT_FIXTURES / "legacy-pref.yml"),
                str(malformed),
                "--expect-reload-failure",
            ],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        json.loads(completed.stdout)
        if "PREFERENCE_YAML_PARSE_FAILED detail=length=" not in completed.stderr:
            raise AssertionError(
                "malformed YAML did not emit the stable parser failure event"
            )
        if secret in completed.stderr:
            raise AssertionError("malformed YAML secret leaked to diagnostics")
        if "hash=" in completed.stderr:
            raise AssertionError("parser diagnostics retained a guessable hash")


def external_config_failure_baseline(binary: Path, fixture_base: str) -> None:
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }
    with running_service(binary, legacy_publish_enabled=True) as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {**common, "config": fixture_base + "/external-valid.ini"},
        )
        if status != 200:
            raise AssertionError(
                f"valid explicit external config returned HTTP {status}"
            )

        for path in (
            "/external-empty.ini",
            "/external-template-failure.ini",
            "/external-template-fetch-failure.ini",
            "/external-no-effective.ini",
            "/external-import-failure.ini",
        ):
            status, _, headers = request(
                base_url,
                "/sub",
                {**common, "config": fixture_base + path},
            )
            if status != 400 or "no-store" not in headers.get(
                "cache-control", ""
            ):
                raise AssertionError(
                    f"explicit config failure {path} returned HTTP {status} "
                    "without no-store"
                )

        status, _, _ = request(
            base_url,
            "/Custom_OpenClash_Rules/main/rule/example.yaml",
        )
        if status != 404:
            raise AssertionError("removed COCR publication route is still active")

    with running_service(
        binary, fallback_to_default_external_config=True
    ) as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {
                **common,
                "config": fixture_base + "/external-no-effective.ini",
            },
        )
        if status != 200:
            raise AssertionError(
                "explicitly enabled default external config fallback failed"
            )

    invalid_default = fixture_base + "/external-no-effective.ini"
    with running_service(
        binary,
        fallback_to_default_external_config=True,
        default_external_config=invalid_default,
    ) as base_url:
        status, _, headers = request(
            base_url,
            "/sub",
            {**common, "config": fixture_base + "/external-empty.ini"},
        )
        if status != 400 or "no-store" not in headers.get(
            "cache-control", ""
        ):
            raise AssertionError(
                "failed explicit and default configs did not fail closed"
            )

    with running_service(
        binary, default_external_config=invalid_default
    ) as base_url:
        status, _, headers = request(base_url, "/sub", common)
        if status != 500 or "no-store" not in headers.get(
            "cache-control", ""
        ):
            raise AssertionError(
                "failed implicit default config did not return 500/no-store"
            )


def request_generation_reload_baseline(binary: Path, fixture_base: str) -> None:
    pref_paths: list[Path] = []
    old_prefix = "https://managed-old.snapshot.test"
    new_prefix = "https://managed-new.snapshot.test"
    replacements = (
        (
            "reload_conf_on_request = false",
            "reload_conf_on_request = true",
        ),
        (
            "async_fetch_ruleset = false",
            "async_fetch_ruleset = true",
        ),
        (
            "enable_request_coalescing = true",
            "enable_request_coalescing = false",
        ),
        (
            'managed_config_prefix = "https://managed.example.test"',
            f'managed_config_prefix = "{old_prefix}"',
        ),
    )

    def write_config_atomically(path: Path, content: str) -> None:
        candidate = path.with_name(path.name + ".next")
        candidate.write_text(content, encoding="utf-8", newline="\n")
        os.replace(candidate, path)

    def stable_response(
        result: tuple[int, bytes, dict[str, str]],
    ) -> tuple[int, bytes, dict[str, str | None]]:
        status, body, headers = result
        stable_headers = {
            name: headers.get(name)
            for name in ("content-type", "profile-update-interval")
        }
        return status, body, stable_headers

    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }

    def lifetime_subscription_requests(base_url: str) -> int:
        # Dashboard snapshots are deliberately cached for one second.
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"generation statistics query returned HTTP {status}: {body!r}"
            )
        return int(
            json.loads(body)["windows"]["lifetime"]["subscription_requests"]
        )

    def require_generation(
        result: tuple[int, bytes, dict[str, str]],
        *,
        prefix: str,
        clash_modes: bool,
        complete_ruleset: bool,
    ) -> None:
        status, body, _ = result
        if status != 200:
            raise AssertionError(
                f"generation request returned HTTP {status}: {body!r}"
            )
        document = json.loads(body)
        if document.get("snapshot_link") != prefix + "/snapshot":
            raise AssertionError(
                "template getLink observed the wrong settings generation: "
                f"{document.get('snapshot_link')!r}"
            )
        if document.get("template_fetch") != "template-ok":
            raise AssertionError("template fetch did not complete")
        tags = {
            outbound.get("tag")
            for outbound in document.get("outbounds", [])
            if isinstance(outbound, dict)
        }
        if ("GLOBAL" in tags) is not clash_modes:
            raise AssertionError(
                "singBoxAddClashModes came from the wrong settings generation"
            )
        serialized_rules = json.dumps(
            document.get("route", {}).get("rules", []), sort_keys=True
        )
        has_third_rule = "third.snapshot.test" in serialized_rules
        if has_third_rule is not complete_ruleset:
            raise AssertionError(
                "maxAllowedRules came from the wrong settings generation"
            )

    with running_service(
        binary,
        statistics=True,
        extra_args=("-cfw",),
        config_replacements=replacements,
        pref_path_capture=pref_paths,
    ) as base_url:
        if len(pref_paths) != 1:
            raise AssertionError("mutable runtime preference path was not captured")
        pref = pref_paths[0]
        old_config = pref.read_text(encoding="utf-8")
        common = {
            "target": "singbox",
            "url": fixture_base + "/subscription.txt",
            "config": fixture_base + "/external-generation.ini",
        }

        pure_old = request(base_url, "/sub", common)
        require_generation(
            pure_old,
            prefix=old_prefix,
            clash_modes=True,
            complete_ruleset=True,
        )
        old_request_count = lifetime_subscription_requests(base_url)
        if old_request_count != 1:
            raise AssertionError(
                "old generation statistics setup did not record exactly one request"
            )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        FixtureHandler.slow_ruleset_started.clear()
        FixtureHandler.slow_ruleset_release.clear()
        slow_result: list[tuple[int, bytes, dict[str, str]]] = []
        slow_error: list[BaseException] = []

        def run_slow_request() -> None:
            try:
                slow_result.append(
                    request(
                        base_url,
                        "/sub",
                        {
                            **common,
                            "url": fixture_base + "/slow-subscription.txt",
                            "config": fixture_base
                            + "/external-generation-slow.ini",
                        },
                    )
                )
            except BaseException as error:  # propagate worker diagnostics
                slow_error.append(error)

        slow_thread = threading.Thread(target=run_slow_request)
        slow_thread.start()
        try:
            if not FixtureHandler.slow_subscription_started.wait(timeout=10):
                raise AssertionError("slow request did not reach nodemanip fetch")
            if not FixtureHandler.slow_ruleset_started.wait(timeout=10):
                raise AssertionError("async ruleset worker did not start")

            new_config = old_config.replace(
                "singbox_add_clash_modes = true",
                "singbox_add_clash_modes = false",
                1,
            ).replace(
                "max_allowed_rules = 4096",
                "max_allowed_rules = 1",
                1,
            ).replace(old_prefix, new_prefix, 1).replace(
                "enabled = true\n",
                "enabled = false\n",
                1,
            )
            if new_config == old_config:
                raise AssertionError("new generation configuration was not changed")
            write_config_atomically(pref, new_config)
            new_result = request(base_url, "/sub", common)
        finally:
            FixtureHandler.slow_ruleset_release.set()
            FixtureHandler.slow_subscription_release.set()
            slow_thread.join(timeout=20)

        if slow_thread.is_alive():
            raise AssertionError("slow request did not finish after fixture release")
        if slow_error:
            raise slow_error[0]
        if len(slow_result) != 1:
            raise AssertionError("slow request did not produce one response")

        require_generation(
            slow_result[0],
            prefix=old_prefix,
            clash_modes=True,
            complete_ruleset=True,
        )
        if stable_response(slow_result[0]) != stable_response(pure_old):
            raise AssertionError(
                "request captured before reload did not remain byte-equivalent "
                "to the old generation"
            )

        require_generation(
            new_result,
            prefix=new_prefix,
            clash_modes=False,
            complete_ruleset=False,
        )
        later_new = request(base_url, "/sub", common)
        if stable_response(later_new) != stable_response(new_result):
            raise AssertionError(
                "request started after reload did not retain the new generation"
            )

        write_config_atomically(pref, "version = 1\n[common\n")
        failed_reload = request(base_url, "/sub", common)
        require_generation(
            failed_reload,
            prefix=new_prefix,
            clash_modes=False,
            complete_ruleset=False,
        )
        if stable_response(failed_reload) != stable_response(new_result):
            raise AssertionError(
                "failed reload changed the last published request generation"
            )
        final_request_count = lifetime_subscription_requests(base_url)
        if final_request_count != old_request_count + 1:
            raise AssertionError(
                "statistics attribution crossed request generations: "
                f"old={old_request_count}, final={final_request_count}"
            )


def getruleset_generation_reload_baseline(binary: Path, fixture_base: str) -> None:
    pref_paths: list[Path] = []
    replacements = (
        (
            "reload_conf_on_request = false",
            "reload_conf_on_request = true",
        ),
    )

    def write_config_atomically(path: Path, content: str) -> None:
        candidate = path.with_name(path.name + ".next")
        candidate.write_text(content, encoding="utf-8", newline="\n")
        os.replace(candidate, path)

    slow_sources = "|".join(
        (
            fixture_base + "/slow-generation-rules.list",
            fixture_base + "/generation-rules.list",
        )
    )
    encoded_slow_sources = base64.urlsafe_b64encode(slow_sources.encode()).decode()
    encoded_source = base64.urlsafe_b64encode(
        (fixture_base + "/generation-rules.list").encode()
    ).decode()
    reload_request = {
        "target": "clash",
        "url": SUBSCRIPTION.strip(),
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
    }

    with running_service(
        binary,
        extra_args=("-cfw",),
        config_replacements=replacements,
        pref_path_capture=pref_paths,
    ) as base_url:
        if len(pref_paths) != 1:
            raise AssertionError("mutable runtime preference path was not captured")
        pref = pref_paths[0]
        old_config = pref.read_text(encoding="utf-8")
        new_config = old_config.replace('profile = "lan"', 'profile = "strict"', 1)
        if new_config == old_config:
            raise AssertionError("new getruleset generation was not changed")

        FixtureHandler.slow_ruleset_started.clear()
        FixtureHandler.slow_ruleset_release.clear()
        slow_result: list[tuple[int, bytes, dict[str, str]]] = []
        slow_error: list[BaseException] = []

        def run_slow_getruleset() -> None:
            try:
                slow_result.append(
                    request(
                        base_url,
                        "/getruleset",
                        {"url": encoded_slow_sources, "type": "6"},
                    )
                )
            except BaseException as error:  # propagate worker diagnostics
                slow_error.append(error)

        slow_thread = threading.Thread(target=run_slow_getruleset)
        slow_thread.start()
        try:
            if not FixtureHandler.slow_ruleset_started.wait(timeout=10):
                raise AssertionError("slow getruleset request did not reach fixture")
            write_config_atomically(pref, new_config)
            reload_status, reload_body, _ = request(
                base_url, "/sub", reload_request
            )
            if reload_status != 200:
                raise AssertionError(
                    "successful getruleset generation reload trigger failed: "
                    f"HTTP {reload_status}: {reload_body!r}"
                )
        finally:
            FixtureHandler.slow_ruleset_release.set()
            slow_thread.join(timeout=20)

        if slow_thread.is_alive():
            raise AssertionError("slow getruleset request did not finish")
        if slow_error:
            raise slow_error[0]
        if len(slow_result) != 1:
            raise AssertionError("slow getruleset request did not return once")
        slow_status, slow_body, _ = slow_result[0]
        slow_text = slow_body.decode("utf-8", errors="replace")
        if slow_status != 200 or slow_text.count("first.snapshot.test") != 2:
            raise AssertionError(
                "getruleset request crossed settings generations: "
                f"HTTP {slow_status}: {slow_text!r}"
            )

        new_status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_source, "type": "6"},
        )
        if new_status != 400:
            raise AssertionError(
                "getruleset request started after reload did not use strict generation: "
                f"HTTP {new_status}"
            )

        write_config_atomically(pref, "version = 1\n[common\n")
        retained_status, retained_body, _ = request(
            base_url, "/sub", reload_request
        )
        if retained_status != 200:
            raise AssertionError(
                "failed reload did not retain the last successful generation: "
                f"HTTP {retained_status}: {retained_body!r}"
            )
        retained_ruleset_status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_source, "type": "6"},
        )
        if retained_ruleset_status != 400:
            raise AssertionError(
                "failed reload changed the published getruleset generation: "
                f"HTTP {retained_ruleset_status}"
            )


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

    deployment_security_defaults_baseline()
    runtime_cli_isolation_baseline(binary)

    snapshots = [
        load_settings_snapshot(settings_snapshot_helper, COMPAT_FIXTURES / name)
        for name in ("legacy-pref.ini", "legacy-pref.yml", "legacy-pref.toml")
    ]
    if snapshots[1:] != snapshots[:1] * 2:
        raise AssertionError("INI/YAML/TOML SettingsSnapshot values differ")
    if "publish_enabled" in snapshots[0]["custom_openclash_rules"]:
        raise AssertionError("removed publish setting remains in runtime state")
    if snapshots[0]["common"]["fallback_to_default_external_config"]:
        raise AssertionError("new default fallback switch did not default false")
    if snapshots[0]["proxy_provider"]["interval"] != 3600:
        raise AssertionError("missing provider interval did not default to 3600")
    if snapshots[0]["proxy_provider"]["proxy_direct"] is not True:
        raise AssertionError("missing provider proxy_direct did not default to true")
    if snapshots[0]["security"]["profile"] != "lan":
        raise AssertionError("historical security profile default changed")
    security_configuration_matrix_baseline(settings_snapshot_helper)
    settings_reload_compatibility_baseline(settings_snapshot_helper)
    common_scalar_binding_compatibility_baseline(settings_snapshot_helper)
    settings_parser_diagnostic_redaction_baseline(settings_snapshot_helper)
    settings_provider_interval_compatibility_baseline(settings_snapshot_helper)
    settings_provider_direct_compatibility_baseline(settings_snapshot_helper)
    settings_dashboard_client_ip_baseline(settings_snapshot_helper)

    with fixture_server() as fixture_base:
        with running_service(binary) as base_url:
            conversion_baselines(base_url, fixture_base, args.update_golden)
            simple_target_protocol_baseline(base_url, fixture_base)
            provider_direct_default_output_baseline(base_url, fixture_base)
        with running_service(
            binary,
            proxy_provider_interval=7200,
            proxy_provider_direct=False,
        ) as base_url:
            provider_interval_output_baseline(base_url, fixture_base)
        dashboard_baseline(binary, fixture_base)
        sensitive_log_baseline(binary, fixture_base)
        template_error_redaction_baseline(binary, fixture_base)
        dashboard_client_ip_security_baseline(binary, fixture_base)
        persistence_degradation_baseline(binary, fixture_base)
        public_request_baseline(binary, fixture_base)
        security_endpoint_matrix_baseline(binary, fixture_base)
        external_config_failure_baseline(binary, fixture_base)
        getruleset_generation_reload_baseline(binary, fixture_base)
        request_generation_reload_baseline(binary, fixture_base)

    print("compatibility and security baselines passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"compatibility/security baseline failed: {error}", file=sys.stderr)
        raise
