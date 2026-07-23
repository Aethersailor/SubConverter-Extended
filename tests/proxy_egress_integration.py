#!/usr/bin/env python3
"""Deterministic Docker integration tests for outbound proxy policy.

The test deliberately uses only loopback HTTP endpoints and a small SOCKS5
implementation below.  It records the SOCKS address type and every target
connection, so a green result proves routing rather than merely a successful
HTTP response.
"""

from __future__ import annotations

import argparse
import contextlib
import http.server
import os
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import re
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


SUBSCRIPTION = b"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#ProxySmoke\n"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


@dataclass
class RequestRecord:
    address_type: str
    host: str
    port: int


@dataclass
class Recorder:
    requests: list[RequestRecord] = field(default_factory=list)
    target_hits: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def clear(self) -> None:
        with self.lock:
            self.requests.clear()
            self.target_hits.clear()


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    recorder: Recorder
    target_name: str

    def do_GET(self) -> None:  # noqa: N802
        with self.recorder.lock:
            self.recorder.target_hits.append(self.path)
        if self.headers.get("Host", "").startswith("raw.githubusercontent.com"):
            self.send_response(503)
            self.end_headers()
            return
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header(
                "Location", f"http://{self.target_name}:{self.server.server_port}/subscription"
            )
            self.end_headers()
            return
        if self.path.startswith("/remote.ini"):
            payload = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                f"ruleset=Proxy,http://{self.target_name}:{self.server.server_port}/rules.list\n"
            ).encode("utf-8")
        elif self.path.startswith("/rules.list"):
            payload = b"DOMAIN,proxy-egress.example\n"
        elif self.path.startswith("/cron.js"):
            payload = (
                f'fetch({{url:"http://{self.target_name}:{self.server.server_port}/quickjs-default"}});\n'
                f'fetch({{url:"http://{self.target_name}:{self.server.server_port}/quickjs-none", proxy:"NONE"}});\n'
                f'fetch({{url:"http://{self.target_name}:{self.server.server_port}/quickjs-system", proxy:"SYSTEM"}});\n'
                f'fetch({{url:"http://{self.target_name}:{self.server.server_port}/quickjs-explicit", proxy:"{self.socks_uri}"}});\n'
            ).encode("utf-8")
        else:
            payload = SUBSCRIPTION
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        with self.recorder.lock:
            self.recorder.target_hits.append(self.path)
        payload = b'{"id":"local-gist","owner":{"login":"proxy-test"}}'
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


class SocksHandler(socketserver.BaseRequestHandler):
    server: "SocksServer"

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(10)
        try:
            version, method_count = recv_exact(client, 2)
            if version != 5:
                return
            methods = recv_exact(client, method_count)
            if self.server.username is None:
                method = 0 if 0 in methods else 0xFF
            else:
                method = 2 if 2 in methods else 0xFF
            client.sendall(bytes((5, method)))
            if method == 0xFF:
                return
            if method == 2:
                auth_version, user_length = recv_exact(client, 2)
                username = recv_exact(client, user_length).decode("utf-8", "replace")
                password_length = recv_exact(client, 1)[0]
                password = recv_exact(client, password_length).decode("utf-8", "replace")
                if auth_version != 1 or username != self.server.username or password != self.server.password:
                    client.sendall(b"\x01\x01")
                    return
                client.sendall(b"\x01\x00")

            version, command, _, atyp = recv_exact(client, 4)
            if version != 5 or command != 1:
                return
            if atyp == 1:
                host = socket.inet_ntoa(recv_exact(client, 4))
                address_type = "IPv4"
            elif atyp == 3:
                host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
                address_type = "domain"
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
                address_type = "IPv6"
            else:
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            with self.server.recorder.lock:
                self.server.recorder.requests.append(RequestRecord(address_type, host, port))
            if self.server.reject:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            target = self.server.host_map.get(host, (host, port))
            upstream = socket.create_connection(target, timeout=10)
            with upstream:
                client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                self.relay(client, upstream)
        except (ConnectionError, OSError, UnicodeError):
            return

    @staticmethod
    def relay(left: socket.socket, right: socket.socket) -> None:
        while True:
            readable, _, _ = select.select((left, right), (), (), 10)
            if not readable:
                return
            for source, destination in ((left, right), (right, left)):
                if source not in readable:
                    continue
                data = source.recv(65536)
                if not data:
                    return
                destination.sendall(data)


class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        recorder: Recorder,
        host_map: dict[str, tuple[str, int]],
        username: str | None = None,
        password: str | None = None,
        reject: bool = False,
    ) -> None:
        super().__init__(("127.0.0.1", 0), SocksHandler)
        self.recorder = recorder
        self.host_map = host_map
        self.username = username
        self.password = password
        self.reject = reject

    @property
    def port(self) -> int:
        return self.server_address[1]


class RunningContainer:
    def __init__(self, image: str, config: Path, port: int, env: dict[str, str], cache: Path | None = None, gist: Path | None = None) -> None:
        command = [
            # Keep a failed container until close() so its startup log is
            # available in the assertion output.
            "docker", "run", "-d", "--network", "host",
            "--add-host", "target.test:127.0.0.1",
            "-v", f"{config}:/tmp/pref.toml:ro",
            "-e", "PREF_PATH=/tmp/pref.toml", "-e", f"PORT={port}",
        ]
        if cache is not None:
            command += ["-v", f"{cache}:/tmp/cache"]
        if gist is not None:
            # main.cpp changes to PREF_PATH's directory after loading it.
            # The fixture mounts the preference at /tmp/pref.toml, so Gist's
            # historical relative gistconf.ini lookup must be /tmp as well.
            command += ["-v", f"{gist}:/tmp/gistconf.ini"]
        for name, value in env.items():
            command += ["-e", f"{name}={value}"]
        command.append(image)
        self.container_id = subprocess.check_output(command, text=True).strip()
        self.port = port

    def wait_ready(self) -> None:
        url = f"http://127.0.0.1:{self.port}/healthz"
        for _ in range(60):
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    if response.read().strip() == b"ok":
                        return
            except OSError:
                time.sleep(0.5)
        self.dump_logs()
        raise AssertionError("SubConverter container did not become ready")

    def dump_logs(self) -> None:
        subprocess.run(["docker", "logs", self.container_id], check=False)

    def logs(self) -> str:
        return subprocess.check_output(["docker", "logs", self.container_id], text=True, stderr=subprocess.STDOUT)

    def close(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.container_id], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def __enter__(self) -> "RunningContainer":
        self.wait_ready()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_config(path: Path, proxy_config: str, proxy_ruleset: str, proxy_subscription: str) -> None:
    # Keep every required preference section in the real distribution sample;
    # this test changes only the egress knobs it is asserting.
    example = Path(__file__).resolve().parents[1] / "base" / "pref.example.toml"
    content = example.read_text(encoding="utf-8")

    def replace(key: str, value: str) -> None:
        nonlocal content
        content, count = re.subn(
            rf"(?m)^{re.escape(key)}\s*=.*$", f'{key} = {value}', content, count=1
        )
        if count != 1:
            raise AssertionError(f"example preference is missing {key}")

    replace("proxy_config", f'"{proxy_config}"')
    replace("proxy_ruleset", f'"{proxy_ruleset}"')
    replace("proxy_subscription", f'"{proxy_subscription}"')
    replace("enable_cache", "true")
    replace("cache_subscription", "120")
    replace("cache_config", "120")
    replace("cache_ruleset", "120")
    path.write_text(content, encoding="utf-8")


def add_cron_task(path: Path, script_url: str) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(
            "\n[[tasks]]\n"
            'name = "proxy-egress"\n'
            'cronexp = "0/1 * * * * ?"\n'
            f'path = "{script_url}"\n'
            "timeout = 5\n"
        )


def wait_until(condition: callable, timeout: float, message: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError(message)


def sub_request(
    port: int,
    url: str,
    config: str = "data:,enable_rule_generator=false",
    list_mode: bool = True,
) -> str:
    arguments = {"target": "clash", "url": url, "config": config}
    if list_mode:
        arguments["list"] = "true"
    query = urllib.parse.urlencode(arguments)
    request_url = f"http://127.0.0.1:{port}/sub?{query}"
    try:
        with urllib.request.urlopen(request_url, timeout=15) as response:
            body = response.read().decode("utf-8", "replace")
            if response.status != 200 or "ProxySmoke" not in body:
                raise AssertionError(f"unexpected /sub response: {response.status} {body[:300]}")
            return body
    except OSError as exc:
        raise AssertionError(f"/sub request failed: {exc}") from exc


def expect_sub_failure(port: int, url: str) -> None:
    query = urllib.parse.urlencode(
        {"target": "clash", "list": "true", "url": url, "config": "data:,enable_rule_generator=false"}
    )
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/sub?{query}", timeout=15):
            raise AssertionError("proxy failure unexpectedly produced a successful conversion")
    except urllib.error.HTTPError:
        return


def upload_request(port: int) -> None:
    query = urllib.parse.urlencode(
        {
            "target": "clash",
            "url": "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#UploadSmoke",
            "config": "data:,enable_rule_generator=false",
            "upload": "true",
        }
    )
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/sub?{query}", timeout=15) as response:
        if response.status != 200:
            raise AssertionError(f"Gist upload conversion failed: {response.status}")


def explain_request(port: int, url: str) -> str:
    query = urllib.parse.urlencode(
        {"target": "clash", "list": "true", "url": url, "config": "data:,enable_rule_generator=false", "explain": "true"}
    )
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/sub?{query}", timeout=15) as response:
        if response.status != 200:
            raise AssertionError(f"explain endpoint failed: {response.status}")
        return response.read().decode("utf-8", "replace")


def provider_request(port: int, url: str) -> str:
    query = urllib.parse.urlencode(
        {"target": "clash", "url": url, "config": "data:,enable_rule_generator=false"}
    )
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/sub?{query}", timeout=15) as response:
        body = response.read().decode("utf-8", "replace")
        if response.status != 200 or "proxy-providers" not in body:
            raise AssertionError(f"unexpected Proxy-Provider response: {response.status} {body[:300]}")
        return body


def run(image: str) -> None:
    recorder = Recorder()
    fixture_class = type("ProxyFixtureHandler", (FixtureHandler,), {"recorder": recorder, "target_name": "target.test"})
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), fixture_class)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    host_map = {
        "target.test": ("127.0.0.1", fixture.server_port),
        "raw.githubusercontent.com": ("127.0.0.1", fixture.server_port),
        "cdn.jsdelivr.net": ("127.0.0.1", fixture.server_port),
    }
    proxy = SocksServer(recorder, host_map)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    authenticated_proxy = SocksServer(
        recorder, host_map, "user", "password"
    )
    authenticated_thread = threading.Thread(target=authenticated_proxy.serve_forever, daemon=True)
    authenticated_thread.start()
    fixture_class.socks_uri = f"socks5h://127.0.0.1:{proxy.port}"

    try:
        with tempfile.TemporaryDirectory(prefix="sce-proxy-egress-") as temp_dir:
            temp = Path(temp_dir)
            remote_url = f"http://target.test:{fixture.server_port}/subscription"
            redirect_url = f"http://target.test:{fixture.server_port}/redirect"
            socks5h = f"socks5h://127.0.0.1:{proxy.port}"
            socks5 = f"socks5://127.0.0.1:{proxy.port}"

            def exercise(label: str, config_proxy: str, env: dict[str, str], url: str, expected_type: str | None) -> None:
                recorder.clear()
                config = temp / f"{label}.toml"
                write_config(config, config_proxy, config_proxy, config_proxy)
                with RunningContainer(image, config, reserve_port(), env) as container:
                    sub_request(container.port, url)
                with recorder.lock:
                    records = list(recorder.requests)
                    hits = list(recorder.target_hits)
                if expected_type is None:
                    assert not records, f"{label}: Direct request reached SOCKS proxy: {records}"
                else:
                    assert records, f"{label}: SOCKS proxy received no connection"
                    assert records[0].address_type == expected_type, f"{label}: {records}"
                assert hits, f"{label}: target server was never reached"

            # Direct and an empty setting must actively ignore ALL_PROXY.
            exercise("none", "NONE", {"ALL_PROXY": socks5h, "NO_PROXY": "", "no_proxy": ""}, remote_url, None)
            exercise("empty", "", {"ALL_PROXY": socks5h, "NO_PROXY": "", "no_proxy": ""}, remote_url, None)

            # System resolves the documented environment priority.  Explicit
            # ignores NO_PROXY; socks5h sends a domain while socks5 sends IPv4.
            exercise("system", "SYSTEM", {"ALL_PROXY": socks5h, "NO_PROXY": "", "no_proxy": ""}, remote_url, "domain")
            exercise("explicit", socks5h, {"NO_PROXY": "*", "no_proxy": "*"}, remote_url, "domain")
            exercise("socks5", socks5, {"NO_PROXY": "", "no_proxy": ""}, remote_url, "IPv4")

            recorder.clear()
            config = temp / "redirect.toml"
            write_config(config, socks5h, socks5h, socks5h)
            with RunningContainer(image, config, reserve_port(), {"NO_PROXY": "*", "no_proxy": "*"}) as container:
                sub_request(container.port, redirect_url)
            with recorder.lock:
                assert len(recorder.requests) >= 2, "redirect did not keep using the SOCKS proxy"
                assert all(item.address_type == "domain" for item in recorder.requests), recorder.requests

            recorder.clear()
            fallback_config = temp / "github-fallback.toml"
            write_config(fallback_config, socks5h, socks5h, socks5h)
            raw_url = "http://raw.githubusercontent.com/owner/repo/main/subscription"
            with RunningContainer(image, fallback_config, reserve_port(), {}) as container:
                sub_request(container.port, raw_url)
            with recorder.lock:
                fallback_hosts = [item.host for item in recorder.requests]
                assert fallback_hosts[:2] == ["raw.githubusercontent.com", "cdn.jsdelivr.net"], fallback_hosts

            # A caller-supplied external configuration and the ruleset it
            # references use proxy_config and proxy_ruleset respectively.
            recorder.clear()
            config_ruleset = temp / "config-ruleset.toml"
            write_config(config_ruleset, socks5h, socks5h, "NONE")
            remote_config = f"http://target.test:{fixture.server_port}/remote.ini"
            with RunningContainer(image, config_ruleset, reserve_port(), {}) as container:
                sub_request(
                    container.port,
                    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#ProxySmoke",
                    config=remote_config,
                    list_mode=False,
                )
            with recorder.lock:
                assert len(recorder.requests) >= 2, "external config or ruleset bypassed its proxy policy"
                assert all(item.address_type == "domain" for item in recorder.requests), recorder.requests
                assert "/remote.ini" in recorder.target_hits and "/rules.list" in recorder.target_hits, recorder.target_hits

            # Cron retrieves its remote script through proxy_config. QuickJS
            # fetch inherits proxy_config when absent, and each of NONE,
            # SYSTEM, and a URI override changes that policy deliberately.
            recorder.clear()
            cron_config = temp / "cron.toml"
            write_config(cron_config, socks5h, "NONE", "NONE")
            add_cron_task(cron_config, f"http://target.test:{fixture.server_port}/cron.js")
            with RunningContainer(
                image, cron_config, reserve_port(), {"ALL_PROXY": socks5h, "NO_PROXY": "", "no_proxy": ""}
            ) as container:
                def quickjs_complete() -> bool:
                    with recorder.lock:
                        return {"/cron.js", "/quickjs-default", "/quickjs-none", "/quickjs-system", "/quickjs-explicit"}.issubset(set(recorder.target_hits))
                try:
                    wait_until(quickjs_complete, 8, "Cron/QuickJS proxy policy requests did not all complete")
                except AssertionError as error:
                    raise AssertionError(f"{error}\nSubConverter logs:\n{container.logs()}") from error
            with recorder.lock:
                proxied_paths = len(recorder.requests)
                assert proxied_paths >= 4, f"Cron/QuickJS expected four SOCKS requests, got {recorder.requests}"

            recorder.clear()
            config = temp / "auth-ok.toml"
            auth_uri = f"socks5h://user:password@127.0.0.1:{authenticated_proxy.port}"
            write_config(config, auth_uri, auth_uri, auth_uri)
            with RunningContainer(image, config, reserve_port(), {}) as container:
                sub_request(container.port, remote_url)
            with recorder.lock:
                assert recorder.requests, "authenticated SOCKS request did not reach proxy"

            # Runtime diagnostics and verbose curl logs carry a redacted
            # endpoint only; credentials never escape through /sub?explain.
            recorder.clear()
            redaction_config = temp / "redaction.toml"
            redaction_uri = f"socks5h://user:password@127.0.0.1:{authenticated_proxy.port}"
            write_config(redaction_config, redaction_uri, "NONE", redaction_uri)
            with RunningContainer(image, redaction_config, reserve_port(), {}) as container:
                explain = explain_request(container.port, remote_url)
                logs = container.logs()
            assert "user:password" not in explain and "password" not in explain, explain
            assert "user:password" not in logs and "password" not in logs, logs

            recorder.clear()
            config = temp / "auth-fail.toml"
            wrong_auth = f"socks5h://user:wrong@127.0.0.1:{authenticated_proxy.port}"
            write_config(config, wrong_auth, wrong_auth, wrong_auth)
            with RunningContainer(image, config, reserve_port(), {}) as container:
                expect_sub_failure(container.port, remote_url)
            with recorder.lock:
                assert not recorder.target_hits, "authentication failure fell back to a direct target connection"

            recorder.clear()
            config = temp / "invalid-proxy.toml"
            invalid_proxy = "socks5h://missing-port.example.test"
            write_config(config, invalid_proxy, invalid_proxy, invalid_proxy)
            with RunningContainer(image, config, reserve_port(), {}) as container:
                expect_sub_failure(container.port, remote_url)
            with recorder.lock:
                assert not recorder.target_hits, "invalid proxy configuration silently fell back to direct"

            recorder.clear()
            config = temp / "unavailable.toml"
            unavailable = f"socks5h://127.0.0.1:{reserve_port()}"
            write_config(config, unavailable, unavailable, unavailable)
            with RunningContainer(image, config, reserve_port(), {}) as container:
                expect_sub_failure(container.port, remote_url)
            with recorder.lock:
                assert not recorder.target_hits, "unavailable explicit proxy fell back to direct"

            # A shared cache directory proves cache identities include both
            # policy mode and endpoint rather than URL alone.
            cache = temp / "cache"
            cache.mkdir()
            recorder.clear()
            explicit_config = temp / "cache-explicit.toml"
            write_config(explicit_config, socks5h, socks5h, socks5h)
            with RunningContainer(image, explicit_config, reserve_port(), {}, cache) as container:
                sub_request(container.port, remote_url)
            recorder.clear()
            direct_config = temp / "cache-direct.toml"
            write_config(direct_config, "NONE", "NONE", "NONE")
            with RunningContainer(image, direct_config, reserve_port(), {}, cache) as container:
                sub_request(container.port, remote_url)
            with recorder.lock:
                assert recorder.target_hits and not recorder.requests, "Direct cache key reused explicit-proxy content"

            # The Gist API is an auxiliary request and inherits proxy_config;
            # its local API-base override exists only to make this test
            # deterministic without contacting GitHub.
            recorder.clear()
            gist_conf = temp / "gistconf.ini"
            gist_conf.write_text("[common]\\ntoken=fixture-token\\n", encoding="utf-8")
            gist_config = temp / "gist.toml"
            write_config(gist_config, socks5h, "NONE", "NONE")
            with RunningContainer(
                image, gist_config, reserve_port(),
                {"SUBCONVERTER_GIST_API_BASE": f"http://target.test:{fixture.server_port}"},
                gist=gist_conf,
            ) as container:
                upload_request(container.port)
                gist_logs = container.logs()
            with recorder.lock:
                gist_records = list(recorder.requests)
                gist_hits = list(recorder.target_hits)
            assert gist_records and gist_records[0].address_type == "domain", (
                f"Gist request bypassed proxy_config: {gist_records}"
            )
            assert "/gists" in gist_hits, (
                "local Gist API did not receive the request; "
                f"SOCKS={gist_records}, target={gist_hits}, logs={gist_logs}"
            )

            # The default Clash Proxy-Provider path is a client-side pull:
            # backend proxy_subscription must not pre-download it.
            recorder.clear()
            provider_config = temp / "provider.toml"
            write_config(provider_config, "NONE", "NONE", socks5h)
            with RunningContainer(image, provider_config, reserve_port(), {}) as container:
                provider_request(container.port, remote_url)
            with recorder.lock:
                assert not recorder.requests and not recorder.target_hits, "Proxy-Provider unexpectedly downloaded the subscription in the backend"
    finally:
        proxy.shutdown()
        authenticated_proxy.shutdown()
        fixture.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="locally built official Docker image")
    args = parser.parse_args()
    run(args.image)
    print("proxy egress Docker integration tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
