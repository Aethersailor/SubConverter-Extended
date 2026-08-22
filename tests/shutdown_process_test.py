#!/usr/bin/env python3
"""Process-level SIGTERM/SIGINT shutdown regression matrix.

The test deliberately launches the production ``subconverter`` executable.
It covers shutdown after idle and completed work, while an asynchronous
ruleset retry is active, and while a legitimate request is in flight.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
PREFERENCE_FIXTURE = REPOSITORY / "tests" / "fixtures" / "compat" / "legacy-pref.toml"
SUBSCRIPTION = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Shutdown\n"
RULESET = "DOMAIN-SUFFIX,shutdown.example,Proxy\n"
SHUTDOWN_DEADLINE_SECONDS = 5.0
LISTENER_CLOSE_DEADLINE_SECONDS = 2.0
STARTUP_DEADLINE_SECONDS = 10.0
HIGH_FD_BACKLOG_CONNECTIONS = 1100


class ShutdownFailure(AssertionError):
    """Raised when a shutdown scenario violates the process contract."""


@dataclass
class FixtureState:
    background_attempts: int = 0
    background_lock: threading.Lock = field(default_factory=threading.Lock)
    background_retry_started: threading.Event = field(default_factory=threading.Event)
    background_retry_release: threading.Event = field(default_factory=threading.Event)
    inflight_started: threading.Event = field(default_factory=threading.Event)
    inflight_release: threading.Event = field(default_factory=threading.Event)

    def release_all(self) -> None:
        self.background_retry_release.set()
        self.inflight_release.set()


def make_fixture_handler(state: FixtureState) -> type[BaseHTTPRequestHandler]:
    class FixtureHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # A production fix may cancel a background fetch during
                # shutdown. The process result, not this fixture socket, is the
                # behavior under test.
                pass

        def do_GET(self) -> None:  # noqa: N802
            request_path = urllib.parse.urlsplit(self.path).path
            if request_path == "/subscription.txt":
                self._send(SUBSCRIPTION.encode())
                return
            if request_path == "/rules.list":
                self._send(RULESET.encode())
                return
            if request_path == "/background-rules.list":
                with state.background_lock:
                    state.background_attempts += 1
                    attempt = state.background_attempts
                if attempt == 1:
                    # An empty reply is a recoverable libcurl error. It enters
                    # the production 200 ms idempotent retry path without DNS
                    # or Internet timing dependencies.
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.connection.close()
                    return
                state.background_retry_started.set()
                if not state.background_retry_release.wait(timeout=10):
                    self.send_error(504, "background retry fixture timed out")
                    return
                self._send(RULESET.encode())
                return
            if request_path == "/inflight-rules.list":
                state.inflight_started.set()
                if not state.inflight_release.wait(timeout=10):
                    self.send_error(504, "in-flight fixture timed out")
                    return
                self._send(RULESET.encode())
                return
            self.send_error(404)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return FixtureHandler


@contextlib.contextmanager
def fixture_server():
    state = FixtureState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_fixture_handler(state))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        state.release_all()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def replace_required(content: str, original: str, replacement: str) -> str:
    if original not in content:
        raise ShutdownFailure(f"preference fixture is missing {original!r}")
    return content.replace(original, replacement, 1)


def write_preference(path: Path, scenario: str, fixture_base: str) -> None:
    content = PREFERENCE_FIXTURE.read_text(encoding="utf-8")
    base_path = (REPOSITORY / "base" / "base").as_posix()
    template_path = path.parent / "templates"
    template_path.mkdir()
    content = replace_required(content, 'base_path = "base"', f'base_path = "{base_path}"')
    content = replace_required(
        content,
        'clash_rule_base = "base/all_base.tpl"',
        f'clash_rule_base = "{base_path}/all_base.tpl"',
    )
    content = replace_required(
        content,
        'template_path = "template"',
        f'template_path = "{template_path.as_posix()}"',
    )
    content = replace_required(
        content,
        'proxy_config = "socks5h://fixture-user:fixture-secret@proxy.example.test:1080"',
        'proxy_config = "NONE"',
    )
    content = replace_required(
        content, 'proxy_subscription = "SYSTEM"', 'proxy_subscription = "NONE"'
    )
    # Keep persistence out of the generic matrix. The background case below
    # targets the executor/curl lifetime that remains active after HTTP stop.
    content = replace_required(content, "enabled = true\n", "enabled = false\n")
    content = replace_required(
        content, "async_fetch_ruleset = false", "async_fetch_ruleset = true"
    )
    content = replace_required(content, "cache_ruleset = 21600", "cache_ruleset = 0")

    if scenario == "background-retry":
        content = replace_required(
            content, "[ruleset]\nenabled = false", "[ruleset]\nenabled = true"
        )
        ruleset = (
            "[[rulesets]]\n"
            'group = "Proxy"\n'
            f'ruleset = "{fixture_base}/background-rules.list"\n'
            'type = "surge-ruleset"\n'
            "interval = 0\n\n"
        )
        content = replace_required(content, "[template]", ruleset + "[template]")

    path.write_text(content, encoding="utf-8", newline="\n")


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
    *,
    timeout: float = 5.0,
) -> tuple[int, bytes]:
    query = urllib.parse.urlencode(params or {})
    url = base_url + path + (f"?{query}" if query else "")
    try:
        with direct_opener().open(url, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def encoded_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode()


def wait_ready(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + STARTUP_DEADLINE_SECONDS
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ShutdownFailure(
                f"service exited before readiness with {describe_returncode(process.returncode)}"
            )
        try:
            # A TCP readiness probe proves that the listener is accepting
            # connections without issuing a business request. This keeps the
            # idle scenario genuinely idle.
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                pass
            return
        except OSError as error:
            last_error = error
        time.sleep(0.05)
    raise ShutdownFailure(f"service did not become ready: {last_error}")


def read_log(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def wait_for_log(
    path: Path, marker: str, process: subprocess.Popen[bytes], deadline: float
) -> None:
    while time.monotonic() < deadline:
        if marker in read_log(path):
            return
        if process.poll() is not None:
            break
        time.sleep(0.02)
    raise ShutdownFailure(f"shutdown log marker is missing: {marker!r}")


def listener_is_closed(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.1)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def wait_listener_closed(
    port: int, process: subprocess.Popen[bytes], shutdown_deadline: float
) -> None:
    deadline = min(
        shutdown_deadline,
        time.monotonic() + LISTENER_CLOSE_DEADLINE_SECONDS,
    )
    while time.monotonic() < deadline:
        if process.poll() is not None or listener_is_closed(port):
            return
        time.sleep(0.02)
    raise ShutdownFailure("HTTP listener still accepts connections during shutdown")


def describe_returncode(returncode: int | None) -> str:
    if returncode is None:
        return "running"
    if returncode < 0:
        try:
            return f"{returncode} ({signal.Signals(-returncode).name})"
        except ValueError:
            pass
    if returncode >= 128:
        try:
            return f"{returncode} (128+{signal.Signals(returncode - 128).name})"
        except ValueError:
            pass
    return str(returncode)


def wait_for_exit(process: subprocess.Popen[bytes], deadline: float) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(process.args, 0)
    return process.wait(timeout=remaining)


def wait_for_process_fd_count(
    process: subprocess.Popen[bytes], minimum: int, deadline: float
) -> None:
    fd_directory = Path(f"/proc/{process.pid}/fd")
    if not fd_directory.is_dir():
        raise ShutdownFailure("high-fd shutdown regression requires Linux /proc")
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ShutdownFailure(
                f"service exited before reaching {minimum} file descriptors"
            )
        try:
            count = sum(1 for _ in fd_directory.iterdir())
        except FileNotFoundError:
            count = 0
        if count >= minimum:
            return
        time.sleep(0.01)
    raise ShutdownFailure(
        f"service did not reach {minimum} file descriptors before timeout"
    )


def complete_ruleset_request(base_url: str, source_url: str) -> tuple[int, bytes]:
    return request(
        base_url,
        "/getruleset",
        {"url": encoded_url(source_url), "type": "6"},
        timeout=10,
    )


def run_case(binary: Path, signal_value: signal.Signals, scenario: str, round_no: int) -> None:
    label = f"{signal_value.name}/{scenario}/round-{round_no}"
    process: subprocess.Popen[bytes] | None = None
    client_thread: threading.Thread | None = None
    client_result: list[tuple[int, bytes]] = []
    client_error: list[BaseException] = []
    backlog_sockets: list[socket.socket] = []

    with fixture_server() as (fixture, fixture_base):
        with tempfile.TemporaryDirectory(prefix="sce-shutdown-") as temporary:
            temporary_path = Path(temporary).resolve()
            try:
                temporary_path.relative_to(REPOSITORY.resolve())
            except ValueError:
                pass
            else:
                raise ShutdownFailure(
                    f"temporary runtime unexpectedly resides inside the repository: {temporary_path}"
                )

            pref = temporary_path / "pref.toml"
            stdout_path = temporary_path / "stdout.log"
            stderr_path = temporary_path / "stderr.log"
            write_preference(pref, scenario, fixture_base)
            port = unused_port()
            base_url = f"http://127.0.0.1:{port}"
            env = os.environ.copy()
            for name in (
                "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
                "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
                "SUBCONVERTER_SECURITY_PROFILE",
                "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
            ):
                env.pop(name, None)
            env["PORT"] = str(port)
            env["NO_PROXY"] = "127.0.0.1,localhost"
            env["no_proxy"] = "127.0.0.1,localhost"

            stdout = stdout_path.open("wb")
            stderr = stderr_path.open("wb")
            failure: BaseException | None = None
            try:
                process = subprocess.Popen(
                    [str(binary), "-f", str(pref)],
                    cwd=temporary_path,
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                )
                wait_ready(port, process)

                if scenario == "completed-request":
                    status, body = complete_ruleset_request(
                        base_url, fixture_base + "/rules.list"
                    )
                    if status != 200 or b"shutdown.example" not in body:
                        raise ShutdownFailure(
                            f"completed request returned HTTP {status}: {body[-1000:]!r}"
                        )
                elif scenario == "background-retry":
                    if not fixture.background_retry_started.wait(timeout=3):
                        raise ShutdownFailure(
                            "asynchronous ruleset fetch did not enter its controlled retry"
                        )
                elif scenario in ("inflight-request", "high-fd-shutdown"):
                    if scenario == "high-fd-shutdown":
                        for _ in range(HIGH_FD_BACKLOG_CONNECTIONS):
                            pending = socket.create_connection(
                                ("127.0.0.1", port), timeout=1
                            )
                            pending.sendall(
                                b"GET /sub HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            )
                            backlog_sockets.append(pending)
                        wait_for_process_fd_count(
                            process,
                            HIGH_FD_BACKLOG_CONNECTIONS,
                            time.monotonic() + 5.0,
                        )
                    source_url = fixture_base + "/inflight-rules.list"

                    def make_inflight_request() -> None:
                        try:
                            client_result.append(
                                complete_ruleset_request(base_url, source_url)
                            )
                        except BaseException as error:  # surfaced on the owner thread
                            client_error.append(error)

                    client_thread = threading.Thread(
                        target=make_inflight_request, daemon=True
                    )
                    client_thread.start()
                    if not fixture.inflight_started.wait(timeout=3):
                        raise ShutdownFailure(
                            "legitimate request did not reach the controlled upstream"
                        )
                elif scenario == "backlog-shutdown":
                    for _ in range(16):
                        pending = socket.create_connection(
                            ("127.0.0.1", port), timeout=1
                        )
                        pending.sendall(
                            b"GET /sub HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        )
                        backlog_sockets.append(pending)

                shutdown_started = time.monotonic()
                shutdown_deadline = shutdown_started + SHUTDOWN_DEADLINE_SECONDS
                process.send_signal(signal_value)
                shutdown_event = (
                    f"SHUTDOWN_REQUESTED signal={signal_value.name} "
                    f"signal_code={signal_value.value} action=graceful-stop"
                )
                wait_for_log(
                    stderr_path,
                    shutdown_event,
                    process,
                    min(shutdown_deadline, time.monotonic() + 2.0),
                )
                wait_listener_closed(port, process, shutdown_deadline)

                if scenario in ("inflight-request", "high-fd-shutdown"):
                    fixture.inflight_release.set()
                    assert client_thread is not None
                    client_thread.join(
                        timeout=max(0.0, shutdown_deadline - time.monotonic())
                    )
                    if client_thread.is_alive():
                        raise ShutdownFailure(
                            "legitimate in-flight request did not finish before the shutdown deadline"
                        )
                    if client_error:
                        raise ShutdownFailure(
                            f"legitimate in-flight request failed: {client_error[0]}"
                        )
                    if len(client_result) != 1:
                        raise ShutdownFailure(
                            "legitimate in-flight request produced no response"
                        )
                    status, body = client_result[0]
                    cancelled = (
                        status == 503 and b"shutting down" in body.lower()
                    )
                    drained_successfully = (
                        status == 200 and b"shutdown.example" in body
                    )
                    if not cancelled and not drained_successfully:
                        raise ShutdownFailure(
                            f"cancelled in-flight request returned HTTP {status}: {body[-1000:]!r}"
                        )

                returncode = wait_for_exit(process, shutdown_deadline)
                elapsed = time.monotonic() - shutdown_started
                if returncode != 0:
                    raise ShutdownFailure(
                        f"process exited with {describe_returncode(returncode)}"
                    )
                if elapsed > SHUTDOWN_DEADLINE_SECONDS:
                    raise ShutdownFailure(
                        f"shutdown took {elapsed:.3f}s, over the {SHUTDOWN_DEADLINE_SECONDS:.1f}s limit"
                    )
                logs = read_log(stderr_path)
                if f"[INFO] {shutdown_event}" not in logs:
                    raise ShutdownFailure(
                        "graceful shutdown event is missing its INFO severity"
                    )
                if f"[FATL] {shutdown_event}" in logs:
                    raise ShutdownFailure(
                        "normal graceful shutdown was mislabeled FATAL"
                    )
                if (
                    scenario not in ("idle", "backlog-shutdown")
                    and "OUTBOUND_MULTI_ENGINE resolver=asynchronous" not in logs
                ):
                    raise ShutdownFailure(
                        "shutdown scenario did not exercise the asynchronous multi engine"
                    )
                if scenario in (
                    "completed-request",
                    "inflight-request",
                    "high-fd-shutdown",
                ):
                    if "HTTP_RESPONSE_PREPARED" not in logs:
                        raise ShutdownFailure(
                            "completed request is missing lifecycle completion telemetry"
                        )
                    if scenario == "completed-request" and "HTTP_RESPONSE_SEND_FAILED" in logs:
                        raise ShutdownFailure(
                            "a successfully delivered request was misclassified as cancelled"
                        )
                if scenario == "background-retry":
                    if fixture.background_attempts < 2:
                        raise ShutdownFailure("controlled background retry was not attempted")
                    if (
                        "出站请求遇到可恢复网络错误，正在分散退避后重试："
                        not in logs
                        or "attempt=1" not in logs
                        or "code=" not in logs
                    ):
                        raise ShutdownFailure("recoverable outbound retry log is missing")
                print(f"PASS {label} exit=0 shutdown={elapsed:.3f}s")
            except subprocess.TimeoutExpired as error:
                failure = ShutdownFailure(
                    f"shutdown exceeded {SHUTDOWN_DEADLINE_SECONDS:.1f}s; "
                    "SIGKILL is cleanup only"
                )
                failure.__cause__ = error
            except BaseException as error:
                failure = error
            finally:
                fixture.release_all()
                for pending in backlog_sockets:
                    with contextlib.suppress(OSError):
                        pending.close()
                if client_thread is not None and client_thread.is_alive():
                    client_thread.join(timeout=1)
                if process is not None and process.poll() is None:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                stdout.close()
                stderr.close()

            if failure is not None:
                diagnostics = read_log(stderr_path)[-8000:]
                raise ShutdownFailure(
                    f"{label} failed: {failure}; service stderr tail: {diagnostics!r}"
                ) from failure


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=(
            "idle",
            "completed-request",
            "background-retry",
            "inflight-request",
            "backlog-shutdown",
            "high-fd-shutdown",
        ),
        help="Run only selected scenarios; may be repeated.",
    )
    args = parser.parse_args()

    if os.name != "posix":
        parser.error("process-level SIGTERM/SIGINT regression requires POSIX")
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")

    scenarios = args.scenario or [
        "idle",
        "completed-request",
        "background-retry",
        "inflight-request",
        "backlog-shutdown",
    ]
    if (
        args.scenario is None
        and sys.platform.startswith("linux")
        and os.environ.get("SUBCONVERTER_HTTP_BACKEND", "beast") == "beast"
        and os.environ.get("SUBCONVERTER_RESOURCE_CONTROL", "compat")
        != "adaptive"
    ):
        scenarios.append("high-fd-shutdown")
    for round_no in range(1, args.rounds + 1):
        for signal_value in (signal.SIGTERM, signal.SIGINT):
            for scenario in scenarios:
                run_case(binary, signal_value, scenario, round_no)
    print(
        f"shutdown process matrix passed: rounds={args.rounds} "
        f"cases={args.rounds * 2 * len(scenarios)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
