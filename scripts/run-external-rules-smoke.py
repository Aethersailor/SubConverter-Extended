#!/usr/bin/env python3
"""Exercise ruleprepend/ruleappend against a running dev instance."""

from __future__ import annotations

import argparse
import base64
import contextlib
import http.server
import shutil
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SAMPLE_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Issue87Smoke"
)


def data_url(content: str) -> str:
    encoded = base64.urlsafe_b64encode(content.encode()).decode()
    return f"data:text/plain;base64,{encoded}"


def request(
    api_base: str, params: dict[str, str], timeout: int
) -> tuple[int, str]:
    query = urllib.parse.urlencode({"url": SAMPLE_SS_LINK, **params})
    url = f"{api_base.rstrip('/')}/sub?{query}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def expect_400(
    api_base: str, params: dict[str, str], timeout: int, label: str
) -> None:
    status, body = request(api_base, params, timeout)
    if status != 400:
        raise AssertionError(
            f"{label}: expected HTTP 400, got {status}\n{body[:1000]}"
        )


def extract_rules(body: str) -> list[str]:
    rules: list[str] = []
    in_rules = False
    for line in body.replace("\r\n", "\n").splitlines():
        if line == "rules:":
            in_rules = True
            continue
        if not in_rules:
            continue
        if not line.startswith("  - "):
            if line and not line.startswith(" "):
                break
            continue
        value = line[4:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        rules.append(value)
    if not rules:
        raise AssertionError(f"no rules: sequence found\n{body[:1500]}")
    return rules


def assert_order(rules: list[str], markers: list[str], label: str) -> None:
    positions = []
    for marker in markers:
        try:
            positions.append(next(i for i, rule in enumerate(rules) if marker in rule))
        except StopIteration as exc:
            raise AssertionError(
                f"{label}: marker {marker!r} missing from rules\n{rules}"
            ) from exc
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise AssertionError(
            f"{label}: wrong marker order {list(zip(markers, positions))}"
        )


class FixtureState:
    mutable_rule = "DOMAIN,issue87-cache-one.example,DIRECT\n"
    mutable_headers: list[dict[str, str]] = []


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    fixtures = {
        "/prepend-one.list": "DOMAIN,issue87-prepend-one.example,DIRECT\n",
        "/prepend-two.list": "DOMAIN,issue87-prepend-two.example,DIRECT\n",
        "/append.yaml": (
            "rules:\n"
            "  - DOMAIN,issue87-append.example,DIRECT\n"
        ),
        "/base.yml": (
            "mixed-port: 7890\n"
            "rules:\n"
            "  - DOMAIN,issue87-base.example,DIRECT\n"
            "  - MATCH,DIRECT\n"
        ),
        "/payload.yaml": (
            "payload:\n"
            "  - DOMAIN-SUFFIX,issue87-payload.example\n"
        ),
        "/provider.yaml": (
            "payload:\n"
            "  - DOMAIN-SUFFIX,issue87-provider.example\n"
        ),
        "/terminal.list": "MATCH,DIRECT\n",
    }

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/mutable.list":
            FixtureState.mutable_headers.append(
                {key.lower(): value for key, value in self.headers.items()}
            )
            content = FixtureState.mutable_rule
        elif self.path in self.fixtures:
            content = self.fixtures[self.path]
        else:
            self.send_error(404)
            return
        payload = content.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class ThreadedFixtureServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def local_fixture_server() -> str:
    server = ThreadedFixtureServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def materialized_fixtures(directory: Path):
    if directory.exists():
        raise AssertionError(f"fixture directory already exists: {directory}")
    directory.mkdir(parents=True)
    try:
        for url_path, content in FixtureHandler.fixtures.items():
            (directory / url_path.lstrip("/")).write_text(content, encoding="utf-8")
        mutable_file = directory / "mutable.list"
        mutable_file.write_text(FixtureState.mutable_rule, encoding="utf-8")
        yield mutable_file
    finally:
        shutil.rmtree(directory)


def ini_config(resource_base: str, *, overwrite: bool = False,
               rulegen: bool = True) -> str:
    return "\n".join(
        (
            "[custom]",
            f"enable_rule_generator={'true' if rulegen else 'false'}",
            f"overwrite_original_rules={'true' if overwrite else 'false'}",
            f"clash_rule_base={resource_base}/base.yml",
            f"ruleprepend={resource_base}/prepend-one.list",
            f"ruleprepend={resource_base}/prepend-two.list",
            f"ruleappend={resource_base}/append.yaml",
            "ruleset=DIRECT,[]DOMAIN-SUFFIX,issue87-generated.example",
            f"ruleset=DIRECT,clash-classic:{resource_base}/provider.yaml",
            "ruleset=GeneratedTail,[]FINAL",
        )
    )


def run(
    api_base: str,
    resource_base: str,
    timeout: int,
    mutable_file: Path | None = None,
    verify_request_headers: bool = True,
) -> None:
    main_config = data_url(ini_config(resource_base))

    status, body = request(
        api_base,
        {"target": "clash", "expand": "true", "config": main_config},
        timeout,
    )
    if status != 200:
        raise AssertionError(f"expanded mode returned {status}\n{body}")
    expanded_rules = extract_rules(body)
    assert_order(
        expanded_rules,
        [
            "issue87-prepend-one",
            "issue87-prepend-two",
            "issue87-base",
            "issue87-generated",
            "issue87-provider",
            "issue87-append",
            "MATCH,",
        ],
        "expanded ordering",
    )

    status, body = request(
        api_base, {"target": "clash", "config": main_config}, timeout
    )
    if status != 200:
        raise AssertionError(f"managed mode returned {status}\n{body}")
    managed_rules = extract_rules(body)
    assert_order(
        managed_rules,
        [
            "issue87-prepend-one",
            "issue87-prepend-two",
            "issue87-generated",
            "RULE-SET,provider",
            "issue87-append",
            "MATCH,",
        ],
        "managed ordering",
    )
    if "rule-providers:" not in body:
        raise AssertionError("managed mode did not retain rule-providers")

    overwrite_config = data_url(ini_config(resource_base, overwrite=True))
    status, body = request(
        api_base,
        {"target": "clash", "expand": "true", "config": overwrite_config},
        timeout,
    )
    if status != 200:
        raise AssertionError(f"overwrite mode returned {status}\n{body}")
    overwrite_rules = extract_rules(body)
    if len(overwrite_rules) != 6:
        raise AssertionError(
            f"overwrite mode retained unexpected base rules: {overwrite_rules}"
        )
    assert_order(
        overwrite_rules,
        [
            "issue87-prepend-one",
            "issue87-prepend-two",
            "issue87-generated",
            "issue87-provider",
            "issue87-append",
            "MATCH,",
        ],
        "overwrite ordering",
    )

    disabled_config = data_url(
        "\n".join(
            (
                "[custom]",
                "enable_rule_generator=false",
                "overwrite_original_rules=false",
                f"clash_rule_base={resource_base}/base.yml",
                f"ruleprepend={resource_base}/prepend-one.list",
                f"ruleappend={resource_base}/append.yaml",
            )
        )
    )
    status, body = request(
        api_base, {"target": "clash", "config": disabled_config}, timeout
    )
    if status != 200:
        raise AssertionError(f"disabled rule generator returned {status}\n{body}")
    disabled_rules = extract_rules(body)
    assert_order(
        disabled_rules,
        [
            "issue87-prepend-one",
            "issue87-base",
            "issue87-append",
            "MATCH,",
        ],
        "disabled rule generator ordering",
    )

    yaml_config = data_url(
        "custom:\n"
        "  enable_rule_generator: false\n"
        f"  clash_rule_base: {resource_base}/base.yml\n"
        "  ruleprepend:\n"
        f"    - {resource_base}/prepend-one.list\n"
        "  ruleappend:\n"
        f"    - {resource_base}/append.yaml\n"
    )
    toml_config = data_url(
        "version = 1\n"
        "[custom]\n"
        "enable_rule_generator = false\n"
        f'clash_rule_base = "{resource_base}/base.yml"\n'
        f'ruleprepend = ["{resource_base}/prepend-one.list"]\n'
        f'ruleappend = ["{resource_base}/append.yaml"]\n'
    )
    for label, config in (("YAML", yaml_config), ("TOML", toml_config)):
        status, body = request(
            api_base, {"target": "clash", "config": config}, timeout
        )
        if status != 200:
            raise AssertionError(f"{label} config returned {status}\n{body}")
        assert_order(
            extract_rules(body),
            ["issue87-prepend-one", "issue87-append", "MATCH,"],
            f"{label} config",
        )

    for label, extra in (
        ("non-Clash", {"target": "surge"}),
        ("list=true", {"target": "clash", "list": "true"}),
        ("script=true", {"target": "clash", "script": "true"}),
    ):
        expect_400(
            api_base, {**extra, "config": main_config}, timeout, label
        )

    for label, path in (
        ("payload", "payload.yaml"),
        ("terminal rule", "terminal.list"),
    ):
        invalid_config = data_url(
            "[custom]\n"
            "enable_rule_generator=false\n"
            f"ruleprepend={resource_base}/{path}\n"
        )
        expect_400(
            api_base,
            {"target": "clash", "config": invalid_config},
            timeout,
            label,
        )

    skip_config = data_url(
        "[custom]\n"
        "enable_rule_generator=false\n"
        f"clash_rule_base={resource_base}/base.yml\n"
        f"ruleprepend={resource_base}/missing.list\n"
        f"ruleprepend={resource_base}/prepend-one.list\n"
    )
    status, body = request(
        api_base, {"target": "clash", "config": skip_config}, timeout
    )
    if status != 200 or not any(
        "issue87-prepend-one" in rule for rule in extract_rules(body)
    ):
        raise AssertionError(f"network failure was not skipped: {status}\n{body}")

    too_many_config = data_url(
        "[custom]\n"
        + "\n".join(
            f"ruleprepend={resource_base}/prepend-one.list" for _ in range(65)
        )
    )
    expect_400(
        api_base,
        {"target": "clash", "config": too_many_config},
        timeout,
        "source count limit",
    )

    baseline_status, baseline_body = request(
        api_base,
        {
            "target": "clash",
            "config": data_url("[custom]\nenable_rule_generator=false\n"),
        },
        timeout,
    )
    if baseline_status != 200 or "proxies:" not in baseline_body:
        raise AssertionError("legacy external config conversion regressed")

    mutable_config = data_url(
        "[custom]\n"
        "enable_rule_generator=false\n"
        f"clash_rule_base={resource_base}/base.yml\n"
        f"ruleappend={resource_base}/mutable.list\n"
    )
    FixtureState.mutable_rule = "DOMAIN,issue87-cache-one.example,DIRECT\n"
    if mutable_file is not None:
        mutable_file.write_text(FixtureState.mutable_rule, encoding="utf-8")
    status, first = request(
        api_base,
        {
            "target": "clash",
            "config": mutable_config,
            "interval": "3600",
        },
        timeout,
    )
    if status != 200 or not any(
        "issue87-cache-one" in rule for rule in extract_rules(first)
    ):
        raise AssertionError("first mutable rule request failed")
    FixtureState.mutable_rule = "DOMAIN,issue87-cache-two.example,DIRECT\n"
    if mutable_file is not None:
        mutable_file.write_text(FixtureState.mutable_rule, encoding="utf-8")
    status, second = request(
        api_base,
        {
            "target": "clash",
            "config": mutable_config,
            "interval": "7200",
        },
        timeout,
    )
    if status != 200 or not any(
        "issue87-cache-two" in rule for rule in extract_rules(second)
    ):
        raise AssertionError("same source URL returned cached rule content")
    if verify_request_headers:
        if len(FixtureState.mutable_headers) < 2:
            raise AssertionError("mutable source was not fetched twice")
        for headers in FixtureState.mutable_headers[-2:]:
            if headers.get("cache-control") != "no-cache, no-store, max-age=0":
                raise AssertionError(f"missing Cache-Control header: {headers}")
            if headers.get("pragma") != "no-cache":
                raise AssertionError(f"missing Pragma header: {headers}")

    print(
        "external rule smoke passed: expanded, managed, overwrite, "
        "rulegen-disabled, INI/YAML/TOML, restrictions, invalid content, "
        "network skip, source limit, legacy config, and no-cache refresh"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--resource-base")
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        help="Create temporary static fixtures here; the directory must not exist.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    if args.fixture_dir and not args.resource_base:
        parser.error("--fixture-dir requires --resource-base")
    if args.fixture_dir:
        with materialized_fixtures(args.fixture_dir) as mutable_file:
            run(
                args.api_base,
                args.resource_base.rstrip("/"),
                args.timeout,
                mutable_file=mutable_file,
                verify_request_headers=False,
            )
    elif args.resource_base:
        run(
            args.api_base,
            args.resource_base.rstrip("/"),
            args.timeout,
            verify_request_headers=False,
        )
    else:
        with local_fixture_server() as resource_base:
            run(args.api_base, resource_base, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
