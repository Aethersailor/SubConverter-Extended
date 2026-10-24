#!/usr/bin/env python3
"""Exercise a portable Linux build using disposable local-resource fixtures.

The required, new --work-dir retains diagnostics for inspection. The caller
owns cleanup; the supplied portable package is copied and never modified.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--portable-root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    (work / ".codex-test.json").write_text(json.dumps({
        "purpose": "local resource canonical-boundary regression fixtures",
        "owning_chat": "caller of verify-local-resource-paths.py",
        "source_repository": "Aethersailor/SubConverter-Extended",
        "safe_cleanup_boundary": str(work),
    }, indent=2))
    app = work / "portable"
    shutil.copytree(args.portable_root.resolve(), app, symlinks=True)
    base = app / "base"
    trusted = work / "trusted"
    outside = work / "trusted-other"
    for directory in (trusted / "templates", outside, base / "base", base / "templates"):
        directory.mkdir(parents=True, exist_ok=True)
    marker = "issue159-local.example"
    for path in (base / "base/rules.list", base / "cwd-rules.list", trusted / "rules.list", outside / "rules.list"):
        path.write_text("DOMAIN," + marker + "\n")
    (trusted / "empty.list").write_text("")
    (trusted / "unreadable.list").write_text("DOMAIN," + marker + "\n")
    (trusted / "unreadable.list").chmod(0)
    static = "mixed-port: 19005\nmode: rule\n"
    for path in (trusted / "templates/custom.yaml", outside / "custom.yaml"):
        path.write_text(static)
    (trusted / "templates/fragment.tpl").write_text("mixed-port: 19006\n")
    (trusted / "root-fragment.tpl").write_text("mixed-port: 19006\n")
    (outside / "fragment.tpl").write_text("mixed-port: 19006\n")
    (base / "templates/fragment.tpl").write_text("mixed-port: 19006\n")
    (trusted / "escape.list").symlink_to(outside / "rules.list")
    (trusted / "templates/escape.yaml").symlink_to(outside / "custom.yaml")
    (trusted / "templates/escape.tpl").symlink_to(outside / "fragment.tpl")
    results = []

    def request(port, path):
        try:
            with urllib.request.urlopen("http://127.0.0.1:" + str(port) + path, timeout=12) as response:
                return response.status, response.read().decode(), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(), dict(error.headers)

    def case(name, profile="lan", external=True, rules=None, template=None,
             include=None, template_scope=True, expected=200, backend="beast",
             expect_rule=True, expect_template=False, expect_include=False,
             config_outside=False):
        rules = trusted / "rules.list" if rules is None else rules
        selected = trusted / "config.ini" if external else base / "base/config.ini"
        if config_outside:
            selected = outside / "config.ini"
        text = "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\n"
        text += "ruleset=DIRECT," + str(rules) + "\nruleset=DIRECT,[]FINAL\n"
        if include is not None:
            template = trusted / "templates/include.yaml"
            template.write_text("{% include " + json.dumps(str(include)) + " %}\nmode: rule\n")
        if template is not None:
            text += "clash_rule_base=" + str(template) + "\n"
        selected.write_text(text)
        pref = "version=1\n[common]\n"
        pref += "base_path=" + json.dumps(str(trusted) if external else "base") + "\n"
        pref += 'clash_rule_base="base/all_base.tpl"\nproxy_config="NONE"\nproxy_ruleset="NONE"\nproxy_subscription="NONE"\n'
        pref += "[template]\ntemplate_path=" + json.dumps(str(trusted / "templates") if template_scope and external else "") + "\n"
        pref += "[ruleset]\nenabled=true\noverwrite_original_rules=true\n"
        pref += "[node_pref]\n[managed_config]\n[surge_external_proxy]\n[emojis]\n[server]\n"
        pref += "[advanced]\nlog_level=\"info\"\nrequest_deadline_ms=5000\n"
        (base / "pref.toml").write_text(pref)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = os.environ.copy()
        env.update(SUBCONVERTER_UPDATE_VALIDATION="1", SUBCONVERTER_SKIP_AUTO_UPDATE="1",
                   SUBCONVERTER_LISTEN_ADDRESS="127.0.0.1", SUBCONVERTER_LISTEN_PORT=str(port),
                   PORT=str(port), SUBCONVERTER_SECURITY_PROFILE=profile,
                   SUBCONVERTER_HTTP_BACKEND=backend, PREF_PATH=str(base / "pref.toml"),
                   SUBCONVERTER_RUNTIME_STATE_FILE=str(work / (name + ".runtime.json")))
        with (work / (name + ".log")).open("w") as log:
            process = subprocess.Popen([str(app / "start.sh")], cwd=app, env=env, stdout=log, stderr=log)
            try:
                for attempt in range(150):
                    if process.poll() is not None:
                        raise AssertionError(name + ": runtime exited during startup")
                    try:
                        if request(port, "/healthz")[0] == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                else:
                    raise AssertionError(name + ": runtime readiness timeout")
                query = urllib.parse.urlencode({
                    "target": "clash", "url": "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#LocalProbe",
                    "config": str(selected), "insert": "false", "emoji": "false", "expand": "true",
                })
                status, body, headers = request(port, "/sub?" + query)
                (work / (name + ".response.txt")).write_text(body)
                assert status == expected, (name, status, body[:200])
                if expected == 200:
                    assert (marker in body) == expect_rule, (name, "rules")
                    if expect_template:
                        assert "19005" in body, (name, "template")
                    if expect_include:
                        assert "19006" in body, (name, "include")
                elif "local ruleset source" in body.lower():
                    assert str(work) not in body, (name, "path disclosure")
                    assert headers.get("Cache-Control") == "private, no-store", name
                results.append({"case": name, "profile": profile, "backend": backend, "status": status, "result": "PASS"})
                print(name + ": PASS", flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    for backend in ("beast", "httplib"):
        for profile in ("lan", "public", "strict"):
            prefix = backend + "-" + profile + "-"
            common = {"profile": profile, "backend": backend}
            case(prefix + "trusted-template", template=trusted / "templates/custom.yaml", expect_template=True, **common)
            case(prefix + "bundled-template", **common)
            case(prefix + "include-relative", include="fragment.tpl", expect_include=True, **common)
            case(prefix + "include-absolute", include=trusted / "templates/fragment.tpl", expect_include=True, **common)
            case(prefix + "rule-outside", rules=outside / "rules.list", expected=400, **common)
            case(prefix + "rule-symlink", rules=trusted / "escape.list", expected=400, **common)
            case(prefix + "rule-missing", rules=trusted / "missing.list", expected=400, **common)
            case(prefix + "rule-empty", rules=trusted / "empty.list", expect_rule=False, **common)
            case(prefix + "template-outside", template=outside / "custom.yaml", expected=400, **common)
            case(prefix + "template-symlink", template=trusted / "templates/escape.yaml", expected=400, **common)
            case(prefix + "include-traversal", include="../../trusted-other/fragment.tpl", expected=400, **common)
            case(prefix + "include-outside-template-scope", include="../root-fragment.tpl", expected=400, **common)
            case(prefix + "include-symlink", include="escape.tpl", expected=400, **common)
            case(prefix + "config-outside", config_outside=True, expected=400, **common)
        case(backend + "-default-local", external=False, rules=base / "base/rules.list", backend=backend)
        case(backend + "-default-external-denied", external=False, rules=trusted / "rules.list", expected=400, backend=backend)
        case(backend + "-lan-cwd", external=False, rules=base / "cwd-rules.list", backend=backend)
        case(backend + "-public-cwd-denied", external=False, rules=base / "cwd-rules.list", expected=400, profile="public", backend=backend)
        case(backend + "-remote-failure-compatible", rules="http://127.0.0.1:1/missing", expect_rule=False, backend=backend)
        case(backend + "-include-default-cwd", include=base / "templates/fragment.tpl", template_scope=False, expect_include=True, backend=backend)
        case(backend + "-include-default-external-denied", include=trusted / "templates/fragment.tpl", template_scope=False, expected=400, backend=backend)
        for profile in ("public", "strict"):
            case(backend + "-" + profile + "-include-untrusted-cwd", include=base / "templates/fragment.tpl", template_scope=False, expected=400, profile=profile, backend=backend)
        if os.geteuid() != 0:
            case(backend + "-unreadable", rules=trusted / "unreadable.list", expected=400, backend=backend)
    (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("PASS: " + str(len(results)) + " cases; disposable diagnostics retained at " + str(work))


if __name__ == "__main__":
    main()
