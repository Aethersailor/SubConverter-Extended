#!/usr/bin/env python3
"""Guard checks for automated upstream parser syncs.

The sync workflow may import parser fixes from upstream subconverter, but it
must never erase this fork's Mihomo/proxy-provider integration. This script
keeps those invariants machine-checkable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


CHECKS = [
    {
        "id": "mihomo-parser-compile-flag",
        "file": "src/generator/config/nodemanip.cpp",
        "pattern": r"USE_MIHOMO_PARSER",
        "message": "Mihomo parser compile flag is missing from nodemanip.cpp.",
    },
    {
        "id": "mihomo-parser-call",
        "file": "src/generator/config/nodemanip.cpp",
        "pattern": r"mihomo::parseSubscription",
        "message": "Mihomo parser call is missing from nodemanip.cpp.",
    },
    {
        "id": "fetch-context",
        "file": "src/generator/config/nodemanip.h",
        "pattern": r"FetchContext\s+fetch_context",
        "message": "FetchContext-aware parsing state is missing.",
    },
    {
        "id": "rawparams-field",
        "file": "src/parser/config/proxy.h",
        "pattern": r"std::map<\s*String\s*,\s*String\s*>\s+RawParams\s*;",
        "message": "Proxy.RawParams must be preserved for Mihomo pass-through.",
    },
    {
        "id": "rawparams-to-clash",
        "file": "src/generator/config/subexport.cpp",
        "pattern": r"if\s*\(!x\.RawParams\.empty\(\)\)",
        "message": "Clash RawParams pass-through block is missing.",
    },
    {
        "id": "proxy-provider-output",
        "file": "src/generator/config/subexport.cpp",
        "pattern": r"proxy-providers",
        "message": "proxy-providers output support is missing.",
    },
    {
        "id": "provider-direct-option",
        "file": "src/generator/config/subexport.h",
        "pattern": r"provider_proxy_direct",
        "message": "provider_proxy_direct option is missing.",
    },
    {
        "id": "provider-name-override",
        "file": "src/generator/config/subexport.cpp",
        "pattern": r"buildProviderProxyNameOverride",
        "message": "provider proxy-name override support is missing.",
    },
    {
        "id": "provider-creation",
        "file": "src/handler/interfaces.cpp",
        "pattern": r"ProxyProvider\s+provider",
        "message": "provider creation path is missing from request handling.",
    },
]


def run_checks() -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    for check in CHECKS:
        path = ROOT / check["file"]
        if not path.exists():
            failures.append(
                {
                    "id": check["id"],
                    "file": check["file"],
                    "message": f"Required file is missing: {check['file']}",
                }
            )
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        if not re.search(check["pattern"], text, flags=re.MULTILINE):
            failures.append(
                {
                    "id": check["id"],
                    "file": check["file"],
                    "message": check["message"],
                }
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    failures = run_checks()
    result = {"ok": not failures, "failures": failures}

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif failures:
        print("Sync guard checks failed:", file=sys.stderr)
        for failure in failures:
            print(
                f"- {failure['id']} ({failure['file']}): {failure['message']}",
                file=sys.stderr,
            )
    else:
        print("Sync guard checks passed.")

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
