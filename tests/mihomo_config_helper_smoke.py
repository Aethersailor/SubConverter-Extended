#!/usr/bin/env python3
"""Verify the independent Mihomo parser helper is actually executable."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validator", type=Path, required=True)
    args = parser.parse_args()
    validator = args.validator.resolve()
    if not validator.is_file():
        parser.error(f"Mihomo validator does not exist: {validator}")

    rule = r"PROCESS-NAME-REGEX,^\($,Proxy"
    completed = subprocess.run(
        [str(validator), "--regex", rule],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "Mihomo helper smoke failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"Mihomo helper smoke returned invalid JSON: {completed.stdout!r}"
        ) from exc
    expected = {
        "type": "PROCESS-NAME-REGEX",
        "payload": r"^\($",
        "target": "Proxy",
    }
    if parsed != expected:
        raise SystemExit(f"Mihomo helper smoke returned {parsed!r}, expected {expected!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
