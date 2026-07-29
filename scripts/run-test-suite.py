#!/usr/bin/env python3
"""Run the repository's fast or full CTest baseline."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("fast", "full"), default="fast")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    command = [
        "ctest",
        "--test-dir",
        str(args.build_dir),
        "--output-on-failure",
        "--timeout",
        str(args.timeout),
    ]
    if args.mode == "fast":
        command.extend(["--label-regex", "^fast$"])
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        return completed.returncode
    print(f"{args.mode} test suite passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
