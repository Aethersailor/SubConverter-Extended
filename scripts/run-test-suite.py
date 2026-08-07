#!/usr/bin/env python3
"""Run a named correctness or benchmark CTest suite."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def build_command(build_dir: Path, mode: str, timeout: int) -> list[str]:
    command = [
        "ctest",
        "--test-dir",
        str(build_dir),
        "--output-on-failure",
        "--timeout",
        str(timeout),
    ]
    if mode == "fast":
        command.extend(["--label-regex", "^fast$"])
    elif mode == "full":
        command.extend(["--label-exclude", "^benchmark$"])
    elif mode == "benchmark":
        command.extend(["--label-regex", "^benchmark$"])
    else:  # Defensive guard for direct imports; argparse validates CLI input.
        raise ValueError(f"unknown test mode: {mode}")
    return command


def benchmark_executable(build_dir: Path) -> Path | None:
    candidates = (
        build_dir / "statistics_v2_benchmark",
        build_dir / "statistics_v2_benchmark.exe",
        build_dir / "Release" / "statistics_v2_benchmark.exe",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument(
        "--mode", choices=("fast", "full", "benchmark"), default="fast"
    )
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    if args.mode == "benchmark" and benchmark_executable(args.build_dir) is None:
        print(
            "benchmark executable is missing; configure with "
            "-DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON",
            file=sys.stderr,
        )
        return 2

    command = build_command(args.build_dir, args.mode, args.timeout)
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        return completed.returncode
    print(f"{args.mode} test suite passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
