#!/usr/bin/env python3
"""Fail CI when build artifacts exceed version-controlled size budgets."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--budget", required=True, help="key in the budget JSON file")
    parser.add_argument(
        "--budget-file",
        default=str(Path(__file__).with_name("size-budgets.json")),
    )
    parser.add_argument("patterns", nargs="+")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    budgets = json.loads(Path(args.budget_file).read_text(encoding="utf-8"))
    if args.budget not in budgets:
        print(f"Unknown size budget: {args.budget}", file=sys.stderr)
        return 2

    limit = int(budgets[args.budget])
    files: list[Path] = []
    for pattern in args.patterns:
        matches = [Path(path) for path in glob.glob(pattern)]
        if not matches:
            print(f"No files matched: {pattern}", file=sys.stderr)
            return 2
        files.extend(matches)

    rows: list[tuple[Path, int, bool]] = []
    failed = False
    for path in sorted(set(files)):
        size = path.stat().st_size
        within_budget = size <= limit
        rows.append((path, size, within_budget))
        failed = failed or not within_budget
        status = "OK" if within_budget else "TOO LARGE"
        print(f"{status}: {path} = {size} bytes (budget {limit})")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(f"\n### Size budget: `{args.budget}`\n\n")
            summary.write("| File | Bytes | Limit | Result |\n")
            summary.write("| --- | ---: | ---: | --- |\n")
            for path, size, within_budget in rows:
                result = "OK" if within_budget else "TOO LARGE"
                summary.write(f"| `{path}` | {size} | {limit} | {result} |\n")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
