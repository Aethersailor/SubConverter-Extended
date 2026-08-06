#!/usr/bin/env python3
"""Write and verify the identity embedded in every formal release package."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path


VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def build_info(*, version: str, revision: str, build_date: str) -> dict[str, str]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be an exact vX.Y.Z tag")
    if not SHA_RE.fullmatch(revision):
        raise ValueError("revision must be a full 40-character Git SHA")
    parsed = datetime.fromisoformat(build_date.replace("Z", "+00:00"))
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("build date must be a UTC timestamp")
    if not build_date.endswith("Z"):
        raise ValueError("build date must use the canonical Z suffix")
    return {
        "build_date": build_date,
        "revision": revision,
        "version": version,
    }


def write(path: Path, identity: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def verify(path: Path, expected: dict[str, str]) -> None:
    actual = json.loads(path.read_text(encoding="utf-8"))
    if actual != expected:
        raise ValueError(f"BUILD-INFO.json identity mismatch: {actual!r} != {expected!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--build-date", required=True)
    args = parser.parse_args()

    identity = build_info(
        version=args.version,
        revision=args.revision,
        build_date=args.build_date,
    )
    if args.mode == "write":
        write(args.path, identity)
    else:
        verify(args.path, identity)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
