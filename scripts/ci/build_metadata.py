#!/usr/bin/env python3
"""Resolve the version metadata shared by binaries and container images."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
RELEASE_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class BuildMetadata:
    mode: str
    version: str
    is_release: bool
    sha: str
    sha_short: str
    build_date: str


def normalize_build_date(value: str) -> str:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("commit date must include a timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_build_metadata(
    *,
    ref: str,
    event_name: str,
    sha: str,
    commit_date: str,
) -> BuildMetadata:
    sha = sha.strip().lower()
    if not SHA_RE.fullmatch(sha):
        raise ValueError("source revision must be a full 40-character Git SHA")
    sha_short = sha[:7]

    if ref.startswith("refs/tags/"):
        mode = "release"
        version = ref.removeprefix("refs/tags/")
    elif event_name == "pull_request":
        mode = "pr"
        version = f"pr-{sha_short}"
    elif ref == "refs/heads/dev":
        mode = "dev"
        version = "dev"
    elif ref == "refs/heads/master":
        mode = "master"
        version = f"master-{sha_short}"
    else:
        raise ValueError(f"unsupported build ref {ref} ({event_name})")

    if mode == "release":
        if event_name != "push":
            raise ValueError("formal releases require a tag push event")
        if not RELEASE_RE.fullmatch(version):
            raise ValueError(f"invalid release tag {version!r}; use vX.Y.Z")

    return BuildMetadata(
        mode=mode,
        version=version,
        is_release=mode == "release",
        sha=sha,
        sha_short=sha_short,
        build_date=normalize_build_date(commit_date),
    )


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], text=True, encoding="utf-8"
    ).strip()


def _write_github_output(path: Path, metadata: BuildMetadata) -> None:
    values = {
        "mode": metadata.mode,
        "version": metadata.version,
        "is_release": str(metadata.is_release).lower(),
        "sha": metadata.sha,
        "sha_short": metadata.sha_short,
        "build_date": metadata.build_date,
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME", ""))
    parser.add_argument("--sha")
    parser.add_argument("--commit-date")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    if not args.ref or not args.event_name:
        parser.error("--ref and --event-name are required")

    metadata = resolve_build_metadata(
        ref=args.ref,
        event_name=args.event_name,
        sha=args.sha or _git("rev-parse", "HEAD"),
        commit_date=args.commit_date or _git("show", "-s", "--format=%cI", "HEAD"),
    )

    if args.github_output:
        _write_github_output(args.github_output, metadata)
    print(
        f"Build mode: {metadata.mode}; version: {metadata.version}; "
        f"revision: {metadata.sha}; build date: {metadata.build_date}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
