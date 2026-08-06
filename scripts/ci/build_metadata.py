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
from typing import Callable, Optional


RELEASE_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True)
class BuildMetadata:
    mode: str
    version: str
    is_release: bool
    sha_short: str
    build_date: str


def _is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def normalize_build_date(value: str) -> str:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("commit date must include a timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_build_metadata(
    *,
    ref: str,
    event_name: str,
    sha_short: str,
    commit_date: str,
    dispatch_release_tag: str = "",
    overwrite_existing_release: bool = False,
    tag_exists: Optional[Callable[[str], bool]] = None,
) -> BuildMetadata:
    if ref.startswith("refs/tags/"):
        mode = "release"
        version = ref.removeprefix("refs/tags/")
    elif event_name == "workflow_dispatch" and overwrite_existing_release:
        if ref != "refs/heads/master":
            raise ValueError("existing releases may be rebuilt only from master")
        mode = "release"
        version = dispatch_release_tag.strip()
        if not version.startswith("v"):
            version = f"v{version}"
        if not RELEASE_RE.fullmatch(version):
            raise ValueError(f"invalid release tag {version!r}; use vX.Y.Z")
        if tag_exists is not None and not tag_exists(version):
            raise ValueError(f"release tag {version!r} does not exist")
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

    return BuildMetadata(
        mode=mode,
        version=version,
        is_release=mode == "release",
        sha_short=sha_short,
        build_date=normalize_build_date(commit_date),
    )


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], text=True, encoding="utf-8"
    ).strip()


def _tag_exists(tag: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _write_github_output(path: Path, metadata: BuildMetadata) -> None:
    values = {
        "mode": metadata.mode,
        "version": metadata.version,
        "is_release": str(metadata.is_release).lower(),
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
    parser.add_argument("--sha-short")
    parser.add_argument("--commit-date")
    parser.add_argument(
        "--dispatch-release-tag",
        default=os.environ.get("DISPATCH_RELEASE_TAG", ""),
    )
    parser.add_argument(
        "--overwrite-existing-release",
        default=os.environ.get("OVERWRITE_EXISTING_RELEASE", "false"),
    )
    parser.add_argument("--validate-release-tag", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    if not args.ref or not args.event_name:
        parser.error("--ref and --event-name are required")

    metadata = resolve_build_metadata(
        ref=args.ref,
        event_name=args.event_name,
        sha_short=args.sha_short or _git("rev-parse", "--short", "HEAD"),
        commit_date=args.commit_date or _git("show", "-s", "--format=%cI", "HEAD"),
        dispatch_release_tag=args.dispatch_release_tag,
        overwrite_existing_release=_is_true(args.overwrite_existing_release),
        tag_exists=_tag_exists if args.validate_release_tag else None,
    )

    if args.github_output:
        _write_github_output(args.github_output, metadata)
    print(
        f"Build mode: {metadata.mode}; version: {metadata.version}; "
        f"revision: {metadata.sha_short}; build date: {metadata.build_date}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
