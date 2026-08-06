#!/usr/bin/env python3
"""Verify that a frozen historical release still has its recorded identity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify(
    *,
    baseline: dict,
    release: dict,
    tag_commit: str,
    dockerhub_digest: str,
    ghcr_digest: str,
) -> None:
    if release.get("id") != baseline["release_id"]:
        raise ValueError("GitHub Release ID changed")
    if release.get("tag_name") != baseline["version"]:
        raise ValueError("GitHub Release tag changed")
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("frozen formal Release changed state")
    if tag_commit != baseline["tag_commit"]:
        raise ValueError("frozen tag commit changed")

    actual_assets = {
        item["name"]: {"size": item["size"], "digest": item.get("digest")}
        for item in release.get("assets", [])
    }
    if actual_assets != baseline["assets"]:
        raise ValueError("frozen GitHub Release assets changed")
    if dockerhub_digest != baseline["images"]["dockerhub"]["digest"]:
        raise ValueError("frozen Docker Hub version digest changed")
    if ghcr_digest != baseline["images"]["ghcr"]["digest"]:
        raise ValueError("frozen GHCR version digest changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--tag-commit", required=True)
    parser.add_argument("--dockerhub-digest", required=True)
    parser.add_argument("--ghcr-digest", required=True)
    args = parser.parse_args()
    verify(
        baseline=json.loads(args.baseline.read_text(encoding="utf-8")),
        release=json.loads(args.release_json.read_text(encoding="utf-8")),
        tag_commit=args.tag_commit,
        dockerhub_digest=args.dockerhub_digest,
        ghcr_digest=args.ghcr_digest,
    )
    print(f"Verified frozen release baseline {args.baseline.stem}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
