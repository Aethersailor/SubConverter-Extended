#!/usr/bin/env python3
"""Fail-closed identity checks for the tag-only formal release entrypoint."""

from __future__ import annotations

import argparse
import re


VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def verify_source_identity(
    *,
    event_name: str,
    ref: str,
    github_sha: str,
    checkout_sha: str,
    tag_sha: str,
) -> str:
    if event_name != "push" or not ref.startswith("refs/tags/"):
        raise ValueError("formal release must originate from a tag push")
    version = ref.removeprefix("refs/tags/")
    if not VERSION_RE.fullmatch(version):
        raise ValueError("formal release tag must match vX.Y.Z exactly")
    identities = {
        "event": github_sha.lower(),
        "checkout": checkout_sha.lower(),
        "tag": tag_sha.lower(),
    }
    for name, revision in identities.items():
        if not SHA_RE.fullmatch(revision):
            raise ValueError(f"{name} revision is not a full Git SHA")
    if len(set(identities.values())) != 1:
        raise ValueError(f"release source identities differ: {identities}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--github-sha", required=True)
    parser.add_argument("--checkout-sha", required=True)
    parser.add_argument("--tag-sha", required=True)
    args = parser.parse_args()
    version = verify_source_identity(
        event_name=args.event_name,
        ref=args.ref,
        github_sha=args.github_sha,
        checkout_sha=args.checkout_sha,
        tag_sha=args.tag_sha,
    )
    print(f"Verified formal release source {version} at {args.github_sha.lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
