#!/usr/bin/env python3
"""Run manifest-driven HTTP smoke checks for a COCR bundle."""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from custom_openclash_rules_policy import ALLOWED_DIRECTORIES
from verify_custom_openclash_rules_bundle import verify_bundle


PUBLISHED_PREFIX = "/Custom_OpenClash_Rules/main/"


def encoded_path(repository_path: str, directory: bool = False) -> str:
    path = PUBLISHED_PREFIX + "/".join(
        urllib.parse.quote(segment, safe="") for segment in repository_path.split("/")
    )
    return path + ("/" if directory else "")


def fetch(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def manifest_paths(root: Path) -> list[str]:
    return [
        line.split("  ", 1)[1][len("main/") :]
        for line in (root / "manifest.sha256")
        .read_text(encoding="utf-8")
        .splitlines()
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--published", choices=("enabled", "disabled"), required=True
    )
    args = parser.parse_args()

    counts = verify_bundle(args.root)
    paths = sorted(manifest_paths(args.root))
    sample = paths[0]
    base_url = args.base_url.rstrip("/")
    sample_url = base_url + encoded_path(sample)

    if args.published == "disabled":
        status, _ = fetch(sample_url)
        if status != 404:
            raise AssertionError(
                f"expected default COCR publication status 404, got {status}"
            )
    else:
        status, _ = fetch(base_url + PUBLISHED_PREFIX)
        if status != 200:
            raise AssertionError(f"COCR root directory returned HTTP {status}")
        for directory in ALLOWED_DIRECTORIES:
            status, _ = fetch(base_url + encoded_path(directory, directory=True))
            if status != 200:
                raise AssertionError(
                    f"COCR directory {directory!r} returned HTTP {status}"
                )

        status, body = fetch(sample_url)
        if status != 200:
            raise AssertionError(
                f"dynamic COCR sample {sample!r} returned HTTP {status}"
            )
        expected = args.root.joinpath("main", *sample.split("/")).read_bytes()
        if body != expected:
            raise AssertionError(
                f"dynamic COCR sample {sample!r} differs from bundled bytes"
            )

        for directory, count in counts.items():
            if count == 0:
                continue
            directory_sample = next(
                path for path in paths if path.startswith(directory + "/")
            )
            status, body = fetch(base_url + encoded_path(directory_sample))
            expected = args.root.joinpath(
                "main", *directory_sample.split("/")
            ).read_bytes()
            if status != 200 or body != expected:
                raise AssertionError(
                    f"COCR sample for {directory!r} failed byte verification"
                )

    print(
        f"COCR HTTP smoke passed: mode={args.published}, "
        f"sample={sample}, total={len(paths)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"COCR HTTP smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
