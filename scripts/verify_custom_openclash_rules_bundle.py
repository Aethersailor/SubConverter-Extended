#!/usr/bin/env python3
"""Verify a policy-driven Custom_OpenClash_Rules runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path

from custom_openclash_rules_policy import (
    ALLOWED_DIRECTORIES,
    split_allowed_resource_path,
)


_MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (main/(.+))$")


class BundleVerificationError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False


def verify_bundle(root: Path) -> dict[str, int]:
    root = root.resolve()
    manifest = root / "manifest.sha256"
    resource_root = root / "main"
    if not _is_regular_file(manifest):
        raise BundleVerificationError("manifest.sha256 is missing or not a regular file")
    if not resource_root.is_dir() or resource_root.is_symlink():
        raise BundleVerificationError("main resource directory is missing or unsafe")

    counts = {directory: 0 for directory in ALLOWED_DIRECTORIES}
    recorded: dict[str, str] = {}
    lines = manifest.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise BundleVerificationError("manifest.sha256 contains no resources")

    for number, line in enumerate(lines, start=1):
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise BundleVerificationError(f"invalid manifest line {number}")
        expected_hash, manifest_path, repository_path = match.groups()
        resource = split_allowed_resource_path(repository_path)
        if resource is None:
            raise BundleVerificationError(
                f"manifest line {number} violates the path policy: {manifest_path!r}"
            )
        if manifest_path in recorded:
            raise BundleVerificationError(f"duplicate manifest path: {manifest_path!r}")
        directory, _ = resource
        file_path = root / Path(*manifest_path.split("/"))
        if file_path.is_symlink() or not _is_regular_file(file_path):
            raise BundleVerificationError(
                f"manifest resource is missing or not a regular file: {manifest_path!r}"
            )
        actual_hash = sha256(file_path)
        if actual_hash != expected_hash:
            raise BundleVerificationError(
                f"manifest hash mismatch for {manifest_path!r}"
            )
        recorded[manifest_path] = actual_hash
        counts[directory] += 1

    if list(recorded) != sorted(recorded):
        raise BundleVerificationError("manifest paths are not deterministically sorted")

    actual: set[str] = set()
    allowed_directories = set(ALLOWED_DIRECTORIES)
    allowed_parent_directories = {""}
    for directory in ALLOWED_DIRECTORIES:
        parts = directory.split("/")
        allowed_parent_directories.update(
            "/".join(parts[:size]) for size in range(1, len(parts) + 1)
        )

    for current, directory_names, file_names in os.walk(
        resource_root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        relative_directory = current_path.relative_to(resource_root).as_posix()
        if relative_directory == ".":
            relative_directory = ""
        if current_path.is_symlink() or relative_directory not in allowed_parent_directories:
            raise BundleVerificationError(
                f"unexpected bundle directory: {relative_directory!r}"
            )
        for name in directory_names:
            child = current_path / name
            child_relative = child.relative_to(resource_root).as_posix()
            if child.is_symlink():
                raise BundleVerificationError(
                    f"bundle contains a symlink directory: {child_relative!r}"
                )
            if child_relative not in allowed_parent_directories:
                raise BundleVerificationError(
                    f"unexpected bundle directory: {child_relative!r}"
                )
        for name in file_names:
            child = current_path / name
            repository_path = child.relative_to(resource_root).as_posix()
            if relative_directory not in allowed_directories:
                raise BundleVerificationError(
                    f"resource is outside an allowed directory: {repository_path!r}"
                )
            if child.is_symlink() or not _is_regular_file(child):
                raise BundleVerificationError(
                    f"bundle contains a non-regular resource: {repository_path!r}"
                )
            if name.casefold() == "readme.md":
                raise BundleVerificationError(
                    f"bundle contains an excluded README: {repository_path!r}"
                )
            actual.add("main/" + repository_path)

    missing = set(recorded) - actual
    extra = actual - set(recorded)
    if missing:
        raise BundleVerificationError(
            "manifest resources missing from bundle: " + ", ".join(sorted(missing))
        )
    if extra:
        raise BundleVerificationError(
            "bundle resources missing from manifest: " + ", ".join(sorted(extra))
        )
    if not actual:
        raise BundleVerificationError("bundle contains no publishable resources")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("base/Custom_OpenClash_Rules"),
        help="Bundle root containing manifest.sha256 and main/.",
    )
    args = parser.parse_args()
    try:
        counts = verify_bundle(args.root)
    except (BundleVerificationError, OSError, UnicodeError) as error:
        parser.error(str(error))
    for directory in ALLOWED_DIRECTORIES:
        print(f"{directory}: {counts[directory]}")
    print(f"total: {sum(counts.values())}")
    print("COCR bundle verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
