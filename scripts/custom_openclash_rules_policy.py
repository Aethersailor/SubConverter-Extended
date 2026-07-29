#!/usr/bin/env python3
"""Load the canonical Custom_OpenClash_Rules bundle policy."""

from __future__ import annotations

import re
from pathlib import Path


POLICY_FILE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "config"
    / "custom_openclash_rules_policy.def"
)
_POLICY_LINE = re.compile(r'^COCR_ALLOWED_DIRECTORY\("([^"]+)"\)$')


def load_allowed_directories(path: Path = POLICY_FILE) -> tuple[str, ...]:
    directories: list[str] = []
    for number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        match = _POLICY_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid COCR policy line {number}: {raw_line!r}")
        directory = match.group(1)
        parts = directory.split("/")
        if (
            not parts
            or any(part in {"", ".", ".."} for part in parts)
            or "\\" in directory
            or directory.startswith("/")
        ):
            raise ValueError(f"unsafe COCR policy directory: {directory!r}")
        if directory in directories:
            raise ValueError(f"duplicate COCR policy directory: {directory!r}")
        directories.append(directory)
    if not directories:
        raise ValueError("COCR policy must contain at least one directory")
    return tuple(directories)


ALLOWED_DIRECTORIES = load_allowed_directories()
SPARSE_CHECKOUT_DIRECTORIES = tuple(
    dict.fromkeys(directory.split("/", 1)[0] for directory in ALLOWED_DIRECTORIES)
)


def split_allowed_resource_path(path: str) -> tuple[str, str] | None:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\0" in path
        or path.startswith("main/")
    ):
        return None
    for directory in sorted(ALLOWED_DIRECTORIES, key=len, reverse=True):
        prefix = directory + "/"
        if not path.startswith(prefix):
            continue
        filename = path[len(prefix) :]
        if (
            not filename
            or "/" in filename
            or filename in {".", ".."}
            or filename.casefold() == "readme.md"
        ):
            return None
        return directory, filename
    return None
