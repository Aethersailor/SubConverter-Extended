#!/usr/bin/env python3

import argparse
import hashlib
import shutil
from pathlib import Path


EXCLUDED_DIRECTORIES = {"archived", "test"}
EXCLUDED_FILES = {"readme.md"}


def ignore_unpublished(directory, names):
    ignored = set()
    for name in names:
        lowered = name.lower()
        path = Path(directory) / name
        if path.is_dir() and lowered in EXCLUDED_DIRECTORIES:
            ignored.add(name)
        elif path.is_file() and lowered in EXCLUDED_FILES:
            ignored.add(name)
    return ignored


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync bundled Custom_OpenClash_Rules cfg and rule files."
    )
    parser.add_argument(
        "source",
        nargs="?",
        default="../Custom_OpenClash_Rules",
        help="Path to the Custom_OpenClash_Rules checkout.",
    )
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    source = Path(args.source).resolve()
    destination = repository / "base" / "Custom_OpenClash_Rules" / "main"

    for name in ("cfg", "rule"):
        source_dir = source / name
        if not source_dir.is_dir():
            raise SystemExit(f"missing source directory: {source_dir}")
        destination_dir = destination / name
        if destination_dir.exists():
            shutil.rmtree(destination_dir)
        shutil.copytree(source_dir, destination_dir, ignore=ignore_unpublished)

    manifest = repository / "base" / "Custom_OpenClash_Rules" / "manifest.sha256"
    entries = []
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            relative = path.relative_to(destination.parent).as_posix()
            entries.append(f"{sha256(path)}  {relative}")
    manifest.write_text("\n".join(entries) + "\n", encoding="ascii")
    print(f"synced {len(entries)} files to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
