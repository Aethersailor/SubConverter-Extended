#!/usr/bin/env python3

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from custom_openclash_rules_policy import (
    ALLOWED_DIRECTORIES,
    SPARSE_CHECKOUT_DIRECTORIES,
)
from verify_custom_openclash_rules_bundle import verify_bundle

UPSTREAM_REPOSITORY = "https://github.com/Aethersailor/Custom_OpenClash_Rules.git"
UPSTREAM_BRANCH = "main"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as error:
        raise SystemExit("git is required to fetch Custom_OpenClash_Rules") from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            f"failed to fetch Custom_OpenClash_Rules with git (exit {error.returncode})"
        ) from error
    return result.stdout.strip() if capture else ""


@contextmanager
def upstream_checkout(ref: str):
    with tempfile.TemporaryDirectory(prefix="custom-openclash-rules-") as temporary:
        checkout = Path(temporary) / "repository"
        run_git("init", "--quiet", str(checkout))
        run_git("config", "core.autocrlf", "false", cwd=checkout)
        run_git("config", "core.eol", "lf", cwd=checkout)
        run_git("remote", "add", "origin", UPSTREAM_REPOSITORY, cwd=checkout)
        run_git("sparse-checkout", "init", "--cone", cwd=checkout)
        run_git(
            "sparse-checkout",
            "set",
            *SPARSE_CHECKOUT_DIRECTORIES,
            cwd=checkout,
        )
        run_git("fetch", "--quiet", "--depth=1", "origin", ref, cwd=checkout)
        run_git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=checkout)
        revision = run_git("rev-parse", "HEAD", cwd=checkout, capture=True)
        yield checkout, revision


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False


def sync_assets(source: Path, repository: Path) -> dict[str, int]:
    bundle_root = repository / "base" / "Custom_OpenClash_Rules"
    destination = bundle_root / "main"
    if bundle_root.exists():
        shutil.rmtree(bundle_root)

    counts = {directory: 0 for directory in ALLOWED_DIRECTORIES}
    copied: list[Path] = []
    for directory in ALLOWED_DIRECTORIES:
        source_dir = source / Path(*directory.split("/"))
        destination_dir = destination / Path(*directory.split("/"))
        destination_dir.mkdir(parents=True, exist_ok=True)
        if not source_dir.exists():
            print(f"warning: allowed COCR directory is missing: {directory}")
            continue
        if source_dir.is_symlink() or not source_dir.is_dir():
            print(f"warning: allowed COCR path is not a safe directory: {directory}")
            continue
        for entry in sorted(source_dir.iterdir(), key=lambda item: item.name):
            if (
                entry.name.casefold() == "readme.md"
                or entry.is_symlink()
                or not _is_regular_file(entry)
            ):
                continue
            target = destination_dir / entry.name
            shutil.copyfile(entry, target)
            os.chmod(target, stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode))
            copied.append(target)
            counts[directory] += 1

    manifest = bundle_root / "manifest.sha256"
    entries = [
        f"{sha256(path)}  {path.relative_to(destination.parent).as_posix()}"
        for path in sorted(copied, key=lambda item: item.relative_to(destination).as_posix())
    ]
    if not entries:
        raise SystemExit("Custom_OpenClash_Rules checkout did not contain publishable files")
    manifest.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
    verified_counts = verify_bundle(bundle_root)
    if counts != verified_counts:
        raise SystemExit("COCR bundle verifier count mismatch after synchronization")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch the current Custom_OpenClash_Rules snapshot and generate the "
            "policy-driven runtime bundle."
        )
    )
    parser.add_argument(
        "--ref",
        default=UPSTREAM_BRANCH,
        help=(
            "Upstream ref selected for this build. CI resolves the latest main "
            "revision once and passes its SHA to every build job."
        ),
    )
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    with upstream_checkout(args.ref) as (source, revision):
        counts = sync_assets(source, repository)

    print(f"COCR revision: {revision}")
    for directory in ALLOWED_DIRECTORIES:
        print(f"{directory}: {counts[directory]}")
    print(f"total: {sum(counts.values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
