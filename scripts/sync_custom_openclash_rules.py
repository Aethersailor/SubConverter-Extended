#!/usr/bin/env python3

import argparse
import hashlib
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


EXCLUDED_DIRECTORIES = {"archived", "test"}
EXCLUDED_FILES = {"readme.md"}
UPSTREAM_REPOSITORY = "https://github.com/Aethersailor/Custom_OpenClash_Rules.git"
UPSTREAM_BRANCH = "main"


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
        run_git("sparse-checkout", "set", "cfg", "rule", cwd=checkout)
        run_git("fetch", "--quiet", "--depth=1", "origin", ref, cwd=checkout)
        run_git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=checkout)
        revision = run_git("rev-parse", "HEAD", cwd=checkout, capture=True)
        yield checkout, revision


def sync_assets(source: Path, repository: Path) -> int:
    for name in ("cfg", "rule"):
        source_dir = source / name
        if not source_dir.is_dir():
            raise SystemExit(f"missing source directory: {source_dir}")

    bundle_root = repository / "base" / "Custom_OpenClash_Rules"
    destination = bundle_root / "main"
    if bundle_root.exists():
        shutil.rmtree(bundle_root)

    for name in ("cfg", "rule"):
        shutil.copytree(
            source / name,
            destination / name,
            ignore=ignore_unpublished,
        )

    manifest = bundle_root / "manifest.sha256"
    entries = []
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            relative = path.relative_to(destination.parent).as_posix()
            entries.append(f"{sha256(path)}  {relative}")
    if not entries:
        raise SystemExit("Custom_OpenClash_Rules checkout did not contain publishable files")
    manifest.write_text("\n".join(entries) + "\n", encoding="ascii")
    print(f"synced {len(entries)} files to {destination}")
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch the current Custom_OpenClash_Rules snapshot and generate the "
            "runtime cfg/rule bundle."
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
        sync_assets(source, repository)

    print(f"Custom_OpenClash_Rules revision: {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
