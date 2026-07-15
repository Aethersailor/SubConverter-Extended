#!/usr/bin/env python3
"""Resolve, validate, and export reproducible CI dependency snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = ROOT / "scripts" / "ci" / "dependencies.lock.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

GIT_DEPENDENCIES = {
    "custom_openclash_rules": {
        "repository": "https://github.com/Aethersailor/Custom_OpenClash_Rules.git",
        "ref": "refs/heads/main",
    },
    "mihomo": {
        "repository": "https://github.com/MetaCubeX/mihomo.git",
        "ref": "refs/heads/Meta",
    },
    "quickjspp": {
        "repository": "https://github.com/ftk/quickjspp.git",
        "ref": "HEAD",
    },
    "libcron": {
        "repository": "https://github.com/PerMalmberg/libcron.git",
        "ref": "HEAD",
    },
    "toml11": {
        "repository": "https://github.com/ToruNiina/toml11.git",
        "ref": "HEAD",
    },
    "cpp_httplib": {
        "repository": "https://github.com/yhirose/cpp-httplib.git",
        "ref": "HEAD",
    },
    "nlohmann_json": {
        "repository": "https://github.com/nlohmann/json.git",
        "ref": "latest-semver-tag",
    },
    "inja": {
        "repository": "https://github.com/pantor/inja.git",
        "ref": "HEAD",
    },
    "jpcre2": {
        "repository": "https://github.com/jpcre2/jpcre2.git",
        "ref": "HEAD",
    },
}

IMAGE_DEPENDENCIES = {
    "golang": "mirror.gcr.io/library/golang:latest",
    "debian_builder": "mirror.gcr.io/library/debian:latest",
    "alpine_runtime": "mirror.gcr.io/library/alpine:latest",
    "debian_trixie": "mirror.gcr.io/library/debian:trixie",
    "debian_trixie_slim": "mirror.gcr.io/library/debian:trixie-slim",
}

EXPORTS = {
    "CUSTOM_OPENCLASH_RULES_REVISION": ("git", "custom_openclash_rules", "revision"),
    "MIHOMO_REF": ("git", "mihomo", "revision"),
    "QUICKJSPP_REF": ("git", "quickjspp", "revision"),
    "LIBCRON_REF": ("git", "libcron", "revision"),
    "TOML11_REF": ("git", "toml11", "revision"),
    "CPP_HTTPLIB_REF": ("git", "cpp_httplib", "revision"),
    "NLOHMANN_JSON_REF": ("git", "nlohmann_json", "revision"),
    "INJA_REF": ("git", "inja", "revision"),
    "JPCRE2_REF": ("git", "jpcre2", "revision"),
    "GO_IMAGE": ("images", "golang", "pinned"),
    "DEBIAN_IMAGE": ("images", "debian_builder", "pinned"),
    "ALPINE_IMAGE": ("images", "alpine_runtime", "pinned"),
    "DEBIAN_TRIXIE_IMAGE": ("images", "debian_trixie", "pinned"),
    "DEBIAN_TRIXIE_SLIM_IMAGE": ("images", "debian_trixie_slim", "pinned"),
}


def resolve_git(repository: str, ref: str) -> str:
    result = subprocess.run(
        ["git", "ls-remote", repository, ref],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    matches = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
    if len(matches) != 1 or not SHA_RE.fullmatch(matches[0]):
        raise RuntimeError(f"unable to resolve one exact revision for {repository} {ref}")
    return matches[0]


def resolve_latest_semver_tag(repository: str) -> tuple[str, str]:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", repository, "refs/tags/v*"],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    candidates: dict[tuple[int, int, int], dict[str, str]] = {}
    pattern = re.compile(r"^refs/tags/v(\d+)\.(\d+)\.(\d+)(\^\{\})?$")
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        revision, ref = line.split(maxsplit=1)
        match = pattern.fullmatch(ref)
        if not match or not SHA_RE.fullmatch(revision):
            continue
        version = tuple(int(part) for part in match.groups()[:3])
        values = candidates.setdefault(version, {})
        values["peeled" if match.group(4) else "direct"] = revision
    if not candidates:
        raise RuntimeError(f"unable to resolve a stable semantic version tag for {repository}")
    version = max(candidates)
    revisions = candidates[version]
    revision = revisions.get("peeled") or revisions.get("direct")
    if not revision:
        raise RuntimeError(f"latest semantic version tag has no revision for {repository}")
    return revision, f"refs/tags/v{version[0]}.{version[1]}.{version[2]}"


def image_manifest_url(source: str) -> str:
    registry, remainder = source.split("/", 1)
    repository, tag = remainder.rsplit(":", 1)
    return f"https://{registry}/v2/{repository}/manifests/{tag}"


def resolve_image(source: str) -> str:
    request = urllib.request.Request(
        image_manifest_url(source),
        method="HEAD",
        headers={"Accept": MANIFEST_ACCEPT, "User-Agent": "SubConverter-Extended-CI"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        digest = response.headers.get("Docker-Content-Digest", "").lower()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"registry did not return a valid manifest digest for {source}")
    return f"{source.rsplit(':', 1)[0]}@{digest}"


def refresh(path: Path) -> dict[str, object]:
    snapshot: dict[str, object] = {"schema": 1, "git": {}, "images": {}}
    git_section = snapshot["git"]
    image_section = snapshot["images"]
    assert isinstance(git_section, dict)
    assert isinstance(image_section, dict)

    for name, dependency in GIT_DEPENDENCIES.items():
        print(f"Resolving {name} ({dependency['ref']})...", file=sys.stderr)
        entry = dict(dependency)
        if dependency["ref"] == "latest-semver-tag":
            revision, selected_ref = resolve_latest_semver_tag(dependency["repository"])
            entry["selected_ref"] = selected_ref
            entry["revision"] = revision
        else:
            entry["revision"] = resolve_git(dependency["repository"], dependency["ref"])
        git_section[name] = entry

    for name, source in IMAGE_DEPENDENCIES.items():
        print(f"Resolving {name} ({source})...", file=sys.stderr)
        image_section[name] = {"source": source, "pinned": resolve_image(source)}

    validate(snapshot)
    rendered = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, path)
    return snapshot


def load(path: Path) -> dict[str, object]:
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"unable to read dependency snapshot {path}: {error}") from error
    if not isinstance(snapshot, dict):
        raise RuntimeError("dependency snapshot root must be an object")
    return snapshot


def validate(snapshot: dict[str, object]) -> None:
    if snapshot.get("schema") != 1:
        raise RuntimeError("dependency snapshot schema must be 1")
    git_section = snapshot.get("git")
    image_section = snapshot.get("images")
    if not isinstance(git_section, dict) or set(git_section) != set(GIT_DEPENDENCIES):
        raise RuntimeError("dependency snapshot Git entries do not match the required set")
    if not isinstance(image_section, dict) or set(image_section) != set(IMAGE_DEPENDENCIES):
        raise RuntimeError("dependency snapshot image entries do not match the required set")

    for name, expected in GIT_DEPENDENCIES.items():
        actual = git_section.get(name)
        if not isinstance(actual, dict):
            raise RuntimeError(f"Git dependency {name} must be an object")
        if actual.get("repository") != expected["repository"] or actual.get("ref") != expected["ref"]:
            raise RuntimeError(f"Git dependency metadata changed unexpectedly for {name}")
        if not SHA_RE.fullmatch(str(actual.get("revision", ""))):
            raise RuntimeError(f"Git dependency {name} is not pinned to a full commit")
        if expected["ref"] == "latest-semver-tag" and not re.fullmatch(
            r"refs/tags/v\d+\.\d+\.\d+", str(actual.get("selected_ref", ""))
        ):
            raise RuntimeError(f"Git dependency {name} does not record its selected release tag")

    for name, source in IMAGE_DEPENDENCIES.items():
        actual = image_section.get(name)
        if not isinstance(actual, dict) or actual.get("source") != source:
            raise RuntimeError(f"image dependency metadata changed unexpectedly for {name}")
        pinned = str(actual.get("pinned", ""))
        expected_prefix = f"{source.rsplit(':', 1)[0]}@"
        if not pinned.startswith(expected_prefix) or not DIGEST_RE.fullmatch(pinned.split("@", 1)[1]):
            raise RuntimeError(f"image dependency {name} is not pinned to a sha256 digest")


def exported_values(snapshot: dict[str, object], path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for variable, keys in EXPORTS.items():
        value: object = snapshot
        for key in keys:
            if not isinstance(value, dict):
                raise RuntimeError(f"unable to export {variable}")
            value = value[key]
        values[variable] = str(value)
    values["DEPENDENCY_SNAPSHOT_SHA"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def append_assignments(path: Path, values: dict[str, str], lower_names: bool = False) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for name, value in values.items():
            handle.write(f"{name.lower() if lower_names else name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("refresh", "check", "emit"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()

    try:
        snapshot = refresh(args.lock) if args.command == "refresh" else load(args.lock)
        validate(snapshot)
        if args.command == "emit":
            values = exported_values(snapshot, args.lock)
            if args.github_output:
                append_assignments(args.github_output, values, lower_names=True)
            if args.github_env:
                append_assignments(args.github_env, values)
            if not args.github_output and not args.github_env:
                for name, value in values.items():
                    print(f"{name}={value}")
    except (KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"dependency snapshot error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
