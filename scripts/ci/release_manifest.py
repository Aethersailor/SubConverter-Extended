#!/usr/bin/env python3
"""Create and verify the identity manifest for a formal release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LINUX_ARCHES = ("amd64", "arm64", "armv7")
OPENWRT_ARCHES = (
    "x86_64",
    "aarch64_generic",
    "aarch64_cortex-a53",
    "aarch64_cortex-a72",
    "arm_cortex-a5_vfpv4",
    "arm_cortex-a7",
    "arm_cortex-a7_vfpv4",
    "arm_cortex-a7_neon-vfpv4",
    "arm_cortex-a8_vfpv3",
    "arm_cortex-a9",
    "arm_cortex-a9_neon",
    "arm_cortex-a9_vfpv3-d16",
    "arm_cortex-a15_neon-vfpv4",
)


def expected_package_names(version: str) -> set[str]:
    return {
        *(f"SubConverter-Extended-{version}-linux-{arch}.tar.gz" for arch in LINUX_ARCHES),
        f"SubConverter-Extended-{version}-windows-amd64.zip",
        *(
            f"SubConverter-Extended-{version}-openwrt-{arch}.apk"
            for arch in OPENWRT_ARCHES
        ),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in files:
            raise ValueError(f"duplicate release asset name: {path.name}")
        files[path.name] = path
    return files


def create_manifest(
    *,
    root: Path,
    version: str,
    revision: str,
    build_date: str,
    dockerhub_digest: str,
    ghcr_digest: str,
) -> dict:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be an exact vX.Y.Z tag")
    if not SHA_RE.fullmatch(revision):
        raise ValueError("revision must be a full 40-character Git SHA")
    for name, digest in (
        ("Docker Hub", dockerhub_digest),
        ("GHCR", ghcr_digest),
    ):
        if not DIGEST_RE.fullmatch(digest):
            raise ValueError(f"{name} digest must be a sha256 manifest digest")
    if dockerhub_digest != ghcr_digest:
        raise ValueError("Docker Hub and GHCR must publish the same manifest digest")

    files = _unique_files(root)
    expected = expected_package_names(version)
    actual_packages = {
        name
        for name in files
        if name.endswith((".tar.gz", ".zip", ".apk"))
    }
    if actual_packages != expected:
        missing = sorted(expected - actual_packages)
        extra = sorted(actual_packages - expected)
        raise ValueError(f"release asset set mismatch; missing={missing}; extra={extra}")
    if "SHA256SUMS" not in files:
        raise ValueError("SHA256SUMS is missing")
    unexpected = set(files) - expected - {"SHA256SUMS", "RELEASE-MANIFEST.json"}
    if unexpected:
        raise ValueError(f"unexpected release assets: {sorted(unexpected)}")

    assets = [
        {
            "name": name,
            "sha256": _sha256(files[name]),
            "size": files[name].stat().st_size,
        }
        for name in sorted(expected | {"SHA256SUMS"})
    ]
    return {
        "schema": 1,
        "version": version,
        "tag": version,
        "revision": revision,
        "build_date": build_date,
        "assets": assets,
        "images": {
            "dockerhub": {
                "reference": f"aethersailor/subconverter-extended:{version}",
                "digest": dockerhub_digest,
                "revision": revision,
            },
            "ghcr": {
                "reference": f"ghcr.io/aethersailor/subconverter-extended:{version}",
                "digest": ghcr_digest,
                "revision": revision,
            },
        },
    }


def verify_manifest(*, root: Path, manifest: dict) -> None:
    files = _unique_files(root)
    for asset in manifest.get("assets", []):
        name = asset["name"]
        path = files.get(name)
        if path is None:
            raise ValueError(f"manifest asset is missing: {name}")
        if path.stat().st_size != asset["size"]:
            raise ValueError(f"asset size mismatch: {name}")
        if _sha256(path) != asset["sha256"]:
            raise ValueError(f"asset checksum mismatch: {name}")

    recreated = create_manifest(
        root=root,
        version=manifest["version"],
        revision=manifest["revision"],
        build_date=manifest["build_date"],
        dockerhub_digest=manifest["images"]["dockerhub"]["digest"],
        ghcr_digest=manifest["images"]["ghcr"]["digest"],
    )
    if recreated != manifest:
        raise ValueError("release manifest content is not canonical")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--revision", required=True)
    build.add_argument("--build-date", required=True)
    build.add_argument("--dockerhub-digest", required=True)
    build.add_argument("--ghcr-digest", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "build":
        manifest = create_manifest(
            root=args.root,
            version=args.version,
            revision=args.revision,
            build_date=args.build_date,
            dockerhub_digest=args.dockerhub_digest,
            ghcr_digest=args.ghcr_digest,
        )
        args.output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    else:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        verify_manifest(root=args.root, manifest=manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
