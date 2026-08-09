#!/usr/bin/env python3
"""Emit the unchanged Linux matrix and image tags used by GitHub Actions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


AMD64 = {
    "arch": "amd64",
    "runner": "ubuntu-latest",
    "dockerfile": "./Dockerfile",
    "builder_platform": "linux/amd64",
    "image_platform": "linux/amd64",
    "builder_tag": "subconverter-temp:amd64-builder",
    "threads": "16",
    "cache_scope": "subconverter-alpine",
    "extract_mode": "shared",
    "extract_generated": "true",
    "bridge_budget": "bridge-linux-amd64",
    "openwrt_arches": "x86_64",
    "qemu_platforms": "",
}
ARM64 = {
    "arch": "arm64",
    "runner": "ubuntu-24.04-arm",
    "dockerfile": "./Dockerfile",
    "builder_platform": "linux/arm64",
    "image_platform": "linux/arm64",
    "builder_tag": "subconverter-temp:arm64-builder",
    "threads": "4",
    "cache_scope": "subconverter-alpine-arm64",
    "extract_mode": "shared",
    "extract_generated": "false",
    "bridge_budget": "bridge-linux-arm64",
    "openwrt_arches": "aarch64_generic,aarch64_cortex-a53,aarch64_cortex-a72",
    "qemu_platforms": "",
}
ARMV7 = {
    "arch": "armv7",
    "runner": "ubuntu-latest",
    "dockerfile": "./docker/Dockerfile.armv7-cross",
    "builder_platform": "linux/amd64",
    "image_platform": "linux/arm/v7",
    "builder_tag": "subconverter-temp:armv7-builder",
    "threads": "2",
    "cache_scope": "subconverter-armv7-cross",
    "extract_mode": "root",
    "extract_generated": "false",
    "bridge_budget": "bridge-linux-armv7",
    "openwrt_arches": (
        "arm_cortex-a5_vfpv4,arm_cortex-a7,arm_cortex-a7_vfpv4,"
        "arm_cortex-a7_neon-vfpv4,arm_cortex-a8_vfpv3,arm_cortex-a9,"
        "arm_cortex-a9_neon,arm_cortex-a9_vfpv3-d16,arm_cortex-a15_neon-vfpv4"
    ),
    "qemu_platforms": "arm",
}
MODES = {"dev", "pr", "master", "release"}


def linux_matrix(mode: str) -> dict[str, list[dict[str, str]]]:
    if mode not in MODES:
        raise ValueError(f"unsupported build mode: {mode}")
    include = [AMD64]
    if mode in {"master", "release"}:
        include.extend((ARM64, ARMV7))
    return {"include": include}


def image_tags(mode: str, version: str) -> list[str]:
    if mode not in MODES:
        raise ValueError(f"unsupported build mode: {mode}")
    if mode == "release":
        tag = version
    elif mode == "dev":
        tag = "dev"
    else:
        return []
    return [
        f"aethersailor/subconverter-extended:{tag}",
        f"ghcr.io/aethersailor/subconverter-extended:{tag}",
    ]


def append_multiline(path: Path, key: str, value: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{key}<<EOF\n")
        if value:
            handle.write(f"{value}\n")
        handle.write("EOF\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    matrix_parser = subparsers.add_parser("matrix")
    matrix_parser.add_argument("--mode", required=True, choices=sorted(MODES))
    matrix_parser.add_argument("--github-output", type=Path, required=True)

    tags_parser = subparsers.add_parser("tags")
    tags_parser.add_argument("--mode", required=True, choices=sorted(MODES))
    tags_parser.add_argument("--version", required=True)
    tags_parser.add_argument("--github-output", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "matrix":
        value = json.dumps(linux_matrix(args.mode), separators=(",", ":"))
        append_multiline(args.github_output, "matrix", value)
    else:
        append_multiline(
            args.github_output,
            "tags",
            "\n".join(image_tags(args.mode, args.version)),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
