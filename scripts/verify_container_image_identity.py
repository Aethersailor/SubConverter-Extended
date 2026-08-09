#!/usr/bin/env python3
"""Verify image, fresh-container, and compiled runtime version identity."""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from typing import Any, Dict, Optional


OCI_VERSION = "org.opencontainers.image.version"
OCI_REVISION = "org.opencontainers.image.revision"
OCI_CREATED = "org.opencontainers.image.created"
COMPOSE_IMAGE = "com.docker.compose.image"


class IdentityError(RuntimeError):
    pass


def _labels(document: Dict[str, Any]) -> Dict[str, str]:
    labels = document.get("Config", {}).get("Labels") or {}
    return {str(key): str(value) for key, value in labels.items()}


def verify_documents(
    *,
    container: Dict[str, Any],
    image: Dict[str, Any],
    version_body: str,
    expected_version: Optional[str] = None,
    expected_revision: Optional[str] = None,
    expected_build_date: Optional[str] = None,
) -> Dict[str, str]:
    image_id = str(image.get("Id", ""))
    container_image_id = str(container.get("Image", ""))
    if not image_id or container_image_id != image_id:
        raise IdentityError(
            f"container image {container_image_id!r} does not match inspected image {image_id!r}"
        )

    image_labels = _labels(image)
    container_labels = _labels(container)
    expected = {
        OCI_VERSION: expected_version or image_labels.get(OCI_VERSION, ""),
        OCI_REVISION: expected_revision or image_labels.get(OCI_REVISION, ""),
        OCI_CREATED: expected_build_date or image_labels.get(OCI_CREATED, ""),
    }

    for key, value in expected.items():
        if not value:
            raise IdentityError(f"expected value for {key} is empty")
        if image_labels.get(key) != value:
            raise IdentityError(
                f"image label {key}={image_labels.get(key)!r}; expected {value!r}"
            )
        if container_labels.get(key) != value:
            raise IdentityError(
                f"container label {key}={container_labels.get(key)!r}; expected {value!r}"
            )

    compose_image = container_labels.get(COMPOSE_IMAGE)
    if compose_image and compose_image != image_id:
        raise IdentityError(
            f"container label {COMPOSE_IMAGE}={compose_image!r}; actual image is {image_id!r}"
        )

    expected_build_id = expected[OCI_REVISION][:7]
    expected_body = (
        f"SubConverter-Extended {expected[OCI_VERSION]}-"
        f"{expected_build_id} backend\n"
    )
    if version_body != expected_body:
        raise IdentityError(
            f"runtime /version returned {version_body!r}; expected {expected_body!r}"
        )

    return {
        "image_id": image_id,
        "version": expected[OCI_VERSION],
        "revision": expected[OCI_REVISION],
        "build_date": expected[OCI_CREATED],
    }


def _docker_inspect(kind: str, target: str) -> Dict[str, Any]:
    command = ["docker"]
    if kind == "image":
        command.append("image")
    command.extend(["inspect", target])
    output = subprocess.check_output(command, text=True, encoding="utf-8")
    documents = json.loads(output)
    if len(documents) != 1:
        raise IdentityError(f"docker {kind} inspect returned {len(documents)} records")
    return documents[0]


def _fetch_plain_version(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Origin": "https://identity-check.invalid",
            "User-Agent": "SubConverter-Extended-identity-check/1",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-build-date")
    args = parser.parse_args()

    container = _docker_inspect("container", args.container)
    image = _docker_inspect("image", str(container.get("Image", "")))
    identity = verify_documents(
        container=container,
        image=image,
        version_body=_fetch_plain_version(args.url),
        expected_version=args.expected_version,
        expected_revision=args.expected_revision,
        expected_build_date=args.expected_build_date,
    )
    print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except IdentityError as error:
        raise SystemExit(f"identity verification failed: {error}") from error
