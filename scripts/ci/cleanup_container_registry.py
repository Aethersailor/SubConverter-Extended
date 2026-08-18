#!/usr/bin/env python3
"""Remove transient container tags without breaking published images.

The GHCR package API exposes manifests as package versions.  A version may be
untagged while still being a required child of a multi-platform image, so this
script computes the complete manifest graph reachable from latest, dev and
vX.Y.Z before deleting anything.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


ALLOWED_TAG_RE = re.compile(r"^(?:latest|dev|v[0-9]+\.[0-9]+\.[0-9]+)$")
TRANSIENT_TAG_RE = re.compile(r"^(?:ci-|buildcache-)")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class CleanupError(RuntimeError):
    pass


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    expected: tuple[int, ...] = (200,),
    retries: int = 5,
) -> tuple[int, Any, bytes]:
    body = None
    request_headers = {"User-Agent": "subconverter-registry-cleanup/1"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    for attempt in range(retries):
        request = Request(url, data=body, headers=request_headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                status = response.status
                response_body = response.read()
                if status not in expected:
                    raise CleanupError(f"unexpected HTTP {status}")
                return status, response.headers, response_body
        except HTTPError as exc:
            if exc.code in expected:
                return exc.code, exc.headers, exc.read()
            retry_after = exc.headers.get("Retry-After")
            retryable = exc.code in {429, 500, 502, 503, 504} or (
                exc.code == 403 and retry_after is not None
            )
            if retryable and attempt + 1 < retries:
                delay = float(retry_after) if retry_after else min(2**attempt, 15)
                time.sleep(delay)
                continue
            location = urlparse(url)
            raise CleanupError(
                f"{method} {location.netloc}{location.path} failed with HTTP {exc.code}"
            ) from exc
        except URLError as exc:
            if attempt + 1 < retries:
                time.sleep(min(2**attempt, 15))
                continue
            raise CleanupError(f"request failed for {urlparse(url).netloc}") from exc
    raise AssertionError("unreachable")


def _json_request(*args: Any, **kwargs: Any) -> tuple[Any, Any]:
    _status, headers, body = _request(*args, **kwargs)
    try:
        return json.loads(body), headers
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CleanupError("registry API returned invalid JSON") from exc


def _github_headers(token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def list_github_versions(owner: str, package: str, token: str) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    for page in range(1, 100):
        url = (
            f"https://api.github.com/users/{quote(owner)}/packages/container/"
            f"{quote(package)}/versions?per_page=100&page={page}"
        )
        data, _headers = _json_request("GET", url, headers=_github_headers(token))
        if not isinstance(data, list):
            raise CleanupError("GitHub Packages returned an invalid version list")
        versions.extend(data)
        if len(data) < 100:
            return versions
    raise CleanupError("GitHub Packages pagination exceeded the safety limit")


def version_tags(version: dict[str, Any]) -> list[str]:
    tags = version.get("metadata", {}).get("container", {}).get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise CleanupError("GitHub Packages returned invalid container tags")
    return tags


def version_digest(version: dict[str, Any]) -> str:
    digest = version.get("name", "")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise CleanupError("GitHub Packages returned a non-digest container version")
    return digest


def delete_github_versions(
    owner: str, package: str, token: str, versions: list[dict[str, Any]]
) -> None:
    if not token:
        raise CleanupError("GITHUB_TOKEN or GH_TOKEN is required for deletion")
    total = len(versions)
    for index, version in enumerate(versions, 1):
        version_id = version.get("id")
        if not isinstance(version_id, int) or version_id <= 0:
            raise CleanupError("GitHub Packages returned an invalid version ID")
        url = (
            f"https://api.github.com/users/{quote(owner)}/packages/container/"
            f"{quote(package)}/versions/{version_id}"
        )
        _request(
            "DELETE",
            url,
            headers=_github_headers(token),
            expected=(204, 404),
        )
        if index % 100 == 0 or index == total:
            print(f"Deleted {index}/{total} GHCR package versions.")
        time.sleep(0.05)


def dockerhub_tags(namespace: str, repository: str) -> dict[str, str]:
    url = (
        "https://hub.docker.com/v2/namespaces/"
        f"{quote(namespace)}/repositories/{quote(repository)}/tags?page_size=100"
    )
    result: dict[str, str] = {}
    for _page in range(100):
        data, _headers = _json_request("GET", url)
        rows = data.get("results", []) if isinstance(data, dict) else []
        if not isinstance(rows, list):
            raise CleanupError("Docker Hub returned an invalid tag list")
        for row in rows:
            name = row.get("name", "")
            digest = row.get("digest", "")
            if not isinstance(name, str) or not isinstance(digest, str):
                raise CleanupError("Docker Hub returned invalid tag metadata")
            result[name] = digest
        next_url = data.get("next")
        if not next_url:
            return result
        if not isinstance(next_url, str) or urlparse(next_url).netloc != "hub.docker.com":
            raise CleanupError("Docker Hub returned an unsafe pagination URL")
        url = next_url
    raise CleanupError("Docker Hub pagination exceeded the safety limit")


def dockerhub_token(username: str, secret: str) -> str:
    if not username or not secret:
        raise CleanupError("Docker Hub credentials are required for deletion")
    data, _headers = _json_request(
        "POST",
        "https://hub.docker.com/v2/auth/token",
        payload={"identifier": username, "secret": secret},
    )
    token = data.get("access_token", "") if isinstance(data, dict) else ""
    if not isinstance(token, str) or not token:
        raise CleanupError("Docker Hub did not issue an access token")
    return token


def delete_dockerhub_tags(
    namespace: str, repository: str, token: str, tags: list[str]
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    for tag in tags:
        url = (
            "https://hub.docker.com/v2/namespaces/"
            f"{quote(namespace)}/repositories/{quote(repository)}/tags/{quote(tag)}"
        )
        _request("DELETE", url, headers=headers, expected=(204, 404))
        print(f"Deleted Docker Hub tag: {tag}")


class GhcrManifestClient:
    def __init__(self, namespace: str, repository: str) -> None:
        self.namespace = namespace.lower()
        self.repository = repository
        scope = f"repository:{self.namespace}/{self.repository}:pull"
        url = "https://ghcr.io/token?" + urlencode(
            {"service": "ghcr.io", "scope": scope}
        )
        data, _headers = _json_request("GET", url)
        token = data.get("token", "") if isinstance(data, dict) else ""
        if not isinstance(token, str) or not token:
            raise CleanupError("GHCR did not issue a pull token")
        self.headers = {"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT}

    @property
    def image(self) -> str:
        return f"ghcr.io/{self.namespace}/{self.repository}"

    def manifest(self, reference: str) -> tuple[str, dict[str, Any]]:
        encoded = quote(reference, safe=":")
        url = (
            f"https://ghcr.io/v2/{self.namespace}/{self.repository}/manifests/"
            f"{encoded}"
        )
        data, headers = _json_request("GET", url, headers=self.headers)
        digest = headers.get("Docker-Content-Digest", "")
        if not DIGEST_RE.fullmatch(digest) or not isinstance(data, dict):
            raise CleanupError(f"GHCR returned invalid manifest metadata for {reference}")
        return digest, data

    def reachable(self, allowed_tags: list[str]) -> set[str]:
        reachable: set[str] = set()
        queue = list(allowed_tags)
        while queue:
            reference = queue.pop()
            if DIGEST_RE.fullmatch(reference) and reference in reachable:
                continue
            digest, manifest = self.manifest(reference)
            if digest in reachable:
                continue
            reachable.add(digest)
            children = manifest.get("manifests", [])
            if children is None:
                children = []
            if not isinstance(children, list):
                raise CleanupError("GHCR returned an invalid manifest index")
            for child in children:
                child_digest = child.get("digest", "") if isinstance(child, dict) else ""
                if not isinstance(child_digest, str) or not DIGEST_RE.fullmatch(
                    child_digest
                ):
                    raise CleanupError("GHCR returned an invalid child digest")
                if child_digest not in reachable:
                    queue.append(child_digest)
        return reachable


def all_package_tags(versions: list[dict[str, Any]]) -> set[str]:
    return {tag for version in versions for tag in version_tags(version)}


def allowed_snapshot(client: GhcrManifestClient, tags: set[str]) -> dict[str, str]:
    return {tag: client.manifest(tag)[0] for tag in sorted(tags) if ALLOWED_TAG_RE.fullmatch(tag)}


def ensure_known_tags(tags: set[str]) -> None:
    unknown = sorted(
        tag
        for tag in tags
        if not ALLOWED_TAG_RE.fullmatch(tag) and not TRANSIENT_TAG_RE.match(tag)
    )
    if unknown:
        raise CleanupError(f"refusing to delete around unknown tags: {', '.join(unknown)}")


def tag_versions(versions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for version in versions:
        for tag in version_tags(version):
            if tag in result:
                raise CleanupError(f"tag {tag} appears on more than one GHCR version")
            result[tag] = version
    return result


def detach_reachable_transient_tags(
    client: GhcrManifestClient,
    versions: list[dict[str, Any]],
    reachable: set[str],
    target_tags: set[str],
    *,
    apply: bool,
) -> list[str]:
    by_tag = tag_versions(versions)
    detach: list[str] = []
    for tag in sorted(target_tags):
        version = by_tag.get(tag)
        if version is None:
            continue
        tags = version_tags(version)
        digest = version_digest(version)
        if digest in reachable or any(item not in target_tags for item in tags):
            detach.append(tag)

    if not apply:
        return detach

    for tag in detach:
        before, _manifest = client.manifest(tag)
        source = f"{client.image}:{tag}"
        dry_run = subprocess.run(
            ["docker", "buildx", "imagetools", "create", "--dry-run", source],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        try:
            preview = json.loads(dry_run.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CleanupError(
                f"could not inspect transient GHCR tag {tag} for detachment"
            ) from exc
        descriptors = preview.get("manifests", []) if isinstance(preview, dict) else []
        if dry_run.returncode != 0 or not isinstance(descriptors, list) or not descriptors:
            raise CleanupError(f"could not inspect transient GHCR tag {tag}")

        nonce = time.time_ns()
        with tempfile.TemporaryDirectory(prefix="registry-cleanup-") as directory:
            command = [
                "docker",
                "buildx",
                "imagetools",
                "create",
                "--tag",
                source,
            ]
            for index, descriptor in enumerate(descriptors):
                if not isinstance(descriptor, dict):
                    raise CleanupError("imagetools returned an invalid descriptor")
                platform = descriptor.get("platform")
                if platform is None:
                    platform = {}
                    descriptor["platform"] = platform
                if not isinstance(platform, dict):
                    raise CleanupError("imagetools returned an invalid platform")
                platform["os.version"] = f"registry-cleanup-{nonce}-{index}"
                path = os.path.join(directory, f"descriptor-{index}.json")
                with open(path, "w", encoding="utf-8", newline="\n") as handle:
                    json.dump(descriptor, handle, sort_keys=True, separators=(",", ":"))
                    handle.write("\n")
                command.extend(("--file", path))

            completed = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if completed.returncode != 0:
                raise CleanupError(f"could not detach transient GHCR tag {tag}")
        for _attempt in range(12):
            time.sleep(2)
            after, _manifest = client.manifest(tag)
            if after != before and after not in reachable:
                print(f"Detached transient GHCR tag: {tag}")
                break
        else:
            raise CleanupError(f"GHCR tag {tag} did not move to a disposable manifest")
    return detach


def wait_for_package_tag_digests(
    owner: str,
    package: str,
    token: str,
    client: GhcrManifestClient,
    tags: list[str],
    target_tags: set[str],
) -> list[dict[str, Any]]:
    for _attempt in range(30):
        versions = list_github_versions(owner, package, token)
        by_tag = tag_versions(versions)
        if all(
            tag in by_tag
            and version_digest(by_tag[tag]) == client.manifest(tag)[0]
            and all(item in target_tags for item in version_tags(by_tag[tag]))
            for tag in tags
        ):
            return versions
        time.sleep(2)
    raise CleanupError("GitHub Packages did not converge after transient tag detachment")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-owner", default="Aethersailor")
    parser.add_argument("--repository", default="subconverter-extended")
    parser.add_argument("--dockerhub-namespace", default="aethersailor")
    parser.add_argument("--current-tag", action="append", default=[])
    parser.add_argument("--current-prefix", action="append", default=[])
    parser.add_argument("--prune-orphans", action="store_true")
    parser.add_argument("--prune-all", action="store_true")
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = set(args.current_tag)
    prefixes = set(args.current_prefix)
    if args.prune_all and (requested or prefixes):
        raise CleanupError("--prune-all cannot be combined with current tag selectors")
    if not args.prune_all and not requested and not prefixes:
        raise CleanupError("provide a current tag selector or --prune-all")
    if any(not TRANSIENT_TAG_RE.match(tag) for tag in requested):
        raise CleanupError("--current-tag accepts only ci-* or buildcache-* tags")
    if any(not TRANSIENT_TAG_RE.match(prefix) for prefix in prefixes):
        raise CleanupError("--current-prefix accepts only ci-* or buildcache-* prefixes")

    def selected(tag: str) -> bool:
        return tag in requested or any(tag.startswith(prefix) for prefix in prefixes)

    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
    docker_username = os.environ.get("DOCKERHUB_USERNAME", "")
    docker_secret = os.environ.get("DOCKERHUB_TOKEN", "")

    docker_before = dockerhub_tags(args.dockerhub_namespace, args.repository)
    ensure_known_tags(set(docker_before))
    docker_targets = {
        tag
        for tag in docker_before
        if TRANSIENT_TAG_RE.match(tag) and (args.prune_all or selected(tag))
    }
    docker_allowed_before = {
        tag: digest for tag, digest in docker_before.items() if ALLOWED_TAG_RE.fullmatch(tag)
    }

    versions = list_github_versions(args.github_owner, args.repository, github_token)
    package_tags = all_package_tags(versions)
    ensure_known_tags(package_tags)
    allowed_tags = sorted(tag for tag in package_tags if ALLOWED_TAG_RE.fullmatch(tag))
    client = GhcrManifestClient(args.github_owner, args.repository)
    ghcr_allowed_before = allowed_snapshot(client, package_tags)
    ghcr_targets = {
        tag
        for tag in package_tags
        if TRANSIENT_TAG_RE.match(tag) and (args.prune_all or selected(tag))
    }
    protected_roots = sorted(
        tag
        for tag in package_tags
        if ALLOWED_TAG_RE.fullmatch(tag)
        or (TRANSIENT_TAG_RE.match(tag) and tag not in ghcr_targets)
    )
    reachable = client.reachable(protected_roots)
    detach = detach_reachable_transient_tags(
        client, versions, reachable, ghcr_targets, apply=args.apply
    )

    untagged_orphans = [
        version
        for version in versions
        if not version_tags(version) and version_digest(version) not in reachable
    ]
    print(
        "Registry cleanup plan: "
        f"Docker Hub tags={len(docker_targets)}, "
        f"GHCR tags={len(ghcr_targets)}, detach={len(detach)}, "
        f"unreachable untagged GHCR versions="
        f"{len(untagged_orphans)}"
        f"{' (report only)' if not (args.prune_all or args.prune_orphans) else ''}."
    )
    if not args.apply:
        return 0

    hub_token = dockerhub_token(docker_username, docker_secret)
    delete_dockerhub_tags(
        args.dockerhub_namespace, args.repository, hub_token, sorted(docker_targets)
    )

    if detach:
        versions = wait_for_package_tag_digests(
            args.github_owner,
            args.repository,
            github_token,
            client,
            detach,
            ghcr_targets,
        )
    else:
        versions = list_github_versions(args.github_owner, args.repository, github_token)

    reachable = client.reachable(allowed_tags)
    tagged_delete: list[dict[str, Any]] = []
    for version in versions:
        tags = version_tags(version)
        selected = [tag for tag in tags if tag in ghcr_targets]
        if not selected:
            continue
        if any(ALLOWED_TAG_RE.fullmatch(tag) for tag in tags):
            raise CleanupError("refusing to delete a GHCR version with an allowed tag")
        if any(not TRANSIENT_TAG_RE.match(tag) for tag in tags):
            raise CleanupError("refusing to delete a GHCR version with an unknown tag")
        if version_digest(version) in reachable:
            raise CleanupError("refusing to delete a GHCR version reachable from an allowed tag")
        tagged_delete.append(version)
    delete_github_versions(
        args.github_owner, args.repository, github_token, tagged_delete
    )

    if args.prune_all or args.prune_orphans:
        versions = list_github_versions(args.github_owner, args.repository, github_token)
        tags_for_prune = all_package_tags(versions)
        protected_roots = sorted(
            tag
            for tag in tags_for_prune
            if ALLOWED_TAG_RE.fullmatch(tag) or TRANSIENT_TAG_RE.match(tag)
        )
        reachable = client.reachable(protected_roots)
        orphan_delete = [
            version
            for version in versions
            if not version_tags(version) and version_digest(version) not in reachable
        ]
        delete_github_versions(
            args.github_owner, args.repository, github_token, orphan_delete
        )

    docker_after = dockerhub_tags(args.dockerhub_namespace, args.repository)
    remaining_docker = docker_targets.intersection(docker_after)
    if remaining_docker:
        raise CleanupError("transient Docker Hub tags remain after cleanup")
    docker_allowed_after = {
        tag: digest for tag, digest in docker_after.items() if ALLOWED_TAG_RE.fullmatch(tag)
    }
    if docker_allowed_after != docker_allowed_before:
        raise CleanupError("allowed Docker Hub tags changed during cleanup")

    versions_after = list_github_versions(args.github_owner, args.repository, github_token)
    tags_after = all_package_tags(versions_after)
    remaining_ghcr = ghcr_targets.intersection(tags_after)
    if remaining_ghcr:
        raise CleanupError("transient GHCR tags remain after cleanup")
    if allowed_snapshot(client, tags_after) != ghcr_allowed_before:
        raise CleanupError("allowed GHCR tags changed during cleanup")
    if args.prune_all or args.prune_orphans:
        protected_roots = sorted(
            tag
            for tag in tags_after
            if ALLOWED_TAG_RE.fullmatch(tag) or TRANSIENT_TAG_RE.match(tag)
        )
        reachable_after = client.reachable(
            protected_roots
        )
        leftovers = [
            version
            for version in versions_after
            if not version_tags(version) and version_digest(version) not in reachable_after
        ]
        if leftovers:
            raise CleanupError("unreachable untagged GHCR versions remain after cleanup")

    print("Registry cleanup completed without changing latest, dev or release tags.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CleanupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
