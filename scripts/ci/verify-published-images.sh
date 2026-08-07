#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
if [ "$#" -ne 4 ]; then
  echo "usage: $0 MODE IMAGE_TAGS REVISION VERSION" >&2
  exit 2
fi
BUILD_MODE="$1"
IMAGE_TAGS="$2"
EXPECTED_REVISION="$3"
EXPECTED_VERSION="$4"

if [ "$BUILD_MODE" = "dev" ]; then
  PLATFORMS=("linux/amd64")
else
  PLATFORMS=("linux/amd64" "linux/arm64" "linux/arm/v7")
fi

DOCKERHUB_DIGEST=""
GHCR_DIGEST=""
for tag in $IMAGE_TAGS; do
  echo "Inspecting $tag"
  for attempt in $(seq 1 6); do
    if docker buildx imagetools inspect "$tag" > manifest.txt; then
      break
    fi
    if [ "$attempt" -eq 6 ]; then
      echo "Failed to inspect $tag"
      exit 1
    fi
    sleep 5
  done

  cat manifest.txt
  digest="$(awk '$1 == "Digest:" {print $2; exit}' manifest.txt)"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::Could not resolve the manifest digest for $tag."
    exit 1
  fi
  if [[ "$tag" == ghcr.io/* ]]; then
    GHCR_DIGEST="$digest"
    echo "ghcr_digest=$digest" >> "$GITHUB_OUTPUT"
  else
    DOCKERHUB_DIGEST="$digest"
    echo "dockerhub_digest=$digest" >> "$GITHUB_OUTPUT"
  fi

  for platform in "${PLATFORMS[@]}"; do
    if ! grep -Eq "Platform:[[:space:]]+${platform}$" manifest.txt; then
      echo "Missing platform ${platform} in ${tag}"
      exit 1
    fi
    docker pull --platform "$platform" "$tag"
    actual_revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$tag")"
    actual_version="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$tag")"
    test "$actual_revision" = "$EXPECTED_REVISION"
    test "$actual_version" = "$EXPECTED_VERSION"
  done
done

test -n "$DOCKERHUB_DIGEST"
test -n "$GHCR_DIGEST"
if [ "$DOCKERHUB_DIGEST" != "$GHCR_DIGEST" ]; then
  echo "::error::Docker Hub and GHCR manifest digests differ."
  exit 1
fi
