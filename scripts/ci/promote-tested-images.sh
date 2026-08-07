#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 MODE VERSION IMAGE_TAGS" >&2
  exit 2
fi
BUILD_MODE="$1"
BUILD_VERSION="$2"
IMAGE_TAGS="$3"

if [ "$BUILD_MODE" = "dev" ]; then
  ARCHES=(amd64)
else
  ARCHES=(amd64 arm64 armv7)
fi
for arch in "${ARCHES[@]}"; do
  test -s "digests/${arch}.txt"
  grep -Eq '^sha256:[0-9a-f]{64}$' "digests/${arch}.txt"
done

IMAGE_NAMES=(
  "aethersailor/subconverter-extended"
  "ghcr.io/aethersailor/subconverter-extended"
)
for image_name in "${IMAGE_NAMES[@]}"; do
  sources=()
  for arch in "${ARCHES[@]}"; do
    candidate="ci-${BUILD_MODE}-${arch}"
    if [ "$BUILD_MODE" = "release" ]; then
      candidate="ci-${BUILD_VERSION}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${arch}"
    fi
    sources+=("${image_name}:${candidate}")
  done
  for tag in $IMAGE_TAGS; do
    if [[ "$tag" == "$image_name:"* ]]; then
      echo "Promoting ${sources[*]} to $tag"
      docker buildx imagetools create -t "$tag" "${sources[@]}"
    fi
  done
done
