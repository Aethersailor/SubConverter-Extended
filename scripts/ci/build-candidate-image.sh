#!/usr/bin/env bash
set -euo pipefail

: "${BUILD_ARGS:?BUILD_ARGS is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
if [ "$#" -ne 7 ]; then
  echo "usage: $0 ARCH DOCKERFILE PLATFORM CACHE_SCOPE EVENT MODE VERSION" >&2
  exit 2
fi
CI_ARCH="$1"
DOCKERFILE="$2"
IMAGE_PLATFORM="$3"
_CACHE_SCOPE="$4"
EVENT_NAME="$5"
BUILD_MODE="$6"
BUILD_VERSION="$7"

args=()
while IFS= read -r arg; do
  [ -n "$arg" ] && args+=(--build-arg "$arg")
done <<< "$BUILD_ARGS"

tags=(--tag "subconverter-extended:${CI_ARCH}-ci")
output=(--load)
provenance=()
if [ "$EVENT_NAME" != "pull_request" ] && [ "$BUILD_MODE" != "master" ]; then
  candidate="ci-${BUILD_MODE}-${CI_ARCH}"
  if [ "$BUILD_MODE" = "release" ]; then
    candidate="ci-${BUILD_VERSION}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${CI_ARCH}"
  fi
  tags=(
    --tag "aethersailor/subconverter-extended:${candidate}"
    --tag "ghcr.io/aethersailor/subconverter-extended:${candidate}"
  )
  output=(--push)
  provenance=(--provenance=false)
fi

metadata_file="${RUNNER_TEMP}/build-metadata-${CI_ARCH}.json"
docker buildx build \
  --file "$DOCKERFILE" \
  --platform "$IMAGE_PLATFORM" \
  "${output[@]}" \
  "${tags[@]}" \
  "${provenance[@]}" \
  "${args[@]}" \
  --metadata-file "$metadata_file" \
  .

digest="$(python3 - "$metadata_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(data.get("containerimage.digest", ""))
PY
)"
if [ "$EVENT_NAME" != "pull_request" ] && \
   [ "$BUILD_MODE" != "master" ] && \
   [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "::error::Build did not return a valid candidate image digest."
  exit 1
fi
echo "digest=$digest" >> "$GITHUB_OUTPUT"
