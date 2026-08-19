#!/usr/bin/env bash
set -euo pipefail

: "${BUILD_ARGS:?BUILD_ARGS is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
if [ "$#" -ne 3 ]; then
  echo "usage: $0 ARCH DOCKERFILE PLATFORM" >&2
  exit 2
fi
CI_ARCH="$1"
DOCKERFILE="$2"
IMAGE_PLATFORM="$3"

args=()
while IFS= read -r arg; do
  [ -n "$arg" ] && args+=(--build-arg "$arg")
done <<< "$BUILD_ARGS"

image="subconverter-extended:${CI_ARCH}-ci"

metadata_file="${RUNNER_TEMP}/build-metadata-${CI_ARCH}.json"
docker buildx build \
  --file "$DOCKERFILE" \
  --platform "$IMAGE_PLATFORM" \
  --load \
  --tag "$image" \
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
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "::error::Build did not return a valid local image digest."
  exit 1
fi
echo "digest=$digest" >> "$GITHUB_OUTPUT"
