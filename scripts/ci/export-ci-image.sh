#!/usr/bin/env bash
set -euo pipefail

: "${BUILD_ARGS:?BUILD_ARGS is required}"
if [ "$#" -ne 3 ]; then
  echo "usage: $0 DOCKERFILE BUILDER_TAG BUILDER_PLATFORM" >&2
  exit 2
fi
DOCKERFILE="$1"
BUILDER_TAG="$2"
BUILDER_PLATFORM="$3"

args=()
while IFS= read -r arg; do
  [ -n "$arg" ] && args+=(--build-arg "$arg")
done <<< "$BUILD_ARGS"

docker buildx build \
  --file "$DOCKERFILE" \
  --load \
  --tag "$BUILDER_TAG" \
  --target ci-export \
  --platform "$BUILDER_PLATFORM" \
  "${args[@]}" \
  .
