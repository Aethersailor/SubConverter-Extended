#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/runner"

cat > "$TEST_ROOT/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$TRACE"
printf '\n' >> "$TRACE"

metadata=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "--metadata-file" ]; then
    metadata="$argument"
  fi
  previous="$argument"
done
if [ -n "$metadata" ]; then
  printf '{"containerimage.digest":"sha256:%064d"}\n' 0 > "$metadata"
fi

if [ "${1:-}" = "buildx" ] && [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "inspect" ]; then
  printf 'Name: test\nDigest: sha256:%064d\n' 1
  printf 'Platform: linux/amd64\n'
  if [ "${FAKE_ALL_PLATFORMS:-false}" = "true" ]; then
    printf 'Platform: linux/arm64\nPlatform: linux/arm/v7\n'
  fi
elif [ "${1:-}" = "image" ] && [ "${2:-}" = "inspect" ]; then
  case "$*" in
    *org.opencontainers.image.revision*) printf '%s\n' "$FAKE_REVISION" ;;
    *org.opencontainers.image.version*) printf '%s\n' "$FAKE_VERSION" ;;
  esac
fi
SH
chmod +x "$TEST_ROOT/bin/docker"

export PATH="$TEST_ROOT/bin:$PATH"
export TRACE="$TEST_ROOT/trace"
export RUNNER_TEMP="$TEST_ROOT/runner"
export GITHUB_OUTPUT="$TEST_ROOT/output"
export GITHUB_RUN_ID=42
export GITHUB_RUN_ATTEMPT=3
export BUILD_ARGS=$'THREADS=16\nSHA=0123456789abcdef0123456789abcdef01234567'

assert_trace() {
  grep -F -- "$1" "$TRACE" >/dev/null || {
    echo "missing trace token: $1" >&2
    cat "$TRACE" >&2
    exit 1
  }
}

deny_trace() {
  if grep -F -- "$1" "$TRACE" >/dev/null; then
    echo "unexpected trace token: $1" >&2
    cat "$TRACE" >&2
    exit 1
  fi
}

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  amd64 ./Dockerfile linux/amd64 subconverter-alpine push dev dev
assert_trace "--push"
assert_trace "aethersailor/subconverter-extended:ci-dev-amd64"
assert_trace "ghcr.io/aethersailor/subconverter-extended:buildcache-subconverter-alpine"
assert_trace "--build-arg THREADS=16"
grep -Eq '^digest=sha256:[0-9]{64}$' "$GITHUB_OUTPUT"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  amd64 ./Dockerfile linux/amd64 subconverter-alpine pull_request pr pr-deadbee
assert_trace "--load"
assert_trace "subconverter-extended:amd64-ci"
deny_trace "--push"
deny_trace "buildcache-"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  arm64 ./Dockerfile linux/arm64 subconverter-alpine-arm64 push release v1.3.1
assert_trace "ci-v1.3.1-42-3-arm64"
assert_trace "--platform linux/arm64"

: > "$TRACE"
bash "$REPOSITORY/scripts/ci/export-ci-image.sh" \
  ./Dockerfile subconverter-temp:amd64-builder linux/amd64
assert_trace "--target ci-export"
assert_trace "--tag subconverter-temp:amd64-builder"
assert_trace "--load"

mkdir -p "$TEST_ROOT/promote/digests"
printf 'sha256:%064d\n' 2 > "$TEST_ROOT/promote/digests/amd64.txt"
pushd "$TEST_ROOT/promote" >/dev/null
: > "$TRACE"
bash "$REPOSITORY/scripts/ci/promote-tested-images.sh" \
  dev dev $'aethersailor/subconverter-extended:dev\nghcr.io/aethersailor/subconverter-extended:dev'
assert_trace "aethersailor/subconverter-extended:ci-dev-amd64"
assert_trace "ghcr.io/aethersailor/subconverter-extended:ci-dev-amd64"
test "$(grep -c 'imagetools create' "$TRACE")" -eq 2

printf 'sha256:%064d\n' 3 > digests/arm64.txt
printf 'sha256:%064d\n' 4 > digests/armv7.txt
: > "$TRACE"
bash "$REPOSITORY/scripts/ci/promote-tested-images.sh" \
  release v1.3.1 $'aethersailor/subconverter-extended:v1.3.1\nghcr.io/aethersailor/subconverter-extended:v1.3.1'
assert_trace "ci-v1.3.1-42-3-amd64"
assert_trace "ci-v1.3.1-42-3-arm64"
assert_trace "ci-v1.3.1-42-3-armv7"

export FAKE_REVISION=0123456789abcdef0123456789abcdef01234567
export FAKE_VERSION=v1.3.1
export FAKE_ALL_PLATFORMS=true
: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/verify-published-images.sh" \
  release $'aethersailor/subconverter-extended:v1.3.1\nghcr.io/aethersailor/subconverter-extended:v1.3.1' \
  "$FAKE_REVISION" "$FAKE_VERSION"
grep -Eq '^dockerhub_digest=sha256:[0-9]{64}$' "$GITHUB_OUTPUT"
grep -Eq '^ghcr_digest=sha256:[0-9]{64}$' "$GITHUB_OUTPUT"
test "$(grep -c 'pull --platform' "$TRACE")" -eq 6
popd >/dev/null

echo "CI delivery script contract passed"
