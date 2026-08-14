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

mapfile -t bridge_sources < <(
  git -C "$REPOSITORY" ls-files 'bridge/*.go' |
    sed 's#^bridge/##' |
    grep -Ev '(_test\.go$|^proxy_validation_generated\.go$)'
)
bridge_dockerfiles=(Dockerfile docker/Dockerfile.debian docker/Dockerfile.armv7-cross)
for dockerfile in "${bridge_dockerfiles[@]}"; do
  for source in "${bridge_sources[@]}"; do
    tr -d '\r' < "$REPOSITORY/$dockerfile" | grep -Fqx "COPY bridge/$source ./" || {
      echo "missing bridge source in $dockerfile: $source" >&2
      exit 1
    }
  done
done

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
assert_trace "--provenance=false"
deny_trace "buildcache-"
assert_trace "--build-arg THREADS=16"
grep -Eq '^digest=sha256:[0-9]{64}$' "$GITHUB_OUTPUT"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  amd64 ./Dockerfile linux/amd64 subconverter-alpine pull_request pr pr-deadbee
assert_trace "--load"
assert_trace "subconverter-extended:amd64-ci"
deny_trace "--push"
deny_trace "--provenance=false"
deny_trace "buildcache-"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  arm64 ./Dockerfile linux/arm64 subconverter-alpine-arm64 push release v1.3.1
assert_trace "ci-v1.3.1-42-3-arm64"
assert_trace "--platform linux/arm64"
assert_trace "--provenance=false"

: > "$TRACE"
bash "$REPOSITORY/scripts/ci/export-ci-image.sh" \
  ./Dockerfile subconverter-temp:amd64-builder linux/amd64
assert_trace "--target ci-export"
assert_trace "--tag subconverter-temp:amd64-builder"
assert_trace "--load"

echo "CI delivery script contract passed"
