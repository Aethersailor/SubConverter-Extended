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
  dockerfile_content="$(tr -d '\r' < "$REPOSITORY/$dockerfile")"
  for source in "${bridge_sources[@]}"; do
    grep -Fqx "COPY bridge/$source ./" <<< "$dockerfile_content" || {
      echo "missing bridge source in $dockerfile: $source" >&2
      exit 1
    }
  done
done

workflow_text="$(tr -d '\r' < "$REPOSITORY/.github/workflows/build-dockerhub.yml")"
dockerfile_text="$(tr -d '\r' < "$REPOSITORY/Dockerfile")"
cmake_text="$(tr -d '\r' < "$REPOSITORY/CMakeLists.txt")"
grep -Fq "github.event_name == 'workflow_dispatch' && 'full' || 'focused'" \
  <<< "$workflow_text"
grep -Fq -- '--build-arg SANITIZER_SUITE="$SANITIZER_SUITE"' \
  <<< "$workflow_text"
grep -Fq 'ARG SANITIZER_SUITE=full' <<< "$dockerfile_text"
for target in subconverter webserver_error_test concurrency_primitives_test \
  settings_view_test curl_handle_pool_test cache_storage_test; do
  grep -Fq "$target" <<< "$dockerfile_text" || {
    echo "focused sanitizer target missing: $target" >&2
    exit 1
  }
done
for test_name in shutdown_process_beast webserver_error_beast \
  concurrency_primitives curl_handle_pool; do
  grep -Fq "$test_name" <<< "$dockerfile_text" || {
    echo "focused sanitizer test missing: $test_name" >&2
    exit 1
  }
done
grep -Fq 'LIST(REMOVE_ITEM SETTINGS_SNAPSHOT_RUNTIME_SOURCES' <<< "$cmake_text"
grep -Fq 'src/parser/mihomo_bridge.cpp' <<< "$cmake_text"

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
  amd64 ./Dockerfile linux/amd64
assert_trace "--load"
assert_trace "subconverter-extended:amd64-ci"
deny_trace "--push"
deny_trace "aethersailor/subconverter-extended"
deny_trace "ghcr.io/aethersailor/subconverter-extended"
deny_trace "buildcache-"
assert_trace "--build-arg THREADS=16"
grep -Eq '^digest=sha256:[0-9]{64}$' "$GITHUB_OUTPUT"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  amd64 ./Dockerfile linux/amd64
assert_trace "--load"
assert_trace "subconverter-extended:amd64-ci"
deny_trace "--push"
deny_trace "buildcache-"

: > "$TRACE"
: > "$GITHUB_OUTPUT"
bash "$REPOSITORY/scripts/ci/build-candidate-image.sh" \
  arm64 ./Dockerfile linux/arm64
assert_trace "subconverter-extended:arm64-ci"
assert_trace "--platform linux/arm64"
deny_trace "--push"

: > "$TRACE"
bash "$REPOSITORY/scripts/ci/export-ci-image.sh" \
  ./Dockerfile subconverter-temp:amd64-builder linux/amd64
assert_trace "--target ci-export"
assert_trace "--tag subconverter-temp:amd64-builder"
assert_trace "--load"

echo "CI delivery script contract passed"

BUILD_WORKFLOW="$REPOSITORY/.github/workflows/build-dockerhub.yml"
CLEANUP_WORKFLOW="$REPOSITORY/.github/workflows/cleanup-container-registry.yml"

grep -Fq 'group: build-core-${{ github.ref }}' "$BUILD_WORKFLOW"
grep -Fq 'group: container-registry-cleanup' "$BUILD_WORKFLOW"
grep -Fq 'group: container-registry-cleanup' "$CLEANUP_WORKFLOW"

build_linux_block="$(sed -n '/^  build-linux:/,/^  build-windows-amd64:/p' "$BUILD_WORKFLOW")"
deny_build_linux_registry_write=false
if grep -Eq 'docker login|docker push|--push|aethersailor/subconverter-extended:ci-|ghcr.io/aethersailor/subconverter-extended:ci-' <<<"$build_linux_block"; then
  deny_build_linux_registry_write=true
fi
if [ "$deny_build_linux_registry_write" = true ]; then
  echo "build-linux still writes to a container registry" >&2
  exit 1
fi
grep -Fq 'image: subconverter-extended:${{ matrix.arch }}-ci' <<<"$build_linux_block"
grep -Fq 'docker save "subconverter-extended:${{ matrix.arch }}-ci"' <<<"$build_linux_block"
grep -Fq 'name: docker-image-${{ matrix.arch }}' <<<"$build_linux_block"

publish_block="$(sed -n '/^  merge-manifest:/,/^  create-release:/p' "$BUILD_WORKFLOW")"
grep -Fq 'needs: [prepare, validate-source, sanitizer, cross-build, build-linux, build-windows-amd64]' <<<"$publish_block"
grep -Fq "needs.build-windows-amd64.result == 'success'" <<<"$publish_block"
grep -Fq 'pattern: docker-image-*' <<<"$publish_block"
grep -Fq 'gzip -dc "images/$archive" | docker load' <<<"$publish_block"
grep -Fq 'actual_platform="$(docker image inspect' <<<"$publish_block"
grep -Fq 'docker push "$dockerhub_candidate"' <<<"$publish_block"
grep -Fq 'docker push "$ghcr_candidate"' <<<"$publish_block"
grep -Fq 'Candidate digest differs across registries' <<<"$publish_block"

cleanup_block="$(sed -n '/^  cleanup-transient-images:/,$p' "$BUILD_WORKFLOW")"
grep -Fq 'always() &&' <<<"$cleanup_block"
grep -Fq "needs.prepare.outputs.mode == 'dev'" <<<"$cleanup_block"
grep -Fq "needs.prepare.outputs.mode == 'release'" <<<"$cleanup_block"
grep -Fq -- '--prune-orphans' <<<"$cleanup_block"
grep -Fq -- '--current-tag ci-dev-amd64' <<<"$cleanup_block"
grep -Fq -- '--current-prefix "ci-${VERSION}-${GITHUB_RUN_ID}-"' <<<"$cleanup_block"
if grep -Fq '!cancelled()' <<<"$cleanup_block" || \
   grep -Fq "needs.merge-manifest.result == 'success'" <<<"$cleanup_block" || \
   grep -Fq "needs.verify-release-complete.result == 'success'" <<<"$cleanup_block"; then
  echo "cleanup job is still restricted to successful publication" >&2
  exit 1
fi

grep -Fq 'schedule:' "$CLEANUP_WORKFLOW"
grep -Fq 'python3 scripts/ci/cleanup_container_registry.py --prune-all --apply' "$CLEANUP_WORKFLOW"

echo "Container registry cleanup contract passed"
