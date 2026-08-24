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
    awk -F/ 'NF == 2' |
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

grep -Fq 'COPY bridge/cmd/portable-updater/ ./cmd/portable-updater/' "$REPOSITORY/Dockerfile"
grep -Fq 'COPY bridge/cmd/portable-updater/ ./cmd/portable-updater/' "$REPOSITORY/docker/Dockerfile.armv7-cross"
grep -Fq 'COPY --from=go-builder /build/bridge/subconverter-update /src/subconverter-update' "$REPOSITORY/Dockerfile"
grep -Fq 'COPY --from=go-builder /build/bridge/subconverter-update /src/subconverter-update' "$REPOSITORY/docker/Dockerfile.armv7-cross"

cmake_text="$(tr -d '\r' < "$REPOSITORY/CMakeLists.txt")"
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
SYNC_WORKFLOW="$REPOSITORY/.github/workflows/sync-dev-to-master.yml"

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

grep -Fq 'git cat-file -e "HEAD:$file"' "$SYNC_WORKFLOW"
grep -Fq 'git ls-tree -rz --name-only HEAD > "$master_tree"' "$SYNC_WORKFLOW"
grep -Fq 'master_docs+=("$file")' "$SYNC_WORKFLOW"
grep -Fq 'git restore --source=HEAD --staged --worktree -- "${master_docs[@]}"' "$SYNC_WORKFLOW"

SYNC_REPOSITORY="$TEST_ROOT/sync-repository"
mkdir -p "$SYNC_REPOSITORY"
git -C "$SYNC_REPOSITORY" init --initial-branch=master >/dev/null
git -C "$SYNC_REPOSITORY" config user.name test
git -C "$SYNC_REPOSITORY" config user.email test@example.com
printf 'shared documentation\n' > "$SYNC_REPOSITORY/README.md"
printf 'base\n' > "$SYNC_REPOSITORY/source.txt"
git -C "$SYNC_REPOSITORY" add README.md source.txt
git -C "$SYNC_REPOSITORY" commit -m base >/dev/null
git -C "$SYNC_REPOSITORY" branch dev

printf 'master documentation\n' > "$SYNC_REPOSITORY/README.md"
git -C "$SYNC_REPOSITORY" add README.md
git -C "$SYNC_REPOSITORY" commit -m master-docs >/dev/null

git -C "$SYNC_REPOSITORY" switch dev >/dev/null
git -C "$SYNC_REPOSITORY" rm README.md >/dev/null
printf 'development source\n' > "$SYNC_REPOSITORY/source.txt"
git -C "$SYNC_REPOSITORY" add source.txt
git -C "$SYNC_REPOSITORY" commit -m dev-without-readme >/dev/null
DEV_SHA="$(git -C "$SYNC_REPOSITORY" rev-parse HEAD)"
if git -C "$SYNC_REPOSITORY" cat-file -e "$DEV_SHA:README.md" 2>/dev/null; then
  echo "dev unexpectedly contains README.md" >&2
  exit 1
fi

git -C "$SYNC_REPOSITORY" switch master >/dev/null
if ! git -C "$SYNC_REPOSITORY" merge "$DEV_SHA" --no-commit --no-ff >/dev/null 2>&1; then
  while IFS= read -r file; do
    if [[ "$file" == README*.md || "$file" == docs/images/readme-flow-*.svg ]]; then
      if git -C "$SYNC_REPOSITORY" cat-file -e "HEAD:$file" 2>/dev/null; then
        git -C "$SYNC_REPOSITORY" checkout --ours -- "$file"
        git -C "$SYNC_REPOSITORY" add -- "$file"
      else
        git -C "$SYNC_REPOSITORY" rm --ignore-unmatch -- "$file"
      fi
    fi
  done < <(git -C "$SYNC_REPOSITORY" diff --name-only --diff-filter=U)
fi
MASTER_TREE="$TEST_ROOT/master-tree"
git -C "$SYNC_REPOSITORY" ls-tree -rz --name-only HEAD > "$MASTER_TREE"
master_docs=()
while IFS= read -r -d '' file; do
  if [[ "$file" == README*.md || "$file" == docs/images/readme-flow-*.svg ]]; then
    master_docs+=("$file")
  fi
done < "$MASTER_TREE"
if [ "${#master_docs[@]}" -gt 0 ]; then
  git -C "$SYNC_REPOSITORY" restore --source=HEAD --staged --worktree -- "${master_docs[@]}"
fi
if [ -n "$(git -C "$SYNC_REPOSITORY" diff --name-only --diff-filter=U)" ]; then
  echo "dev-to-master simulation left unresolved conflicts" >&2
  exit 1
fi
git -C "$SYNC_REPOSITORY" commit -m sync >/dev/null
git -C "$SYNC_REPOSITORY" tag -a v1.0.0 -m release
grep -Fqx 'master documentation' "$SYNC_REPOSITORY/README.md"
test "$(git -C "$SYNC_REPOSITORY" show v1.0.0:README.md)" = 'master documentation'
test "$(git -C "$SYNC_REPOSITORY" show HEAD:source.txt)" = 'development source'

echo "Dev-to-master README deletion contract passed"
