#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
THREADS="${THREADS:-2}"
WORK_DIR="${RUNNER_TEMP:?RUNNER_TEMP is required}/sce-codeql-cpp"
if [ "${RUNNER_OS:-Linux}" = "Windows" ]; then
  WORK_DIR="$(cygpath -u "$RUNNER_TEMP")/sce-codeql-cpp"
fi
PREFIX="${WORK_DIR}/prefix"

checkout_dependency() {
  local repository="$1" revision="$2" destination="$3"
  git init "$destination"
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --depth=1 origin "$revision"
  git -C "$destination" checkout --detach FETCH_HEAD
  git -C "$destination" submodule update --init --recursive --depth=1
}

case "${1:?prepare or build is required}" in
  prepare)
    mkdir -p "$PREFIX/include/quickjs" "$PREFIX/lib/quickjs"
    python3 "$ROOT/scripts/ci/dependency_snapshot.py" emit > "$WORK_DIR/dependencies.env"
    while IFS='=' read -r name value; do
      case "$name" in
        QUICKJSPP_REF) QUICKJSPP_REF="$value" ;;
        LIBCRON_REF) LIBCRON_REF="$value" ;;
      esac
    done < "$WORK_DIR/dependencies.env"

    checkout_dependency https://github.com/ftk/quickjspp.git \
      "${QUICKJSPP_REF:?missing locked QuickJS revision}" "$WORK_DIR/quickjspp"
    cmake -S "$WORK_DIR/quickjspp" -B "$WORK_DIR/quickjspp-build" \
      -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build "$WORK_DIR/quickjspp-build" --target quickjs --parallel "$THREADS"
    cp "$WORK_DIR/quickjspp-build/quickjs/libquickjs.a" "$PREFIX/lib/quickjs/"
    cp "$WORK_DIR/quickjspp/quickjs/quickjs.h" \
      "$WORK_DIR/quickjspp/quickjs/quickjs-libc.h" "$PREFIX/include/quickjs/"

    checkout_dependency https://github.com/PerMalmberg/libcron.git \
      "${LIBCRON_REF:?missing locked LibCron revision}" "$WORK_DIR/libcron"
    cmake -S "$WORK_DIR/libcron" -B "$WORK_DIR/libcron-build" \
      -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build "$WORK_DIR/libcron-build" --target libcron --parallel "$THREADS"
    cp "$WORK_DIR/libcron/libcron/out/Release/liblibcron.a" "$PREFIX/lib/"
    cp -a "$WORK_DIR/libcron/libcron/include/libcron" "$PREFIX/include/"
    cp -a "$WORK_DIR/libcron/libcron/externals/date/include/date" "$PREFIX/include/"

    # Match the shipped bridge and let CMake enable USE_MIHOMO_PARSER.
    if [ "${RUNNER_OS:-Linux}" = "Windows" ]; then
      bridge_mode=c-archive
      bridge_file=libmihomo.a
    else
      bridge_mode=c-shared
      bridge_file=libmihomo.so
    fi
    (
      cd "$ROOT/bridge"
      CGO_ENABLED=1 go build -p "$THREADS" -mod=readonly -trimpath \
        -buildmode="$bridge_mode" -o "$bridge_file" .
    )

    for variant in application static; do
      static=OFF
      [ "$variant" != static ] || static=ON
      cmake -S "$ROOT" -B "$WORK_DIR/$variant" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_STATIC_LIBRARY="$static" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_CXX_COMPILER_LAUNCHER= \
        -DCMAKE_PREFIX_PATH="$PREFIX;${MINGW_PREFIX:-/usr}" \
        -DQUICKJS_INCLUDE_DIRS="$PREFIX/include" \
        -DQUICKJS_LIBRARY="$PREFIX/lib/quickjs/libquickjs.a" \
        -DLIBCRON_INCLUDE_DIR="$PREFIX/include" \
        -DDATE_INCLUDE_DIR="$PREFIX/include" \
        -DLIBCRON_LIBRARY="$PREFIX/lib/liblibcron.a" \
        -DTOML11_INCLUDE_DIR="$ROOT/include"
    done
    ;;
  build)
    # Both macro configurations must be compiled under CodeQL's tracer.
    export CCACHE_DISABLE=1
    for variant in application static; do
      cmake --build "$WORK_DIR/$variant" --clean-first --parallel "$THREADS"
    done
    ;;
  *)
    echo 'Usage: build-codeql-cpp.sh prepare|build' >&2
    exit 2
    ;;
esac
