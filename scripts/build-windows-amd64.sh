#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
SHA="${2:-}"
BUILD_DATE="${3:-}"
THREADS="${THREADS:-4}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${ROOT}/build/windows-amd64"
DEPS_DIR="${WORK_DIR}/deps"
BUILD_DIR="${WORK_DIR}/build"

rm -rf "${WORK_DIR}"
mkdir -p "${DEPS_DIR}/include" "${DEPS_DIR}/lib" "${BUILD_DIR}"

cd "${ROOT}"

if [ -n "${SHA}" ]; then
  sed -i "s/#define BUILD_ID \"\"/#define BUILD_ID \"${SHA}\"/ " src/version.h || true
fi
if [ -n "${VERSION}" ]; then
  sed -i "s/#define VERSION \"dev\"/#define VERSION \"${VERSION}\"/" src/version.h || true
fi
if [ -n "${BUILD_DATE}" ]; then
  sed -i "s/#define BUILD_DATE \"\"/#define BUILD_DATE \"${BUILD_DATE}\"/" src/version.h || true
fi

(
  cd bridge
  go mod download
  go run ../scripts/generate_schemes.go ../src/parser/mihomo_schemes.h
  go run ../scripts/generate_param_compat.go -o ../src/parser/param_compat.h
  CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=gcc \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w" -o libmihomo.a .
)

git clone --depth=1 --recurse-submodules --shallow-submodules \
  https://github.com/ftk/quickjspp.git "${WORK_DIR}/quickjspp"
cmake -S "${WORK_DIR}/quickjspp" -B "${WORK_DIR}/quickjspp-build" \
  -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${WORK_DIR}/quickjspp-build" --target quickjs -j "${THREADS}"
mkdir -p "${DEPS_DIR}/lib/quickjs" "${DEPS_DIR}/include/quickjs"
cp "${WORK_DIR}/quickjspp-build/quickjs/libquickjs.a" "${DEPS_DIR}/lib/quickjs/"
cp "${WORK_DIR}/quickjspp/quickjs/quickjs.h" \
   "${WORK_DIR}/quickjspp/quickjs/quickjs-libc.h" \
   "${DEPS_DIR}/include/quickjs/"
cp "${WORK_DIR}/quickjspp/quickjspp.hpp" "${DEPS_DIR}/include/"

git clone --depth=1 --recurse-submodules --shallow-submodules \
  https://github.com/PerMalmberg/libcron.git "${WORK_DIR}/libcron"
cmake -S "${WORK_DIR}/libcron" -B "${WORK_DIR}/libcron-build" \
  -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${WORK_DIR}/libcron-build" --target libcron -j "${THREADS}"
mkdir -p "${DEPS_DIR}/include/libcron" "${DEPS_DIR}/include/date"
cp "${WORK_DIR}/libcron/libcron/out/Release/liblibcron.a" "${DEPS_DIR}/lib/"
cp "${WORK_DIR}/libcron/libcron/include/libcron/"* "${DEPS_DIR}/include/libcron/"
cp "${WORK_DIR}/libcron/libcron/externals/date/include/date/"* "${DEPS_DIR}/include/date/"

git clone --depth=1 https://github.com/ToruNiina/toml11.git "${WORK_DIR}/toml11"
cp -a "${WORK_DIR}/toml11/include/." "${DEPS_DIR}/include/"

cmake -S "${ROOT}" -B "${BUILD_DIR}" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="${DEPS_DIR};/ucrt64" \
  -DQUICKJS_INCLUDE_DIRS="${DEPS_DIR}/include" \
  -DQUICKJS_LIBRARY="${DEPS_DIR}/lib/quickjs/libquickjs.a" \
  -DLIBCRON_INCLUDE_DIR="${DEPS_DIR}/include" \
  -DDATE_INCLUDE_DIR="${DEPS_DIR}/include" \
  -DLIBCRON_LIBRARY="${DEPS_DIR}/lib/liblibcron.a" \
  -DTOML11_INCLUDE_DIR="${DEPS_DIR}/include"
cmake --build "${BUILD_DIR}" -j "${THREADS}"

RUNTIME_DLLS="${WORK_DIR}/runtime-dlls.txt"
: > "${RUNTIME_DLLS}"
ldd "${BUILD_DIR}/subconverter.exe" | awk '
  /=>/ { print $(NF - 1) }
  /^[[:space:]]*\/ucrt64\/bin\/.*\.dll/ { print $1 }
' | while read -r dll; do
  case "${dll}" in
    /ucrt64/bin/*.dll)
      cygpath -w "${dll}" >> "${RUNTIME_DLLS}"
      ;;
  esac
done

for dll in /ucrt64/bin/libssl-3-x64.dll /ucrt64/bin/libcrypto-3-x64.dll; do
  if [ -f "${dll}" ]; then
    cygpath -w "${dll}" >> "${RUNTIME_DLLS}"
  fi
done

sort -u "${RUNTIME_DLLS}" -o "${RUNTIME_DLLS}"
