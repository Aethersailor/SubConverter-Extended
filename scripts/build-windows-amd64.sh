#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
REVISION="${2:-}"
BUILD_DATE="${3:-}"
THREADS="${THREADS:-4}"
: "${QUICKJSPP_REF:?QUICKJSPP_REF is required}"
: "${LIBCRON_REF:?LIBCRON_REF is required}"
: "${TOML11_REF:?TOML11_REF is required}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${ROOT}/build/windows-amd64"
DEPS_DIR="${WORK_DIR}/deps"
BUILD_DIR="${WORK_DIR}/build"

rm -rf "${WORK_DIR}"
mkdir -p "${DEPS_DIR}/include" "${DEPS_DIR}/lib" "${BUILD_DIR}"

cd "${ROOT}"

checkout_dependency() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  local with_submodules="${4:-false}"

  git init "${destination}"
  git -C "${destination}" remote add origin "${repository}"
  git -C "${destination}" fetch --depth=1 origin "${revision}"
  git -C "${destination}" checkout --detach FETCH_HEAD
  if [ "${with_submodules}" = "true" ]; then
    git -C "${destination}" submodule update --init --recursive --depth=1
  fi
}

BUILD_ID="$(printf '%.7s' "${REVISION}")"
if [ -n "${BUILD_ID}" ]; then
  sed -i "s/#define BUILD_ID \"\"/#define BUILD_ID \"${BUILD_ID}\"/ " src/version.h || true
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
  go run ../scripts/generate_proxy_validation.go -o proxy_validation_generated.go -manifest mihomo_capabilities.json
  go run ../scripts/generate_schemes.go -manifest mihomo_capabilities.json -o ../src/parser/mihomo_schemes.h
  go run ../scripts/generate_param_compat.go -manifest mihomo_capabilities.json -o ../src/parser/param_compat.h
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o "${WORK_DIR}/subconverter-update.exe" ./cmd/portable-updater
  CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=gcc \
    go build -trimpath -buildmode=c-archive -ldflags="-s -w" -o libmihomo.a .
)

checkout_dependency \
  https://github.com/ftk/quickjspp.git "${QUICKJSPP_REF}" "${WORK_DIR}/quickjspp" true
cmake -S "${WORK_DIR}/quickjspp" -B "${WORK_DIR}/quickjspp-build" \
  -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${WORK_DIR}/quickjspp-build" --target quickjs -j "${THREADS}"
mkdir -p "${DEPS_DIR}/lib/quickjs" "${DEPS_DIR}/include/quickjs"
cp "${WORK_DIR}/quickjspp-build/quickjs/libquickjs.a" "${DEPS_DIR}/lib/quickjs/"
cp "${WORK_DIR}/quickjspp/quickjs/quickjs.h" \
   "${WORK_DIR}/quickjspp/quickjs/quickjs-libc.h" \
   "${DEPS_DIR}/include/quickjs/"
cp "${WORK_DIR}/quickjspp/quickjspp.hpp" "${DEPS_DIR}/include/"

checkout_dependency \
  https://github.com/PerMalmberg/libcron.git "${LIBCRON_REF}" "${WORK_DIR}/libcron" true
cmake -S "${WORK_DIR}/libcron" -B "${WORK_DIR}/libcron-build" \
  -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${WORK_DIR}/libcron-build" --target libcron -j "${THREADS}"
mkdir -p "${DEPS_DIR}/include/libcron" "${DEPS_DIR}/include/date"
cp "${WORK_DIR}/libcron/libcron/out/Release/liblibcron.a" "${DEPS_DIR}/lib/"
cp "${WORK_DIR}/libcron/libcron/include/libcron/"* "${DEPS_DIR}/include/libcron/"
cp "${WORK_DIR}/libcron/libcron/externals/date/include/date/"* "${DEPS_DIR}/include/date/"

checkout_dependency \
  https://github.com/ToruNiina/toml11.git "${TOML11_REF}" "${WORK_DIR}/toml11"
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
