#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
LINUX_ARCH="${2:?linux arch is required}"
OPENWRT_ARCHES="${3:?OpenWrt apk arch list is required}"
SOURCE_DIR="${SOURCE_DIR:-SubConverter-Extended}"

PACKAGE_NAME="subconverter-extended"
DISPLAY_NAME="SubConverter-Extended"
ROOT_DIR="/opt/${PACKAGE_NAME}"
CONFIG_DIR="/etc/subconverter"
WORK_DIR="build/openwrt-apk/${LINUX_ARCH}"
APK_VERSION="${VERSION#v}-r0"
BUILD_TIME="${BUILD_TIME:-$(date +%s)}"
REPO_COMMIT="${GITHUB_SHA:-${SHA:-unknown}}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_LAUNCHER="${SCRIPT_DIR}/ci/render-linux-launcher.sh"

if [ ! -d "${SOURCE_DIR}" ]; then
  echo "Package source directory not found: ${SOURCE_DIR}" >&2
  exit 1
fi

case "${APK_VERSION}" in
  [0-9]*-r[0-9]*) ;;
  *)
    echo "Invalid apk version '${APK_VERSION}' derived from '${VERSION}'." >&2
    echo "Release builds should use tags such as v1.2.3." >&2
    exit 1
    ;;
esac

run_mkpkg() {
  local script="$1"
  if command -v apk >/dev/null 2>&1 && apk mkpkg --help >/dev/null 2>&1; then
    sh "$script"
    return
  fi

  if command -v docker >/dev/null 2>&1; then
    local image="${APK_MKPKG_IMAGE:-mirror.gcr.io/library/alpine:latest}"
    docker run --rm \
      -v "${PWD}:/work" \
      -w /work \
      "${image}" \
      sh "$script"
    return
  fi

  echo "apk mkpkg is required. Install apk-tools v3 or run in an environment with Docker." >&2
  exit 1
}

create_launcher() {
  local path="$1"
  bash "${RENDER_LAUNCHER}" "${path}" openwrt "/opt/subconverter-extended" "/etc/subconverter"
}

create_init_script() {
  local path="$1"
  cat > "${path}" <<'EOF'
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

start_service() {
  procd_open_instance
  procd_set_param command /usr/bin/subconverter-extended
  procd_set_param respawn
  procd_close_instance
}
EOF
  chmod 0755 "${path}"
}

create_readme() {
  local path="$1"
  cat > "${path}" <<'EOF'
SubConverter-Extended OpenWrt APK

Install:
  apk add --allow-untrusted ./<package>.apk

Start manually:
  subconverter-extended

Run as an OpenWrt service:
  /etc/init.d/subconverter-extended enable
  /etc/init.d/subconverter-extended start

Configuration priority:
  1. PREF_PATH environment variable
  2. /etc/subconverter/pref.toml
  3. /etc/subconverter/pref.yml
  4. /etc/subconverter/pref.ini
  5. /opt/subconverter-extended/base/pref.toml (legacy fallback)
  6. /opt/subconverter-extended/base/pref.yml (legacy fallback)
  7. /opt/subconverter-extended/base/pref.ini (legacy fallback)

On first start, if no user configuration exists, the launcher creates
/etc/subconverter/pref.toml from pref.example.toml. Existing configuration
files are never overwritten by the launcher.
EOF
}

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

IFS=',' read -r -a ARCH_ARRAY <<< "${OPENWRT_ARCHES}"
for OPENWRT_ARCH in "${ARCH_ARRAY[@]}"; do
  OPENWRT_ARCH="$(printf '%s' "${OPENWRT_ARCH}" | xargs)"
  if [ -z "${OPENWRT_ARCH}" ]; then
    continue
  fi

  PKG_DIR="${WORK_DIR}/${OPENWRT_ARCH}"
  PKG_ROOT="${PKG_DIR}/root"
  OUT_FILE="${DISPLAY_NAME}-${VERSION}-openwrt-${OPENWRT_ARCH}.apk"
  MKPKG_SCRIPT="${PKG_DIR}/mkpkg.sh"

  rm -rf "${PKG_DIR}"
  mkdir -p \
    "${PKG_ROOT}${ROOT_DIR}" \
    "${PKG_ROOT}${CONFIG_DIR}" \
    "${PKG_ROOT}/usr/bin" \
    "${PKG_ROOT}/etc/init.d" \
    "${PKG_ROOT}/usr/share/doc/${PACKAGE_NAME}"

  cp -a "${SOURCE_DIR}/." "${PKG_ROOT}${ROOT_DIR}/"
  rm -f "${PKG_ROOT}${ROOT_DIR}/start.sh"
  create_launcher "${PKG_ROOT}/usr/bin/subconverter-extended"
  create_init_script "${PKG_ROOT}/etc/init.d/subconverter-extended"
  create_readme "${PKG_ROOT}/usr/share/doc/${PACKAGE_NAME}/README.OpenWrt"

  cat > "${MKPKG_SCRIPT}" <<EOF
#!/bin/sh
set -eu
apk mkpkg \\
  --compat 3.0.0_pre1 \\
  --files "${PKG_ROOT}" \\
  --output "${OUT_FILE}" \\
  --info name:${PACKAGE_NAME} \\
  --info version:${APK_VERSION} \\
  --info arch:${OPENWRT_ARCH} \\
  --info description:"SubConverter-Extended portable package for OpenWrt" \\
  --info license:GPL-3.0-only \\
  --info origin:${PACKAGE_NAME} \\
  --info maintainer:"Aethersailor" \\
  --info url:"https://github.com/Aethersailor/SubConverter-Extended" \\
  --info repo-commit:${REPO_COMMIT} \\
  --info build-time:${BUILD_TIME}
EOF
  chmod +x "${MKPKG_SCRIPT}"

  rm -f "${OUT_FILE}"
  run_mkpkg "${MKPKG_SCRIPT}"
  test -s "${OUT_FILE}"
done
