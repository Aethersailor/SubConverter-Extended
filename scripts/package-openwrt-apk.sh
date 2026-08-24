#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
LINUX_ARCH="${2:?linux arch is required}"
OPENWRT_ARCHES="${3:?OpenWrt apk arch list is required}"
SOURCE_DIR="${SOURCE_DIR:-SubConverter-Extended}"

PACKAGE_NAME="subconverter-extended"
DISPLAY_NAME="SubConverter-Extended"
ROOT_DIR="/opt/${PACKAGE_NAME}"
WORK_DIR="build/openwrt-apk/${LINUX_ARCH}"
APK_RELEASE="${APK_RELEASE:-0}"
APK_VERSION="${VERSION#v}-r${APK_RELEASE}"
BUILD_TIME="${BUILD_TIME:-$(date +%s)}"
REPO_COMMIT="${GITHUB_SHA:-${SHA:-unknown}}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_LAUNCHER="${SCRIPT_DIR}/ci/render-linux-launcher.sh"
OPENWRT_DIR="${SCRIPT_DIR}/../openwrt"
OVERLAY_DIR="${OPENWRT_DIR}/root"
APK_SCRIPTS_DIR="${OPENWRT_DIR}/apk-scripts"
PACKAGE_DEPENDS="luci-base curl jsonfilter ca-bundle"

if [ ! -d "${SOURCE_DIR}" ]; then
  echo "Package source directory not found: ${SOURCE_DIR}" >&2
  exit 1
fi

if [ ! -d "${OVERLAY_DIR}" ] || [ ! -d "${APK_SCRIPTS_DIR}" ]; then
  echo "OpenWrt package overlay or lifecycle scripts are missing." >&2
  exit 1
fi

case "${APK_RELEASE}" in
  ''|*[!0-9]*)
    echo "APK_RELEASE must be a non-negative integer." >&2
    exit 1
    ;;
esac

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid version '${VERSION}'; expected vMAJOR.MINOR.PATCH." >&2
  exit 1
fi

case "${BUILD_TIME}" in
  ''|*[!0-9]*)
    echo "BUILD_TIME must be a non-negative integer." >&2
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
    local image="${APK_MKPKG_IMAGE:-mirror.gcr.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b}"
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

create_readme() {
  local path="$1"
  cat > "${path}" <<'EOF'
SubConverter-Extended OpenWrt APK

Install:
  if [ -L /etc/apk/cache ]; then
    APK_CACHE="$(readlink -f /etc/apk/cache)"
  elif [ -d /etc/apk/cache ]; then
    APK_CACHE=/etc/apk/cache
  elif [ ! -e /etc/apk/cache ]; then
    APK_CACHE=/opt/subconverter-extended-update/apk-cache
    mkdir -p "$APK_CACHE"
    ln -s "$APK_CACHE" /etc/apk/cache
  else
    echo "Unsupported /etc/apk/cache configuration" >&2
    exit 1
  fi
  cp ./<package>.apk "$APK_CACHE/"
  apk add --allow-untrusted --force-non-repository --cache-packages \
    "$APK_CACHE/<package>.apk"

The persistent APK cache is required on OpenWrt apk-based systems so a locally
installed Release package remains available across reboot. Reuse an existing
/etc/apk/cache configuration instead of replacing it.

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
files are never overwritten. Compatibility links resolve the built-in relative
resource paths and keep older generated configurations working after an
in-place package upgrade.

The package includes LuCI under Services -> SubConverter-Extended and an
external updater. Stable GitHub Releases are the only update source; public
GitHub proxy endpoints may be used for both metadata and assets.
EOF
}

install_overlay() {
  local root="$1"

  cp -a "${OVERLAY_DIR}/." "${root}/"
  find "${root}/etc/init.d" "${root}/etc/uci-defaults" \
       -type f -exec chmod 0755 {} +
  if [ -d "${root}/usr/libexec" ]; then
    find "${root}/usr/libexec" -type f -exec chmod 0755 {} +
  fi
}

normalize_package_modes() {
  local root="$1"

  # Windows and DrvFS worktrees commonly expose every file as executable.
  # Normalize staged executable text and mode bits before apk records metadata.
  find "${root}/etc/config" "${root}/etc/init.d" \
       "${root}/etc/uci-defaults" "${root}/lib/upgrade/keep.d" \
       "${root}/usr/libexec" "${root}/usr/share/luci/menu.d" \
       "${root}/usr/share/rpcd/acl.d" "${root}/usr/share/rpcd/ucode" \
       "${root}/www/luci-static/resources/subconverter_extended" \
       "${root}/www/luci-static/resources/view/subconverter_extended" \
       -type f -exec sed -i 's/\r$//' {} +
  find "${root}" -type d -exec chmod 0755 {} +
  find "${root}" -type f -exec chmod 0644 {} +

  chmod 0755 \
    "${root}${ROOT_DIR}/subconverter" \
    "${root}/usr/bin/subconverter-extended"
  find "${root}/etc/init.d" "${root}/etc/uci-defaults" \
       "${root}/usr/libexec" "${root}/usr/share/rpcd/ucode" \
       -type f -exec chmod 0755 {} +
  find "${root}${ROOT_DIR}" -type f \
       \( -name 'ld-*.so*' -o -name 'ld-linux*.so*' -o -name '*.so' \) \
       -exec chmod 0755 {} +
}

write_conffile_metadata() {
  local root="$1"
  local metadata_dir="${root}/lib/apk/packages"
  local conffile="/etc/config/${PACKAGE_NAME}"
  local checksum

  mkdir -p "${metadata_dir}"
  printf '%s\n' "${conffile}" > \
    "${metadata_dir}/${PACKAGE_NAME}.conffiles"
  checksum="$(sha256sum "${root}${conffile}" | awk '{print $1}')"
  printf '%s %s\n' "${conffile}" "${checksum}" > \
    "${metadata_dir}/${PACKAGE_NAME}.conffiles_static"
}

write_package_file_list() {
  local root="$1"
  local metadata_dir="${root}/lib/apk/packages"
  local temporary_list="${root}.package-list.$$"

  mkdir -p "${metadata_dir}"
  (
    cd "${root}"
    find . \( -type f -o -type l \) -printf '/%P\n' | LC_ALL=C sort
  ) > "${temporary_list}"
  mv -f "${temporary_list}" "${metadata_dir}/${PACKAGE_NAME}.list"
}

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

IFS=',' read -r -a ARCH_ARRAY <<< "${OPENWRT_ARCHES}"
built_arches=0
for OPENWRT_ARCH in "${ARCH_ARRAY[@]}"; do
  OPENWRT_ARCH="$(printf '%s' "${OPENWRT_ARCH}" | xargs)"
  if [ -z "${OPENWRT_ARCH}" ]; then
    continue
  fi
  case "${OPENWRT_ARCH}" in
    x86_64|aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|\
    arm_cortex-a5_vfpv4|arm_cortex-a7|arm_cortex-a7_vfpv4|\
    arm_cortex-a7_neon-vfpv4|arm_cortex-a8_vfpv3|arm_cortex-a9|\
    arm_cortex-a9_neon|arm_cortex-a9_vfpv3-d16|arm_cortex-a15_neon-vfpv4) ;;
    *)
      echo "Unsupported OpenWrt APK architecture: ${OPENWRT_ARCH}" >&2
      exit 1
      ;;
  esac

  PKG_DIR="${WORK_DIR}/${OPENWRT_ARCH}"
  PKG_ROOT="${PKG_DIR}/root"
  PKG_SCRIPT_DIR="${PKG_DIR}/apk-scripts"
  OUT_FILE="${DISPLAY_NAME}-${VERSION}-openwrt-${OPENWRT_ARCH}.apk"
  MKPKG_SCRIPT="${PKG_DIR}/mkpkg.sh"

  rm -rf "${PKG_DIR}"
  mkdir -p \
    "${PKG_ROOT}${ROOT_DIR}" \
    "${PKG_ROOT}/usr/bin" \
    "${PKG_ROOT}/usr/share/doc/${PACKAGE_NAME}"

  cp -a "${SOURCE_DIR}/." "${PKG_ROOT}${ROOT_DIR}/"
  rm -f \
    "${PKG_ROOT}${ROOT_DIR}/start.sh" \
    "${PKG_ROOT}${ROOT_DIR}/subconverter-update" \
    "${PKG_ROOT}${ROOT_DIR}/update.sh" \
    "${PKG_ROOT}${ROOT_DIR}/UPDATE-README.txt"
  install_overlay "${PKG_ROOT}"
  create_launcher "${PKG_ROOT}/usr/bin/subconverter-extended"
  create_readme "${PKG_ROOT}/usr/share/doc/${PACKAGE_NAME}/README.OpenWrt"
  normalize_package_modes "${PKG_ROOT}"
  write_conffile_metadata "${PKG_ROOT}"
  write_package_file_list "${PKG_ROOT}"
  mkdir -p "${PKG_SCRIPT_DIR}"
  cp -a "${APK_SCRIPTS_DIR}/." "${PKG_SCRIPT_DIR}/"
  sed -i 's/\r$//' "${PKG_SCRIPT_DIR}"/*
  chmod 0755 "${PKG_SCRIPT_DIR}"/*
  PKG_OWNER="$(stat -c '%u:%g' "${PKG_ROOT}")"

  cat > "${MKPKG_SCRIPT}" <<EOF
#!/bin/sh
set -eu
trap 'chown -R "${PKG_OWNER}" "${PKG_ROOT}"' EXIT
chown -R 0:0 "${PKG_ROOT}"
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
  --info depends:"${PACKAGE_DEPENDS}" \\
  --info build-time:${BUILD_TIME} \\
  --script "pre-upgrade:${PKG_SCRIPT_DIR}/pre-upgrade" \\
  --script "post-install:${PKG_SCRIPT_DIR}/post-install" \\
  --script "post-upgrade:${PKG_SCRIPT_DIR}/post-upgrade" \\
  --script "pre-deinstall:${PKG_SCRIPT_DIR}/pre-deinstall" \\
  --script "post-deinstall:${PKG_SCRIPT_DIR}/post-deinstall"

apk adbdump "${OUT_FILE}" > "${OUT_FILE}.metadata"
if grep -q "\$(printf '\r')" "${OUT_FILE}.metadata" || ! awk '
  function finish_entry() {
    if (entry_mode == "") return
    modes++
    if (entry_mode == "0777" && !entry_target) exit 1
    if (entry_mode != "0644" && entry_mode != "0755" && entry_mode != "0777") exit 1
    entry_mode = ""
    entry_target = 0
  }
  \$1 == "-" && \$2 == "name:" { finish_entry(); next }
  \$1 == "user:"  { users++;  if (\$2 != "root") exit 1 }
  \$1 == "group:" { groups++; if (\$2 != "root") exit 1 }
  \$1 == "mode:"  { entry_mode = \$2; next }
  \$1 == "target:" { entry_target = 1; next }
  END { finish_entry(); if (!users || !groups || !modes) exit 1 }
' "${OUT_FILE}.metadata"; then
  echo "Refusing APK with CRLF scripts or non-canonical ownership/modes: ${OUT_FILE}" >&2
  rm -f "${OUT_FILE}.metadata" "${OUT_FILE}"
  exit 1
fi
rm -f "${OUT_FILE}.metadata"
EOF
  chmod +x "${MKPKG_SCRIPT}"

  rm -f "${OUT_FILE}"
  run_mkpkg "${MKPKG_SCRIPT}"
  test -s "${OUT_FILE}"
  built_arches=$((built_arches + 1))
done

if [ "${built_arches}" -eq 0 ]; then
  echo "No OpenWrt APK architecture was selected." >&2
  exit 1
fi
