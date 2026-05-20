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
    docker run --rm \
      -v "${PWD}:/work" \
      -w /work \
      alpine:latest \
      sh "$script"
    return
  fi

  echo "apk mkpkg is required. Install apk-tools v3 or run in an environment with Docker." >&2
  exit 1
}

create_launcher() {
  local path="$1"
  cat > "${path}" <<'EOF'
#!/bin/sh
set -e

ROOT="/opt/subconverter-extended"
CONFIG_DIR="/etc/subconverter"

join_config_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$CONFIG_DIR/$1" ;;
  esac
}

create_config() {
  target="$(join_config_path "$1")"
  target_dir="$(dirname "$target")"
  mkdir -p "$target_dir"

  case "$target" in
    *.yml|*.yaml) example="$ROOT/base/pref.example.yml" ;;
    *.ini) example="$ROOT/base/pref.example.ini" ;;
    *) example="$ROOT/base/pref.example.toml" ;;
  esac

  if [ ! -f "$example" ]; then
    echo "Cannot create configuration file: $target" >&2
    echo "Missing example file: $example" >&2
    exit 1
  fi

  cp "$example" "$target"
  chmod 0600 "$target"
  printf '%s\n' "$target"
}

resolve_config() {
  if [ -n "${PREF_PATH:-}" ]; then
    conf="$(join_config_path "$PREF_PATH")"
    if [ ! -f "$conf" ]; then
      create_config "$conf"
      return
    fi
    printf '%s\n' "$conf"
    return
  fi

  for conf in "$CONFIG_DIR/pref.toml" "$CONFIG_DIR/pref.yml" "$CONFIG_DIR/pref.ini"; do
    if [ -f "$conf" ]; then
      printf '%s\n' "$conf"
      return
    fi
  done

  for conf in "$ROOT/base/pref.toml" "$ROOT/base/pref.yml" "$ROOT/base/pref.ini"; do
    if [ -f "$conf" ]; then
      printf '%s\n' "$conf"
      return
    fi
  done

  for pair in \
    "pref.example.toml:pref.toml" \
    "pref.example.yml:pref.yml" \
    "pref.example.ini:pref.ini"; do
    example="${pair%%:*}"
    target="${pair#*:}"
    if [ -f "$ROOT/base/$example" ]; then
      create_config "$target"
      return
    fi
  done

  echo "No configuration file found. Expected $CONFIG_DIR/pref.toml, pref.yml, or pref.ini." >&2
  exit 1
}

if [ -x "$ROOT/lib64/ld-linux-x86-64.so.2" ]; then
  LOADER="$ROOT/lib64/ld-linux-x86-64.so.2"
  LIB_PATH="$ROOT/lib/x86_64-linux-gnu:$ROOT/usr/lib/x86_64-linux-gnu:$ROOT/lib64:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ]; then
  LOADER="$ROOT/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
  LIB_PATH="$ROOT/lib/x86_64-linux-gnu:$ROOT/usr/lib/x86_64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/ld-linux-aarch64.so.1" ]; then
  LOADER="$ROOT/lib/ld-linux-aarch64.so.1"
  LIB_PATH="$ROOT/lib/aarch64-linux-gnu:$ROOT/usr/lib/aarch64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ]; then
  LOADER="$ROOT/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
  LIB_PATH="$ROOT/lib/aarch64-linux-gnu:$ROOT/usr/lib/aarch64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/lib/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
else
  echo "glibc loader not found in package." >&2
  exit 1
fi

CONF="$(resolve_config)"
exec "$LOADER" --library-path "$LIB_PATH" "$ROOT/subconverter" -f "$CONF"
EOF
  chmod 0755 "${path}"
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
