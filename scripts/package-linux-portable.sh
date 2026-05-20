#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?arch is required}"
PACKAGE_DIR="SubConverter-Extended"

copy_dir_contents() {
  local source_dir="$1"
  if [ ! -d "$source_dir" ]; then
    return 0
  fi

  shopt -s dotglob nullglob
  local entries=("${source_dir}"/*)
  if [ "${#entries[@]}" -gt 0 ]; then
    cp -a "${entries[@]}" "${PACKAGE_DIR}/"
  fi
  shopt -u dotglob nullglob
}

rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}"

install -m755 subconverter "${PACKAGE_DIR}/subconverter"
cp -a base "${PACKAGE_DIR}/"

if [ -f libmihomo.so ]; then
  mkdir -p "${PACKAGE_DIR}/usr/lib"
  install -m755 libmihomo.so "${PACKAGE_DIR}/usr/lib/libmihomo.so"
fi

copy_dir_contents runtime-libs
copy_dir_contents runtime-root

cat > "${PACKAGE_DIR}/start.sh" <<'EOF'
#!/bin/sh
set -e

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
CONF="${PREF_PATH:-$ROOT/base/pref.toml}"
CONF_DIR="$(dirname "$CONF")"
mkdir -p "$CONF_DIR"

if [ ! -f "$CONF" ] && [ -f "$ROOT/base/pref.example.toml" ]; then
  cp "$ROOT/base/pref.example.toml" "$CONF"
fi

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
else
  echo "glibc loader not found in package."
  exit 1
fi

exec "$LOADER" --library-path "$LIB_PATH" "$ROOT/subconverter" -f "$CONF"
EOF

chmod +x "${PACKAGE_DIR}/start.sh"
tar -czf "SubConverter-Extended-${VERSION}-linux-${ARCH}.tar.gz" "${PACKAGE_DIR}"
