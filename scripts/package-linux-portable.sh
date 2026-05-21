#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?arch is required}"
PACKAGE_DIR="SubConverter-Extended"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_LAUNCHER="${SCRIPT_DIR}/ci/render-linux-launcher.sh"

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

bash "${RENDER_LAUNCHER}" "${PACKAGE_DIR}/start.sh" portable "__PORTABLE_ROOT__" "__ROOT_BASE__"
tar -czf "SubConverter-Extended-${VERSION}-linux-${ARCH}.tar.gz" "${PACKAGE_DIR}"
