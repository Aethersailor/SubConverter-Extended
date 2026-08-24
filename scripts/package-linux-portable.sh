#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?arch is required}"
REVISION="${SHA:?full source revision is required}"
RELEASE_BUILD_DATE="${BUILD_DATE:?build date is required}"
PACKAGE_DIR="SubConverter-Extended"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_LAUNCHER="${SCRIPT_DIR}/ci/render-linux-launcher.sh"
UPDATE_LAUNCHER="${SCRIPT_DIR}/templates/linux-update.sh"
UPDATE_README="${SCRIPT_DIR}/templates/portable-update-readme.txt"

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
install -m755 subconverter-update "${PACKAGE_DIR}/subconverter-update"
cp -a base "${PACKAGE_DIR}/"
rm -rf "${PACKAGE_DIR}/base/Custom_OpenClash_Rules"

copy_dir_contents runtime-libs
copy_dir_contents runtime-root

python3 scripts/ci/write_build_info.py write \
  --path "${PACKAGE_DIR}/BUILD-INFO.json" \
  --version "${VERSION}" \
  --revision "${REVISION}" \
  --build-date "${RELEASE_BUILD_DATE}"

bash "${RENDER_LAUNCHER}" "${PACKAGE_DIR}/start.sh" portable "__PORTABLE_ROOT__" "__ROOT_BASE__"
install -m755 "${UPDATE_LAUNCHER}" "${PACKAGE_DIR}/update.sh"
install -m644 "${UPDATE_README}" "${PACKAGE_DIR}/UPDATE-README.txt"
tar -czf "SubConverter-Extended-${VERSION}-linux-${ARCH}.tar.gz" "${PACKAGE_DIR}"
