#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?OpenWrt package architecture is required}"
SOURCE_ROOT="${3:?staged package root is required}"
WORK_DIR="${4:?IPK work directory is required}"
PACKAGE_NAME=subconverter-extended
PACKAGE_VERSION="${PACKAGE_VERSION:-${VERSION#v}-r0}"
PACKAGE_DEPENDS="${PACKAGE_DEPENDS:-luci-base luci-i18n-base-zh-cn curl jsonfilter ca-bundle}"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${PWD}/SubConverter-Extended-${VERSION}-openwrt-${ARCH}.ipk"

mkdir "${WORK_DIR}"
mkdir "${WORK_DIR}/root" "${WORK_DIR}/control"
cp -a "${SOURCE_ROOT}/." "${WORK_DIR}/root/"
printf 'ipk\n' > "${WORK_DIR}/root/usr/share/${PACKAGE_NAME}/package-manager"
installed_size="$(du -sb "${WORK_DIR}/root" | awk '{print $1}')"
depends="$(printf '%s' "${PACKAGE_DEPENDS}" | sed 's/ /, /g')"

cat > "${WORK_DIR}/control/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Architecture: ${ARCH}
Installed-Size: ${installed_size}
Section: net
Priority: optional
Maintainer: Aethersailor
License: GPL-3.0-only
Depends: ${depends}
Source: https://github.com/Aethersailor/SubConverter-Extended
Description: SubConverter-Extended portable package with LuCI
EOF
printf '/etc/config/%s\n' "${PACKAGE_NAME}" > "${WORK_DIR}/control/conffiles"
cp "${SCRIPT_DIR}/../openwrt/apk-scripts/post-install" "${WORK_DIR}/control/postinst"
cp "${SCRIPT_DIR}/../openwrt/apk-scripts/pre-deinstall" "${WORK_DIR}/control/prerm"
cp "${SCRIPT_DIR}/../openwrt/apk-scripts/post-deinstall" "${WORK_DIR}/control/postrm"
chmod 0644 "${WORK_DIR}/control/control" "${WORK_DIR}/control/conffiles"
chmod 0755 "${WORK_DIR}/control/postinst" "${WORK_DIR}/control/prerm" "${WORK_DIR}/control/postrm"

tar --owner=0 --group=0 --numeric-owner -czf "${WORK_DIR}/control.tar.gz" -C "${WORK_DIR}/control" .
tar --owner=0 --group=0 --numeric-owner -czf "${WORK_DIR}/data.tar.gz" -C "${WORK_DIR}/root" .
printf '2.0\n' > "${WORK_DIR}/debian-binary"
tar --owner=0 --group=0 --numeric-owner -czf "${OUTPUT}" -C "${WORK_DIR}" \
  ./debian-binary ./control.tar.gz ./data.tar.gz
