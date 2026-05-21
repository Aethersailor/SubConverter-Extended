#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?version is required}"
ARCH="${2:?linux arch is required}"
OPENWRT_ARCHES="${3:?OpenWrt apk arch list is required}"

bash scripts/package-linux-portable.sh "${VERSION}" "${ARCH}"
bash scripts/package-openwrt-apk.sh "${VERSION}" "${ARCH}" "${OPENWRT_ARCHES}"
