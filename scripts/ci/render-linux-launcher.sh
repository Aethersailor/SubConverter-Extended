#!/usr/bin/env bash
set -euo pipefail

OUTPUT="${1:?output path is required}"
MODE="${2:?mode is required}"
ROOT_VALUE="${3:?root value is required}"
CONFIG_DIR_VALUE="${4:?config dir value is required}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../templates/linux-launcher.sh"

case "${MODE}" in
  portable|openwrt) ;;
  *)
    echo "Unsupported launcher mode: ${MODE}" >&2
    exit 1
    ;;
esac

if [ ! -f "${TEMPLATE}" ]; then
  echo "Launcher template not found: ${TEMPLATE}" >&2
  exit 1
fi

sed \
  -e "s|__CONFIG_MODE__|${MODE}|g" \
  -e "s|__ROOT__|${ROOT_VALUE}|g" \
  -e "s|__CONFIG_DIR__|${CONFIG_DIR_VALUE}|g" \
  "${TEMPLATE}" > "${OUTPUT}"
chmod 0755 "${OUTPUT}"
