#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?builder image tag is required}"
MODE="${2:?extract mode is required: shared or root}"
EXTRACT_GENERATED="${EXTRACT_GENERATED:-false}"

case "${MODE}" in
  shared|root) ;;
  *)
    echo "Unsupported extract mode: ${MODE}" >&2
    exit 1
    ;;
esac

CID="$(docker create "${IMAGE}")"
cleanup() {
  docker rm "${CID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker cp "${CID}:/src/subconverter" ./subconverter
chmod +x ./subconverter

case "${MODE}" in
  shared)
    docker cp "${CID}:/runtime-libs" ./runtime-libs
    ;;
  root)
    docker cp "${CID}:/runtime-root" ./runtime-root
    ;;
esac

if [ "${EXTRACT_GENERATED}" = "true" ]; then
  docker cp "${CID}:/src/bridge/go.mod" bridge/go.mod
  docker cp "${CID}:/src/bridge/go.sum" bridge/go.sum
  docker cp "${CID}:/src/bridge/libmihomo.h" bridge/libmihomo.h

  docker cp "${CID}:/src/src/parser/mihomo_schemes.h" src/parser/mihomo_schemes.h
  docker cp "${CID}:/src/src/parser/param_compat.h" src/parser/param_compat.h

  docker cp "${CID}:/src/include/httplib.h" include/httplib.h
  docker cp "${CID}:/src/include/nlohmann/json.hpp" include/nlohmann/json.hpp
  docker cp "${CID}:/src/include/inja.hpp" include/inja.hpp
  docker cp "${CID}:/src/include/jpcre2.hpp" include/jpcre2.hpp
  docker cp "${CID}:/src/include/quickjspp.hpp" include/quickjspp.hpp

  rm -rf include/libcron include/date include/toml11 include/toml.hpp
  docker cp "${CID}:/src/include/libcron" include/
  docker cp "${CID}:/src/include/date" include/
  docker cp "${CID}:/src/include/toml.hpp" include/toml.hpp
  docker cp "${CID}:/src/include/toml11" include/

  find include/libcron include/date include/toml11 -type f -print0 | xargs -0 sed -i 's/[[:blank:]]\+$//'
  sed -i 's/[[:blank:]]\+$//' include/toml.hpp
fi
