#!/bin/sh
set -e

ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
exec "$ROOT/subconverter-update" "$@"
