#!/usr/bin/env bash
# Build the Mihomo parser bridge as a static c-archive.

set -euo pipefail

cd "$(dirname "$0")"

echo "==> Downloading Go dependencies..."
go mod download

echo "==> Generating proxy validation metadata..."
go run ../scripts/generate_proxy_validation.go \
    -o proxy_validation_generated.go \
    -manifest mihomo_capabilities.json

echo "==> Generating supported schemes header..."
go run ../scripts/generate_schemes.go \
    -manifest mihomo_capabilities.json \
    -o ../src/parser/mihomo_schemes.h

echo "==> Generating parameter compatibility header..."
go run ../scripts/generate_param_compat.go \
    -manifest mihomo_capabilities.json \
    -o ../src/parser/param_compat.h

echo "==> Building static library..."
CGO_ENABLED=1 go build \
    -trimpath \
    -buildmode=c-archive \
    -ldflags="-s -w" \
    -o libmihomo.a \
    .

echo "==> Build completed."
echo "Generated files:"
ls -lh libmihomo.a libmihomo.h mihomo_capabilities.json

echo ""
echo "==> Library info:"
if command -v file >/dev/null 2>&1; then
    file libmihomo.a
fi
size libmihomo.a 2>/dev/null || stat -c%s libmihomo.a
