#!/bin/bash
# Build Go static library for mihomo parser bridge

set -e

cd "$(dirname "$0")"

echo "==> Downloading Go dependencies..."
echo "==> Downloading Go dependencies..."
go mod download

echo "==> Generating supported schemes header..."
go run ../scripts/generate_schemes.go ../src/parser/mihomo_schemes.h

echo "==> Generating parameter compatibility header..."
go run ../scripts/generate_param_compat.go -o ../src/parser/param_compat.h

echo "==> Building static library..."
go build \
    -buildmode=c-archive \
    -ldflags="-s -w" \
    -o libmihomo.a \
    .

echo "==> Build完成！"
echo "Generated files:"
ls -lh libmihomo.a libmihomo.h

echo ""
echo "==> Library info:"
file libmihomo.a
size libmihomo.a 2>/dev/null || stat -c%s libmihomo.a
