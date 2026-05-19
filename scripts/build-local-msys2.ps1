param(
    [ValidateRange(1, 32)]
    [int]$Jobs = 8,

    [ValidateSet("Debug", "Release", "RelWithDebInfo")]
    [string]$BuildType = "RelWithDebInfo",

    [switch]$RebuildBridge,
    [switch]$RebuildLibCron
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$bash = "C:\msys64\usr\bin\bash.exe"

if (-not (Test-Path $bash)) {
    throw "MSYS2 was not found at C:\msys64. Install MSYS2 first."
}

$env:SCX_ROOT_WIN = $repoRoot
$env:SCX_JOBS = [string]$Jobs
$env:SCX_BUILD_TYPE = $BuildType
$env:SCX_REBUILD_BRIDGE = if ($RebuildBridge) { "1" } else { "0" }
$env:SCX_REBUILD_LIBCRON = if ($RebuildLibCron) { "1" } else { "0" }

$script = @'
set -euo pipefail

export MSYSTEM=UCRT64
export PATH="/c/Program Files/Go/bin:/ucrt64/bin:/usr/bin:$PATH"

root="$(cygpath -u "$SCX_ROOT_WIN")"
cd "$root"

for tool in gcc g++ cmake ninja pkg-config git go; do
  command -v "$tool" >/dev/null || {
    echo "Missing required tool: $tool" >&2
    exit 1
  }
done

pkg-config --exists libcurl yaml-cpp libpcre2-8 || {
  echo "Missing one or more pkg-config dependencies: libcurl yaml-cpp libpcre2-8" >&2
  exit 1
}

if [ ! -f /ucrt64/include/quickjs/quickjs.h ] || [ ! -f /ucrt64/lib/quickjs/libquickjs.a ]; then
  echo "Missing QuickJS. Install mingw-w64-ucrt-x86_64-quickjs in MSYS2." >&2
  exit 1
fi

if [ "$SCX_REBUILD_LIBCRON" = "1" ] || [ ! -f /ucrt64/lib/liblibcron.a ]; then
  work=/tmp/subconverter-build-deps
  mkdir -p "$work"
  cd "$work"
  if [ ! -d libcron/.git ]; then
    git clone --depth=1 https://github.com/PerMalmberg/libcron
  fi
  cd libcron
  git submodule update --init
  cmake -S . -B build-ucrt -G Ninja -DCMAKE_BUILD_TYPE=Release
  cmake --build build-ucrt --target libcron -j "$SCX_JOBS"
  mkdir -p /ucrt64/lib /ucrt64/include/libcron /ucrt64/include/date
  cp -f libcron/out/Release/liblibcron.a /ucrt64/lib/
  cp -f libcron/include/libcron/* /ucrt64/include/libcron/
  cp -f libcron/externals/date/include/date/* /ucrt64/include/date/
  cd "$root"
fi

if [ "$SCX_REBUILD_BRIDGE" = "1" ] || [ ! -f bridge/libmihomo.a ]; then
  cd "$root/bridge"
  go mod download
  CC=gcc CXX=g++ CGO_ENABLED=1 go build -buildmode=c-archive -o libmihomo.a .
  unix2dos libmihomo.h >/dev/null 2>&1 || true
  cd "$root"
fi

cmake -S . -B build/ucrt64 -G Ninja \
  -DCMAKE_BUILD_TYPE="$SCX_BUILD_TYPE" \
  -DCMAKE_PREFIX_PATH=/ucrt64 \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache

cmake --build build/ucrt64 -j "$SCX_JOBS"

echo
echo "Built: $root/build/ucrt64/subconverter.exe"
echo "Run:   ./scripts/run-local-msys2.ps1"
'@

& $bash -lc $script
exit $LASTEXITCODE
