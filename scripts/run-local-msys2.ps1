param(
    [string]$Config = "base/pref.example.toml"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$bash = "C:\msys64\usr\bin\bash.exe"
$exe = Join-Path $repoRoot "build\ucrt64\subconverter.exe"
$configPath = Resolve-Path (Join-Path $repoRoot $Config)

if (-not (Test-Path $bash)) {
    throw "MSYS2 was not found at C:\msys64."
}

if (-not (Test-Path $exe)) {
    throw "subconverter.exe was not found. Run scripts\build-local-msys2.ps1 first."
}

$env:SCX_ROOT_WIN = $repoRoot
$env:SCX_CONFIG_WIN = $configPath.Path

$script = @'
set -euo pipefail

export MSYSTEM=UCRT64
export PATH="/ucrt64/bin:/usr/bin:$PATH"

root="$(cygpath -u "$SCX_ROOT_WIN")"
config="$(cygpath -w "$SCX_CONFIG_WIN")"

cd "$root"
exec ./build/ucrt64/subconverter.exe -f "$config"
'@

& $bash -lc $script
exit $LASTEXITCODE
