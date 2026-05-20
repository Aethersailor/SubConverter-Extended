param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [string]$BuildRoot = "build/windows-amd64"
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path ".").Path
$BuildRootPath = Join-Path $Root $BuildRoot
$PackageDir = Join-Path $Root "SubConverter-Extended"
$ZipPath = Join-Path $Root "SubConverter-Extended-$Version-windows-amd64.zip"
$ExePath = Join-Path $BuildRootPath "build/subconverter.exe"
$DllListPath = Join-Path $BuildRootPath "runtime-dlls.txt"

Remove-Item -Recurse -Force $PackageDir -ErrorAction SilentlyContinue
Remove-Item -Force $ZipPath -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $PackageDir | Out-Null
Copy-Item -Path $ExePath -Destination (Join-Path $PackageDir "subconverter.exe")
Copy-Item -Path (Join-Path $Root "base") -Destination (Join-Path $PackageDir "base") -Recurse

Get-Content $DllListPath | ForEach-Object {
  if ($_ -and (Test-Path $_)) {
    Copy-Item -Path $_ -Destination $PackageDir -Force
  }
}

Set-Content -Path (Join-Path $PackageDir "start.bat") -Encoding ASCII -Value @"
@echo off
setlocal
set "ROOT=%~dp0"
if not defined PREF_PATH set "PREF_PATH=%ROOT%base\pref.toml"
if not exist "%PREF_PATH%" (
  if exist "%ROOT%base\pref.example.toml" copy "%ROOT%base\pref.example.toml" "%PREF_PATH%" >nul
)
"%ROOT%subconverter.exe" -f "%PREF_PATH%"
exit /b %ERRORLEVEL%
"@

Set-Content -Path (Join-Path $PackageDir "start.ps1") -Encoding ASCII -Value @'
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PrefPath = if ($env:PREF_PATH) { $env:PREF_PATH } else { Join-Path $Root "base\pref.toml" }
$PrefDir = Split-Path -Parent $PrefPath
New-Item -ItemType Directory -Path $PrefDir -Force | Out-Null
if (-not (Test-Path $PrefPath)) {
  $Example = Join-Path $Root "base\pref.example.toml"
  if (Test-Path $Example) {
    Copy-Item $Example $PrefPath
  }
}
& (Join-Path $Root "subconverter.exe") -f $PrefPath
exit $LASTEXITCODE
'@

Compress-Archive -Path $PackageDir -DestinationPath $ZipPath -Force
