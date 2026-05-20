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
pushd "%ROOT%" || exit /b 1

if not defined PREF_PATH (
  if exist "%ROOT%base\pref.toml" set "PREF_PATH=%ROOT%base\pref.toml"
  if not defined PREF_PATH if exist "%ROOT%base\pref.yml" set "PREF_PATH=%ROOT%base\pref.yml"
  if not defined PREF_PATH if exist "%ROOT%base\pref.ini" set "PREF_PATH=%ROOT%base\pref.ini"
  if not defined PREF_PATH if exist "%ROOT%base\pref.example.toml" (
    copy "%ROOT%base\pref.example.toml" "%ROOT%base\pref.toml" >nul
    set "PREF_PATH=%ROOT%base\pref.toml"
  )
  if not defined PREF_PATH if exist "%ROOT%base\pref.example.yml" (
    copy "%ROOT%base\pref.example.yml" "%ROOT%base\pref.yml" >nul
    set "PREF_PATH=%ROOT%base\pref.yml"
  )
  if not defined PREF_PATH if exist "%ROOT%base\pref.example.ini" (
    copy "%ROOT%base\pref.example.ini" "%ROOT%base\pref.ini" >nul
    set "PREF_PATH=%ROOT%base\pref.ini"
  )
)

if not defined PREF_PATH (
  echo No configuration file found. Expected base\pref.toml, base\pref.yml, or base\pref.ini.
  exit /b 1
)

if not exist "%PREF_PATH%" (
  call :create_config "%PREF_PATH%" || exit /b 1
)

"%ROOT%subconverter.exe" -f "%PREF_PATH%"
set "EXITCODE=%ERRORLEVEL%"
popd
exit /b %EXITCODE%

:create_config
set "TARGET=%~1"
for %%I in ("%TARGET%") do (
  set "TARGET_DIR=%%~dpI"
  set "TARGET_EXT=%%~xI"
)
if defined TARGET_DIR if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" >nul 2>nul
set "EXAMPLE="
if /I "%TARGET_EXT%"==".yml" set "EXAMPLE=%ROOT%base\pref.example.yml"
if /I "%TARGET_EXT%"==".yaml" set "EXAMPLE=%ROOT%base\pref.example.yml"
if /I "%TARGET_EXT%"==".ini" set "EXAMPLE=%ROOT%base\pref.example.ini"
if not defined EXAMPLE set "EXAMPLE=%ROOT%base\pref.example.toml"
if not exist "%EXAMPLE%" (
  echo Cannot create configuration file: "%TARGET%"
  echo Missing example file: "%EXAMPLE%"
  exit /b 1
)
copy "%EXAMPLE%" "%TARGET%" >nul
exit /b 0
"@

Set-Content -Path (Join-Path $PackageDir "start.ps1") -Encoding ASCII -Value @'
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Join-RootPath([string]$Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return Join-Path $Root $Path
}

function New-ConfigFromExample([string]$Target) {
  $TargetPath = Join-RootPath $Target
  $PrefDir = Split-Path -Parent $TargetPath
  if ($PrefDir) {
    New-Item -ItemType Directory -Path $PrefDir -Force | Out-Null
  }

  $Extension = [System.IO.Path]::GetExtension($TargetPath).ToLowerInvariant()
  $ExampleName = switch ($Extension) {
    ".yml" { "pref.example.yml"; break }
    ".yaml" { "pref.example.yml"; break }
    ".ini" { "pref.example.ini"; break }
    default { "pref.example.toml"; break }
  }

  $Example = Join-Path $Root "base\$ExampleName"
  if (Test-Path $Example) {
    Copy-Item $Example $TargetPath
    return $TargetPath
  }

  throw "Cannot create configuration file '$TargetPath'. Missing '$Example'."
}

function Resolve-PrefPath {
  if ($env:PREF_PATH) {
    $Target = Join-RootPath $env:PREF_PATH
    if (-not (Test-Path $Target)) {
      return New-ConfigFromExample $Target
    }
    return $Target
  }

  foreach ($Name in @("pref.toml", "pref.yml", "pref.ini")) {
    $Candidate = Join-Path $Root "base\$Name"
    if (Test-Path $Candidate) {
      return $Candidate
    }
  }

  foreach ($Pair in @(
    @{ Example = "pref.example.toml"; Target = "pref.toml" },
    @{ Example = "pref.example.yml"; Target = "pref.yml" },
    @{ Example = "pref.example.ini"; Target = "pref.ini" }
  )) {
    $Example = Join-Path $Root ("base\" + $Pair.Example)
    if (Test-Path $Example) {
      $Target = Join-Path $Root ("base\" + $Pair.Target)
      Copy-Item $Example $Target
      return $Target
    }
  }

  throw "No configuration file found. Expected base\pref.toml, base\pref.yml, or base\pref.ini."
}

$PrefPath = Resolve-PrefPath
& (Join-Path $Root "subconverter.exe") -f $PrefPath
exit $LASTEXITCODE
'@

Set-Content -Path (Join-Path $PackageDir "README-Windows.txt") -Encoding ASCII -Value @'
SubConverter-Extended Windows portable package

Start the program with start.bat or start.ps1.

Configuration priority:
1. PREF_PATH environment variable
2. base\pref.toml
3. base\pref.yml
4. base\pref.ini

On first start, if no user configuration exists, the launcher creates one from
the matching example file. The default generated file is base\pref.toml from
base\pref.example.toml.

Existing configuration files are never overwritten by the launcher. To keep a
custom configuration outside this directory, set PREF_PATH to the target file
before starting the launcher.
'@

Compress-Archive -Path $PackageDir -DestinationPath $ZipPath -Force
