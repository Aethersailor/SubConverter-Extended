param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [Parameter(Mandatory = $true)]
  [string]$Revision,

  [Parameter(Mandatory = $true)]
  [string]$BuildDate,

  [string]$BuildRoot = "build/windows-amd64"
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path ".").Path
$BuildRootPath = Join-Path $Root $BuildRoot
$PackageDir = Join-Path $Root "SubConverter-Extended"
$ZipPath = Join-Path $Root "SubConverter-Extended-$Version-windows-amd64.zip"
$ExePath = Join-Path $BuildRootPath "build/subconverter.exe"
$UpdaterPath = Join-Path $BuildRootPath "subconverter-update.exe"
$DllListPath = Join-Path $BuildRootPath "runtime-dlls.txt"
$TemplateDir = Join-Path $Root "scripts/templates"

foreach ($RequiredFile in @($ExePath, $UpdaterPath, $DllListPath)) {
  if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
    throw "Required Windows build output is missing: $RequiredFile"
  }
}

Remove-Item -LiteralPath $PackageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $PackageDir | Out-Null
Copy-Item -LiteralPath $ExePath -Destination (Join-Path $PackageDir "subconverter.exe")
Copy-Item -LiteralPath $UpdaterPath -Destination (Join-Path $PackageDir "subconverter-update.exe")
Copy-Item -LiteralPath (Join-Path $Root "base") -Destination (Join-Path $PackageDir "base") -Recurse

$IdentityArgs = @(
  "scripts/ci/write_build_info.py",
  "write",
  "--path", (Join-Path $PackageDir "BUILD-INFO.json"),
  "--version", $Version,
  "--revision", $Revision,
  "--build-date", $BuildDate
)
& python @IdentityArgs
if ($LASTEXITCODE -ne 0 -and (Get-Command py -ErrorAction SilentlyContinue)) {
  & py -3 @IdentityArgs
}
if ($LASTEXITCODE -ne 0) {
  throw "Failed to write package identity with python or py -3."
}

$BundledCocrPath = Join-Path $PackageDir "base\Custom_OpenClash_Rules"
if (Test-Path -LiteralPath $BundledCocrPath) {
  Remove-Item -LiteralPath $BundledCocrPath -Recurse -Force
}

Get-Content -LiteralPath $DllListPath | ForEach-Object {
  if ($_ -and (Test-Path -LiteralPath $_ -PathType Leaf)) {
    Copy-Item -LiteralPath $_ -Destination $PackageDir -Force
  }
}

$Templates = @{
  "windows-start.bat" = "start.bat"
  "windows-start.ps1" = "start.ps1"
  "windows-update.bat" = "update.bat"
  "windows-update.ps1" = "update.ps1"
  "portable-update-readme-windows.txt" = "UPDATE-README.txt"
}
foreach ($Entry in $Templates.GetEnumerator()) {
  Copy-Item -LiteralPath (Join-Path $TemplateDir $Entry.Key) `
    -Destination (Join-Path $PackageDir $Entry.Value) -Force
}

Set-Content -LiteralPath (Join-Path $PackageDir "README-Windows.txt") -Encoding ASCII -Value @'
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

See UPDATE-README.txt for stable Release checks, automatic installation,
rollback, proxy selection, persistent state, and interrupted-update recovery.
'@

Compress-Archive -Path $PackageDir -DestinationPath $ZipPath -Force
