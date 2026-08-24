$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateRoot = "$Root.update"
$OriginalLocation = Get-Location

if (-not (Test-Path -LiteralPath $StateRoot)) {
  New-Item -ItemType Directory -Path $StateRoot | Out-Null
}
if (-not $env:SUBCONVERTER_RUNTIME_STATE_FILE) {
  $env:SUBCONVERTER_RUNTIME_STATE_FILE = Join-Path $StateRoot "runtime.json"
}

function Invoke-UpdateCommand([string]$Command) {
  $ShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  Set-Location -LiteralPath (Split-Path -Parent $Root)
  $Output = & $ShellPath -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "update.ps1") $Command 2>&1
  $Result = $LASTEXITCODE
  if ($Output) {
    $Output | ForEach-Object { Write-Host $_ }
  }
  return [int]$Result
}

function Enter-CurrentLauncher {
  $ShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  Set-Location -LiteralPath (Split-Path -Parent $Root)
  & $ShellPath -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "start.ps1")
  exit $LASTEXITCODE
}

if ($env:SUBCONVERTER_UPDATE_VALIDATION -ne "1") {
  $RecoveryResult = Invoke-UpdateCommand "recover"
  if ($RecoveryResult -eq 10) {
    Enter-CurrentLauncher
  }
  if ($RecoveryResult -ne 0) {
    throw "Portable update recovery failed; refusing to start from an uncertain root."
  }

  if ($env:SUBCONVERTER_SKIP_AUTO_UPDATE -ne "1") {
    $AutomaticResult = Invoke-UpdateCommand "auto"
    if ($AutomaticResult -eq 10) {
      Enter-CurrentLauncher
    }
    if ($AutomaticResult -ne 0) {
      Write-Warning "Automatic update failed; starting the currently validated portable version."
    }
  }
}

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
  if (Test-Path -LiteralPath $Example) {
    Copy-Item -LiteralPath $Example -Destination $TargetPath
    return $TargetPath
  }

  throw "Cannot create configuration file '$TargetPath'. Missing '$Example'."
}

function Resolve-PrefPath {
  if ($env:PREF_PATH) {
    $Target = Join-RootPath $env:PREF_PATH
    if (-not (Test-Path -LiteralPath $Target)) {
      return New-ConfigFromExample $Target
    }
    return $Target
  }

  foreach ($Name in @("pref.toml", "pref.yml", "pref.ini")) {
    $Candidate = Join-Path $Root "base\$Name"
    if (Test-Path -LiteralPath $Candidate) {
      return $Candidate
    }
  }

  foreach ($Pair in @(
    @{ Example = "pref.example.toml"; Target = "pref.toml" },
    @{ Example = "pref.example.yml"; Target = "pref.yml" },
    @{ Example = "pref.example.ini"; Target = "pref.ini" }
  )) {
    $Example = Join-Path $Root ("base\" + $Pair.Example)
    if (Test-Path -LiteralPath $Example) {
      $Target = Join-Path $Root ("base\" + $Pair.Target)
      Copy-Item -LiteralPath $Example -Destination $Target
      return $Target
    }
  }

  throw "No configuration file found. Expected base\pref.toml, base\pref.yml, or base\pref.ini."
}

try {
  Set-Location -LiteralPath $Root
  $PrefPath = Resolve-PrefPath
  & (Join-Path $Root "subconverter.exe") -f $PrefPath
  exit $LASTEXITCODE
} finally {
  if (Test-Path -LiteralPath $OriginalLocation.Path) {
    Set-Location -LiteralPath $OriginalLocation.Path
  }
}
