$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateRoot = "$Root.update"
$SourceUpdater = Join-Path $Root "subconverter-update.exe"
$Worker = Join-Path $StateRoot "subconverter-update-worker.exe"
$WorkerTemporary = Join-Path $StateRoot (".subconverter-update-worker-{0}.exe" -f $PID)

if (Test-Path -LiteralPath $StateRoot) {
  $StateItem = Get-Item -LiteralPath $StateRoot -Force
  if (-not $StateItem.PSIsContainer -or
      ($StateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "The persistent updater path must be a real directory: $StateRoot"
  }
} else {
  New-Item -ItemType Directory -Path $StateRoot | Out-Null
}

if (-not (Test-Path -LiteralPath $SourceUpdater -PathType Leaf)) {
  throw "The packaged updater is missing: $SourceUpdater"
}

Copy-Item -LiteralPath $SourceUpdater -Destination $WorkerTemporary -Force
Move-Item -LiteralPath $WorkerTemporary -Destination $Worker -Force

$EscapedRoot = $Root.Replace("'", "''")
$RecoveryScript = @"
`$ErrorActionPreference = 'Stop'
`$env:SUBCONVERTER_PORTABLE_ROOT = '$EscapedRoot'
Set-Location -LiteralPath '$($StateRoot.Replace("'", "''"))'
& '.\subconverter-update-worker.exe' recover
exit `$LASTEXITCODE
"@
Set-Content -LiteralPath (Join-Path $StateRoot "recover.ps1") -Value $RecoveryScript -Encoding UTF8

$PreviousRoot = $env:SUBCONVERTER_PORTABLE_ROOT
$PreviousLocation = Get-Location
try {
  $env:SUBCONVERTER_PORTABLE_ROOT = $Root
  Set-Location -LiteralPath (Split-Path -Parent $Root)
  & $Worker @args
  $Result = $LASTEXITCODE
} finally {
  if (Test-Path -LiteralPath $PreviousLocation.Path) {
    Set-Location -LiteralPath $PreviousLocation.Path
  }
  if ($null -eq $PreviousRoot) {
    Remove-Item Env:SUBCONVERTER_PORTABLE_ROOT -ErrorAction SilentlyContinue
  } else {
    $env:SUBCONVERTER_PORTABLE_ROOT = $PreviousRoot
  }
  Remove-Item -LiteralPath $WorkerTemporary -Force -ErrorAction SilentlyContinue
}

exit $Result
