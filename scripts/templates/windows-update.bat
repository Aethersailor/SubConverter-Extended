@echo off
setlocal
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "POWERSHELL_EXE=%ProgramFiles%\PowerShell\7\pwsh.exe"
"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0update.ps1" %*
exit /b %ERRORLEVEL%
