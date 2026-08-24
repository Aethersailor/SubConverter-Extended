@echo off
setlocal
for %%I in ("%~dp0.") do set "ROOT=%%~fI"
set "STATE_ROOT=%ROOT%.update"
if not exist "%STATE_ROOT%" mkdir "%STATE_ROOT%" >nul 2>nul
if not defined SUBCONVERTER_RUNTIME_STATE_FILE set "SUBCONVERTER_RUNTIME_STATE_FILE=%STATE_ROOT%\runtime.json"

if "%SUBCONVERTER_UPDATE_VALIDATION%"=="1" goto after_updates
cd /d "%ROOT%\.." || exit /b 1
call "%ROOT%\update.bat" recover
set "UPDATE_RESULT=%ERRORLEVEL%"
if "%UPDATE_RESULT%"=="10" goto reenter
if not "%UPDATE_RESULT%"=="0" (
  echo Portable update recovery failed; refusing to start from an uncertain root.
  exit /b %UPDATE_RESULT%
)

if "%SUBCONVERTER_SKIP_AUTO_UPDATE%"=="1" goto after_updates
call "%ROOT%\update.bat" auto
set "UPDATE_RESULT=%ERRORLEVEL%"
if "%UPDATE_RESULT%"=="10" goto reenter
if not "%UPDATE_RESULT%"=="0" echo Automatic update failed; starting the currently validated portable version.
goto after_updates

:reenter
call "%ROOT%\start.bat"
exit /b %ERRORLEVEL%

:after_updates
pushd "%ROOT%" || exit /b 1

if not defined PREF_PATH (
  if exist "%ROOT%\base\pref.toml" set "PREF_PATH=%ROOT%\base\pref.toml"
  if not defined PREF_PATH if exist "%ROOT%\base\pref.yml" set "PREF_PATH=%ROOT%\base\pref.yml"
  if not defined PREF_PATH if exist "%ROOT%\base\pref.ini" set "PREF_PATH=%ROOT%\base\pref.ini"
  if not defined PREF_PATH if exist "%ROOT%\base\pref.example.toml" (
    copy "%ROOT%\base\pref.example.toml" "%ROOT%\base\pref.toml" >nul
    set "PREF_PATH=%ROOT%\base\pref.toml"
  )
  if not defined PREF_PATH if exist "%ROOT%\base\pref.example.yml" (
    copy "%ROOT%\base\pref.example.yml" "%ROOT%\base\pref.yml" >nul
    set "PREF_PATH=%ROOT%\base\pref.yml"
  )
  if not defined PREF_PATH if exist "%ROOT%\base\pref.example.ini" (
    copy "%ROOT%\base\pref.example.ini" "%ROOT%\base\pref.ini" >nul
    set "PREF_PATH=%ROOT%\base\pref.ini"
  )
)

if not defined PREF_PATH (
  echo No configuration file found. Expected base\pref.toml, base\pref.yml, or base\pref.ini.
  exit /b 1
)

if not exist "%PREF_PATH%" call :create_config "%PREF_PATH%" || exit /b 1
"%ROOT%\subconverter.exe" -f "%PREF_PATH%"
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
if /I "%TARGET_EXT%"==".yml" set "EXAMPLE=%ROOT%\base\pref.example.yml"
if /I "%TARGET_EXT%"==".yaml" set "EXAMPLE=%ROOT%\base\pref.example.yml"
if /I "%TARGET_EXT%"==".ini" set "EXAMPLE=%ROOT%\base\pref.example.ini"
if not defined EXAMPLE set "EXAMPLE=%ROOT%\base\pref.example.toml"
if not exist "%EXAMPLE%" (
  echo Cannot create configuration file: "%TARGET%"
  echo Missing example file: "%EXAMPLE%"
  exit /b 1
)
copy "%EXAMPLE%" "%TARGET%" >nul
exit /b 0
