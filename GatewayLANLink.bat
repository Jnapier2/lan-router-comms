@echo off
REM Copyright 2026 Gateway Information Group LLC. All rights reserved.
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0" || (
    echo ERROR: The Gateway LAN Link project folder could not be opened.
    exit /b 2
)

set "GLL_VERIFY=%~dp0Verify-Release.ps1"
set "GLL_SCRIPT=%~dp0LAN_Router_Comms.ps1"
if not exist "%GLL_VERIFY%" (
    echo ERROR: Verify-Release.ps1 is missing beside this launcher.
    exit /b 20
)
if not exist "%GLL_SCRIPT%" (
    echo ERROR: LAN_Router_Comms.ps1 is missing beside this launcher.
    exit /b 20
)

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows PowerShell 5.1 was not found on PATH.
    exit /b 3
)

powershell.exe -NoLogo -NoProfile -File "%GLL_VERIFY%" -Quiet
if errorlevel 1 (
    echo ERROR: Gateway LAN Link did not start because release identity or managed-file verification failed.
    echo Replace this folder with one complete checksum-verified package, then try again.
    exit /b 20
)

powershell.exe -NoLogo -NoProfile -File "%GLL_SCRIPT%" %*
exit /b %errorlevel%
