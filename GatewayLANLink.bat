@echo off
REM Copyright 2026 Gateway Information Group LLC. All rights reserved.
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0" || (
    echo ERROR: The Gateway LAN Link project folder could not be opened.
    exit /b 2
)

set "GLL_SCRIPT=%~dp0LAN_Router_Comms.ps1"
if not exist "%GLL_SCRIPT%" (
    echo ERROR: LAN_Router_Comms.ps1 is missing beside this launcher.
    exit /b 2
)

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows PowerShell 5.1 was not found on PATH.
    exit /b 3
)

powershell.exe -NoLogo -NoProfile -File "%GLL_SCRIPT%" %*
exit /b %errorlevel%
