@echo off
setlocal
title NetShaper Setup
cd /d "%~dp0"

:: Elevate if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo.
echo  NetShaper - easy setup
echo  ======================
echo.
echo  [1] Install app (Program Files + shortcuts)
echo  [2] Install app + CLI on PATH
echo  [3] Install app + WinDivert (packet mode)
echo  [4] Full install (PATH + WinDivert + start app)
echo  [5] Uninstall
echo  [0] Exit
echo.
set /p choice=Choose option [1]: 
if "%choice%"=="" set choice=1

if "%choice%"=="0" exit /b 0
if "%choice%"=="5" goto uninstall

set EXTRA=
if "%choice%"=="2" set EXTRA=-AddToPath
if "%choice%"=="3" set EXTRA=-WinDivert
if "%choice%"=="4" set EXTRA=-AddToPath -WinDivert -StartApp

:: Prefer Install.ps1 next to this cmd (release zip), else repo scripts
if exist "%~dp0Install.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %EXTRA%
) else if exist "%~dp0Install-FromRelease.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-FromRelease.ps1" %EXTRA%
) else if exist "%~dp0..\dist\NetShaper-win-x64\NetShaper.exe" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-FromRelease.ps1" -SourceDir "%~dp0..\dist\NetShaper-win-x64" %EXTRA%
) else (
  echo Could not find NetShaper.exe. Unzip the release, then run Setup.cmd from that folder.
  pause
  exit /b 1
)
echo.
pause
exit /b 0

:uninstall
if exist "%ProgramFiles%\NetShaper\Uninstall.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ProgramFiles%\NetShaper\Uninstall.ps1"
) else if exist "%~dp0uninstall-app.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-app.ps1"
) else (
  echo Uninstall script not found. Remove Program Files\NetShaper manually.
)
pause
exit /b 0
