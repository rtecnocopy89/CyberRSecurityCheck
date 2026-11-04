@echo off
setlocal EnableExtensions
title CyberRSecurityCheck - console
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PS=powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0cyberrsecuritycheck.ps1" -Console"

echo.
echo  CyberRSecurityCheck - modalita' console
echo  ----------------------------------------
echo   1. Analisi completa
echo   2. Test appunti
echo   3. Monitor durante il bonifico (30 minuti)
echo   4. Test automatici dello strumento
echo.
set "scelta="
set /p "scelta=  Scelta: "
if "%scelta%"=="1" %PS% -Mode Completo
if "%scelta%"=="2" %PS% -Mode ClipTest
if "%scelta%"=="3" %PS% -Mode Monitor -MonitorMinutes 30
if "%scelta%"=="4" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tests\Test-CyberRSecurityCheck.ps1"
echo.
pause
