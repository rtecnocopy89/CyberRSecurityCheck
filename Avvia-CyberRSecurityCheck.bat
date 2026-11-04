@echo off
setlocal EnableExtensions
title CyberRSecurityCheck
cd /d "%~dp0"

if not exist "%~dp0cyberrsecuritycheck.ps1" (
    echo File cyberrsecuritycheck.ps1 mancante: estrarre tutta la cartella, oppure eseguire Compile.ps1.
    pause
    exit /b 1
)

rem Richiede i privilegi di amministratore (servono per eventi, memoria, altri utenti)
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0cyberrsecuritycheck.ps1"
exit /b 0
