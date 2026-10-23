@echo off
title CyberGuard Grid Platform
cd /d "%~dp0"
echo =======================================================
echo          STARTING CYBERGUARD GRID PLATFORM
echo =======================================================
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not found in PATH!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)
node run.js
pause
