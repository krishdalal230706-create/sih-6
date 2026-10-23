# CyberGuard Grid Platform PowerShell Launcher
Set-Location $PSScriptRoot
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "       ⚡ STARTING CYBERGUARD GRID PLATFORM ⚡        " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Please install Node.js from https://nodejs.org/"
    exit 1
}

node run.js
