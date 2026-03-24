@echo off
chcp 65001 >nul
title Security Map Server

echo.
echo  ==========================================
echo   Security Map Server
echo  ==========================================
echo.

cd /d "%~dp0"

echo  [1] Checking port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo  [2] Killing process %%a on port 8000...
    taskkill /F /PID %%a >nul 2>&1
)

echo  [3] Starting server...
echo  [4] Open http://localhost:8000
echo.

uvicorn server:app --host 0.0.0.0 --port 8000

pause
