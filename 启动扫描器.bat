@echo off
chcp 65001 >nul
title VulnScan Scanner
cd /d "%~dp0"

set "PY="
where python >nul 2>nul
if %errorlevel%==0 (
    set "PY=python"
) else if exist "G:\python3.12\python.exe" (
    set "PY=G:\python3.12\python.exe"
)

if not defined PY (
    echo [ERROR] Python not found. Please install Python 3.
    pause
    exit /b 1
)

echo ============================================
echo   VulnScan - Third-party Library Vuln Scanner
echo   Starting Web UI, browser will open automatically...
echo   URL: http://127.0.0.1:8000
echo   Close this window to stop the service.
echo ============================================
echo.
%PY% "%~dp0python\webui.py"
pause
