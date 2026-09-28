@echo off
chcp 65001 >nul
title VulnScan CLI Scanner
cd /d "%~dp0"

set "PY=C:\Users\Administrator\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\python.exe"
if not exist "%PY%" set "PY=G:\python3.12\python.exe"

echo ============================================
echo   VulnScan - Third-party Library Vuln Scanner
echo   (CLI mode, no web server needed)
echo ============================================
echo.
set /p DIR=Enter the directory to scan (e.g. E:\Program Files\QQ): 
if "%DIR%"=="" (
    echo [ERROR] No directory entered.
    pause
    exit /b 1
)
echo.
echo Scanning, please wait...
echo.
"%PY%" "%~dp0python\vulnscan.py" "%DIR%" --out "%~dp0output"
echo.
echo Report saved. Opening the latest report...
start "" "%~dp0output\vulnscan_report.html"
echo.
echo Done. Press any key to close.
pause
