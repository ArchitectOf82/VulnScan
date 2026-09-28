@echo off
chcp 65001 >nul
title VulnScan Info Leak Scan (Module 3)
cd /d "%~dp0"

set "PY=C:\Users\Administrator\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\python.exe"
if not exist "%PY%" set "PY=G:\python3.12\python.exe"

echo ============================================
echo   VulnScan - Information Leakage Scan (Module 3)
echo   Backup/VCS/config/key/DB/log/source leaks
echo   + hardcoded credential content scan
echo ============================================
echo.
set /p DIR=Enter the directory to scan (e.g. E:\Program Files\QQ\versions\9.9.35-52892\resources\app): 
if "%DIR%"=="" (
    echo [ERROR] No directory entered.
    pause
    exit /b 1
)
echo.
echo Scanning...
echo.
"%PY%" -c "import sys; sys.path.insert(0, r'%~dp0python'); from vulnscan import main; sys.argv=['vulnscan', r'%DIR%', '--leak', '--out', r'%~dp0output', '--no-nvd']; sys.exit(main())"
echo.
echo Opening the info-leak report...
start "" "%~dp0output\info_leak_report.html"
echo.
echo Done. Press any key to close.
pause
