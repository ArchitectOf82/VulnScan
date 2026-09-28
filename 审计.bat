@echo off
chcp 65001 >nul
title VulnScan Binary Audit (Module 2)
cd /d "%~dp0"

set "PY=C:\Users\Administrator\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\python.exe"
if not exist "%PY%" set "PY=G:\python3.12\python.exe"

echo ============================================
echo   VulnScan - Binary Security Audit (Module 2)
echo   Parse imports, classify risky APIs,
echo   scan for hardcoded keys / sensitive strings
echo ============================================
echo.
set /p DIR=Enter the directory to audit (e.g. E:\Program Files\QQ\versions\9.9.35-52892\resources\app): 
if "%DIR%"=="" (
    echo [ERROR] No directory entered.
    pause
    exit /b 1
)
echo.
echo Auditing, this may take a while for large directories...
echo.
"%PY%" -c "import sys; sys.path.insert(0, r'%~dp0python'); from vulnscan import main; sys.argv=['vulnscan', r'%DIR%', '--audit', '--out', r'%~dp0output', '--no-nvd']; sys.exit(main())"
echo.
echo Opening the binary audit report...
start "" "%~dp0output\binary_audit_report.html"
echo.
echo Done. Press any key to close.
pause
