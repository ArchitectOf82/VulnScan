@echo off
chcp 65001 >nul
title VulnScan Studio
cd /d "%~dp0"

set "PY=C:\Users\Administrator\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\python.exe"
if not exist "%PY%" set "PY=G:\python3.12\python.exe"

echo VulnScan Studio - unified multi-module scanner
echo Opening the product window...
start "" "%PY%" "%~dp0python\VulnScan_Studio.py"
