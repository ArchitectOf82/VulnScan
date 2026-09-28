@echo off
setlocal
call "G:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0..\cpp"
cl /nologo /std:c++17 /O2 /EHsc pe_scanner.cpp /link version.lib bcrypt.lib /out:"%~dp0..\build\pe_scanner.exe"
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK: %~dp0..\build\pe_scanner.exe
