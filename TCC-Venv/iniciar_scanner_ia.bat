@echo off
setlocal
title Scanner IA
REM Portatil: usa pasta do .bat + .venv local (sem caminhos fixos de disco).

call "%~dp0_env.bat"
if errorlevel 1 (
    pause
    exit /b 1
)

set SCANNER_SSL_MODE=
set SCANNER_FORCE_HTTPS_REDIRECT=0
set SCANNER_TRUST_PROXY=0

start /min "Scanner IA" cmd /c "cd /d ""%SCRIPTS_DIR%"" && ""%PYTHON_EXE%"" app_web.py"
timeout /t 4 /nobreak >nul
start "" "http://127.0.0.1:5000"
endlocal
