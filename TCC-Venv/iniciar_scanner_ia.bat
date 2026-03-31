@echo off
setlocal
title Scanner IA
REM Script portátil: funciona mesmo mudando de pasta/PC.
set "ROOT_DIR=%~dp0"
set "SCRIPTS_DIR=%ROOT_DIR%Scripts"

if not exist "%SCRIPTS_DIR%\app_web.py" (
    echo [ERRO] app_web.py nao encontrado em "%SCRIPTS_DIR%".
    echo Verifique se este .bat esta na raiz do projeto.
    pause
    exit /b 1
)

if exist "%SCRIPTS_DIR%\activate.bat" (
    call "%SCRIPTS_DIR%\activate.bat"
)

set SCANNER_SSL_MODE=
set SCANNER_FORCE_HTTPS_REDIRECT=0
set SCANNER_TRUST_PROXY=0

start /min "Scanner IA" cmd /c "cd /d ""%SCRIPTS_DIR%"" && python app_web.py"
timeout /t 4 /nobreak >nul
start "" "http://127.0.0.1:5000"