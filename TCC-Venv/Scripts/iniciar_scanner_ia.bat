@echo off
title Scanner IA
setlocal
set "SCRIPTS_DIR=%~dp0"
call "%SCRIPTS_DIR%activate.bat"
cd /d "%SCRIPTS_DIR%"
set SCANNER_SSL_MODE=adhoc
set SCANNER_FORCE_HTTPS_REDIRECT=1
set SCANNER_HTTPS_PORT=5000
rem Para usar certificado proprio, descomente as 3 linhas abaixo:
rem set SCANNER_SSL_MODE=cert
rem set SCANNER_SSL_CERT=d:\venv\Scripts\certs\localhost.crt
rem set SCANNER_SSL_KEY=d:\venv\Scripts\certs\localhost.key
set SCANNER_TRUST_PROXY=0
start /min "Scanner IA" cmd /k "python app_web.py"
timeout /t 5 /nobreak >nul
start "" "https://127.0.0.1:5000"
