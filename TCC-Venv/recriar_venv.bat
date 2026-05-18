@echo off
title Recriar .venv
setlocal
set "ROOT=%~dp0"
echo [INFO] Removendo .venv antigo...
if exist "%ROOT%.venv" rmdir /s /q "%ROOT%.venv"
echo [INFO] Recriando ambiente...
call "%ROOT%_env.bat"
if errorlevel 1 (pause & exit /b 1)
echo [OK] Ambiente recriado.
pause
