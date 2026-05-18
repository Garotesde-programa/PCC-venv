@echo off
setlocal EnableDelayedExpansion
title E2E Avancado
REM Portatil: mesmo bootstrap do iniciar_scanner_ia.bat

call "%~dp0_env.bat"
if errorlevel 1 (
    pause
    exit /b 1
)

cd /d "%SCRIPTS_DIR%"

if "%~1"=="" (
    set /p URL="URL alvo (ex: https://seu-site.com): "
    "%PYTHON_EXE%" e2e_playwright.py "!URL!"
) else (
    "%PYTHON_EXE%" e2e_playwright.py %*
)
pause
endlocal
