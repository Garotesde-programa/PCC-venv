@echo off
REM E2E avançado via CLI (Turnstile, profile, Bézier) — mesmo stack do site
call "d:\venv\Scripts\activate.bat"
cd /d "d:\venv\Scripts"

if "%~1"=="" (
    set /p URL="URL alvo (ex: https://seu-site.com): "
    python e2e_playwright.py "%URL%"
) else (
    python e2e_playwright.py %*
)
pause
