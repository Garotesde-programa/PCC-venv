@echo off
REM Scanner de Vulnerabilidades + E2E (Turnstile, profile, Bézier)
REM Ativa o ambiente virtual
call "d:\venv\Scripts\activate.bat"

REM Sobe o servidor Flask em uma janela separada
start "Scanner IA" cmd /k "cd /d d:\venv\Scripts && python app_web.py"

REM Espera alguns segundos para o servidor subir
timeout /t 3 /nobreak >nul

REM Abre o navegador na interface web (scan + E2E humanizado e E2E avançado)
start "" "http://127.0.0.1:5000"