@echo off
REM Bootstrap portavel: define ROOT_DIR, SCRIPTS_DIR, PYTHON_EXE (funciona em qualquer PC/pasta).
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
set "SCRIPTS_DIR=%ROOT_DIR%\Scripts"
set "VENV_DIR=%ROOT_DIR%\.venv"
set "PYTHON_EXE="
set "PIP_EXE="

if not exist "%SCRIPTS_DIR%\app_web.py" (
    echo [ERRO] app_web.py nao encontrado em "%SCRIPTS_DIR%".
    echo Coloque este projeto intacto e execute o .bat na raiz.
    endlocal
    exit /b 1
)

REM 1) Ambiente local do projeto (.venv)
if exist "%VENV_DIR%\Scripts\python.exe" (
    set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
    set "PIP_EXE=%VENV_DIR%\Scripts\pip.exe"
    goto :env_ready
)

REM 2) Estrutura legada: pasta do projeto ja e um venv (python em Scripts\)
if exist "%SCRIPTS_DIR%\python.exe" (
    set "PYTHON_EXE=%SCRIPTS_DIR%\python.exe"
    if exist "%SCRIPTS_DIR%\pip.exe" set "PIP_EXE=%SCRIPTS_DIR%\pip.exe"
    goto :env_ready
)

REM 3) Launcher oficial do Windows (py -3)
where py >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%P"
)

REM 4) python no PATH
if not defined PYTHON_EXE (
    where python >nul 2>&1
    if not errorlevel 1 (
        for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%P"
    )
)

if not defined PYTHON_EXE (
    echo [ERRO] Python 3.9+ nao encontrado.
    echo Instale em https://www.python.org/downloads/ e marque "Add python.exe to PATH".
    echo Ou use: winget install Python.Python.3.12
    endlocal
    exit /b 1
)

"%PYTHON_EXE%" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python 3.9 ou superior e obrigatorio.
    endlocal
    exit /b 1
)

REM Cria .venv na primeira execucao (portavel entre PCs)
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [INFO] Primeira execucao neste PC: criando .venv ...
    "%PYTHON_EXE%" -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERRO] Nao foi possivel criar o ambiente virtual em "%VENV_DIR%".
        endlocal
        exit /b 1
    )
    set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
    set "PIP_EXE=%VENV_DIR%\Scripts\pip.exe"
    echo [INFO] Instalando dependencias ...
    "%PYTHON_EXE%" -m pip install --upgrade pip -q
    "%PYTHON_EXE%" -m pip install -r "%ROOT_DIR%\requirements.txt"
    if errorlevel 1 (
        echo [ERRO] Falha ao instalar requirements.txt
        endlocal
        exit /b 1
    )
    goto :env_ready
)

set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
set "PIP_EXE=%VENV_DIR%\Scripts\pip.exe"

:env_ready
"%PYTHON_EXE%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Instalando dependencias em .venv ...
    "%PYTHON_EXE%" -m pip install -r "%ROOT_DIR%\requirements.txt"
    if errorlevel 1 (
        echo [ERRO] Falha ao instalar requirements.txt
        endlocal
        exit /b 1
    )
)

if defined PIP_EXE (
    for %%A in ("%ROOT_DIR%") do for %%B in ("%SCRIPTS_DIR%") do for %%C in ("%VENV_DIR%") do for %%D in ("%PYTHON_EXE%") do for %%E in ("%PIP_EXE%") do (
        endlocal
        set "ROOT_DIR=%%~A"
        set "SCRIPTS_DIR=%%~B"
        set "VENV_DIR=%%~C"
        set "PYTHON_EXE=%%~D"
        set "PIP_EXE=%%~E"
    )
) else (
    for %%A in ("%ROOT_DIR%") do for %%B in ("%SCRIPTS_DIR%") do for %%C in ("%VENV_DIR%") do for %%D in ("%PYTHON_EXE%") do (
        endlocal
        set "ROOT_DIR=%%~A"
        set "SCRIPTS_DIR=%%~B"
        set "VENV_DIR=%%~C"
        set "PYTHON_EXE=%%~D"
    )
)
exit /b 0
