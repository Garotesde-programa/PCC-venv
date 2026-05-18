@echo off
title Verificar ambiente
call "%~dp0_env.bat" || (pause & exit /b 1)
echo.
echo ROOT: %ROOT_DIR%
echo PYTHON: %PYTHON_EXE%
"%PYTHON_EXE%" -c "import flask; import sys; print('Python', sys.version.split()[0]); print('Flask OK')"
echo.
pause
