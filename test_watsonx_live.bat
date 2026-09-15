@echo off
setlocal
cd /d "%~dp0"

set PYTHON_CMD=.venv\Scripts\python.exe
if not exist "%PYTHON_CMD%" (
    set PYTHON_CMD=python
)

"%PYTHON_CMD%" -m src.ai.test_watsonx
endlocal
