@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Project ARES: Ingesting and Correlating Custom Telemetry
echo   Dataset: src\data\sample_custom_alerts.json
echo ============================================================

set PYTHON_CMD=.venv\Scripts\python.exe
if not exist "%PYTHON_CMD%" (
    set PYTHON_CMD=python
)

"%PYTHON_CMD%" -m src.cli --scenario custom

echo.
echo ============================================================
echo  Custom telemetry test complete!
echo  To run your own custom JSON file:
echo    .\.venv\Scripts\python.exe -m src.cli --file path\to\your_alerts.json
echo  To enter alerts interactively in the console:
echo    .\.venv\Scripts\python.exe -m src.cli --interactive
echo ============================================================
endlocal
