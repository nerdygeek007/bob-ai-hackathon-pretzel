@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Project ARES: Live IBM Bob Agent and Cloud Reasoning Test
echo   Consuming Bobcoins via live BOB_API_KEY from .env
echo ============================================================

set PYTHON_CMD=.venv\Scripts\python.exe
if not exist "%PYTHON_CMD%" (
    set PYTHON_CMD=python
)

"%PYTHON_CMD%" -m src.ai.bob_live_agent

echo.
echo ============================================================
echo   Check your IBM Bob Panel: Coins utilized and Task logged!
echo   Transcript saved in: bob_sessions\
echo ============================================================
endlocal
