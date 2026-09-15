@echo off
echo ============================================================
echo   Project ARES: Threat Correlation Engine
echo   Tactical War Room Server: http://127.0.0.1:8000
echo ============================================================

if exist .run.pid (
    call "%~dp0stop.bat" >nul 2>&1
)

set PYTHON_CMD=.venv\Scripts\python.exe
if not exist "%PYTHON_CMD%" (
    set PYTHON_CMD=python
)

powershell -NoProfile -Command ^
  "$p = Start-Process -FilePath '%PYTHON_CMD%' -ArgumentList @('-m', 'uvicorn', 'src.api:app', '--host', '127.0.0.1', '--port', '8000') -PassThru; Set-Content -Path '.run.pid' -Value $p.Id; Write-Host 'Server running with PID' $p.Id"

echo.
echo Server active at: http://127.0.0.1:8000
echo Run stop.bat to stop the server, or restart.bat to restart.
echo ============================================================

echo Starting Sentinel-X Modern SaaS UI...
cd "%~dp0src"
npm run dev
endlocal
