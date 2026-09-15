@echo off
REM ARES SIEM & Multi-Source Telemetry Streaming Launcher
REM Streams realistic heterogeneous alerts (CEF, Syslog, EDR, OCSF, CoT) into ARES API
echo ======================================================================
echo    ARES Threat Intelligence - Continuous SIEM Streamer
echo ======================================================================

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

if exist ".venv\Scripts\python.exe" (
    set PYTHON_EXE=.venv\Scripts\python.exe
) else (
    set PYTHON_EXE=python
)

echo [*] Target Ingestion API: http://127.0.0.1:8000/api/ingest
echo [*] Streaming Rate: 10 Events Per Second (EPS)
echo [*] Formats: IBM QRadar CEF, CrowdStrike EDR, Suricata, OCSF v1.1, CoT
echo.
echo Press Ctrl+C to terminate stream.
echo.

"%PYTHON_EXE%" -m src.data.siem_simulator --mode stream --eps 10 --push-api http://127.0.0.1:8000/api/ingest --scenario apt_hybrid

pause
