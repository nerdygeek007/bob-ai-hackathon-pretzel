@echo off
setlocal
cd /d "%~dp0"

if not exist .run.pid (
    echo No active .run.pid file found. Checking for processes on port 8000...
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
        echo Killing PID %%a on port 8000...
        taskkill /PID %%a /F >nul 2>&1
    )
    echo Server stopped.
    goto :done
)

set /p SERVER_PID=<.run.pid
if not "%SERVER_PID%"=="" (
    echo Stopping server PID %SERVER_PID%...
    taskkill /PID %SERVER_PID% /F /T >nul 2>&1
    del /f /q .run.pid >nul 2>&1
    echo Server PID %SERVER_PID% stopped.
) else (
    del /f /q .run.pid >nul 2>&1
)

:: Extra cleanup in case child processes remain on port 8000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

:done
echo Server cleanup complete.
endlocal
