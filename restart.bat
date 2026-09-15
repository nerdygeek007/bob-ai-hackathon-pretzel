@echo off
setlocal
cd /d "%~dp0"
echo Restarting Project ARES server...
call "%~dp0stop.bat"
timeout /t 1 /nobreak >nul
call "%~dp0run.bat"
endlocal
