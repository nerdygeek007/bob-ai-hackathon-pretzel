@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Project ARES: Running Automated Test Suite and Benchmarks
echo ============================================================

set PYTHON_CMD=.venv\Scripts\python.exe
if not exist "%PYTHON_CMD%" (
    set PYTHON_CMD=python
)

echo [1/3] Running Pytest Unit and Submission Gate Tests...
"%PYTHON_CMD%" -m pytest src/tests/ -v
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Pytest tests failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Running Quantitative Benchmark Evaluator...
"%PYTHON_CMD%" -m src.tests.benchmark_evaluator
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Benchmark evaluator failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Running CLI Multi-Domain Pipeline Simulation...
"%PYTHON_CMD%" -m src.cli --scenario apt_hybrid
if %ERRORLEVEL% neq 0 (
    echo [FAIL] CLI simulation failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo   ALL TESTS PASSED SUCCESSFULLY! (100%% Operational)
echo ============================================================
endlocal
