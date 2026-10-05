@echo off
REM ============================================================================
REM Cybersecurity Awareness & Threat Intelligence Dashboard - Windows setup
REM Automates: virtual environment + dependencies + .env + synthetic data
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."
echo ============================================================
echo  Cybersecurity Awareness ^& Threat Intelligence Dashboard
echo  Step 1-4: environment setup
echo ============================================================

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    echo         Install Python 3.9+ from https://www.python.org/downloads/
    echo         and tick "Add Python to PATH", then run this script again.
    pause & exit /b 1
)

echo [1/5] Creating virtual environment "venv" ...
if not exist venv (
    python -m venv venv
    if errorlevel 1 ( echo [ERROR] venv creation failed & pause & exit /b 1 )
) else (
    echo       venv already exists - reusing it.
)

echo [2/5] Activating virtual environment ...
call venv\Scripts\activate.bat

echo [3/5] Installing dependencies (requirements.txt) ...
python -m pip install --upgrade pip >nul 2>nul
pip install -r requirements.txt
if errorlevel 1 ( echo [ERROR] dependency installation failed & pause & exit /b 1 )

echo [4/5] Creating .env from .env.example (if missing) ...
if not exist .env (
    copy .env.example .env >nul
    echo       Created .env with demo keys ^(change them for shared deployments^).
) else (
    echo       .env already exists - keeping it.
)

echo [5/5] Generating synthetic threat dataset ...
python data\generate_threat_data.py
if errorlevel 1 ( echo [ERROR] data generation failed & pause & exit /b 1 )

echo.
echo ============================================================
echo  SETUP COMPLETE
echo  Next steps:
echo    scripts\start_backend.bat     (init DB + start API server)
echo    scripts\start_frontend.bat    (open the dashboard)
echo    scripts\run_tests.bat         (run the automated test suite)
echo ============================================================
pause
