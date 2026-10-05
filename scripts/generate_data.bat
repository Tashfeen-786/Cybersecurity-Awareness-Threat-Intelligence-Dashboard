@echo off
REM Regenerate the synthetic threat-intelligence dataset (2,200 records)
REM and the synthetic vulnerability dataset (60 CVEs). Deterministic seed.
cd /d "%~dp0.."
if exist venv\Scripts\activate.bat ( call venv\Scripts\activate.bat )
echo Generating synthetic datasets (safe documentation-range indicators only) ...
python data\generate_threat_data.py
if errorlevel 1 ( echo [ERROR] generation failed & pause & exit /b 1 )
echo.
echo Done. Re-initialize the database to load the new data:
echo    python -m scripts.init_database
pause
