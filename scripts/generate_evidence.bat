@echo off
REM Generate the local evidence screenshots (items 1-34 of the 37-item
REM checklist) from the REAL running application.
REM Requires: backend running (scripts\start_backend.bat)
REM           playwright installed  (pip install playwright && playwright install chromium)
REM Items 35-37 (GitHub commits / repository / README preview) are MANUAL.
cd /d "%~dp0.."
if exist venv\Scripts\activate.bat ( call venv\Scripts\activate.bat )
echo Generating evidence from the live application ...
python scripts\generate_evidence.py
if errorlevel 1 (
    echo.
    echo [INFO] Browser evidence requires Playwright:
    echo    pip install playwright
    echo    playwright install chromium
    echo Data-derived evidence (dataset/tests/API/DB) still generated above.
)
pause
