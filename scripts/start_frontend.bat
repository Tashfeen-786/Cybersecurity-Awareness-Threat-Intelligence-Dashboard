@echo off
REM Open the dashboard in the browser. The FastAPI backend serves the
REM frontend at http://127.0.0.1:8000 - start_backend.bat must be running.
REM (Optional alternative: a separate static server on port 5500.)
cd /d "%~dp0.."
echo Opening the Cybersecurity Awareness & Threat Intelligence Dashboard ...
start "" "http://127.0.0.1:8000/"
echo.
echo If the page cannot reach the API, start the backend first:
echo    scripts\start_backend.bat
echo.
echo OPTIONAL - separate static frontend server on port 5500:
echo    python -m http.server 5500 --directory frontend
echo    (then open http://127.0.0.1:5500 - the frontend auto-detects the API)
timeout /t 3 >nul
