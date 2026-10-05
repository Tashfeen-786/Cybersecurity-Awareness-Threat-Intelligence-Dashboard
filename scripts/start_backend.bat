@echo off
REM Initialize the SQLite database (if missing) and start the FastAPI
REM backend on http://127.0.0.1:8000  (API + docs + frontend in one server)
cd /d "%~dp0.."
set PYTHON=python
if exist venv\Scripts\python.exe set PYTHON=venv\Scripts\python.exe

if not exist data\threat_intelligence_dataset.csv (
    echo [INFO] Dataset missing - generating it first ...
    %PYTHON% data\generate_threat_data.py || ( echo [ERROR] generation failed & pause & exit /b 1 )
)

if not exist backend\threat_intel.db (
    echo [INFO] Database missing - initializing from synthetic data ...
    %PYTHON% -m scripts.init_database || ( echo [ERROR] DB init failed & pause & exit /b 1 )
)

echo ============================================================
echo  Starting backend:  http://127.0.0.1:8000
echo  API docs (Swagger): http://127.0.0.1:8000/docs
echo  Dashboard:          http://127.0.0.1:8000/
echo  Press CTRL+C to stop.
echo ============================================================
cd backend
..\%PYTHON% -m uvicorn app:app --host 127.0.0.1 --port 8000
pause
