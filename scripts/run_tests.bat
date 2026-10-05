@echo off
REM Run the complete automated test suite (72 tests:
REM 35 functional scenarios + security/privacy verification).
cd /d "%~dp0.."
if exist venv\Scripts\activate.bat ( call venv\Scripts\activate.bat )
echo Running automated tests ...
python -m pytest tests -v --junitxml=reports\junit_results.xml
set RESULT=%ERRORLEVEL%
echo.
if %RESULT%==0 (
    echo ============================================================
    echo  ALL TESTS PASSED
    echo  JUnit results: reports\junit_results.xml
    echo  Human-readable report: run  python scripts\make_test_report.py
    echo ============================================================
) else (
    echo SOME TESTS FAILED - see output above.
)
pause
