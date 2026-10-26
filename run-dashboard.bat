@echo off
cd /d "%~dp0"
title GIGANG SecOps Dashboard

echo ============================================================
echo   Starting GIGANG SecOps Dashboard...
echo   Browser will open automatically: http://localhost:8501
echo ============================================================
echo.

python -m streamlit run app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Streamlit failed to run.
    echo Please ensure dependencies are installed: pip install -r requirements.txt
    pause
)
