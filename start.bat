@echo off
rem Double-click to start Sentinela and open it in your browser.
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" start.py
) else (
    python start.py
)
pause
