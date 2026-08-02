@echo off
if not exist "%~dp0venv\Scripts\python.exe" (
    echo Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)
"%~dp0venv\Scripts\python.exe" -m cloudsec_scanner.cli %*
