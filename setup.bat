@echo off
setlocal

echo ============================================
echo   CloudSec Scanner - Windows Setup
echo ============================================
echo.

REM --- check python is installed and on PATH ---
where python >nul 2>&1
if errorlevel 1 (
    echo [X] Python was not found.
    echo.
    echo     Install it from https://python.org/downloads
    echo     IMPORTANT: on the install screen, check the box
    echo     "Add python.exe to PATH" before clicking Install.
    echo.
    echo     Then run this setup.bat again.
    pause
    exit /b 1
)
echo [OK] Python found:
python --version
echo.

REM --- create the virtual environment ---
if exist venv (
    echo [OK] Virtual environment already exists, skipping creation.
) else (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [X] Failed to create virtual environment. See error above.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
)
echo.

REM --- install the package (using venv's python directly avoids any
REM     PowerShell/cmd activation-script issues entirely) ---
echo Installing CloudSec Scanner and dependencies...
venv\Scripts\python.exe -m pip install --upgrade pip -q
venv\Scripts\python.exe -m pip install -e . -q
if errorlevel 1 (
    echo [X] Install failed. See error above.
    pause
    exit /b 1
)
echo [OK] Installed.
echo.

REM --- verify it actually works ---
echo Verifying installation...
venv\Scripts\python.exe -m cloudsec_scanner.cli doctor
echo.

echo ============================================
echo   Setup complete!
echo ============================================
echo.
echo   To use the tool from now on, just run:
echo       run.bat scan --provider aws
echo       run.bat list-checks --provider aws
echo.
echo   (run.bat handles the venv for you automatically)
echo.
pause
