@echo off
setlocal EnableDelayedExpansion
color 0A
echo ============================================================
echo   SOC EMERGENCY SCANNER — FIRST-TIME SETUP
echo ============================================================
echo.
echo This script will:
echo   [1] Download the Qwen2.5 AI model  (~4.4 GB)
echo   [2] Download ClamAV signature DB   (~33 MB)
echo   [3] Download MalwareBazaar DB      (~70 MB)
echo   [4] Install frontend dependencies  (npm install)
echo   [5] Build the React frontend       (npm run build)
echo   [6] Build SOC-Scanner.exe          (PyInstaller)
echo.
echo  Prerequisites (must be installed first):
echo   - Python 3.8 or higher  (https://www.python.org/downloads/)
echo   - pip install pyinstaller pywebview requests
echo   - Node.js + npm          (https://nodejs.org/)
echo.
pause

set PROJ=%~dp0
set PROJ=%PROJ:~0,-1%

:: ── Verify Python is available ───────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://www.python.org/downloads/
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
echo [OK] Python found.

:: ── Verify pip packages ───────────────────────────────────────────────────────
echo.
echo [STEP] Installing Python dependencies from requirements.txt...
pip install -r "%PROJ%\requirements.txt"
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Python dependencies installed.

:: ── Verify Node.js is available ──────────────────────────────────────────────
npm --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js / npm not found. Install from https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js found.

:: ── Create required folders ───────────────────────────────────────────────────
if not exist "%PROJ%\bin"     mkdir "%PROJ%\bin"
if not exist "%PROJ%\models"  mkdir "%PROJ%\models"
if not exist "%PROJ%\reports" mkdir "%PROJ%\reports"
echo [OK] Folders created.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 1 — Download Qwen2.5 AI Model (~4.4 GB)
:: ═══════════════════════════════════════════════════════════════════════════
set MODEL_FILE=%PROJ%\models\Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
set MODEL_URL=https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf

if exist "%MODEL_FILE%" (
    echo [SKIP] AI model already present. Skipping download.
) else (
    echo.
    echo [STEP 1/6] Downloading AI model from HuggingFace...
    echo            This is a 4.4 GB file — may take 10-30 minutes.
    echo.
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%MODEL_URL%' -OutFile '%MODEL_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo [ERROR] Model download failed. Check internet connection.
        echo         Manual download: https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF
        echo         File: Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf  →  place in .\models\
        pause
        exit /b 1
    )
    echo [OK] AI model downloaded.
)

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 2 — Download ClamAV Main Signature Database (~33 MB)
:: ═══════════════════════════════════════════════════════════════════════════
set CLAMAV_FILE=%PROJ%\bin\clamav.hsb
set CLAMAV_URL=https://database.clamav.net/main.hsb

if exist "%CLAMAV_FILE%" (
    echo [SKIP] ClamAV database already present. Skipping download.
) else (
    echo.
    echo [STEP 2/6] Downloading ClamAV signature database...
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%CLAMAV_URL%' -OutFile '%CLAMAV_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo [WARN] ClamAV download failed. The app will still work without it.
        echo        Manual: https://database.clamav.net/main.hsb  →  rename to clamav.hsb  →  place in .\bin\
    ) else (
        echo [OK] ClamAV database downloaded.
    )
)

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 3 — Download MalwareBazaar Signature Database (~70 MB)
:: ═══════════════════════════════════════════════════════════════════════════
set BAZAAR_FILE=%PROJ%\bin\bazaar.hsb
set BAZAAR_URL=https://bazaar.abuse.ch/export/txt/sha256/full/

if exist "%BAZAAR_FILE%" (
    echo [SKIP] MalwareBazaar database already present. Skipping download.
) else (
    echo.
    echo [STEP 3/6] Downloading MalwareBazaar hash database...
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%BAZAAR_URL%' -OutFile '%BAZAAR_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo [WARN] MalwareBazaar download failed. The app will still work without it.
        echo        Manual: https://bazaar.abuse.ch/export/txt/sha256/full/  →  rename to bazaar.hsb  →  place in .\bin\
    ) else (
        echo [OK] MalwareBazaar database downloaded.
    )
)

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 4 — Frontend: npm install
:: ═══════════════════════════════════════════════════════════════════════════
echo.
echo [STEP 4/6] Installing frontend Node.js dependencies...
cd /d "%PROJ%\frontend"
call npm install
if errorlevel 1 (
    echo [ERROR] npm install failed. Check your internet connection and Node.js install.
    pause
    exit /b 1
)
echo [OK] Frontend dependencies installed.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 5 — Frontend: npm run build
:: ═══════════════════════════════════════════════════════════════════════════
echo.
echo [STEP 5/6] Building React frontend...
call npm run build
if errorlevel 1 (
    echo [ERROR] Frontend build failed. Check Node.js / npm version.
    pause
    exit /b 1
)
echo [OK] Frontend built.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 6 — Build the EXE with PyInstaller
:: ═══════════════════════════════════════════════════════════════════════════
echo.
echo [STEP 6/6] Building SOC-Scanner.exe with PyInstaller...
echo            (This takes 3-5 minutes — do not close this window)
cd /d "%PROJ%"
python -m PyInstaller --onefile --add-data "frontend\build;frontend\build" app.py --name SOC-Scanner --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller build FAILED. Make sure pyinstaller is installed:
    echo         pip install pyinstaller
    pause
    exit /b 1
)

:: Copy built exe to project root
copy /Y "%PROJ%\dist\SOC-Scanner.exe" "%PROJ%\SOC-Scanner.exe"
echo [OK] SOC-Scanner.exe built successfully.

:: ═══════════════════════════════════════════════════════════════════════════
:: DONE
:: ═══════════════════════════════════════════════════════════════════════════
echo.
echo ============================================================
echo   SETUP COMPLETE!
echo ============================================================
echo.
echo   To run the scanner:
echo     Double-click SOC-Scanner.exe
echo     (bin\ and models\ must be in the SAME folder as the exe)
echo.
echo   To deploy to USB:
echo     1. Copy SOC-Scanner.exe  to USB
echo     2. Copy bin\             to USB
echo     3. Copy models\          to USB
echo     4. Create empty reports\ folder on USB
echo.
echo ============================================================
pause
