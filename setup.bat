@echo off
setlocal EnableDelayedExpansion
color 0A
echo ============================================================
echo   SOC EMERGENCY SCANNER — FIRST-TIME SETUP
echo ============================================================
echo.
echo  This script will automatically download:
echo    - Qwen2.5 AI model      (~4.4 GB)
echo    - ClamAV signature DB   (~33 MB)
echo    - MalwareBazaar hash DB (~70 MB)
echo.
echo  No Python, no installs, no browser needed.
echo  After this is done, just double-click SOC-Scanner.exe
echo.
echo  NOTE: The model download is ~4.4 GB.
echo        Make sure you have enough disk space and a stable connection.
echo        You only need to run this ONCE.
echo.
pause

:: ── Create required folders ───────────────────────────────────────────────────
if not exist "%~dp0bin"     mkdir "%~dp0bin"
if not exist "%~dp0models"  mkdir "%~dp0models"
if not exist "%~dp0reports" mkdir "%~dp0reports"
echo [OK] Folders ready.
echo.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 1 — Download Qwen2.5 AI Model (~4.4 GB)
:: ═══════════════════════════════════════════════════════════════════════════
set MODEL_FILE=%~dp0models\Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
set MODEL_URL=https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf

if exist "%MODEL_FILE%" (
    echo [SKIP] AI model already present.
) else (
    echo [1/3] Downloading AI model from HuggingFace...
    echo       File size: ~4.4 GB. This will take time. Do NOT close this window.
    echo.
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%MODEL_URL%' -OutFile '%MODEL_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo.
        echo [ERROR] Model download failed.
        echo         Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo [OK] AI model downloaded.
)
echo.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 2 — Download ClamAV Signature Database (~33 MB)
:: ═══════════════════════════════════════════════════════════════════════════
set CLAMAV_FILE=%~dp0bin\clamav.hsb
set CLAMAV_URL=https://database.clamav.net/main.hsb

if exist "%CLAMAV_FILE%" (
    echo [SKIP] ClamAV database already present.
) else (
    echo [2/3] Downloading ClamAV signature database...
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%CLAMAV_URL%' -OutFile '%CLAMAV_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo [WARN] ClamAV download failed. App will still work without it.
    ) else (
        echo [OK] ClamAV database downloaded.
    )
)
echo.

:: ═══════════════════════════════════════════════════════════════════════════
:: STEP 3 — Download MalwareBazaar Hash Database (~70 MB)
:: ═══════════════════════════════════════════════════════════════════════════
set BAZAAR_FILE=%~dp0bin\bazaar.hsb
set BAZAAR_URL=https://bazaar.abuse.ch/export/txt/sha256/full/

if exist "%BAZAAR_FILE%" (
    echo [SKIP] MalwareBazaar database already present.
) else (
    echo [3/3] Downloading MalwareBazaar hash database...
    powershell -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%BAZAAR_URL%' -OutFile '%BAZAAR_FILE%' -UseBasicParsing }"
    if errorlevel 1 (
        echo [WARN] MalwareBazaar download failed. App will still work without it.
    ) else (
        echo [OK] MalwareBazaar database downloaded.
    )
)
echo.

:: ═══════════════════════════════════════════════════════════════════════════
:: DONE
:: ═══════════════════════════════════════════════════════════════════════════
echo ============================================================
echo   SETUP COMPLETE!
echo ============================================================
echo.
echo   Everything is ready. To launch the scanner:
echo   - Double-click SOC-Scanner.exe
echo.
echo   To put this on a USB drive:
echo   1. Copy SOC-Scanner.exe  to USB
echo   2. Copy bin\             to USB
echo   3. Copy models\          to USB
echo   4. Create empty reports\ folder on USB
echo   Then double-click SOC-Scanner.exe from the USB.
echo.
echo ============================================================
pause
