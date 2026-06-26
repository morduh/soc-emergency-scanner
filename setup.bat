@echo off
setlocal EnableDelayedExpansion
color 0A
echo ============================================================
echo   SOC EMERGENCY SCANNER -- FIRST-TIME SETUP
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

:: ── Verify curl.exe is available (built into Windows 10/11) ──────────────────
curl.exe --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl.exe not found.
    echo         This requires Windows 10 or Windows 11.
    echo         Please update your Windows version and try again.
    pause
    exit /b 1
)
echo [OK] curl.exe found.

:: ── Create required folders ───────────────────────────────────────────────────
if not exist "%~dp0bin"     mkdir "%~dp0bin"
if not exist "%~dp0models"  mkdir "%~dp0models"
if not exist "%~dp0reports" mkdir "%~dp0reports"
echo [OK] Folders ready.
echo.

:: =============================================================================
:: STEP 1 -- Download Qwen2.5 AI Model (~4.4 GB)
:: =============================================================================
set MODEL_FILE=%~dp0models\Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
set MODEL_URL_1=https://huggingface.co/tensorblock/Qwen2.5-7B-Instruct-1M-GGUF/resolve/main/Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
set MODEL_URL_2=https://huggingface.co/lmstudio-community/Qwen2.5-7B-Instruct-1M-GGUF/resolve/main/Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf

if exist "%MODEL_FILE%" (
    for %%A in ("%MODEL_FILE%") do set EXISTING_SIZE=%%~zA
    if !EXISTING_SIZE! GTR 3000000000 (
        echo [SKIP] AI model already present and valid.
        goto MODEL_DONE
    ) else (
        echo [INFO] Existing model file looks incomplete. Re-downloading...
        del "%MODEL_FILE%"
    )
)

echo [1/3] Downloading AI model from HuggingFace...
echo       File size: ~4.4 GB. This will take time. Do NOT close this window.
echo.

echo       Trying mirror 1 of 2...
curl.exe -L --fail --progress-bar -o "%MODEL_FILE%" "%MODEL_URL_1%"
echo.

:: Validate: file must be larger than 3 GB to be real
set MODEL_SIZE=0
if exist "%MODEL_FILE%" (
    for %%A in ("%MODEL_FILE%") do set MODEL_SIZE=%%~zA
)
if !MODEL_SIZE! GTR 3000000000 (
    echo [OK] AI model downloaded successfully.
    goto MODEL_DONE
)

:: First mirror failed - try second
echo       Mirror 1 failed. Trying mirror 2 of 2...
if exist "%MODEL_FILE%" del "%MODEL_FILE%"
curl.exe -L --fail --progress-bar -o "%MODEL_FILE%" "%MODEL_URL_2%"
echo.

set MODEL_SIZE=0
if exist "%MODEL_FILE%" (
    for %%A in ("%MODEL_FILE%") do set MODEL_SIZE=%%~zA
)
if !MODEL_SIZE! GTR 3000000000 (
    echo [OK] AI model downloaded successfully.
    goto MODEL_DONE
)

:: Both mirrors failed
if exist "%MODEL_FILE%" del "%MODEL_FILE%"
echo.
echo [ERROR] Could not download the AI model from either mirror.
echo.
echo  Please download it manually:
echo  1. Go to: https://huggingface.co/tensorblock/Qwen2.5-7B-Instruct-1M-GGUF
echo  2. Download: Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
echo  3. Place it in the 'models' folder next to this script
echo.
pause
exit /b 1

:MODEL_DONE
echo.

:: =============================================================================
:: STEP 2 -- Download ClamAV Signature Database (~33 MB)
:: =============================================================================
set CLAMAV_FILE=%~dp0bin\clamav.hsb
set CLAMAV_URL=https://database.clamav.net/main.hsb

if exist "%CLAMAV_FILE%" (
    for %%A in ("%CLAMAV_FILE%") do set EXISTING_SIZE=%%~zA
    if !EXISTING_SIZE! GTR 10000000 (
        echo [SKIP] ClamAV database already present and valid.
    ) else (
        del "%CLAMAV_FILE%"
        goto DOWNLOAD_CLAMAV
    )
) else (
    :DOWNLOAD_CLAMAV
    echo [2/3] Downloading ClamAV signature database...
    curl.exe -L -A "ClamAV/1.0.0" --progress-bar -o "%CLAMAV_FILE%" "%CLAMAV_URL%"
    echo.

    :: Validate: file must be larger than 10 MB to be real (not an HTML error page)
    if exist "%CLAMAV_FILE%" (
        for %%A in ("%CLAMAV_FILE%") do set CLAMAV_SIZE=%%~zA
        if !CLAMAV_SIZE! GTR 10000000 (
            echo [OK] ClamAV database downloaded.
        ) else (
            echo [WARN] ClamAV download was blocked by the server.
            echo        The app will still work - just with fewer offline signatures.
            del "%CLAMAV_FILE%" 2>nul
        )
    ) else (
        echo [WARN] ClamAV download failed. App will still work without it.
    )
)
echo.

:: =============================================================================
:: STEP 3 -- Download MalwareBazaar Hash Database (~70 MB)
:: =============================================================================
set BAZAAR_FILE=%~dp0bin\bazaar.hsb
set BAZAAR_URL=https://bazaar.abuse.ch/export/txt/sha256/full/

if exist "%BAZAAR_FILE%" (
    for %%A in ("%BAZAAR_FILE%") do set EXISTING_SIZE=%%~zA
    if !EXISTING_SIZE! GTR 10000000 (
        echo [SKIP] MalwareBazaar database already present and valid.
    ) else (
        del "%BAZAAR_FILE%"
        goto DOWNLOAD_BAZAAR
    )
) else (
    :DOWNLOAD_BAZAAR
    echo [3/3] Downloading MalwareBazaar hash database...
    curl.exe -L --progress-bar -o "%BAZAAR_FILE%" "%BAZAAR_URL%"
    echo.

    :: Validate: file must be larger than 10 MB to be real
    if exist "%BAZAAR_FILE%" (
        for %%A in ("%BAZAAR_FILE%") do set BAZAAR_SIZE=%%~zA
        if !BAZAAR_SIZE! GTR 10000000 (
            echo [OK] MalwareBazaar database downloaded.
        ) else (
            echo [WARN] MalwareBazaar download was blocked or failed.
            echo        The app will still work - just with fewer offline signatures.
            del "%BAZAAR_FILE%" 2>nul
        )
    ) else (
        echo [WARN] MalwareBazaar download failed. App will still work without it.
    )
)
echo.

:: =============================================================================
:: DONE
:: =============================================================================
echo ============================================================
echo   SETUP COMPLETE!
echo ============================================================
echo.
echo   To launch the scanner:
echo   -- Double-click SOC-Scanner.exe
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
