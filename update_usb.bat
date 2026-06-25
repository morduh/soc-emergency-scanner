@echo off
setlocal
color 0A
echo ========================================================
echo   SOC SCANNER - BUILD + USB SMART DEPLOYMENT SCRIPT
echo ========================================================
echo.

set PROJ=D:\College SOC Analyst\Projects\Final Project
set PYTHON=%PROJ%\WinPython\Python3.8\WPy64-38100\python-3.8.10.amd64\python.exe
set dest=J:

if not exist "%dest%\" (
    echo [ERROR] Drive %dest%\ does not exist or is not plugged in!
    pause
    exit /b
)

:: ── Step 1: Rebuild the EXE via python -m PyInstaller ────────────────────────
echo [1/5] Rebuilding SOC-Scanner.exe from app.py...
echo       (This takes 3-5 minutes - do not close this window)
echo.
cd /d "%PROJ%"
"%PYTHON%" -m PyInstaller --onefile --add-data "frontend\build;frontend\build" app.py --name SOC-Scanner --noconfirm > "%PROJ%\build.log" 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build FAILED! See build.log for details:
    echo   %PROJ%\build.log
    type "%PROJ%\build.log" | findstr /i "ERROR"
    pause
    exit /b 1
)

if not exist "%PROJ%\dist\SOC-Scanner.exe" (
    echo [ERROR] dist\SOC-Scanner.exe not found after build. Check build.log.
    pause
    exit /b 1
)

:: Move freshly built exe to project root
copy /Y "%PROJ%\dist\SOC-Scanner.exe" "%PROJ%\SOC-Scanner.exe"
echo [OK] New SOC-Scanner.exe built successfully.
echo.

:: ── Steps 2-5: Deploy to USB ─────────────────────────────────────────────────
echo [2/5] Deploying to %dest%\ ...

echo [3/5] Copying SOC-Scanner.exe...
copy /Y "%PROJ%\SOC-Scanner.exe" "%dest%\"

echo [4/5] Syncing bin\ (signatures + LLM engine)...
xcopy /E /I /Y /D "%PROJ%\bin" "%dest%\bin"

echo [5/5] Syncing models\ (skips existing large files)...
xcopy /E /I /Y /D "%PROJ%\models" "%dest%\models"

if not exist "%dest%\reports" mkdir "%dest%\reports"

echo.
echo ========================================================
echo SUCCESS! USB at %dest%\ rebuilt and fully updated.
echo ========================================================
pause