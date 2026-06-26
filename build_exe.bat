@echo off
::
:: ─────────────────────────────────────────────────────────────────────────────
:: build_exe.bat — FOR DEVELOPERS ONLY
::
:: PURPOSE : Rebuilds SOC-Scanner.exe from source (app.py + React frontend).
::           Only needed if you modified app.py or the frontend source code.
::           End users do NOT need to run this — SOC-Scanner.exe is already
::           included in the repository and ready to use.
::
:: REQUIRES:
::   - Python 3.8+  installed and on PATH  (python.org/downloads)
::   - PyInstaller  installed               (pip install pyinstaller)
::   - Node.js      installed               (nodejs.org)
::   - pip install -r requirements.txt      (run once before building)
:: ─────────────────────────────────────────────────────────────────────────────
::
setlocal
color 0A
echo ========================================================
echo   SOC SCANNER - REBUILD EXE FROM SOURCE
echo   (For developers only — end users: use SOC-Scanner.exe)
echo ========================================================
echo.

set PROJ=%~dp0
set PROJ=%PROJ:~0,-1%

echo [1/3] Building React frontend...
cd /d "%PROJ%\frontend"
call npm install
call npm run build
if errorlevel 1 (
    echo [WARN] Frontend build failed or skipped - using existing build.
)

echo.
echo [2/3] Building SOC-Scanner.exe with PyInstaller...
cd /d "%PROJ%"
python -m PyInstaller --onefile --add-data "frontend\build;frontend\build" app.py --name SOC-Scanner --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller build FAILED. Check output above.
    pause
    exit /b 1
)

echo.
echo [3/3] Copying new exe to project root...
copy /Y "%PROJ%\dist\SOC-Scanner.exe" "%PROJ%\SOC-Scanner.exe"
echo.
echo [DONE] SOC-Scanner.exe has been rebuilt successfully.
echo ========================================================
pause
