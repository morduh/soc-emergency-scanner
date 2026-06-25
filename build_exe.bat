@echo off
setlocal
color 0A
echo ========================================================
echo       SOC SCANNER - BUILD + DEPLOY SCRIPT
echo ========================================================
echo.

set PYTHON=D:\College SOC Analyst\Projects\Final Project\WinPython\Python3.8\WPy64-38100\python-3.8.10.amd64\python.exe
set PYI=D:\College SOC Analyst\Projects\Final Project\WinPython\Python3.8\WPy64-38100\python-3.8.10.amd64\Scripts\pyinstaller.exe
set PROJ=D:\College SOC Analyst\Projects\Final Project

echo [1/3] Building React frontend...
cd /d "%PROJ%\frontend"
call npm run build
if errorlevel 1 (
    echo [WARN] Frontend build failed or skipped - using existing build.
)

echo.
echo [2/3] Building SOC-Scanner.exe with PyInstaller...
cd /d "%PROJ%"
"%PYI%" --onefile --add-data "frontend\build;frontend\build" app.py --name SOC-Scanner --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller build FAILED. Check output above.
    pause
    exit /b 1
)

echo.
echo [3/3] Moving new exe to project root...
copy /Y "%PROJ%\dist\SOC-Scanner.exe" "%PROJ%\SOC-Scanner.exe"
echo.
echo [DONE] Build complete. SOC-Scanner.exe updated in project root.
echo Run update_usb.bat to deploy to USB.
echo ========================================================
pause
