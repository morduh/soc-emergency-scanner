@echo off
echo Updating USB Drive (J:)...

:: 1. Copy the main python file
copy "d:\College SOC Analyst\Projects\Final Project\app.py" J:\ /Y

:: 2. Copy the frontend folder (overwriting old files)
xcopy /E /I /Y "d:\College SOC Analyst\Projects\Final Project\frontend" J:\frontend

echo.
echo =========================================
echo DONE! Your USB is fully updated on J:
echo =========================================
pause