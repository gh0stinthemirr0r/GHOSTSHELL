@echo off
REM GHOSTSHELL Application Launcher for Windows
REM This batch file runs the Python launcher script

echo Starting GHOSTSHELL Application Launcher...
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python from https://python.org/
    echo Make sure to add Python to your PATH during installation.
    pause
    exit /b 1
)

REM Run the Python launcher
python run.py

REM Keep window open if there was an error
if %errorlevel% neq 0 (
    echo.
    echo Application exited with error code %errorlevel%
    pause
)
