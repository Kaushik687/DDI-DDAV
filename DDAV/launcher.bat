@echo off
chcp 65001 >nul
cls
echo ==========================================
echo    DDAV - Deep Device Anti Virus
echo ==========================================
echo.
echo Requesting Administrator privileges...
echo.

:: Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    goto :run_app
) else (
    echo Not running as administrator. Requesting elevation...
    goto :request_admin
)

:request_admin
:: Create a temporary VBScript to request admin elevation
set "vbsFile=%TEMP%\DDAV_Admin_Elevator.vbs"
echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsFile%"
echo UAC.ShellExecute "%~f0", "", "", "runas", 1 >> "%vbsFile%"
"%vbsFile%"
del "%vbsFile%"
exit /b

:run_app
echo.
echo ==========================================
echo    Starting DDAV Scanner...
echo ==========================================
echo.

:: Find Python executable
set "PYTHON_EXE="

:: Check for managed Python runtime
if exist "%USERPROFILE%\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%USERPROFILE%\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Scripts\python.exe"
    goto :found_python
)

:: Check for common Python installations
if exist "C:\Python312\python.exe" (
    set "PYTHON_EXE=C:\Python312\python.exe"
    goto :found_python
)
if exist "C:\Python311\python.exe" (
    set "PYTHON_EXE=C:\Python311\python.exe"
    goto :found_python
)
if exist "C:\Python310\python.exe" (
    set "PYTHON_EXE=C:\Python310\python.exe"
    goto :found_python
)
if exist "C:\Python39\python.exe" (
    set "PYTHON_EXE=C:\Python39\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    goto :found_python
)

:: Check if python is in PATH
for %%X in (python.exe) do (set "PYTHON_EXE=%%~$PATH:X")
if not defined PYTHON_EXE (
    for %%X in (python3.exe) do (set "PYTHON_EXE=%%~$PATH:X")
)

:found_python
if not defined PYTHON_EXE (
    echo ERROR: Python was not found on this system.
    echo.
    echo Please install Python 3.9 or later from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo Using Python: %PYTHON_EXE%
echo.

:: Get the directory where this batch file is located
set "DDAV_DIR=%~dp0"
set "DDAV_MAIN=%DDAV_DIR%ddav_main.py"

if not exist "%DDAV_MAIN%" (
    echo ERROR: DDAV main file not found at: %DDAV_MAIN%
    echo.
    echo Please ensure all DDAV files are in the same folder.
    pause
    exit /b 1
)

echo Launching DDAV...
echo.

:: Run the application
"%PYTHON_EXE%" "%DDAV_MAIN%"

if %errorLevel% neq 0 (
    echo.
    echo DDAV exited with an error.
    pause
)

exit /b
