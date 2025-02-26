@echo off
echo Building deploy-gen binary...

REM Ensure we're using the Python from the virtual environment
if "%VIRTUAL_ENV%"=="" (
    echo Warning: No active virtual environment detected.
    echo It's recommended to run this script within a virtual environment.
    echo Activate your virtual environment first with:
    echo   .venv\Scripts\activate
    
    set /p CONTINUE=Continue anyway? (y/n): 
    if /i not "%CONTINUE%"=="y" (
        echo Build aborted.
        exit /b 1
    )
) else (
    echo Using Python from virtual environment: %VIRTUAL_ENV%
)

REM Use python from the virtual environment if available
set PYTHON=python
if not "%VIRTUAL_ENV%"=="" (
    if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
        set PYTHON=%VIRTUAL_ENV%\Scripts\python.exe
    )
)

REM Check if PyInstaller is installed
%PYTHON% -m pip show pyinstaller > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo PyInstaller not found. Installing...
    %PYTHON% -m pip install pyinstaller
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install PyInstaller. Please install it manually.
        exit /b 1
    )
)

REM Make sure all dependencies are installed
echo Installing dependencies...
%PYTHON% -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo Warning: Some dependencies may not have installed correctly.
    echo Continuing with build anyway...
)

REM Build the binary using the spec file
echo Building binary with PyInstaller...
%PYTHON% -m PyInstaller deploy-gen.spec
if %ERRORLEVEL% NEQ 0 (
    echo Error: PyInstaller build failed.
    exit /b 1
)

echo.

REM Create dist\deploy-gen directory if it doesn't exist
if not exist dist\deploy-gen (
    echo Creating dist\deploy-gen directory...
    mkdir dist\deploy-gen
)

if exist dist\deploy-gen (
    echo Build complete! The executable can be found in the dist\deploy-gen directory.
    
    REM Check if the executable exists
    if exist dist\deploy-gen\deploy-gen.exe (
        echo Executable found at: dist\deploy-gen\deploy-gen.exe
    ) else (
        echo Note: Could not find deploy-gen.exe in the expected location.
        echo The executable may have a different name or location.
        dir /b dist\deploy-gen\*.exe
    )
) else (
    echo Warning: dist\deploy-gen directory not found. Build may have failed or used a different output path.
)
echo. 