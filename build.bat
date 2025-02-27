@echo off
echo Building deploy-gen binary...

REM Build the binary using the spec file
set PYTHON=python
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