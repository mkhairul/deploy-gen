#!/bin/bash

echo "Building deploy-gen binary..."

# Ensure we're using the Python from the virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Warning: No active virtual environment detected."
    echo "It's recommended to run this script within a virtual environment."
    echo "Activate your virtual environment first with:"
    echo "  source .venv/bin/activate (Linux/macOS)"
    echo "  .venv\\Scripts\\activate (Windows)"
    
    # Ask if user wants to continue
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Build aborted."
        exit 1
    fi
else
    echo "Using Python from virtual environment: $VIRTUAL_ENV"
fi

# Use python from the virtual environment
PYTHON="python"
if [ -n "$VIRTUAL_ENV" ]; then
    if [ -f "$VIRTUAL_ENV/bin/python" ]; then
        PYTHON="$VIRTUAL_ENV/bin/python"
    elif [ -f "$VIRTUAL_ENV/Scripts/python.exe" ]; then
        PYTHON="$VIRTUAL_ENV/Scripts/python.exe"
    fi
fi

# Check if PyInstaller is installed
if ! $PYTHON -m pip show pyinstaller > /dev/null 2>&1; then
    echo "PyInstaller not found. Installing..."
    $PYTHON -m pip install pyinstaller
    if [ $? -ne 0 ]; then
        echo "Failed to install PyInstaller. Please install it manually."
        exit 1
    fi
fi

# Make sure all dependencies are installed
echo "Installing dependencies..."
$PYTHON -m pip install -r requirements.txt

# Build the binary using the spec file
echo "Building binary with PyInstaller..."
$PYTHON -m PyInstaller deploy-gen.spec

echo ""
echo "Build complete! The executable can be found in the dist/deploy-gen directory."
echo ""

# Create dist/deploy-gen directory if it doesn't exist
if [ ! -d "dist/deploy-gen" ]; then
    echo "Creating dist/deploy-gen directory..."
    mkdir -p dist/deploy-gen
fi

# Make the binary executable if it exists
if [ -f "dist/deploy-gen/deploy-gen" ]; then
    chmod +x dist/deploy-gen/deploy-gen
    echo "Made binary executable."
elif [ -d "dist/deploy-gen" ]; then
    # Try to find the executable in the directory
    BINARY=$(find dist/deploy-gen -type f -executable -name "deploy-gen*" | head -1)
    if [ -n "$BINARY" ]; then
        echo "Found binary at: $BINARY"
        chmod +x "$BINARY"
        echo "Made binary executable."
    else
        echo "Warning: Could not find the binary to make executable."
        echo "You may need to manually make it executable after locating it."
    fi
else
    echo "Warning: dist/deploy-gen directory not found. Build may have failed or used a different output path."
fi 