#!/bin/bash

# GHOSTSHELL Application Launcher for Unix/Linux/macOS
# This script runs the Python launcher

set -e  # Exit on any error

echo "Starting GHOSTSHELL Application Launcher..."
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python not found. Please install Python from https://python.org/"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

echo "Using Python: $PYTHON_CMD"

# Make sure we're in the right directory
cd "$(dirname "$0")"

# Run the Python launcher
$PYTHON_CMD run.py
