#!/bin/bash

# Check if Inkscape is installed
if ! command -v inkscape &> /dev/null; then
    echo "Error: Inkscape is not installed. Please install it first."
    echo "On Ubuntu/Debian: sudo apt-get install inkscape"
    echo "On Fedora: sudo dnf install inkscape"
    echo "On macOS: brew install inkscape"
    exit 1
fi

# Check if logo.svg exists
if [ ! -f "logo.svg" ]; then
    echo "Error: logo.svg not found in current directory"
    exit 1
fi

# Generate the logo
echo "Generating logo.png from logo.svg..."
if inkscape -w 192 -h 192 logo.svg -o logo.png; then
    echo "Successfully generated logo.png"
else
    echo "Error: Failed to generate logo.png"
    exit 1
fi
