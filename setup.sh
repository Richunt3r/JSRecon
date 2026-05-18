#!/bin/bash
# Quick Start Script for JS Recon Tool
# Author: VIVEK GOSWAMI
# LinkedIn: https://www.linkedin.com/in/vivek-goswami

echo "=========================================="
echo "JS Recon Tool - Quick Start"
echo "Author: VIVEK GOSWAMI"
echo "=========================================="
echo ""

# Check Python version
python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

echo "✅ Python 3 detected"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -q requests urllib3 2>/dev/null || pip install -q requests urllib3
echo "✅ Dependencies installed"

# Make script executable
chmod +x js_recon.py

echo ""
echo "=========================================="
echo "Setup Complete! 🎉"
echo "=========================================="
echo ""
echo "Usage Examples:"
echo ""
echo "  Basic scan:"
echo "  python3 js_recon.py -u example.com"
echo ""
echo "  Fast scan (more threads):"
echo "  python3 js_recon.py -u example.com -t 20"
echo ""
echo "  Deep scan:"
echo "  python3 js_recon.py -u example.com -d 5"
echo ""
echo "  Full scan with custom output:"
echo "  python3 js_recon.py -u example.com -t 30 -d 4 -o my_results"
echo ""
echo "For help:"
echo "  python3 js_recon.py -h"
echo ""
echo "=========================================="
echo "Created by: VIVEK GOSWAMI"
echo "LinkedIn: https://www.linkedin.com/in/vivek-goswami"
echo "Follow for more security tools!"
echo "=========================================="
echo ""
