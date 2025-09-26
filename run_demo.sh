#!/bin/bash

# Demo script for Terraform Security Scanner
# Generates examples for documentation

echo "═══════════════════════════════════════════════════════"
echo "    TERRAFORM SECURITY SCANNER - DEMONSTRATION"
echo "═══════════════════════════════════════════════════════"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "▶ TEST 1: Scanning VULNERABLE configuration"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/vulnerable.tf

echo ""
echo "▶ TEST 2: Scanning SECURE configuration"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/secure.tf

echo ""
echo "▶ TEST 3: Error handling - Non-existent file"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/nonexistent.tf

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✓ Demo completed! Take screenshots of the output above"
echo "═══════════════════════════════════════════════════════"