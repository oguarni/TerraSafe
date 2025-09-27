#!/bin/bash

# Demo script for Terraform Security Scanner
# Shows three different security levels: Critical, Clean, and Mixed

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

# Create models directory if it doesn't exist
mkdir -p models

echo ""
echo "▶ TEST 1: HIGH RISK Configuration (vulnerable.tf)"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/vulnerable.tf

echo ""
echo "▶ TEST 2: SECURE Configuration (secure.tf)"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/secure.tf

echo ""
echo "▶ TEST 3: MEDIUM RISK Configuration (mixed.tf)"
echo "═══════════════════════════════════════════════════════"
python security_scanner.py test_files/mixed.tf

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✓ Security analysis completed for all configurations!"
echo ""
echo "Summary:"
echo "  • vulnerable.tf: Multiple critical issues detected"
echo "  • secure.tf: Follows security best practices"
echo "  • mixed.tf: Some improvements recommended"
echo "═══════════════════════════════════════════════════════"
