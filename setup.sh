#!/bin/bash
set -e

echo "============================================"
echo "  CloudSec Scanner - Setup"
echo "============================================"
echo

# --- check python3 is installed ---
if ! command -v python3 &> /dev/null; then
    echo "[X] python3 was not found."
    echo
    echo "    Install it with:"
    echo "      sudo apt update && sudo apt install python3 python3-pip python3-venv"
    echo
    exit 1
fi
echo "[OK] Python found:"
python3 --version
echo

# --- create the virtual environment ---
if [ -d "venv" ]; then
    echo "[OK] Virtual environment already exists, skipping creation."
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "[OK] Virtual environment created."
fi
echo

# --- install the package ---
echo "Installing CloudSec Scanner and dependencies..."
venv/bin/python -m pip install --upgrade pip -q
venv/bin/python -m pip install -e . -q
echo "[OK] Installed."
echo

# --- verify it actually works ---
echo "Verifying installation..."
venv/bin/python -m cloudsec_scanner.cli doctor
echo

chmod +x run.sh 2>/dev/null || true

echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo
echo "  To use the tool from now on, just run:"
echo "      ./run.sh scan --provider aws"
echo "      ./run.sh list-checks --provider aws"
echo
echo "  (run.sh handles the venv for you automatically)"
echo
