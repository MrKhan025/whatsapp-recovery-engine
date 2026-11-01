#!/usr/bin/env bash
# WhatsApp Recovery Engine (v1.0) - One-Step Android Termux Setup & Launcher
set -euo pipefail

echo "=========================================================="
echo "  WhatsApp Recovery Engine (v1.0) - Termux Setup          "
echo "=========================================================="

if command -v pkg >/dev/null 2>&1; then
  echo "[1/4] Updating Termux packages and installing Python & Git..."
  pkg update -y && pkg upgrade -y
  pkg install -y python git libjpeg-turbo freetype
fi

if command -v termux-setup-storage >/dev/null 2>&1; then
  echo "[2/4] Requesting Android shared storage access (tap Allow if prompted)..."
  termux-setup-storage
fi

echo "[3/4] Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements-termux.txt

echo "[4/4] Initializing synthetic sample data & starting dashboard on http://127.0.0.1:8000 ..."
python -m wtk init-sample
exec python -m wtk serve --host 127.0.0.1 --port 8000
