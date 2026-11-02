#!/usr/bin/env bash
# WhatsApp Recovery Engine (v1.0) - Android Termux Setup & Launcher
# Fixed for Termux Python 3.13:
# 1. Never runs 'pip install --upgrade pip' (forbidden by Termux python-pip).
# 2. Automatically cd's into the repository root directory.
# 3. Uses --extra-index-url https://termux-user-repository.github.io/pypi/ so
#    pydantic-core installs from prebuilt Android aarch64 wheels without Rust/maturin errors.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "=========================================================="
echo "  WhatsApp Recovery Engine (v1.0) - Termux Launcher       "
echo "  Directory: ${REPO_ROOT}"
echo "=========================================================="

if command -v pkg >/dev/null 2>&1; then
  echo "[1/4] Checking Termux system packages..."
  pkg install -y python git libjpeg-turbo freetype || true
fi

if command -v termux-setup-storage >/dev/null 2>&1; then
  if [ ! -d "$HOME/storage" ]; then
    echo "[2/4] Requesting Android shared storage access (tap Allow if prompted)..."
    termux-setup-storage || true
  else
    echo "[2/4] Android shared storage (~/storage) already configured."
  fi
fi

echo "[3/4] Installing Python dependencies (using prebuilt Termux wheels)..."
pip install --extra-index-url https://termux-user-repository.github.io/pypi/ -r requirements-termux.txt

echo "[4/4] Initializing sample data & starting dashboard at http://127.0.0.1:8000 ..."
python main.py init-sample
exec python main.py serve --host 127.0.0.1 --port 8000
