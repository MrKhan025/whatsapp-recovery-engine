#!/usr/bin/env bash
# WhatsApp Recovery Engine v2.0 — Android Termux Setup & Launcher
# 1. Never runs 'pip install --upgrade pip' (forbidden by Termux python-pip).
# 2. Sets PIP_EXTRA_INDEX_URL to Termux User Repository so pydantic-core/cryptography
#    never trigger Rust/maturin source builds.
# 3. Automatically runs 'main.py' (or falls back to 'python -m wtk').

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

export PIP_EXTRA_INDEX_URL="https://termux-user-repository.github.io/pypi/"

echo "=========================================================="
echo "  WhatsApp Recovery Engine v2.0 — Termux Launcher         "
echo "  Directory: ${REPO_ROOT}"
echo "=========================================================="

if command -v pkg >/dev/null 2>&1; then
  echo "[1/4] Checking Termux system packages..."
  pkg install -y tur-repo || true
  pkg install -y python git libjpeg-turbo freetype android-tools python-cryptography || true
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
if [ -f "${REPO_ROOT}/main.py" ]; then
  python main.py init-sample
  exec python main.py serve --host 127.0.0.1 --port 8000
else
  python -m wtk init-sample
  exec python -m wtk serve --host 127.0.0.1 --port 8000
fi
