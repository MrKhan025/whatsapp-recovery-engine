#!/usr/bin/env python3
"""Root entry point (`main.py`) for WhatsApp Recovery Engine (v1.0).

Allows users on Termux, Android, Windows, Linux, and macOS to start the platform
simply by running:

    python main.py

If CLI subcommands are provided (e.g. `python main.py scan --source ...`),
it forwards them to `wtk.cli.main()`. With no arguments, it initializes sample
data and launches the local web dashboard at http://127.0.0.1:8000.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wtk.cli import main

if __name__ == "__main__":
    main()
