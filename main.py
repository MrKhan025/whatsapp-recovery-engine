#!/usr/bin/env python3
"""Root entry point (`main.py`) for WhatsApp Recovery Engine v2.0."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wtk.cli import main

if __name__ == "__main__":
    main()
