"""
Vercel Serverless ASGI Entrypoint (`api/index.py`)
Exposes the FastAPI `app` instance from `reality_gate.api.app` for Vercel Python runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from reality_gate.api.app import app

__all__ = ["app"]
