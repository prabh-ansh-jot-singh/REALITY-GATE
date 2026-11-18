"""
REALITY-GATE v2.0 — Clean Application Entrypoint
Launches the modular FastAPI application (`reality_gate.api.app:app`) with Uvicorn.
"""

from __future__ import annotations

import os
import uvicorn

from reality_gate.api.app import app

__all__ = ["app"]


if __name__ == "__main__":
    host = os.getenv("REALITY_GATE_HOST", "127.0.0.1")
    port = int(os.getenv("REALITY_GATE_PORT", "8000"))
    print(f"\n[REALITY-GATE v2.0] Starting Modular Enterprise Security Platform on http://{host}:{port}")
    print(f"[REALITY-GATE v2.0] Interactive Swagger API Docs: http://{host}:{port}/docs\n")
    uvicorn.run("reality_gate.api.app:app", host=host, port=port, reload=False)
