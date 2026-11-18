"""
REALITY-GATE v2.0 — Configuration & Environment Settings
Loads .env configuration via python-dotenv with safe local defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR
LOGS_DIR = Path(os.getenv("REALITY_GATE_LOGS_DIR", str(BASE_DIR / "logs")))
LOGS_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv("REALITY_GATE_DB_PATH", str(DATA_DIR / "reality_gate.db")))
AUDIT_JSONL_PATH = Path(os.getenv("REALITY_GATE_AUDIT_PATH", str(LOGS_DIR / "audit.jsonl")))

# Cryptographic HMAC-SHA256 keys (override via environment in production)
JIT_HMAC_SECRET: bytes = os.getenv(
    "REALITY_GATE_JIT_SECRET",
    "rg-v2-hmac-jit-broker-secret-2026-deterministic"
).encode("utf-8")

TELEMETRY_HMAC_SECRET: bytes = os.getenv(
    "REALITY_GATE_TELEMETRY_SECRET",
    "rg-v2-vnet-flow-telemetry-integrity-key-2026"
).encode("utf-8")

# Deterministic invariant defaults
DEFAULT_NOISE_FLOOR_PKT_HR: int = int(os.getenv("RG_NOISE_FLOOR_PKT_HR", "10"))
DEFAULT_FRESHNESS_SLA_SEC: int = int(os.getenv("RG_FRESHNESS_SLA_SEC", "300"))
DEFAULT_JIT_TTL_SEC: int = int(os.getenv("RG_JIT_TTL_SEC", "60"))

# Optional live external integrations (gracefully fall back to local adapter when blank)
AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "sub-apex-retail-prod-441")
AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
AZURE_OPENAI_DEPLOYMENT: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini").strip()
SERVICENOW_INSTANCE_URL: str = os.getenv("SERVICENOW_INSTANCE_URL", "").strip()
TEAMS_WEBHOOK_URL: str = os.getenv("TEAMS_WEBHOOK_URL", "").strip()

DESTRUCTIVE_OPERATIONS = frozenset({
    "DELETE_ROUTE",
    "FLUSH_NSG_RULE",
    "REVOKE_BGP_PEER",
    "DELETE_SUBNET",
    "DETACH_VNET_PEERING",
})

# Friendly tenant ID aliases so Swagger default "apex-retail" & UI IDs both work seamlessly
TENANT_ALIASES: Dict[str, str] = {
    "apex-retail": "apex_protected",
    "apex_protected": "apex_protected",
    "apex-retail-raw": "apex_raw",
    "apex_raw": "apex_raw",
    "global-trust": "global_trust",
    "global_trust": "global_trust",
}

DEFAULT_TENANTS = [
    {
        "tenant_id": "apex_protected",
        "tenant_name": "Apex Retail Corp",
        "mode_label": "Apex Retail Corp [Protected Mode]",
        "subscription_id": AZURE_SUBSCRIPTION_ID or "sub-apex-retail-prod-441",
        "default_protected": True,
    },
    {
        "tenant_id": "apex_raw",
        "tenant_name": "Apex Retail Corp",
        "mode_label": "Apex Retail Corp [Unprotected Raw Mode]",
        "subscription_id": "sub-apex-retail-raw-441",
        "default_protected": False,
    },
    {
        "tenant_id": "global_trust",
        "tenant_name": "Global Trust Bank",
        "mode_label": "Global Trust Bank [Protected Mode]",
        "subscription_id": "sub-globaltrust-core-001",
        "default_protected": True,
    },
]


def resolve_tenant_id(raw_id: str | None, fallback: str = "apex_protected") -> str:
    if not raw_id:
        return fallback
    key = raw_id.strip().lower()
    if key in TENANT_ALIASES:
        return TENANT_ALIASES[key]
    raise ValueError(
        f"Unknown tenant_id '{raw_id}'. Valid values: apex-retail (apex_protected), "
        f"apex-retail-raw (apex_raw), global-trust (global_trust)."
    )
