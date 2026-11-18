"""
REALITY-GATE v2.0 — Tamper-Evident SHA-256 Audit Ledger
Writes every governance & execution event to BOTH SQLite (`audit_blocks`)
and disk (`logs/audit.jsonl`) with strict cryptographic hash chaining.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from reality_gate.config import AUDIT_JSONL_PATH
from reality_gate.database import DatabaseManager
from reality_gate.models import AuditRecord


def compute_block_hash(record: Dict[str, Any]) -> str:
    """Canonical SHA-256 digest covering all immutable audit fields."""
    raw = "|".join([
        str(record["block_index"]),
        str(record["tenant_id"]),
        str(record["change_id"]),
        str(record["timestamp"]),
        str(record["prev_hash"]),
        str(record["actor"]),
        str(record["operation"]),
        str(record["target_cidr"]),
        str(record["verdict"]),
        str(record["reason_code"]),
        str(record["risk_score"]),
        str(record["evidence_state"]),
        str(record.get("token_id") or "NONE"),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditHashChain:
    def __init__(self, db: DatabaseManager, jsonl_path: Path | str = AUDIT_JSONL_PATH):
        self.db = db
        self.jsonl_path = Path(jsonl_path)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sync_genesis()

    def _sync_genesis(self) -> None:
        with self._lock:
            with self.db.connect() as conn:
                cnt = conn.execute("SELECT COUNT(*) AS c FROM audit_blocks").fetchone()["c"]
            if cnt == 0:
                if self.jsonl_path.exists():
                    # Reset stale file if DB was freshly created
                    self.jsonl_path.write_text("", encoding="utf-8")
                self.append(
                    tenant_id="system",
                    change_id="CHG-GENESIS",
                    actor="reality-gate-boot",
                    operation="INITIALIZE_AUDIT_CHAIN",
                    target_cidr="0.0.0.0/0",
                    verdict="ALLOW",
                    reason_code="SHA256_GENESIS_SEALED",
                    risk_score=0,
                    evidence_state="CHAIN_INITIALIZED",
                    token_id=None,
                )
            elif not self.jsonl_path.exists() or self.jsonl_path.stat().st_size == 0:
                # Rebuild JSONL on disk cleanly from SQLite blocks
                rows = self.get_all_blocks()
                with self.jsonl_path.open("w", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row, sort_keys=True) + "\n")

    def append(
        self,
        tenant_id: str,
        change_id: str,
        actor: str,
        operation: str,
        target_cidr: str,
        verdict: str,
        reason_code: str,
        risk_score: int,
        evidence_state: str,
        token_id: Optional[str] = None,
    ) -> AuditRecord:
        with self._lock:
            with self.db.connect() as conn:
                last = conn.execute(
                    "SELECT block_index, block_hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1"
                ).fetchone()
                idx = (last["block_index"] + 1) if last else 0
                prev_hash = last["block_hash"] if last else ("0" * 64)
                ts = datetime.now(timezone.utc).isoformat()

                payload = {
                    "block_index": idx,
                    "tenant_id": tenant_id,
                    "change_id": change_id,
                    "timestamp": ts,
                    "prev_hash": prev_hash,
                    "actor": actor,
                    "operation": operation,
                    "target_cidr": target_cidr,
                    "verdict": verdict,
                    "reason_code": reason_code,
                    "risk_score": int(risk_score),
                    "evidence_state": evidence_state,
                    "token_id": token_id,
                }
                bh = compute_block_hash(payload)
                payload["block_hash"] = bh

                conn.execute(
                    """
                    INSERT INTO audit_blocks (
                        block_index, tenant_id, change_id, timestamp, prev_hash,
                        actor, operation, target_cidr, verdict, reason_code,
                        risk_score, evidence_state, token_id, block_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        idx,
                        tenant_id,
                        change_id,
                        ts,
                        prev_hash,
                        actor,
                        operation,
                        target_cidr,
                        verdict,
                        reason_code,
                        int(risk_score),
                        evidence_state,
                        token_id,
                        bh,
                    ),
                )

            with self.jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True) + "\n")
                fh.flush()

            return AuditRecord(**payload)

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC").fetchall()
            return [dict(r) for r in rows]

    def get_recent_blocks(self, tenant_id: Optional[str] = None, limit: int = 40) -> List[Dict[str, Any]]:
        with self.db.connect() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM audit_blocks WHERE tenant_id = ? OR tenant_id = 'system' ORDER BY block_index DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_blocks ORDER BY block_index DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_blocks_for_change(self, change_id: str) -> List[Dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_blocks WHERE change_id = ? ORDER BY block_index ASC",
                (change_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def verify_integrity(self) -> Dict[str, Any]:
        """Re-hash every single line in logs/audit.jsonl from block #0 to latest."""
        with self._lock:
            if not self.jsonl_path.exists():
                return {
                    "valid": False,
                    "blocks_verified": 0,
                    "jsonl_path": str(self.jsonl_path),
                    "error": "Audit log file logs/audit.jsonl is missing.",
                    "tampered_block_index": 0,
                }

            lines = [ln.strip() for ln in self.jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if not lines:
                return {
                    "valid": False,
                    "blocks_verified": 0,
                    "jsonl_path": str(self.jsonl_path),
                    "error": "Audit log file is empty.",
                    "tampered_block_index": 0,
                }

            expected_prev = "0" * 64
            latest_hash = expected_prev
            for expected_idx, raw_line in enumerate(lines):
                try:
                    rec = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    return {
                        "valid": False,
                        "blocks_verified": expected_idx,
                        "jsonl_path": str(self.jsonl_path),
                        "error": f"Corrupted JSON on line {expected_idx}: {exc}",
                        "tampered_block_index": expected_idx,
                    }

                if rec.get("block_index") != expected_idx:
                    return {
                        "valid": False,
                        "blocks_verified": expected_idx,
                        "jsonl_path": str(self.jsonl_path),
                        "error": f"Block index discontinuity at line {expected_idx}: found #{rec.get('block_index')}",
                        "tampered_block_index": expected_idx,
                    }

                if rec.get("prev_hash") != expected_prev:
                    return {
                        "valid": False,
                        "blocks_verified": expected_idx,
                        "jsonl_path": str(self.jsonl_path),
                        "error": f"Broken prev_hash link at block #{expected_idx}",
                        "tampered_block_index": expected_idx,
                    }

                recomputed = compute_block_hash(rec)
                if rec.get("block_hash") != recomputed:
                    return {
                        "valid": False,
                        "blocks_verified": expected_idx,
                        "jsonl_path": str(self.jsonl_path),
                        "error": f"SHA-256 digest mismatch at block #{expected_idx} (tampering detected!)",
                        "tampered_block_index": expected_idx,
                        "expected_hash": recomputed,
                        "found_hash": rec.get("block_hash"),
                    }

                expected_prev = recomputed
                latest_hash = recomputed

            return {
                "valid": True,
                "blocks_verified": len(lines),
                "genesis_hash": json.loads(lines[0])["block_hash"],
                "latest_hash": latest_hash,
                "jsonl_path": str(self.jsonl_path),
                "status": "CHAIN_INTEGRITY_VERIFIED",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
