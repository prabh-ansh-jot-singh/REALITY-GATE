"""
REALITY-GATE v2.0 — Real SQLite Persistence Layer (`reality_gate.db`)
Thread-safe SQLite store persisting tenants, effective routes, flow records,
scheduled batch jobs, CMDB CIs, agent runs, JIT leases, replay nonces,
Teams HITL dispatches, Red-Team results, and SHA-256 audit blocks.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from reality_gate.config import (
    AZURE_OPENAI_ENDPOINT,
    DB_PATH,
    DEFAULT_FRESHNESS_SLA_SEC,
    DEFAULT_NOISE_FLOOR_PKT_HR,
    DEFAULT_TENANTS,
    SERVICENOW_INSTANCE_URL,
    TEAMS_WEBHOOK_URL,
)


class DatabaseManager:
    def __init__(self, db_path: Path | str = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()
        self.ensure_default_tenants()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL,
                    mode_label TEXT NOT NULL,
                    subscription_id TEXT NOT NULL,
                    default_protected INTEGER NOT NULL,
                    is_protected INTEGER NOT NULL,
                    guardrail_stages_json TEXT NOT NULL,
                    stage_handshakes_json TEXT NOT NULL,
                    policy_config_json TEXT NOT NULL,
                    outage_active INTEGER NOT NULL DEFAULT 0,
                    rerouted_to_backup INTEGER NOT NULL DEFAULT 0,
                    run_seq INTEGER NOT NULL DEFAULT 1047,
                    active_run_id TEXT DEFAULT 'RUN-1047',
                    changes_evaluated INTEGER NOT NULL DEFAULT 0,
                    allowed_count INTEGER NOT NULL DEFAULT 0,
                    constrained_count INTEGER NOT NULL DEFAULT 0,
                    held_count INTEGER NOT NULL DEFAULT 0,
                    denied_count INTEGER NOT NULL DEFAULT 0,
                    rollback_count INTEGER NOT NULL DEFAULT 0,
                    outage_count INTEGER NOT NULL DEFAULT 0,
                    latency_samples_json TEXT NOT NULL DEFAULT '[]',
                    wave_history_json TEXT NOT NULL DEFAULT '[]',
                    azure_openai_endpoint TEXT NOT NULL DEFAULT '',
                    servicenow_instance_url TEXT NOT NULL DEFAULT '',
                    teams_webhook_url TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS effective_routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    prefix TEXT NOT NULL,
                    next_hop_ip TEXT NOT NULL,
                    next_hop_type TEXT NOT NULL,
                    route_table TEXT NOT NULL,
                    vnet_peering TEXT NOT NULL,
                    nsg_rule TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'ACTIVE',
                    UNIQUE(tenant_id, prefix)
                );

                CREATE TABLE IF NOT EXISTS flow_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    workload TEXT NOT NULL,
                    packets_per_hr INTEGER NOT NULL,
                    last_seen_sec INTEGER NOT NULL,
                    matched_cidr TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    hmac_valid INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(tenant_id, flow_id)
                );

                CREATE TABLE IF NOT EXISTS scheduled_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    cidr TEXT NOT NULL,
                    cron TEXT NOT NULL,
                    schedule_label TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    bursts_30d INTEGER NOT NULL,
                    avg_pkt_hr INTEGER NOT NULL,
                    UNIQUE(tenant_id, cidr)
                );

                CREATE TABLE IF NOT EXISTS cmdb_cis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    ci_id TEXT NOT NULL,
                    cidr TEXT NOT NULL,
                    name TEXT NOT NULL,
                    declared_state TEXT NOT NULL,
                    observed_state TEXT NOT NULL,
                    historical_30d TEXT NOT NULL,
                    sync_status TEXT NOT NULL,
                    proposal_status TEXT NOT NULL,
                    servicenow_ticket TEXT,
                    UNIQUE(tenant_id, cidr)
                );

                CREATE TABLE IF NOT EXISTS agent_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(tenant_id, run_id)
                );

                CREATE TABLE IF NOT EXISTS change_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target TEXT NOT NULL,
                    proposed_by TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jit_leases (
                    token_id TEXT PRIMARY KEY,
                    jwt_token TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_cidr TEXT NOT NULL,
                    issued_epoch INTEGER NOT NULL,
                    expires_epoch INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    hmac_signature TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    consumed_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_blocks (
                    block_index INTEGER PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_cidr TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    evidence_state TEXT NOT NULL,
                    token_id TEXT,
                    block_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS redteam_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(tenant_id, test_id)
                );

                CREATE TABLE IF NOT EXISTS teams_inbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    change_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    target_cidr TEXT NOT NULL,
                    delivery_mode TEXT NOT NULL,
                    http_status INTEGER,
                    webhook_url TEXT NOT NULL,
                    card_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS broker_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """
            )

    def ensure_default_tenants(self) -> None:
        with self.connect() as conn:
            for spec in DEFAULT_TENANTS:
                row = conn.execute(
                    "SELECT tenant_id FROM tenants WHERE tenant_id = ?",
                    (spec["tenant_id"],),
                ).fetchone()
                if not row:
                    self._seed_tenant_conn(conn, spec)

    def _seed_tenant_conn(self, conn: sqlite3.Connection, spec: Dict[str, Any]) -> None:
        tid = spec["tenant_id"]
        prot = bool(spec["default_protected"])
        stages = {
            "stage_1_telemetry": prot,
            "stage_2_zero_key_broker": prot,
            "stage_3_invariant_twin": prot,
            "stage_4_cmdb_auditor": prot,
        }
        handshakes = (
            {
                "stage_1": "Azure Resource Graph (Passive) • VNet Flow Logs v2 (45s lag) • 30-Day Archive • CMDB Read-Only",
                "stage_2": "Standing AI ARM Keys Revoked • Azure Policy Direct-ARM Deny Active • Scoped Execution Broker Bound",
                "stage_3": "5-Check Deterministic Engine + NetworkX Digital Twin + 6-Point Failover Verifier Armed",
                "stage_4": "Auditor Post-Exec Verifier + ServiceNow CMDB Draft Approval Workflow + SHA-256 Chain Active",
            }
            if prot
            else {}
        )
        policy_cfg = {
            "noise_floor_pkt_hr": DEFAULT_NOISE_FLOOR_PKT_HR,
            "freshness_sla_sec": DEFAULT_FRESHNESS_SLA_SEC,
            "require_backup_failover": True,
        }

        conn.execute(
            """
            INSERT OR REPLACE INTO tenants (
                tenant_id, tenant_name, mode_label, subscription_id, default_protected,
                is_protected, guardrail_stages_json, stage_handshakes_json, policy_config_json,
                outage_active, rerouted_to_backup, run_seq, active_run_id,
                changes_evaluated, allowed_count, constrained_count, held_count,
                denied_count, rollback_count, outage_count,
                latency_samples_json, wave_history_json,
                azure_openai_endpoint, servicenow_instance_url, teams_webhook_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, '[]', '[]', ?, ?, ?)
            """,
            (
                tid,
                spec["tenant_name"],
                spec["mode_label"],
                spec["subscription_id"],
                1 if prot else 0,
                1 if prot else 0,
                json.dumps(stages),
                json.dumps(handshakes),
                json.dumps(policy_cfg),
                0,
                1 if prot else 0,
                1047,
                "RUN-1047",
                AZURE_OPENAI_ENDPOINT,
                SERVICENOW_INSTANCE_URL or f"https://{tid.replace('_', '')}.service-now.com",
                TEAMS_WEBHOOK_URL,
            ),
        )

        # Clear tenant-scoped tables before seeding
        for tbl in (
            "effective_routes",
            "flow_records",
            "scheduled_jobs",
            "cmdb_cis",
            "agent_runs",
            "change_requests",
            "redteam_results",
            "teams_inbox",
            "broker_logs",
            "jit_leases",
            "used_nonces",
        ):
            conn.execute(f"DELETE FROM {tbl} WHERE tenant_id = ?", (tid,))

        # Effective Routes (LPM Table)
        routes = [
            ("10.40.0.0/16", "10.0.254.1", "ExpressRouteGateway", "rt-apex-transit", "peer-vnet-sql", "ALLOW OUTBOUND TCP/1433 -> 172.16.4.90", "ACTIVE"),
            ("10.40.1.0/24", "10.0.254.1", "ExpressRouteGateway", "rt-apex-transit", "peer-vnet-sql", "ALLOW OUTBOUND TCP/1433 (LPM Specific)", "ACTIVE"),
            ("10.41.0.0/16", "10.0.254.2", "ExpressRouteGateway (Backup)", "rt-apex-backup", "peer-vnet-dr", "ALLOW BIDIRECTIONAL TCP/1433 <-> 172.16.4.90", "ACTIVE"),
            ("10.77.0.0/24", "10.0.254.3", "ExpressRouteGateway (Batch)", "rt-batch-backup", "peer-vnet-batch", "ALLOW OUTBOUND TCP/50000 -> 172.16.8.40", "ACTIVE"),
            ("10.88.0.0/24", "10.0.254.4", "VirtualAppliance", "rt-dmz-legacy", "peer-vnet-dmz", "DENY INBOUND (External SSH Recon 6 pkt/hr)", "ACTIVE"),
            ("10.99.0.0/24", "10.0.254.5", "VnetLocal", "rt-dev-scratch", "peer-vnet-dev", "ISOLATED (0 flows 30d)", "ACTIVE"),
        ]
        conn.executemany(
            """
            INSERT INTO effective_routes (tenant_id, prefix, next_hop_ip, next_hop_type, route_table, vnet_peering, nsg_rule, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(tid, *r) for r in routes],
        )

        # Flow Logs v2
        flows = [
            ("flw-1040-sql", "10.40.1.12", "172.16.4.90", 49218, 1433, "TCP", "SQL Replication (Active Production)", 14200, 45, "10.40.0.0/16", "OBSERVED_ONLY", 1),
            ("flw-1041-dr", "10.41.2.10", "172.16.4.90", 51104, 1433, "TCP", "Prod Services (Backup / Failover Path)", 14200 if prot else 0, 12, "10.41.0.0/16", "DUAL_VERIFIED", 1),
            ("flw-1088-scan", "45.33.22.11", "10.88.0.14", 58102, 22, "TCP", "External Internet SSH Recon Probe (<10 pkt/hr Noise)", 6, 82, "10.88.0.0/24", "SCANNER_NOISE", 1),
        ]
        conn.executemany(
            """
            INSERT INTO flow_records (tenant_id, flow_id, src_ip, dst_ip, src_port, dst_port, protocol, workload, packets_per_hr, last_seen_sec, matched_cidr, classification, hmac_valid)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(tid, *f) for f in flows],
        )

        # Scheduled Weekly Batch Jobs
        jobs = [
            ("cron-sun-0200-sql", "10.77.0.0/24", "0 2 * * 0", "Weekly Backup (Sun, 2 AM)", "172.16.8.40:50000", 4, 9850),
            ("cron-sun-0200-repl", "10.40.0.0/16", "0 2 * * 0", "Weekly Backup (Sun, 2 AM)", "172.16.4.90:1433", 4, 18400),
        ]
        conn.executemany(
            """
            INSERT INTO scheduled_jobs (tenant_id, job_id, cidr, cron, schedule_label, destination, bursts_30d, avg_pkt_hr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(tid, *j) for j in jobs],
        )

        # ServiceNow CMDB Configuration Items (2 DUAL_VERIFIED / 5 total -> 40% baseline alignment)
        cis = [
            ("CI-NET-1040", "10.40.0.0/16", "SQL Replication Spoke", "DECOMMISSIONED (Unused)", "14,200 pkt/hr TCP/1433 (SQL Replication)", "Active daily + Weekly Backup (Sun, 2 AM)", "OBSERVED_ONLY", "Draft", None),
            ("CI-NET-1041", "10.41.0.0/16", "Backup / DR Failover Path", "ACTIVE_STANDBY", "Bidirectional TCP/1433 Verified (40K Cap)", "Validated 6-Point Failover Ready", "DUAL_VERIFIED", "Synchronized", None),
            ("CI-NET-1077", "10.77.0.0/24", "Weekly Batch Backup Subnet", "UNUSED (Stale CMDB)", "0 pkt/hr live (Tue)", "4 Sunday 2:00 AM bursts (9,850 pkt/hr)", "HISTORICAL_SCHEDULED", "Needs Review", None),
            ("CI-NET-1088", "10.88.0.0/24", "DMZ Legacy Staging", "UNUSED_STAGING", "6 pkt/hr External SSH Recon Noise", "0 prod flows in 30d", "SCANNER_NOISE", "Safe to Clean", None),
            ("CI-NET-1099", "10.99.0.0/24", "Dev Scratch Subnet", "UNUSED_DEV", "0 pkt/hr live", "0 flows & 0 cron jobs in 30d", "DUAL_VERIFIED", "Safe to Clean", None),
        ]
        conn.executemany(
            """
            INSERT INTO cmdb_cis (tenant_id, ci_id, cidr, name, declared_state, observed_state, historical_30d, sync_status, proposal_status, servicenow_ticket)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(tid, *c) for c in cis],
        )

        # Seed initial broker boot log
        now_ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        conn.execute(
            "INSERT INTO broker_logs (tenant_id, ts, level, component, message) VALUES (?, ?, ?, ?, ?)",
            (
                tid,
                now_ts,
                "OK" if prot else "WARN",
                "SQLITE-BOOT",
                f"[{spec['tenant_name']}] Initialized in SQLite ({'Protected 4/4' if prot else 'Unprotected Raw 0/4'}) — 0 session mutations.",
            ),
        )

    def reset_tenant(self, tenant_id: str, force_unprotected: bool = False) -> None:
        spec = next((t for t in DEFAULT_TENANTS if t["tenant_id"] == tenant_id), None)
        if not spec:
            raise ValueError(f"Unknown tenant_id: {tenant_id}")
        spec_copy = dict(spec)
        if force_unprotected:
            spec_copy["default_protected"] = False
        with self.connect() as conn:
            self._seed_tenant_conn(conn, spec_copy)

    # ------------------------------------------------------------------
    # TENANT & METRICS ACCESSORS
    # ------------------------------------------------------------------
    def get_tenant(self, tenant_id: str) -> Dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
            if not row:
                raise ValueError(f"Unknown tenant_id: {tenant_id}")
            d = dict(row)
            d["is_protected"] = bool(d["is_protected"])
            d["default_protected"] = bool(d["default_protected"])
            d["outage_active"] = bool(d["outage_active"])
            d["rerouted_to_backup"] = bool(d["rerouted_to_backup"])
            d["guardrail_stages"] = json.loads(d["guardrail_stages_json"])
            d["stage_handshakes"] = json.loads(d["stage_handshakes_json"])
            d["policy_config"] = json.loads(d["policy_config_json"])
            d["latency_samples"] = json.loads(d["latency_samples_json"])
            d["wave_history"] = json.loads(d["wave_history_json"])
            return d

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT tenant_id, mode_label, is_protected FROM tenants ORDER BY rowid").fetchall()
            return [
                {"tenant_id": r["tenant_id"], "mode_label": r["mode_label"], "is_protected": bool(r["is_protected"])}
                for r in rows
            ]

    def update_tenant_fields(self, tenant_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols = []
        vals = []
        for k, v in fields.items():
            if k == "guardrail_stages":
                cols.append("guardrail_stages_json = ?")
                vals.append(json.dumps(v))
            elif k == "stage_handshakes":
                cols.append("stage_handshakes_json = ?")
                vals.append(json.dumps(v))
            elif k == "policy_config":
                cols.append("policy_config_json = ?")
                vals.append(json.dumps(v))
            elif k == "latency_samples":
                cols.append("latency_samples_json = ?")
                vals.append(json.dumps(v[-200:]))
            elif k == "wave_history":
                cols.append("wave_history_json = ?")
                vals.append(json.dumps(v[-24:]))
            elif isinstance(v, bool):
                cols.append(f"{k} = ?")
                vals.append(1 if v else 0)
            else:
                cols.append(f"{k} = ?")
                vals.append(v)
        vals.append(tenant_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE tenants SET {', '.join(cols)} WHERE tenant_id = ?", vals)

    def increment_counter(self, tenant_id: str, column: str, delta: int = 1) -> None:
        allowed_cols = {
            "changes_evaluated",
            "allowed_count",
            "constrained_count",
            "held_count",
            "denied_count",
            "rollback_count",
            "outage_count",
            "run_seq",
        }
        if column not in allowed_cols:
            raise ValueError(f"Unsupported counter column: {column}")
        with self.connect() as conn:
            conn.execute(f"UPDATE tenants SET {column} = {column} + ? WHERE tenant_id = ?", (delta, tenant_id))

    def record_latency_and_wave(
        self, tenant_id: str, elapsed_ms: float, wave_point: Optional[Dict[str, Any]] = None
    ) -> float:
        t = self.get_tenant(tenant_id)
        samples: List[float] = list(t["latency_samples"])
        samples.append(round(max(elapsed_ms, 0.001), 3))
        samples = samples[-200:]
        updates: Dict[str, Any] = {"latency_samples": samples}
        if wave_point is not None:
            wave = list(t["wave_history"])
            wave.append(wave_point)
            updates["wave_history"] = wave[-24:]
        self.update_tenant_fields(tenant_id, **updates)
        ordered = sorted(samples)
        idx = min(len(ordered) - 1, max(0, int(round(0.95 * (len(ordered) - 1)))))
        return round(ordered[idx], 3)

    # ------------------------------------------------------------------
    # ROUTES, FLOWS, SCHEDULED JOBS & CMDB (PERSISTED MUTATIONS)
    # ------------------------------------------------------------------
    def get_effective_routes(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT prefix, next_hop_ip, next_hop_type, route_table, vnet_peering, nsg_rule, state FROM effective_routes WHERE tenant_id = ? ORDER BY id",
                (tenant_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def mutate_route_state(self, tenant_id: str, target_cidr: str, operation: str) -> Dict[str, Any]:
        """Apply a REAL SQLite mutation to the simulated Azure route table"""
        op = operation.upper().strip()
        with self.connect() as conn:
            if op in ("DELETE_ROUTE", "FLUSH_NSG_RULE", "REVOKE_BGP_PEER"):
                conn.execute(
                    "UPDATE effective_routes SET state = 'DELETED' WHERE tenant_id = ? AND prefix = ?",
                    (tenant_id, target_cidr),
                )
                return {"mutated_prefix": target_cidr, "new_state": "DELETED"}
            if op == "SHIFT_ROUTE_TO_BACKUP":
                conn.execute(
                    "UPDATE effective_routes SET state = 'FAILOVER_ACTIVE', next_hop_type = 'ExpressRouteGateway (Active Failover)' WHERE tenant_id = ? AND prefix = ?",
                    (tenant_id, target_cidr),
                )
                conn.execute(
                    "UPDATE flow_records SET packets_per_hr = 14200, last_seen_sec = 8 WHERE tenant_id = ? AND matched_cidr = ?",
                    (tenant_id, target_cidr),
                )
                return {"mutated_prefix": target_cidr, "new_state": "FAILOVER_ACTIVE"}
            if op == "ROLLBACK_ROUTE":
                conn.execute(
                    "UPDATE effective_routes SET state = 'ACTIVE' WHERE tenant_id = ? AND prefix = ?",
                    (tenant_id, target_cidr),
                )
                return {"mutated_prefix": target_cidr, "new_state": "ACTIVE (ROLLED_BACK)"}
        return {"mutated_prefix": target_cidr, "new_state": "UNCHANGED"}

    def get_flows(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, workload, packets_per_hr, last_seen_sec, matched_cidr, classification, hmac_valid FROM flow_records WHERE tenant_id = ? ORDER BY id",
                (tenant_id,),
            ).fetchall()
            res = []
            for r in rows:
                d = dict(r)
                d["hmac_valid"] = bool(d["hmac_valid"])
                res.append(d)
            return res

    def get_scheduled_jobs(self, tenant_id: str) -> Dict[str, Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT job_id, cidr, cron, schedule_label, destination, bursts_30d, avg_pkt_hr FROM scheduled_jobs WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            return {r["cidr"]: dict(r) for r in rows}

    def get_cmdb_cis(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ci_id, cidr, name, declared_state, observed_state, historical_30d, sync_status, proposal_status, servicenow_ticket FROM cmdb_cis WHERE tenant_id = ? ORDER BY id",
                (tenant_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def update_cmdb_ci(
        self,
        tenant_id: str,
        cidr: str,
        declared_state: Optional[str] = None,
        sync_status: Optional[str] = None,
        proposal_status: Optional[str] = None,
        servicenow_ticket: Optional[str] = None,
    ) -> None:
        sets, vals = [], []
        if declared_state is not None:
            sets.append("declared_state = ?")
            vals.append(declared_state)
        if sync_status is not None:
            sets.append("sync_status = ?")
            vals.append(sync_status)
        if proposal_status is not None:
            sets.append("proposal_status = ?")
            vals.append(proposal_status)
        if servicenow_ticket is not None:
            sets.append("servicenow_ticket = ?")
            vals.append(servicenow_ticket)
        if not sets:
            return
        vals.extend([tenant_id, cidr])
        with self.connect() as conn:
            conn.execute(f"UPDATE cmdb_cis SET {', '.join(sets)} WHERE tenant_id = ? AND cidr = ?", vals)
            if sync_status == "DUAL_VERIFIED":
                conn.execute(
                    "UPDATE flow_records SET classification = 'DUAL_VERIFIED' WHERE tenant_id = ? AND matched_cidr = ?",
                    (tenant_id, cidr),
                )

    # ------------------------------------------------------------------
    # RUNS, CHANGE REQUESTS, RED-TEAM, TEAMS INBOX & LOGS
    # ------------------------------------------------------------------
    def save_run(self, tenant_id: str, run_dict: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agent_runs (tenant_id, run_id, change_id, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, run_dict["run_id"], run_dict["change_id"], json.dumps(run_dict), time.time()),
            )

    def get_runs(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM agent_runs WHERE tenant_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            return [json.loads(r["payload_json"]) for r in rows]

    def get_run(self, tenant_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM agent_runs WHERE tenant_id = ? AND run_id = ?",
                (tenant_id, run_id),
            ).fetchone()
            return json.loads(row["payload_json"]) if row else None

    def find_run_by_change(self, tenant_id: str, change_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM agent_runs WHERE tenant_id = ? AND change_id = ? ORDER BY id DESC LIMIT 1",
                (tenant_id, change_id),
            ).fetchone()
            return json.loads(row["payload_json"]) if row else None

    def add_change_request(self, tenant_id: str, rec: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO change_requests (tenant_id, change_id, run_id, operation, target, proposed_by, verdict, risk_score, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    rec["change_id"],
                    rec["run_id"],
                    rec["operation"],
                    rec["target"],
                    rec["proposed_by"],
                    rec["verdict"],
                    int(rec["risk_score"]),
                    rec["status"],
                    rec["timestamp"],
                ),
            )

    def get_change_requests(self, tenant_id: str, limit: int = 25) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT change_id, run_id, operation, target, proposed_by, verdict, risk_score, status, timestamp FROM change_requests WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def save_redteam_result(self, tenant_id: str, test_id: str, rec: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO redteam_results (tenant_id, test_id, payload_json) VALUES (?, ?, ?)",
                (tenant_id, test_id, json.dumps(rec)),
            )

    def get_redteam_results(self, tenant_id: str) -> Dict[str, Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT test_id, payload_json FROM redteam_results WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            return {r["test_id"]: json.loads(r["payload_json"]) for r in rows}

    def save_teams_dispatch(
        self,
        tenant_id: str,
        change_id: str,
        verdict: str,
        target_cidr: str,
        delivery_mode: str,
        http_status: Optional[int],
        webhook_url: str,
        card_payload: Dict[str, Any],
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO teams_inbox (tenant_id, change_id, verdict, target_cidr, delivery_mode, http_status, webhook_url, card_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, change_id, verdict, target_cidr, delivery_mode, http_status, webhook_url, json.dumps(card_payload), ts),
            )

    def get_teams_inbox(self, tenant_id: str, limit: int = 15) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, change_id, verdict, target_cidr, delivery_mode, http_status, webhook_url, card_json, created_at FROM teams_inbox WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["card"] = json.loads(d.pop("card_json"))
                out.append(d)
            return out

    def append_log(self, tenant_id: str, level: str, component: str, message: str) -> None:
        now = datetime.now(timezone.utc)
        ts = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO broker_logs (tenant_id, ts, level, component, message) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, ts, level, component, message),
            )

    def get_logs(self, tenant_id: str, limit: int = 60) -> List[Dict[str, str]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ts, level, component, message FROM broker_logs WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            return [dict(r) for r in reversed(rows)]

    # ------------------------------------------------------------------
    # JIT LEASES & SQLITE NONCE REPLAY PROTECTION
    # ------------------------------------------------------------------
    def store_lease(self, lease: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO jit_leases (token_id, jwt_token, nonce, tenant_id, change_id, operation, target_cidr, issued_epoch, expires_epoch, ttl_seconds, hmac_signature, used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease["token_id"],
                    lease["jwt_token"],
                    lease["nonce"],
                    lease["tenant_id"],
                    lease["change_id"],
                    lease["operation"],
                    lease["target_cidr"],
                    lease["issued_epoch"],
                    lease["expires_epoch"],
                    lease["ttl_seconds"],
                    lease["hmac_signature"],
                    1 if lease.get("used") else 0,
                ),
            )

    def get_lease(self, token_or_jwt: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM jit_leases WHERE token_id = ? OR jwt_token = ?",
                (token_or_jwt, token_or_jwt),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["used"] = bool(d["used"])
            return d

    def mark_lease_used(self, token_id: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jit_leases SET used = 1 WHERE token_id = ?", (token_id,))

    def is_nonce_used(self, nonce: str) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT nonce FROM used_nonces WHERE nonce = ?", (nonce,)).fetchone()
            return row is not None

    def consume_nonce(self, nonce: str, tenant_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO used_nonces (nonce, tenant_id, consumed_at) VALUES (?, ?, ?)",
                (nonce, tenant_id, time.time()),
            )
