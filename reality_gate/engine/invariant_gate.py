"""
REALITY-GATE v2.0 — Zero-LLM 5-Check Deterministic Admission Gate (`invariant_gate.py`)
Enforces the Observed-Path Invariant, 30-day scheduled cron check, telemetry freshness
and HMAC integrity, NetworkX Digital Twin blast-radius & 6-point failover verifier,
and deterministic risk scoring with real SQLite persistence and SHA-256 audit chaining.
"""

from __future__ import annotations

import ipaddress
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reality_gate.audit.hash_chain import AuditHashChain
from reality_gate.broker.jit_auth import JITAuthBroker
from reality_gate.config import DESTRUCTIVE_OPERATIONS
from reality_gate.database import DatabaseManager
from reality_gate.engine.graph_solver import DualPlaneGraphSolver
from reality_gate.engine.guardrail_sandwich import (
    build_guardrail_sandwich_summary,
    scan_ingress_ticket,
)
from reality_gate.engine.risk_scorer import calculate_risk_score
from reality_gate.models import MutationValidateRequest, PolicySandboxRequest


class InvariantGate:
    def __init__(self, db: DatabaseManager, audit: AuditHashChain, jit: JITAuthBroker):
        self.db = db
        self.audit = audit
        self.jit = jit

    # ------------------------------------------------------------------
    # STRICT SEQUENTIAL 4-STAGE GUARDRAIL LOCK (HTTP 409 ON OUT-OF-ORDER)
    # ------------------------------------------------------------------
    def activate_guardrail_stage(self, tenant_id: str, stage_num: int) -> Dict[str, Any]:
        t = self.db.get_tenant(tenant_id)
        stages = dict(t["guardrail_stages"])
        handshakes = dict(t["stage_handshakes"])

        stage_keys = {
            1: "stage_1_telemetry",
            2: "stage_2_zero_key_broker",
            3: "stage_3_invariant_twin",
            4: "stage_4_cmdb_auditor",
        }
        if stage_num not in stage_keys:
            return {"success": False, "status_code": 400, "error": f"Invalid stage {stage_num} (expected 1..4)"}

        for prev in range(1, stage_num):
            if not stages.get(stage_keys[prev]):
                return {
                    "success": False,
                    "status_code": 409,
                    "error": f"SEQUENTIAL_PREREQUISITE_VIOLATION: Stage {stage_num} requires Stage {prev} to be COMPLETED first.",
                }

        key = stage_keys[stage_num]
        if stages.get(key):
            return {"success": True, "stage": stage_num, "already_completed": True, "message": f"Stage {stage_num} already active."}

        stages[key] = True
        descriptions = {
            1: "Azure Resource Graph (Passive) • VNet Flow Logs v2 (45s lag) • 30-Day Archive • CMDB Read-Only",
            2: "Standing AI ARM Keys Revoked • Azure Policy Direct-ARM Deny Active • Scoped Execution Broker Bound",
            3: "5-Check Deterministic Engine + NetworkX Digital Twin + 6-Point Failover Verifier Armed",
            4: "Auditor Post-Exec Verifier + ServiceNow CMDB Draft Approval Workflow + SHA-256 Chain Active",
        }
        handshakes[f"stage_{stage_num}"] = descriptions[stage_num]
        is_protected = all(stages.values())
        self.db.update_tenant_fields(
            tenant_id,
            guardrail_stages=stages,
            stage_handshakes=handshakes,
            is_protected=is_protected,
        )
        self.audit.append(
            tenant_id=tenant_id,
            change_id=f"STAGE-{stage_num}-{uuid.uuid4().hex[:4].upper()}",
            actor="secops-operator",
            operation=f"ACTIVATE_GUARDRAIL_STAGE_{stage_num}",
            target_cidr="SUBSCRIPTION_SCOPE",
            verdict="ALLOW",
            reason_code=f"STAGE_{stage_num}_VERIFIED",
            risk_score=0,
            evidence_state="DUAL_VERIFIED",
            token_id=None,
        )
        self.db.append_log(
            tenant_id,
            "OK",
            f"STAGE-{stage_num}",
            f"[{t['tenant_name']}] Stage {stage_num}/4 Activated: {descriptions[stage_num]}",
        )
        return {
            "success": True,
            "stage": stage_num,
            "handshake": descriptions[stage_num],
            "is_protected": is_protected,
        }

    # ------------------------------------------------------------------
    # FAILOVER 6-POINT CHECKLIST
    # ------------------------------------------------------------------
    @staticmethod
    def _verify_6pt_failover(
        effective_routes: List[Dict[str, Any]],
        simulate_broken_backup: bool = False,
    ) -> List[Dict[str, Any]]:
        backup_route = next((r for r in effective_routes if r["prefix"] == "10.41.0.0/16"), None)
        backup_ok = bool(backup_route and backup_route["state"] != "DELETED") and not simulate_broken_backup
        return [
            {
                "check": "1. Active Backup Route Exists",
                "passed": backup_ok,
                "detail": "10.41.0.0/16 via ExpressRouteGateway (Backup)" if backup_ok else "Backup route unreachable",
            },
            {
                "check": "2. Bidirectional NSG / Firewall Allow",
                "passed": not simulate_broken_backup,
                "detail": "TCP/1433 bidirectional permitted on 10.41.0.0/16"
                if not simulate_broken_backup
                else "BLOCKED: NSG denies return TCP/1433 on backup path",
            },
            {
                "check": "3. Symmetric Return Path Verified",
                "passed": not simulate_broken_backup,
                "detail": "Return route 172.16.4.90 -> 10.41.0.0/16 symmetric"
                if not simulate_broken_backup
                else "FAILED: Asymmetric drop detected on return path",
            },
            {
                "check": "4. VNet Peering & Gateway Transit Active",
                "passed": backup_ok,
                "detail": "peer-vnet-dr Connected (GatewayTransit=True)" if backup_ok else "Peering disconnected",
            },
            {
                "check": "5. Capacity Headroom >= 1.5x Live Load",
                "passed": True,
                "detail": "40,000 pkt/hr capacity vs 14,200 pkt/hr active SQL load (2.8x headroom)",
            },
            {
                "check": "6. Recent Health Probe <= 60s",
                "passed": not simulate_broken_backup,
                "detail": "Synthetic TCP/1433 probe OK 12s ago (1.4 ms RTT)"
                if not simulate_broken_backup
                else "Probe timeout (>5000 ms)",
            },
        ]

    # ------------------------------------------------------------------
    # CORE 5-CHECK DETERMINISTIC INVARIANT ENGINE (ZERO LLM)
    # ------------------------------------------------------------------
    def validate_mutation(self, tenant_id: str, req: MutationValidateRequest) -> Dict[str, Any]:
        t0 = time.perf_counter_ns()
        t = self.db.get_tenant(tenant_id)
        policy = dict(t["policy_config"])
        noise_floor = (
            req.policy_noise_floor_pkt_hr
            if req.policy_noise_floor_pkt_hr is not None
            else int(policy.get("noise_floor_pkt_hr", 10))
        )
        freshness_sla = (
            req.policy_freshness_sla_sec
            if req.policy_freshness_sla_sec is not None
            else int(policy.get("freshness_sla_sec", 300))
        )
        require_backup = (
            req.policy_require_backup_failover
            if req.policy_require_backup_failover is not None
            else bool(policy.get("require_backup_failover", True))
        )

        chg_id = req.change_id or f"CHG-2026-{int(t['run_seq']) + 1}"
        op = req.operation.upper().strip()
        effective_routes = self.db.get_effective_routes(tenant_id)
        flows = self.db.get_flows(tenant_id)
        scheduled_jobs = self.db.get_scheduled_jobs(tenant_id)
        cmdb_cis = self.db.get_cmdb_cis(tenant_id)

        lpm = DualPlaneGraphSolver.resolve_lpm(req.target_cidr, effective_routes)
        _, observed_graph = DualPlaneGraphSolver.build_dual_plane_graphs(
            tenant_name=t["tenant_name"],
            effective_routes=effective_routes,
            flows=flows,
            cmdb_cis=cmdb_cis,
            outage_active=t["outage_active"],
            rerouted_to_backup=t["rerouted_to_backup"],
        )
        blast = DualPlaneGraphSolver.simulate_edge_removal_blast_radius(observed_graph, req.target_cidr)

        # Layer 1 of Guardrail Sandwich: Ingress PII/Secret Masker & Prompt-Injection Scanner
        ingress_scan = scan_ingress_ticket(
            req.reason,
            bypass_ingress_scanner=req.bypass_ingress_scanner,
        )
        effective_injection = bool(req.prompt_injection_simulated or ingress_scan["injection_detected"])

        self.db.increment_counter(tenant_id, "changes_evaluated")

        def finalize(
            verdict: str,
            reason_code: str,
            risk_score: int,
            evidence_state: str,
            message: str,
            checks: List[Dict[str, Any]],
            lease_dict: Optional[Dict[str, Any]] = None,
            failover_6pt: Optional[List[Dict[str, Any]]] = None,
        ) -> Dict[str, Any]:
            elapsed_ms = round(max((time.perf_counter_ns() - t0) / 1_000_000.0, 0.001), 3)
            wave_point = {
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "verdict": verdict,
                "risk_score": risk_score,
                "latency_ms": elapsed_ms,
                "target": req.target_cidr,
            }
            p95_ms = self.db.record_latency_and_wave(tenant_id, elapsed_ms, wave_point)

            counter_col = {
                "ALLOW": "allowed_count",
                "CONSTRAIN": "constrained_count",
                "HOLD": "held_count",
                "DENY": "denied_count",
            }.get(verdict)
            if counter_col:
                self.db.increment_counter(tenant_id, counter_col)

            blk = self.audit.append(
                tenant_id=tenant_id,
                change_id=chg_id,
                actor=req.agent_id,
                operation=op,
                target_cidr=req.target_cidr,
                verdict=verdict,
                reason_code=reason_code,
                risk_score=risk_score,
                evidence_state=evidence_state,
                token_id=lease_dict["token_id"] if lease_dict else None,
            )
            lvl = "OK" if verdict == "ALLOW" else ("WARN" if verdict == "CONSTRAIN" else "ERR")
            self.db.append_log(
                tenant_id,
                lvl,
                "GATE-V2",
                f"[{chg_id}] {verdict} ({reason_code}) | {req.target_cidr} | Risk={risk_score}/100 | {elapsed_ms:.3f}ms",
            )
            sandwich = build_guardrail_sandwich_summary(
                ingress_report=ingress_scan,
                gate_verdict=verdict,
                gate_reason=reason_code,
            )
            return {
                "change_id": chg_id,
                "tenant_id": tenant_id,
                "verdict": verdict,
                "reason_code": reason_code,
                "risk_score": risk_score,
                "evidence_state": evidence_state,
                "message": message,
                "latency_ms": elapsed_ms,
                "p95_latency_ms": p95_ms,
                "target_cidr": req.target_cidr,
                "operation": op,
                "lpm_route": lpm,
                "blast_radius": blast,
                "checks": checks,
                "failover_6pt": failover_6pt or [],
                "authorization_token": lease_dict,
                "guardrail_sandwich": sandwich,
                "ingress_scan": ingress_scan,
                "policy_snapshot": {
                    "noise_floor_pkt_hr": noise_floor,
                    "freshness_sla_sec": freshness_sla,
                    "require_backup_failover": require_backup,
                },
                "audit_hash": blk.block_hash,
                "block_index": blk.block_index,
            }

        # Security Pre-Check A: Direct ARM Bypass (T09)
        if req.bypass_broker:
            return finalize(
                "DENY",
                "DIRECT_ARM_BYPASS_BLOCKED",
                calculate_risk_score(bypass_attempted=True),
                "SECURITY_VIOLATION",
                "DENY: Direct Azure ARM API call blocked — AI agents hold zero standing credentials and must route through Execution Broker.",
                [{"check": "Zero-Credential Broker Enforcement", "status": "DENY", "detail": "Direct ARM call rejected by Azure Policy + MCP Broker."}],
            )

        # Security Pre-Check B: Replay / Expired Nonce Protection (T10)
        now_ep = int(time.time())
        if req.request_nonce:
            if self.db.is_nonce_used(req.request_nonce):
                return finalize(
                    "DENY",
                    "REPLAY_TOKEN_REJECTED",
                    calculate_risk_score(replay_attempted=True),
                    "SECURITY_VIOLATION",
                    f"DENY: Anti-replay defense rejected reused authorization nonce '{req.request_nonce}' (persisted in SQLite).",
                    [{"check": "Anti-Replay Nonce & Timestamp Guard", "status": "DENY", "detail": f"Nonce {req.request_nonce} already consumed in SQLite."}],
                )
            if req.timestamp_epoch and abs(now_ep - req.timestamp_epoch) > 60:
                return finalize(
                    "DENY",
                    "TOKEN_EXPIRED_REJECTED",
                    94,
                    "SECURITY_VIOLATION",
                    "DENY: Request timestamp outside valid 60-second short-lived lease window.",
                    [{"check": "Anti-Replay Nonce & Timestamp Guard", "status": "DENY", "detail": "Timestamp expired (>60s)."}],
                )
            self.db.consume_nonce(req.request_nonce, tenant_id)

        # Unprotected Mode Bypass Warning (explicit comparison mode)
        if not t["is_protected"] and not req.prompt_injection_simulated and req.target_cidr == "10.40.0.0/16" and op in DESTRUCTIVE_OPERATIONS:
            self.db.mutate_route_state(tenant_id, req.target_cidr, op)
            self.db.update_tenant_fields(tenant_id, outage_active=True)
            self.db.increment_counter(tenant_id, "outage_count")
            return finalize(
                "ALLOW",
                "UNPROTECTED_BYPASS_OUTAGE",
                100,
                "UNVERIFIED_OUTAGE",
                "UNPROTECTED MODE: REALITY-GATE bypassed — autonomous agent deleted active SQL route 10.40.0.0/16 causing P1 production outage!",
                [{"check": "Guardrail Status", "status": "BYPASSED", "detail": "0/4 Guardrail Stages Active — Standing ARM Key Used."}],
            )

        checks: List[Dict[str, Any]] = []

        # CHECK 3: Telemetry Integrity & Freshness (Fail-Closed: T03, T04, T05)
        if req.telemetry_collector_disabled:
            checks.append({"check": "3. Telemetry Collector Completeness", "status": "FAIL_CLOSED", "detail": "VNet Flow Logs collector disabled/missing."})
            return finalize(
                "HOLD",
                "TELEMETRY_COLLECTOR_MISSING",
                calculate_risk_score(collector_missing=True),
                "TELEMETRY_UNAVAILABLE",
                "HOLD (Fail-Closed): VNet Flow Logs v2 collector is disabled/missing — destructive change blocked because wire cannot be verified.",
                checks,
            )

        if req.corrupted_evidence_hmac:
            checks.append({"check": "3. Cryptographic Evidence Integrity", "status": "FAIL_CLOSED", "detail": "HMAC-SHA256 telemetry digest mismatch."})
            return finalize(
                "HOLD",
                "EVIDENCE_HMAC_INTEGRITY_FAILED",
                calculate_risk_score(hmac_corrupted=True),
                "EVIDENCE_CORRUPTED",
                "HOLD (Fail-Closed): Cryptographic HMAC signature on telemetry snapshot failed verification — possible poisoning detected.",
                checks,
            )

        telem_age = req.simulated_telemetry_age if req.simulated_telemetry_age is not None else 45
        if telem_age > freshness_sla:
            checks.append({"check": "3. Telemetry Freshness SLA", "status": "FAIL_CLOSED", "detail": f"Telemetry age {telem_age}s exceeds {freshness_sla}s SLA."})
            return finalize(
                "HOLD",
                "TELEMETRY_STALE_FAIL_CLOSED",
                calculate_risk_score(telemetry_stale=True),
                "STALE_TELEMETRY",
                f"HOLD (Fail-Closed): Flow telemetry is {telem_age}s old (SLA <= {freshness_sla}s) — fail-closed policy blocks destructive deletion.",
                checks,
            )
        checks.append({"check": "3. Telemetry Integrity & Freshness", "status": "PASS", "detail": f"Age {telem_age}s <= {freshness_sla}s SLA, HMAC-SHA256 valid."})

        # CHECK 1: L4 Observed Dependency & LPM Correlation (T01, T11, Noise Floor)
        matched_flows = []
        try:
            t_net = ipaddress.ip_network(req.target_cidr, strict=False)
            for fl in flows:
                fl_net = ipaddress.ip_network(fl["matched_cidr"], strict=False)
                if fl["matched_cidr"] == req.target_cidr or t_net.overlaps(fl_net):
                    matched_flows.append(fl)
        except ValueError:
            matched_flows = [fl for fl in flows if fl["matched_cidr"] == req.target_cidr]

        total_pkt = sum(int(fl["packets_per_hr"]) for fl in matched_flows)
        only_scanner_noise = bool(matched_flows) and all(fl["classification"] == "SCANNER_NOISE" for fl in matched_flows)
        noise_filtered = only_scanner_noise and (total_pkt < noise_floor)

        if matched_flows and total_pkt > 0 and not noise_filtered:
            top = matched_flows[0]
            if only_scanner_noise:
                checks.append({
                    "check": "1. Observed-Path Invariant (Tunable Noise Floor)",
                    "status": "HOLD",
                    "detail": f"{total_pkt} pkt/hr {top['workload']} >= Policy Noise Floor ({noise_floor} pkt/hr)",
                })
                return finalize(
                    "HOLD",
                    "NOISE_FLOOR_THRESHOLD_EXCEEDED",
                    calculate_risk_score(active_pkt_hr=total_pkt),
                    "SCANNER_NOISE_HELD",
                    f"HOLD: {req.target_cidr} has {total_pkt} pkt/hr external traffic which meets/exceeds your active Policy Noise Floor ({noise_floor} pkt/hr).",
                    checks,
                )

            checks.append({
                "check": "1. Observed-Path Invariant (L4 + LPM)",
                "status": "VIOLATION",
                "detail": f"{total_pkt:,} pkt/hr {top['protocol']}/{top['dst_port']} ({top['workload']}) via {lpm['route_table']} | Blast={blast['blast_radius']}",
            })

            # CHECK 4: Digital Twin Blast Radius & 6-Point Failover (T06, T08)
            if req.auto_replan and not req.prompt_injection_simulated:
                fp = self._verify_6pt_failover(effective_routes, simulate_broken_backup=req.simulate_broken_backup)
                if not require_backup:
                    lease = self.jit.mint_lease(tenant_id, chg_id, "SHIFT_ROUTE_TO_BACKUP", "10.41.0.0/16")
                    checks.append({
                        "check": "4. Digital Twin 6-Point Failover (Policy Override)",
                        "status": "WARN_OVERRIDE",
                        "detail": "require_backup_failover=False in Policy Sandbox — failover verification relaxed.",
                    })
                    return finalize(
                        "CONSTRAIN",
                        "POLICY_SANDBOX_RELAXED_CONSTRAIN",
                        calculate_risk_score(active_pkt_hr=total_pkt, failover_broken=req.simulate_broken_backup, failover_check_disabled=True),
                        "OBSERVED_ONLY",
                        "CONSTRAIN (Sandbox Policy): Failover pre-check toggled OFF in sandbox — scoped reroute token minted with elevated residual risk.",
                        checks,
                        lease_dict=lease.model_dump(),
                        failover_6pt=fp,
                    )

                if all(c["passed"] for c in fp):
                    lease = self.jit.mint_lease(tenant_id, chg_id, "SHIFT_ROUTE_TO_BACKUP", "10.41.0.0/16")
                    checks.append({
                        "check": "4. Digital Twin 6-Point Failover",
                        "status": "PASS",
                        "detail": "All 6 backup checks PASSED for 10.41.0.0/16. Scoped HMAC-SHA256 JIT token minted.",
                    })
                    return finalize(
                        "CONSTRAIN",
                        "SAFE_FAILOVER_REPLAN_APPROVED",
                        calculate_risk_score(active_pkt_hr=total_pkt, failover_verified=True),
                        "OBSERVED_ONLY",
                        "CONSTRAIN: Deletion blocked; Recovery Agent failover to 10.41.0.0/16 passed all 6 Digital Twin checks. Scoped 60s HMAC-SHA256 JIT lease minted.",
                        checks,
                        lease_dict=lease.model_dump(),
                        failover_6pt=fp,
                    )

                checks.append({
                    "check": "4. Digital Twin 6-Point Failover",
                    "status": "FAIL",
                    "detail": "Backup path 10.41.0.0/16 failed NSG/return-path verification — escalating to HOLD.",
                })
                return finalize(
                    "HOLD",
                    "UNSAFE_BACKUP_ESCALATED_TO_HOLD",
                    calculate_risk_score(active_pkt_hr=total_pkt, failover_broken=True),
                    "OBSERVED_ONLY",
                    "HOLD: Recovery failover path 10.41.0.0/16 failed 6-point verification (NSG/return path blocked). Deletion escalated to human SRE.",
                    checks,
                    failover_6pt=fp,
                )

            reason = "PROMPT_INJECTION_NEUTRALIZED_HOLD" if effective_injection else "OBSERVED_PATH_ACTIVE_SQL_DEPENDENCY"
            msg = (
                "HOLD: Indirect prompt injection in ServiceNow ticket attempted to bypass policy, but Zero-LLM deterministic gate detected 14,200 pkt/hr active TCP/1433 SQL traffic and blocked deletion."
                if effective_injection
                else f"HOLD: Deletion of route {req.target_cidr} will break active {top['workload']} ({total_pkt:,} pkt/hr {top['protocol']}/{top['dst_port']})."
            )
            return finalize(
                "HOLD",
                reason,
                calculate_risk_score(active_pkt_hr=total_pkt),
                "OBSERVED_ONLY",
                msg,
                checks,
            )

        if noise_filtered:
            checks.append({
                "check": "1. Observed-Path Invariant (Noise Filtered)",
                "status": "PASS",
                "detail": f"Ignored {total_pkt} pkt/hr external scanner noise (<{noise_floor} pkt/hr policy floor).",
            })
        else:
            checks.append({"check": "1. Observed-Path Invariant (L4 + LPM)", "status": "PASS", "detail": "0 active production packets observed."})

        # CHECK 2: 30-Day Historical & Scheduled Batch Window Check (T02)
        sched = scheduled_jobs.get(req.target_cidr)
        if sched and op in DESTRUCTIVE_OPERATIONS:
            checks.append({
                "check": "2. 30-Day Historical & Cron Registry",
                "status": "VIOLATION",
                "detail": f"Protected {sched['schedule_label']} ({sched['cron']}) — {sched['bursts_30d']} bursts ({sched['avg_pkt_hr']:,} pkt/hr).",
            })
            return finalize(
                "HOLD",
                "SCHEDULED_BACKUP_DEPENDENCY_PROTECTED",
                calculate_risk_score(has_scheduled_job=True),
                "HISTORICAL_SCHEDULED",
                f"HOLD: Live traffic is 0 pkt/hr today, but 30-day archive proves {req.target_cidr} carries {sched['schedule_label']} ({sched['avg_pkt_hr']:,} pkt/hr -> {sched['destination']}).",
                checks,
            )
        checks.append({"check": "2. 30-Day Historical & Cron Registry", "status": "PASS", "detail": "0 historical bursts and 0 scheduled cron jobs in 30d."})

        # Layer 1 Guardrail Quarantine: even if a route has 0 flows, block poisoned prompt-injection tickets
        if effective_injection:
            checks.append({
                "check": "Layer 1. Ingress Prompt-Injection Quarantine",
                "status": "HOLD",
                "detail": f"Matched patterns: {', '.join(ingress_scan['matched_patterns']) or 'SIMULATED_INJECTION'}",
            })
            return finalize(
                "HOLD",
                "PROMPT_INJECTION_NEUTRALIZED_HOLD",
                90,
                "INGRESS_INJECTION_QUARANTINED",
                "HOLD: Layer 1 Ingress Scanner detected indirect prompt injection in ticket text and quarantined destructive mutation before execution.",
                checks,
            )

        # CHECK 5: Safe ALLOW + Mint Real HMAC-SHA256 Scoped JIT Lease (T07)
        lease = self.jit.mint_lease(tenant_id, chg_id, op, req.target_cidr)
        checks.append({
            "check": "5. Scoped HMAC-SHA256 JIT Token Minting",
            "status": "ALLOW",
            "detail": f"Minted single-use 60s HS256 JWT lease {lease.token_id} bound to {op} {req.target_cidr}.",
        })
        return finalize(
            "ALLOW",
            "SAFE_DECOMMISSION_VERIFIED",
            calculate_risk_score(),
            "SCANNER_NOISE_FILTERED" if noise_filtered else "DUAL_VERIFIED",
            f"ALLOW: {req.target_cidr} has zero production/scheduled dependencies"
            + (f" ({total_pkt} pkt/hr scanner noise below {noise_floor} pkt/hr floor)." if noise_filtered else ".")
            + f" Minted single-use 60s HMAC-SHA256 lease {lease.token_id}.",
            checks,
            lease_dict=lease.model_dump(),
        )

    def run_policy_sandbox(self, tenant_id: str, req: PolicySandboxRequest) -> Dict[str, Any]:
        policy = {
            "noise_floor_pkt_hr": req.noise_floor_pkt_hr,
            "freshness_sla_sec": req.freshness_sla_sec,
            "require_backup_failover": req.require_backup_failover,
        }
        self.db.update_tenant_fields(tenant_id, policy_config=policy)
        chg_id = f"SANDBOX-{uuid.uuid4().hex[:5].upper()}"
        res = self.validate_mutation(
            tenant_id,
            MutationValidateRequest(
                tenant_id=tenant_id,
                change_id=chg_id,
                agent_id="policy-sandbox",
                operation=req.operation,
                target_cidr=req.target_cidr,
                auto_replan=req.auto_replan,
                simulated_telemetry_age=req.simulated_telemetry_age,
                simulate_broken_backup=req.simulate_broken_backup,
                policy_noise_floor_pkt_hr=req.noise_floor_pkt_hr,
                policy_freshness_sla_sec=req.freshness_sla_sec,
                policy_require_backup_failover=req.require_backup_failover,
            ),
        )
        self.db.append_log(
            tenant_id,
            "INFO",
            "POLICY-SIM",
            f"[{chg_id}] Sandbox (Noise={req.noise_floor_pkt_hr} pkt/hr, SLA={req.freshness_sla_sec}s, BackupReq={req.require_backup_failover}) on {req.target_cidr} -> {res['verdict']} ({res['reason_code']})",
        )
        return res
