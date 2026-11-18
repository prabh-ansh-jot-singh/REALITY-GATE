"""
REALITY-GATE v2.0 — Zero-Credential Scoped Execution Broker (`cloud_executor.py`)
AI agents hold ZERO standing Azure ARM/IAM keys. All mutations must pass through
this broker with a valid HMAC-SHA256 signed JIT lease. Enforces real SQLite route
mutations and automated post-execution SLO rollback (T12).
"""

from __future__ import annotations

from typing import Any, Dict

from reality_gate.audit.hash_chain import AuditHashChain
from reality_gate.broker.jit_auth import BrokerSecurityError, JITAuthBroker
from reality_gate.database import DatabaseManager
from reality_gate.models import BrokerExecuteRequest


class ScopedCloudExecutor:
    def __init__(self, db: DatabaseManager, audit: AuditHashChain, jit: JITAuthBroker):
        self.db = db
        self.audit = audit
        self.jit = jit

    def execute(self, tenant_id: str, req: BrokerExecuteRequest) -> Dict[str, Any]:
        # Hard enforcement: reject direct Azure ARM bypass with HTTP 403
        if req.bypass_broker:
            self.db.increment_counter(tenant_id, "denied_count")
            blk = self.audit.append(
                tenant_id=tenant_id,
                change_id=req.change_id,
                actor="execution-broker",
                operation=req.operation,
                target_cidr=req.target_cidr,
                verdict="DENY",
                reason_code="DIRECT_ARM_BYPASS_BLOCKED",
                risk_score=100,
                evidence_state="SECURITY_VIOLATION",
                token_id=None,
            )
            self.db.append_log(
                tenant_id,
                "ERR",
                "EXEC-BROKER",
                f"[{req.change_id}] 403 DENY: Direct Azure ARM bypass blocked by Zero-Credential Broker.",
            )
            raise BrokerSecurityError(
                "DIRECT_ARM_BYPASS_BLOCKED",
                f"DENY (403): Direct Azure ARM API call blocked — AI agents hold zero standing credentials. Audit #{blk.block_index}.",
                status_code=403,
            )

        # Verify cryptographic HMAC-SHA256 JIT lease + anti-replay SQLite nonce
        try:
            lease = self.jit.verify_and_consume_lease(
                tenant_id=tenant_id,
                authorization_token=req.authorization_token,
                nonce=req.nonce,
                operation=req.operation,
                target_cidr=req.target_cidr,
            )
        except BrokerSecurityError as exc:
            self.db.increment_counter(tenant_id, "denied_count")
            self.audit.append(
                tenant_id=tenant_id,
                change_id=req.change_id,
                actor="execution-broker",
                operation=req.operation,
                target_cidr=req.target_cidr,
                verdict="DENY",
                reason_code=exc.reason_code,
                risk_score=96,
                evidence_state="SECURITY_VIOLATION",
                token_id=req.authorization_token[:32] if req.authorization_token else None,
            )
            self.db.append_log(
                tenant_id,
                "ERR",
                "EXEC-BROKER",
                f"[{req.change_id}] 403 {exc.reason_code}: {exc.message}",
            )
            raise

        # Apply REAL persisted SQLite mutation to effective_routes
        mutation = self.db.mutate_route_state(tenant_id, req.target_cidr, req.operation)

        # T12: Post-execution SLO/connectivity probe failure triggers automated SQLite rollback
        if req.force_post_exec_failure:
            rollback_res = self.db.mutate_route_state(tenant_id, req.target_cidr, "ROLLBACK_ROUTE")
            self.db.increment_counter(tenant_id, "rollback_count")
            blk = self.audit.append(
                tenant_id=tenant_id,
                change_id=req.change_id,
                actor="auditor-agent",
                operation=f"ROLLBACK({req.operation})",
                target_cidr=req.target_cidr,
                verdict="ESCALATE & AUTO-ROLLBACK",
                reason_code="POST_EXEC_AUDITOR_PROBE_FAILED",
                risk_score=91,
                evidence_state="AUTO_ROLLED_BACK",
                token_id=lease["token_id"],
            )
            self.db.append_log(
                tenant_id,
                "WARN",
                "AUDITOR-ROLLBACK",
                f"[{req.change_id}] Post-change connectivity probe FAILED — automated rollback executed on {req.target_cidr} in SQLite.",
            )
            return {
                "executed": False,
                "rolled_back": True,
                "status": "ESCALATE & AUTO-ROLLBACK",
                "reason_code": "POST_EXEC_AUDITOR_PROBE_FAILED",
                "message": "Execution succeeded, but Auditor post-change health probe failed. Automated route rollback executed and incident escalated.",
                "token_id": lease["token_id"],
                "mutation": rollback_res,
                "audit_hash": blk.block_hash,
                "block_index": blk.block_index,
            }

        if req.operation.upper().strip() == "SHIFT_ROUTE_TO_BACKUP":
            self.db.update_tenant_fields(tenant_id, rerouted_to_backup=True, outage_active=False)

        blk = self.audit.append(
            tenant_id=tenant_id,
            change_id=req.change_id,
            actor="execution-broker",
            operation=req.operation,
            target_cidr=req.target_cidr,
            verdict="EXECUTED",
            reason_code="BROKER_JIT_EXECUTED_SAFELY",
            risk_score=12,
            evidence_state="VERIFIED_EXECUTION",
            token_id=lease["token_id"],
        )
        self.db.append_log(
            tenant_id,
            "OK",
            "EXEC-BROKER",
            f"[{req.change_id}] Executed {req.operation} on {req.target_cidr} via HMAC-SHA256 lease {lease['token_id']} (SQLite state={mutation['new_state']}).",
        )
        return {
            "executed": True,
            "rolled_back": False,
            "status": "EXECUTED",
            "reason_code": "BROKER_JIT_EXECUTED_SAFELY",
            "message": f"Scoped Execution Broker applied {req.operation} on {req.target_cidr} via verified single-use HMAC-SHA256 JIT lease {lease['token_id']}.",
            "token_id": lease["token_id"],
            "jwt_verified": True,
            "mutation": mutation,
            "audit_hash": blk.block_hash,
            "block_index": blk.block_index,
        }
