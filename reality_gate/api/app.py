"""
REALITY-GATE v2.0 — Modular FastAPI Application (`reality_gate/api/app.py`)
Serves the Blue & White Light-Mode Corporate Landing Page + HUD Operations Console
(`frontend/index.html`) alongside all deterministic safety, MCP proxy, cryptographic
broker (HTTP 403 enforcement), SHA-256 audit verification/download, and integration APIs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse

from reality_gate.agents.orchestrator import platform
from reality_gate.broker.jit_auth import BrokerSecurityError
from reality_gate.config import AUDIT_JSONL_PATH, BASE_DIR, DB_PATH
from reality_gate.models import (
    AgentRunRequest,
    BrokerExecuteRequest,
    IntegrationConfigUpdate,
    MutationValidateRequest,
    PolicySandboxRequest,
    RedTeamRunBody,
    StepAdvanceBody,
)

app = FastAPI(
    title="REALITY-GATE v2.0 — Deterministic Safety Layer for Autonomous Infrastructure Agents",
    description=(
        "Modular Enterprise Cyber-Resiliency Platform: SQLite-persisted Dual-Plane NetworkX Digital Twin, "
        "Zero-LLM 5-Check Admission Gate, Cryptographic HMAC-SHA256 JIT Execution Broker (HTTP 403 enforcement), "
        "and Tamper-Evident SHA-256 JSONL Audit Ledger."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_INDEX = BASE_DIR / "frontend" / "index.html"
LOGO_PNG_PATH = BASE_DIR / "logo.png"
LOGO_JPG_PATH = BASE_DIR / "logo.jpg"


# ============================================================================
# STATIC FRONTEND & BRAND ASSETS
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_console():
    if not FRONTEND_INDEX.exists():
        raise HTTPException(status_code=500, detail="frontend/index.html is missing.")
    return HTMLResponse(content=FRONTEND_INDEX.read_text(encoding="utf-8"))


@app.get("/logo.png")
async def serve_logo():
    if LOGO_PNG_PATH.exists():
        return FileResponse(LOGO_PNG_PATH, media_type="image/png")
    raise HTTPException(status_code=404, detail="logo.png not present")


@app.get("/logo.jpg")
async def serve_logo_full():
    if LOGO_JPG_PATH.exists():
        return FileResponse(LOGO_JPG_PATH, media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="logo.jpg not present")


# ============================================================================
# HEALTH & STATE
# ============================================================================

@app.get("/api/health")
async def health():
    integrity = platform.audit.verify_integrity()
    return {
        "status": "ONLINE",
        "service": "REALITY-GATE v2.0",
        "active_tenant": platform.active_tenant_id,
        "sqlite_db": str(DB_PATH),
        "audit_jsonl": str(AUDIT_JSONL_PATH),
        "audit_chain_valid": integrity["valid"],
        "audit_blocks_verified": integrity["blocks_verified"],
    }


@app.get("/api/state")
async def get_state(tenant_id: Optional[str] = Query(default=None)):
    try:
        return platform.full_state(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# TENANT SELECTION & SEQUENTIAL 4-STAGE GUARDRAIL LOCK
# ============================================================================

@app.post("/api/tenant/select/{tenant_id}")
async def select_tenant(tenant_id: str):
    try:
        tid = platform.select(tenant_id)
        return platform.full_state(tid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/tenant/{tenant_id}/stage/{stage_num}")
async def activate_guardrail_stage(tenant_id: str, stage_num: int):
    """Strict sequential 4-stage guardrail activation: HTTP 409 if stage N-1 not completed."""
    try:
        res = platform.activate_guardrail_stage(tenant_id, stage_num)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not res.get("success"):
        raise HTTPException(status_code=res.get("status_code", 400), detail=res.get("error"))
    return {"result": res, "state": platform.full_state(tenant_id)}


@app.post("/api/tenant/{tenant_id}/reset-unprotected")
async def reset_tenant_unprotected(tenant_id: str):
    try:
        state = platform.reset_tenant(tenant_id, force_unprotected=True)
        return {"status": "RESET_UNPROTECTED", "state": state}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# POLICY SANDBOX & AGENT ORCHESTRATION
# ============================================================================

@app.post("/api/policy/sandbox")
async def run_policy_sandbox(req: PolicySandboxRequest):
    try:
        res = platform.run_policy_sandbox(req)
        return {"result": res, "state": platform.full_state(req.tenant_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/agents/run")
async def run_agentic_task(req: AgentRunRequest):
    try:
        run = platform.start_agentic_run(req)
        return {"run": run.model_dump(), "state": platform.full_state(run.tenant_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/agents/{run_id}/advance")
async def advance_agentic_run(run_id: str, body: StepAdvanceBody = StepAdvanceBody()):
    try:
        res = platform.advance_manual_run(body.tenant_id, run_id, expected_next_step=body.expected_next_step)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not res.get("success"):
        raise HTTPException(status_code=res.get("status_code", 400), detail=res.get("error"))
    return {"run": res["run"], "state": platform.full_state(body.tenant_id)}


@app.get("/api/agents/{run_id}")
async def get_agentic_run(run_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        tid = platform.resolve_tenant(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    run = platform.db.get_run(tid, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


@app.post("/api/agents/{run_id}/select")
async def select_agentic_run(run_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        tid = platform.resolve_tenant(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    run = platform.db.get_run(tid, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    platform.db.update_tenant_fields(tid, active_run_id=run_id)
    return {"run": run, "state": platform.full_state(tid)}


# ============================================================================
# MCP DETERMINISTIC GATE & CRYPTOGRAPHIC JIT EXECUTION BROKER (HTTP 403)
# ============================================================================

@app.post("/api/mutations/validate")
@app.post("/mcp/tools/validate_infrastructure_mutation")
async def validate_mutation(req: MutationValidateRequest):
    try:
        verdict = platform.validate_mutation(req)
        return {"result": verdict, "state": platform.full_state(verdict["tenant_id"])}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/mutations/execute")
async def execute_mutation(req: BrokerExecuteRequest):
    """
    Zero-Credential Scoped Execution Broker.
    Returns HTTP 403 Forbidden on direct ARM bypass, forged/expired HMAC-SHA256 JWT,
    scope mismatch, or replayed single-use nonce.
    """
    try:
        res = platform.execute_via_broker(req)
        return {"result": res, "state": platform.full_state(req.tenant_id)}
    except BrokerSecurityError as sec_err:
        raise HTTPException(
            status_code=sec_err.status_code,
            detail={
                "verdict": "DENY",
                "reason_code": sec_err.reason_code,
                "message": sec_err.message,
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# TOPOLOGY, EVIDENCE & TAMPER-EVIDENT SHA-256 AUDIT ENDPOINTS
# ============================================================================

@app.get("/api/topology")
async def get_topology(tenant_id: Optional[str] = Query(default=None)):
    try:
        return platform.get_topology(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/evidence/{change_id}")
async def get_evidence(change_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        return platform.get_evidence(tenant_id, change_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/audit/verify-integrity")
async def verify_audit_integrity():
    """Cryptographically re-hashes every single line in logs/audit.jsonl from block #0 to latest."""
    return platform.audit.verify_integrity()


@app.get("/api/audit/download")
async def download_audit_jsonl():
    """Downloads the append-only SHA-256 hash-chained audit ledger (`logs/audit.jsonl`)."""
    p = Path(platform.audit.jsonl_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Audit ledger logs/audit.jsonl not found.")
    return FileResponse(p, media_type="application/x-ndjson", filename="audit.jsonl")


@app.get("/api/audit/{change_id}")
async def get_audit(change_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        tid = platform.resolve_tenant(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    blocks = platform.audit.get_blocks_for_change(change_id)
    integrity = platform.audit.verify_integrity()
    return {
        "change_id": change_id,
        "chain_integrity": "VERIFIED_SHA256" if integrity["valid"] else "TAMPER_DETECTED",
        "integrity_report": integrity,
        "matching_blocks": blocks if blocks else platform.audit.get_recent_blocks(tid, limit=5),
    }


# ============================================================================
# SERVICENOW CMDB RECONCILIATION, INTEGRATIONS & TEAMS HITL INBOX
# ============================================================================

@app.post("/api/cmdb/proposal/{change_id}/ticket")
async def cmdb_create_ticket(change_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        res = platform.create_servicenow_ticket(tenant_id, change_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not res.get("success"):
        raise HTTPException(status_code=404, detail=res.get("error"))
    return {"result": res, "state": platform.full_state(tenant_id)}


@app.post("/api/cmdb/proposal/{change_id}/approve")
async def cmdb_approve_update(change_id: str, tenant_id: Optional[str] = Query(default=None)):
    try:
        res = platform.approve_cmdb_proposal(tenant_id, change_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not res.get("success"):
        raise HTTPException(status_code=404, detail=res.get("error"))
    return {"result": res, "state": platform.full_state(tenant_id)}


@app.get("/api/integrations")
async def get_integrations(tenant_id: Optional[str] = Query(default=None)):
    try:
        return platform.get_integrations(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/integrations/config")
async def update_integrations(req: IntegrationConfigUpdate):
    try:
        cfg = platform.update_integrations(req)
        return {"integrations": cfg, "state": platform.full_state(req.tenant_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/teams/inbox")
async def get_teams_inbox(tenant_id: Optional[str] = Query(default=None)):
    try:
        tid = platform.resolve_tenant(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"tenant_id": tid, "messages": platform.db.get_teams_inbox(tid, limit=15)}


# ============================================================================
# 12-VECTOR RED-TEAM LAB & RESET
# ============================================================================

@app.post("/api/redteam/run")
async def redteam_run_post(body: RedTeamRunBody):
    try:
        tid = platform.resolve_tenant(body.tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    vec = body.test_id.upper().strip()
    if vec == "ALL":
        results = [platform.run_redteam_test(tid, f"T{i:02d}") for i in range(1, 13)]
        return {"results": results, "state": platform.full_state(tid)}
    try:
        rec = platform.run_redteam_test(tid, vec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"result": rec, "state": platform.full_state(tid)}


@app.post("/api/redteam/run/{test_id}")
async def redteam_run_single(test_id: str, tenant_id: Optional[str] = Query(default=None)):
    return await redteam_run_post(RedTeamRunBody(test_id=test_id, tenant_id=tenant_id))


# ============================================================================
# 40-SCENARIO EVALUATION BENCHMARK SUITE & GUARDRAIL SANDWICH SCANNER
# ============================================================================

@app.post("/api/eval/run")
async def run_evaluation_benchmark():
    """Runs all 40 benchmark cloud mutations across 6 categories and returns measured KPIs."""
    from eval.run_eval import run_benchmark_suite

    report = run_benchmark_suite()
    platform._latest_eval_report = report
    return report


@app.get("/api/eval/latest")
async def get_latest_evaluation_benchmark():
    if platform._latest_eval_report is None:
        return {"has_report": False, "report": None}
    return {"has_report": True, "report": platform._latest_eval_report}


@app.post("/api/guardrail/scan")
async def scan_ticket_guardrail(req: MutationValidateRequest):
    """
    Demonstrates the 3-Layer Guardrail Sandwich (Ingress PII/Prompt-Injection Scanner
    + Zero-LLM NetworkX Wire Gate + Post-Exec Auto-Rollback), including when Layer 1 is bypassed.
    """
    try:
        verdict = platform.validate_mutation(req)
        return {
            "guardrail_sandwich": verdict["guardrail_sandwich"],
            "result": verdict,
            "state": platform.full_state(verdict["tenant_id"]),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/reset")
async def reset_current(tenant_id: Optional[str] = Query(default=None)):
    try:
        state = platform.reset_tenant(tenant_id, force_unprotected=False)
        return {"status": "RESET_OK", "state": state}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
