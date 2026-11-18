"""
REALITY-GATE v2.0 — Agent Structured Tool Contracts, Optional Azure OpenAI Reasoning,
and Real Microsoft Teams Adaptive Card Webhook Dispatcher (`prompts_and_tools.py`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from reality_gate.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_ENDPOINT,
)
from reality_gate.database import DatabaseManager

AGENT_TOOL_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "planner-agent": {
        "role": "Infrastructure Cost & Route Hygiene Planner",
        "standing_cloud_keys": False,
        "allowed_tools": ["read_servicenow_cmdb", "read_azure_resource_graph", "propose_change_contract"],
        "system_prompt": (
            "You are the REALITY-GATE Planner Agent. Inspect declared ServiceNow CMDB state and Azure "
            "Resource Graph to identify decommissioned routes for hygiene cleanup. You hold ZERO write keys "
            "and must output a strict JSON change proposal for the Reviewer and Deterministic Gate."
        ),
    },
    "reviewer-agent": {
        "role": "Adversarial Telemetry & Dependency Skeptic",
        "standing_cloud_keys": False,
        "allowed_tools": ["read_vnet_flow_logs", "read_30d_schedule_registry", "flag_declared_vs_observed_drift"],
        "system_prompt": (
            "You are the REALITY-GATE Reviewer Agent. Never trust CMDB or Terraform documentation alone. "
            "Correlate VNet Flow Logs v2 and 30-day scheduled batch archives to surface active production dependencies."
        ),
    },
    "recovery-agent": {
        "role": "Zero-Downtime Failover & Replanning Specialist",
        "standing_cloud_keys": False,
        "allowed_tools": ["search_backup_routes", "simulate_digital_twin_failover", "propose_constrained_detour"],
        "system_prompt": (
            "You are the REALITY-GATE Recovery Agent. When a destructive route deletion receives HOLD, "
            "identify a symmetric, NSG-permitted backup path with >=1.5x capacity headroom and resubmit to the gate."
        ),
    },
    "auditor-agent": {
        "role": "Post-Execution Verifier & ServiceNow CMDB Reconciler",
        "standing_cloud_keys": False,
        "allowed_tools": ["post_exec_slo_probe", "write_sha256_ledger", "draft_servicenow_cmdb_ci"],
        "system_prompt": (
            "You are the REALITY-GATE Auditor Agent. Verify zero packet loss after execution, trigger immediate "
            "rollback if SLO probes degrade, seal the SHA-256 audit chain, and draft CMDB updates for human approval."
        ),
    },
}


def generate_agent_reasoning(
    agent_id: str,
    context_summary: str,
    fallback_text: str,
    endpoint_override: str = "",
) -> Dict[str, Any]:
    """
    If AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY are configured, invokes Azure OpenAI Chat Completions
    via httpx to enrich agent reasoning. Otherwise returns clean deterministic reasoning with zero failure.
    """
    endpoint = (endpoint_override or AZURE_OPENAI_ENDPOINT).strip().rstrip("/")
    api_key = AZURE_OPENAI_API_KEY.strip()
    if endpoint and api_key:
        url = (
            f"{endpoint}/openai/deployments/{AZURE_OPENAI_DEPLOYMENT}/chat/completions"
            f"?api-version=2024-06-01"
        )
        system_msg = AGENT_TOOL_CONTRACTS.get(agent_id, {}).get("system_prompt", "You are a cloud NetOps agent.")
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(
                    url,
                    headers={"api-key": api_key, "Content-Type": "application/json"},
                    json={
                        "messages": [
                            {"role": "system", "content": system_msg},
                            {"role": "user", "content": f"Summarize concisely in 1 sentence: {context_summary}"},
                        ],
                        "max_tokens": 90,
                        "temperature": 0.1,
                    },
                )
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                return {"mode": "AZURE_OPENAI_LIVE", "text": text}
        except Exception:
            pass
    return {"mode": "DETERMINISTIC_LOCAL_ADAPTER", "text": fallback_text}


def build_teams_adaptive_card(
    *,
    tenant_name: str,
    change_id: str,
    verdict: str,
    reason_code: str,
    target_cidr: str,
    risk_score: int,
    explanation: str,
    audit_hash: str,
) -> Dict[str, Any]:
    """Builds a real Microsoft Teams Adaptive Card v1.4 webhook payload for HITL approval."""
    accent = "Attention" if verdict in ("HOLD", "DENY") else ("Warning" if verdict == "CONSTRAIN" else "Good")
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "color": accent,
                            "text": f"REALITY-GATE™ HITL Alert — {verdict} ({change_id})",
                        },
                        {
                            "type": "TextBlock",
                            "wrap": True,
                            "text": explanation,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Tenant", "value": tenant_name},
                                {"title": "Target CIDR", "value": target_cidr},
                                {"title": "Verdict", "value": f"{verdict} ({reason_code})"},
                                {"title": "Risk Score", "value": f"{risk_score} / 100"},
                                {"title": "Audit SHA-256", "value": audit_hash[:18] + "..."},
                                {"title": "Timestamp (UTC)", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")},
                            ],
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Inspect in REALITY-GATE Console",
                            "url": "http://127.0.0.1:8000",
                        },
                        {
                            "type": "Action.Submit",
                            "title": "Approve ServiceNow CMDB Reconcile",
                            "data": {"action": "approve_cmdb", "change_id": change_id, "target_cidr": target_cidr},
                        },
                    ],
                },
            }
        ],
    }


def dispatch_teams_card(
    db: DatabaseManager,
    *,
    tenant_id: str,
    tenant_name: str,
    webhook_url: str,
    change_id: str,
    verdict: str,
    reason_code: str,
    target_cidr: str,
    risk_score: int,
    explanation: str,
    audit_hash: str,
) -> Dict[str, Any]:
    """
    If TEAMS_WEBHOOK_URL is configured, sends a real HTTP POST to Microsoft Teams.
    If blank, stores the exact Adaptive Card HTTP payload in SQLite `teams_inbox` for UI inspection.
    """
    card = build_teams_adaptive_card(
        tenant_name=tenant_name,
        change_id=change_id,
        verdict=verdict,
        reason_code=reason_code,
        target_cidr=target_cidr,
        risk_score=risk_score,
        explanation=explanation,
        audit_hash=audit_hash,
    )
    url = (webhook_url or "").strip()
    delivery_mode = "LOCAL_HITL_INBOX"
    http_status: Optional[int] = None

    if url and url.startswith(("http://", "https://")):
        try:
            with httpx.Client(timeout=3.5) as client:
                resp = client.post(url, json=card, headers={"Content-Type": "application/json"})
                http_status = resp.status_code
                delivery_mode = "TEAMS_WEBHOOK_DISPATCHED" if 200 <= resp.status_code < 300 else "TEAMS_WEBHOOK_ERROR"
        except Exception:
            http_status = 0
            delivery_mode = "TEAMS_WEBHOOK_OFFLINE_QUEUED"

    db.save_teams_dispatch(
        tenant_id=tenant_id,
        change_id=change_id,
        verdict=verdict,
        target_cidr=target_cidr,
        delivery_mode=delivery_mode,
        http_status=http_status,
        webhook_url=url or "local://teams-hitl-inbox",
        card_payload=card,
    )
    db.append_log(
        tenant_id,
        "INFO" if delivery_mode != "TEAMS_WEBHOOK_ERROR" else "WARN",
        "TEAMS-HITL",
        f"[{change_id}] Teams Adaptive Card ({verdict}) -> {delivery_mode}"
        + (f" (HTTP {http_status})" if http_status is not None else " (Stored in SQLite Teams Inbox)"),
    )
    return {
        "delivery_mode": delivery_mode,
        "http_status": http_status,
        "webhook_url": url or "local://teams-hitl-inbox",
        "card": card,
    }
