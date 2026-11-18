"""
REALITY-GATE v2.0 — Strict Pydantic v2 Schemas
Swagger-friendly defaults (default="apex-retail") so /docs works with one click.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentRunRequest(BaseModel):
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])
    scenario: str = Field(
        default="demo_replan",
        description="demo_replan | allow_dead | allow_noise | hold_sql | hold_scheduled | hold_stale | raw_outage",
        examples=["demo_replan"],
    )
    target_cidr: Optional[str] = Field(default="10.40.0.0/16", examples=["10.40.0.0/16"])
    operation: str = Field(default="DELETE_ROUTE", examples=["DELETE_ROUTE"])
    manual_step_mode: bool = Field(default=False)
    prompt_injection: bool = Field(default=False)


class MutationValidateRequest(BaseModel):
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])
    change_id: Optional[str] = Field(default=None, examples=["CHG-2026-2001"])
    agent_id: str = Field(default="planner-agent", examples=["planner-agent"])
    operation: str = Field(default="DELETE_ROUTE", examples=["DELETE_ROUTE"])
    target_cidr: str = Field(default="10.40.0.0/16", examples=["10.40.0.0/16"])
    route_table: str = Field(default="rt-apex-transit", examples=["rt-apex-transit"])
    reason: str = Field(default="Route marked DECOMMISSIONED in ServiceNow CMDB")
    auto_replan: bool = Field(default=False)
    simulated_telemetry_age: Optional[int] = Field(default=45, examples=[45])
    telemetry_collector_disabled: bool = Field(default=False)
    corrupted_evidence_hmac: bool = Field(default=False)
    simulate_broken_backup: bool = Field(default=False)
    bypass_broker: bool = Field(default=False)
    prompt_injection_simulated: bool = Field(default=False)
    bypass_ingress_scanner: bool = Field(default=False)
    request_nonce: Optional[str] = Field(default=None, examples=[None])
    timestamp_epoch: Optional[int] = Field(default=None, examples=[None])
    force_post_exec_failure: bool = Field(default=False)
    policy_noise_floor_pkt_hr: Optional[int] = Field(default=None, examples=[10])
    policy_freshness_sla_sec: Optional[int] = Field(default=None, examples=[300])
    policy_require_backup_failover: Optional[bool] = Field(default=None, examples=[True])


class PolicySandboxRequest(BaseModel):
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])
    noise_floor_pkt_hr: int = Field(default=10, ge=0, le=50)
    freshness_sla_sec: int = Field(default=300, ge=60, le=600)
    require_backup_failover: bool = Field(default=True)
    target_cidr: str = Field(default="10.88.0.0/24", examples=["10.88.0.0/24"])
    operation: str = Field(default="DELETE_ROUTE", examples=["DELETE_ROUTE"])
    simulated_telemetry_age: int = Field(default=45, ge=0, le=900)
    auto_replan: bool = Field(default=False)
    simulate_broken_backup: bool = Field(default=False)


class BrokerExecuteRequest(BaseModel):
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])
    change_id: str = Field(default="CHG-2026-1047", examples=["CHG-2026-1047"])
    authorization_token: str = Field(default="", description="Signed HMAC-SHA256 JIT lease JWT or token_id")
    nonce: str = Field(default="", description="Single-use anti-replay nonce bound to lease")
    operation: str = Field(default="DELETE_ROUTE", examples=["DELETE_ROUTE"])
    target_cidr: str = Field(default="10.99.0.0/24", examples=["10.99.0.0/24"])
    bypass_broker: bool = Field(default=False)
    force_post_exec_failure: bool = Field(default=False)


class RedTeamRunBody(BaseModel):
    test_id: str = Field(default="T01", description="T01..T12 or ALL", examples=["T01"])
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])


class StepAdvanceBody(BaseModel):
    expected_next_step: Optional[int] = Field(default=None, examples=[2])
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])


class IntegrationConfigUpdate(BaseModel):
    tenant_id: Optional[str] = Field(default="apex-retail", examples=["apex-retail"])
    azure_subscription_id: str = Field(default="sub-apex-retail-prod-441")
    azure_openai_endpoint: str = Field(default="")
    servicenow_instance_url: str = Field(default="https://apexretail.service-now.com")
    teams_webhook_url: str = Field(default="")


class AgentStepRecord(BaseModel):
    step_num: int
    agent_id: str
    title: str
    role_type: str
    timestamp: str
    summary: str
    status: str
    verdict_badge: Optional[str] = None
    duration_ms: float
    tools_used: List[str] = Field(default_factory=list)
    input_contract: Dict[str, Any] = Field(default_factory=dict)
    output_contract: Dict[str, Any] = Field(default_factory=dict)


class CMDBProposal(BaseModel):
    change_id: str
    ci_id: str
    route: str
    service: str
    declared_before: str
    observed_wire: str
    proposed_action: str
    status: str
    servicenow_ticket_id: Optional[str] = None
    updated_at: str


class AgenticRunRecord(BaseModel):
    run_id: str
    change_id: str
    tenant_id: str
    title: str
    agent_label: str
    environment: str
    timestamp_display: str
    duration_display: str
    status_badge: str
    status_tone: str
    manual_step_mode: bool = False
    revealed_steps: int = 7
    total_steps: int = 7
    target_cidr: str
    final_verdict: str
    steps: List[AgentStepRecord]
    digital_twin: Dict[str, Any]
    admission_decision: Dict[str, Any]
    cmdb_proposal: Optional[CMDBProposal] = None
    outcome_summary: Dict[str, Any]
    agent_debate: List[Dict[str, Any]] = Field(default_factory=list)
    recovery_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    otel_trace: Dict[str, Any] = Field(default_factory=dict)
    guardrail_sandwich: Dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    block_index: int
    tenant_id: str
    change_id: str
    timestamp: str
    prev_hash: str
    actor: str
    operation: str
    target_cidr: str
    verdict: str
    reason_code: str
    risk_score: int
    evidence_state: str
    token_id: Optional[str]
    block_hash: str


class FlowRecord(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    workload: str
    packets_per_hr: int
    last_seen_sec: int
    matched_cidr: str
    classification: str
    hmac_valid: bool = True


class EffectiveRoute(BaseModel):
    prefix: str
    next_hop_ip: str
    next_hop_type: str
    route_table: str
    vnet_peering: str
    nsg_rule: str
    state: str = "ACTIVE"


class ScheduledJob(BaseModel):
    job_id: str
    cidr: str
    cron: str
    schedule_label: str
    destination: str
    bursts_30d: int
    avg_pkt_hr: int


class CMDBRecord(BaseModel):
    ci_id: str
    cidr: str
    name: str
    declared_state: str
    observed_state: str
    historical_30d: str
    sync_status: str
    proposal_status: str
    servicenow_ticket: Optional[str] = None


class JITLease(BaseModel):
    token_id: str
    jwt_token: str
    nonce: str
    tenant_id: str
    change_id: str
    operation: str
    target_cidr: str
    issued_epoch: int
    expires_epoch: int
    ttl_seconds: int
    hmac_signature: str
    used: bool = False
