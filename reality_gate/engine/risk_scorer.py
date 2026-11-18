"""
REALITY-GATE v2.0 — Deterministic Weighted Change-Risk Intelligence Calculator (0–100)
Pure math scoring with zero LLM involvement.
"""

from __future__ import annotations


def calculate_risk_score(
    *,
    active_pkt_hr: int = 0,
    has_scheduled_job: bool = False,
    telemetry_stale: bool = False,
    collector_missing: bool = False,
    hmac_corrupted: bool = False,
    bypass_attempted: bool = False,
    replay_attempted: bool = False,
    failover_verified: bool = False,
    failover_broken: bool = False,
    failover_check_disabled: bool = False,
) -> int:
    """Deterministic risk score in [0, 100]."""
    if bypass_attempted:
        return 100
    if replay_attempted:
        return 96
    if hmac_corrupted:
        return 95
    if collector_missing:
        return 85
    if telemetry_stale:
        return 78
    if active_pkt_hr >= 100:
        if failover_broken and not failover_check_disabled:
            return 88
        if failover_verified:
            return 18
        if failover_check_disabled and failover_broken:
            return 64
        return 92
    if active_pkt_hr > 0:
        return 74
    if has_scheduled_job:
        return 82
    return 8
