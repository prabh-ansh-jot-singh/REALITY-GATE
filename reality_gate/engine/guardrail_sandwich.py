"""
REALITY-GATE v2.0 — 3-Layer Guardrail Sandwich (`guardrail_sandwich.py`)
Layer 1: Ingress PII/Secret Masker & Indirect Prompt-Injection Scanner
Layer 2: Zero-LLM Deterministic NetworkX Wire Gate (blocks even if Layer 1 is bypassed!)
Layer 3: Post-Execution Auditor SLO Probe & Automated SQLite Rollback
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

INJECTION_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("IGNORE_PRIOR_POLICY", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|policy|policies|rules|safety)", re.I)),
    ("OVERRIDE_SAFETY", re.compile(r"(override|bypass|disable|skip)\s+(all\s+)?(safety|guardrail|policy|gate|broker|verification)", re.I)),
    ("SYSTEM_PROMPT_SPOOF", re.compile(r"(<\s*system\s*>|\[system\]|system\s*prompt\s*:|you\s+are\s+now\s+in\s+admin\s+mode)", re.I)),
    ("URGENT_FORCE_DELETE", re.compile(r"(urgent(ly)?\s+delete|force[_\s-]?delete|approved\s+by\s+ceo|emergency\s+override)", re.I)),
    ("CREDENTIAL_EXFIL", re.compile(r"(dump|print|reveal|exfiltrate)\s+(secrets?|keys?|tokens?|credentials?|env)", re.I)),
]

PII_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    ("AZURE_SAS_OR_KEY", re.compile(r"(AccountKey|SharedAccessSignature|sig)=[A-Za-z0-9+/=%_-]{8,}", re.I), r"\1=[REDACTED_SECRET]"),
    ("BEARER_TOKEN", re.compile(r"Bearer\s+[A-Za-z0-9._-]{10,}", re.I), "Bearer [REDACTED_TOKEN]"),
    ("API_KEY_KV", re.compile(r"(api[_-]?key|password|passwd|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9._!@#$%^&*-]{6,}['\"]?", re.I), r"\1=[REDACTED_CREDENTIAL]"),
    ("EMAIL_PII", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    ("SSN_PII", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
]


def scan_ingress_ticket(
    text: str,
    *,
    bypass_ingress_scanner: bool = False,
) -> Dict[str, Any]:
    """
    Layer 1 Guardrail: Scans incoming ServiceNow / Jira / agent ticket text for
    indirect prompt-injection patterns and masks credentials/PII before LLM reasoning.
    If `bypass_ingress_scanner=True`, simulates an evasion/bypass of Layer 1 to prove
    that Layer 2 (Deterministic NetworkX Wire Gate) still enforces HOLD!
    """
    raw = text or ""
    if bypass_ingress_scanner:
        return {
            "layer": "Layer 1 — Ingress PII & Prompt-Injection Scanner",
            "scanner_bypassed": True,
            "injection_detected": False,
            "matched_patterns": [],
            "masked_entities": [],
            "sanitized_text": raw,
            "status": "BYPASSED_SIMULATED",
            "note": "Ingress scanner intentionally bypassed to prove Layer 2 Zero-LLM Wire Gate defense-in-depth.",
        }

    matched_patterns: List[str] = []
    for name, rx in INJECTION_PATTERNS:
        if rx.search(raw):
            matched_patterns.append(name)

    sanitized = raw
    masked_entities: List[str] = []
    for label, rx, repl in PII_SECRET_PATTERNS:
        if rx.search(sanitized):
            masked_entities.append(label)
            sanitized = rx.sub(repl, sanitized)

    injection_detected = len(matched_patterns) > 0
    if injection_detected:
        status = "FLAGGED_INJECTION"
    elif masked_entities:
        status = "PII_MASKED_CLEAN"
    else:
        status = "CLEAN"

    return {
        "layer": "Layer 1 — Ingress PII & Prompt-Injection Scanner",
        "scanner_bypassed": False,
        "injection_detected": injection_detected,
        "matched_patterns": matched_patterns,
        "masked_entities": masked_entities,
        "sanitized_text": sanitized,
        "status": status,
        "note": (
            f"Detected indirect prompt injection ({', '.join(matched_patterns)}) and quarantined ticket before LLM execution."
            if injection_detected
            else (
                f"Masked sensitive entities ({', '.join(masked_entities)}) before agent context injection."
                if masked_entities
                else "No prompt injection or exposed credentials detected in ticket payload."
            )
        ),
    }


def build_guardrail_sandwich_summary(
    ingress_report: Dict[str, Any],
    gate_verdict: str,
    gate_reason: str,
    post_exec_status: str = "ARMED_AUTO_ROLLBACK",
) -> Dict[str, Any]:
    """Assembles the 3-Layer Guardrail Sandwich telemetry object."""
    defense_in_depth_proven = bool(
        ingress_report.get("scanner_bypassed") and gate_verdict in ("HOLD", "DENY")
    )
    return {
        "architecture": "3-Layer Defense-in-Depth Guardrail Sandwich",
        "defense_in_depth_proven": defense_in_depth_proven,
        "layer_1_ingress": ingress_report,
        "layer_2_deterministic_wire_gate": {
            "layer": "Layer 2 — Zero-LLM Deterministic NetworkX Wire Gate",
            "verdict": gate_verdict,
            "reason_code": gate_reason,
            "llm_involved": False,
            "status": "ENFORCED",
        },
        "layer_3_post_exec_auditor": {
            "layer": "Layer 3 — Post-Execution Auditor SLO Probe & Auto-Rollback",
            "status": post_exec_status,
            "auto_rollback_armed": True,
        },
    }
