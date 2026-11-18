"""
REALITY-GATE v2.0 — Automated 12-Vector Adversarial Red-Team Pytest Suite (T01–T12)
Plus live FastAPI endpoint verification (HTTP 403 Broker Enforcement & Swagger defaults).
Run with: python -m pytest -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reality_gate.agents.orchestrator import RealityGatePlatform
from reality_gate.api.app import app


@pytest.fixture()
def isolated_platform(tmp_path: Path) -> RealityGatePlatform:
    return RealityGatePlatform(
        db_path=tmp_path / "rt_test.db",
        audit_jsonl_path=tmp_path / "rt_audit.jsonl",
    )


@pytest.mark.parametrize(
    "test_id,expected_verdict",
    [
        ("T01", "HOLD"),
        ("T02", "HOLD"),
        ("T03", "HOLD"),
        ("T04", "HOLD"),
        ("T05", "HOLD"),
        ("T06", "CONSTRAIN"),
        ("T07", "ALLOW"),
        ("T08", "HOLD"),
        ("T09", "DENY"),
        ("T10", "DENY"),
        ("T11", "HOLD"),
        ("T12", "ESCALATE & AUTO-ROLLBACK"),
    ],
)
def test_red_team_vector(isolated_platform: RealityGatePlatform, test_id: str, expected_verdict: str):
    result = isolated_platform.run_redteam_test("apex-retail", test_id)
    assert result["passed"] is True, f"{test_id} failed: {result}"
    assert result["actual"] == expected_verdict
    assert result["audit_hash"]
    assert isolated_platform.audit.verify_integrity()["valid"] is True


def test_fastapi_endpoints_http_403_and_audit_verify():
    client = TestClient(app)

    # 1. Health & Swagger-default validation works with 1 click
    h = client.get("/api/health")
    assert h.status_code == 200
    assert h.json()["audit_chain_valid"] is True

    # 2. Direct ARM bypass at /api/mutations/execute returns HTTP 403 Forbidden
    bypass = client.post(
        "/api/mutations/execute",
        json={
            "tenant_id": "apex-retail",
            "change_id": "CHG-HTTP-403",
            "operation": "DELETE_ROUTE",
            "target_cidr": "10.40.0.0/16",
            "bypass_broker": True,
        },
    )
    assert bypass.status_code == 403
    assert bypass.json()["detail"]["reason_code"] == "DIRECT_ARM_BYPASS_BLOCKED"

    # 3. Audit integrity endpoint & download work cleanly
    ver = client.get("/api/audit/verify-integrity")
    assert ver.status_code == 200
    assert ver.json()["valid"] is True

    dl = client.get("/api/audit/download")
    assert dl.status_code == 200
    assert "SHA256_GENESIS_SEALED" in dl.text

    # 4. Reset tenant back to clean state after API test
    rst = client.post("/api/reset", params={"tenant_id": "apex-retail"})
    assert rst.status_code == 200
