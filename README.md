# REALITY-GATE™ v2.0 — Deterministic Safety Layer for Autonomous Infrastructure Agents

**The Wire Never Lies.** REALITY-GATE v2.0 is a modular, SQLite-persisted, cryptographically enforced cyber-resiliency platform that prevents autonomous AI SRE agents from deleting live production cloud network routes based on stale CMDB or Terraform documentation.

---

## Modular Enterprise Architecture

```text
reality-gate/
├── reality_gate/
│   ├── config.py                  # Policy thresholds, HMAC secrets, SQLite/JSONL paths, tenant aliases
│   ├── database.py                # Real SQLite WAL persistence (`reality_gate.db`) across 13 tables
│   ├── models.py                  # Strict Pydantic v2 schemas (Swagger 1-click default: `apex-retail`)
│   ├── audit/
│   │   └── hash_chain.py          # Append-only SHA-256 ledger (`logs/audit.jsonl` + SQLite) & verifier
│   ├── broker/
│   │   ├── jit_auth.py            # HMAC-SHA256 signed 60s JIT JWT leases + SQLite anti-replay nonces
│   │   └── cloud_executor.py      # Zero-credential broker (HTTP 403 on bypass/replay) + T12 auto-rollback
│   ├── engine/
│   │   ├── graph_solver.py        # Real NetworkX DiGraph dual-plane & ipaddress LPM blast-radius solver
│   │   ├── risk_scorer.py         # Deterministic 0–100 change-risk calculator (zero LLM)
│   │   └── invariant_gate.py      # 5-Check Zero-LLM Admission Gate + Policy Sandbox + 4-Stage Lock
│   ├── agents/
│   │   ├── prompts_and_tools.py   # Agent contracts, optional Azure OpenAI, & Teams Adaptive Card dispatcher
│   │   └── orchestrator.py        # 4-Agent sequential loop (Planner -> Reviewer -> Recovery -> Auditor)
│   └── api/
│       └── app.py                 # FastAPI REST + MCP proxy + audit verify/download + console UI
├── frontend/
│   └── index.html                 # Blue & White Light-Mode Corporate Landing Page + HUD Operations Console
├── tests/
│   ├── test_invariants.py         # Persistence, HMAC JWT, HTTP 403/409, Policy Sandbox, & Tamper Detection
│   └── test_red_team_t01_t12.py   # Automated T01–T12 Red-Team Suite + FastAPI TestClient checks
├── scripts/
│   └── run_live_attack_demo.py    # Live terminal attack & closed-loop failover simulator
├── logs/
│   └── audit.jsonl                # Auto-created append-only SHA-256 hash-chained audit ledger
├── main.py                        # Clean Uvicorn launcher
├── Dockerfile
└── docker-compose.yml
```

---

## Quick Start (Local)

```bash
pip install -r requirements.txt
python main.py
```

Open:
- **Corporate Website & Operations Console:** `http://127.0.0.1:8000`
- **Interactive Swagger API Docs (1-Click Ready):** `http://127.0.0.1:8000/docs`

---

## Automated Verification & Live Attack Demo

### 1. One-Command Demo Launcher (FastAPI + Pytest + 40-Scenario Eval + Browser)
```powershell
# Windows PowerShell
.\scripts\run_demo.ps1
```
```bash
# Linux / macOS / Git Bash
bash scripts/run_demo.sh
```

### 2. Run the Full Pytest Security & Red-Team Suite (`T01–T12` + Tamper Detection + Eval + Guardrail Sandwich)
```bash
python -m pytest -v
```

### 3. Run the 40-Scenario Evaluation Benchmark (`eval/run_eval.py`)
```bash
python eval/run_eval.py
```

### 4. Run the Live Terminal Attack Simulator (against running server)
```bash
python scripts/run_live_attack_demo.py
```
Fires live HTTP attacks verifying:
1. **Direct Azure ARM Bypass** → Rejected with **HTTP 403 Forbidden** (`DIRECT_ARM_BYPASS_BLOCKED`)
2. **Indirect Prompt Injection** → Neutralized with deterministic **HOLD** (`PROMPT_INJECTION_NEUTRALIZED_HOLD`)
3. **HMAC-SHA256 JIT Lease Replay** → 1st execution succeeds (`200 OK`), 2nd replay rejected with **HTTP 403 Forbidden** (`REPLAY_TOKEN_REJECTED`)
4. **7-Step Closed-Loop CONSTRAIN Failover** → Reroutes SQL `10.40.0.0/16` safely onto verified `10.41.0.0/16` with `0 ms` downtime
5. **End-to-End SHA-256 Chain Verification** → Re-hashes every line of `logs/audit.jsonl` from genesis block `#0` to latest

---

## Docker Deployment

```bash
docker compose up --build
```

---

## Key Security & Governance APIs

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/mutations/validate` & `/mcp/tools/validate_infrastructure_mutation` | `POST` | Zero-LLM 5-Check Deterministic Admission Gate + Guardrail Sandwich |
| `/api/mutations/execute` | `POST` | Zero-Credential Scoped Execution Broker (HTTP 403 on bypass/replay/invalid HMAC) |
| `/api/agents/run` | `POST` | Run 4-Agent Debate + Dual-Candidate Twin + OTel Trace Waterfall (`demo_replan`, `allow_dead`, `hold_sql`, `raw_outage`) |
| `/api/eval/run` & `/api/eval/latest` | `POST` / `GET` | 40-Scenario Cloud Safety Evaluation Benchmark (False-ALLOW, Outage Prevention, Noise False-Block, p50/p95/p99) |
| `/api/guardrail/scan` | `POST` | 3-Layer Guardrail Sandwich tester (PII masking + prompt-injection scan + Layer-1 bypass defense-in-depth proof) |
| `/api/policy/sandbox` | `POST` | Live What-If Policy & Blast-Radius Simulator |
| `/api/audit/verify-integrity` | `GET` | Cryptographically re-hash every block in `logs/audit.jsonl` |
| `/api/audit/download` | `GET` | Download raw `logs/audit.jsonl` tamper-evident audit ledger |
| `/api/integrations/config` & `/api/teams/inbox` | `POST` / `GET` | Configure Azure/ServiceNow/Teams Webhook & inspect dispatched Teams Adaptive Cards |
| `/api/redteam/run` | `POST` | Execute adversarial vectors `T01–T12` or `ALL` |
