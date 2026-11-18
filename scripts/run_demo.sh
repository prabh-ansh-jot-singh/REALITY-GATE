#!/usr/bin/env bash
# REALITY-GATE v2.0 — One-Command Demo Startup Script (Linux / macOS / Git Bash)
# Launches FastAPI, runs pytest + 40-scenario evaluation benchmark, prints summary,
# and opens http://127.0.0.1:8000 in the default browser.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

PORT="${REALITY_GATE_PORT:-8000}"
URL="http://127.0.0.1:${PORT}"

echo "=============================================================================="
echo "  REALITY-GATE v2.0 — One-Command Enterprise Demo Launcher"
echo "=============================================================================="

# 1. Start FastAPI server if not already listening
if curl -sf "${URL}/api/health" >/dev/null 2>&1; then
  echo "[OK] REALITY-GATE server already running at ${URL}"
else
  echo "[1/4] Launching FastAPI server on ${URL} ..."
  python3 main.py > logs/server.log 2>&1 &
  SERVER_PID=$!
  for i in $(seq 1 30); do
    if curl -sf "${URL}/api/health" >/dev/null 2>&1; then
      echo "[OK] Server ready (PID ${SERVER_PID}) at ${URL}"
      break
    fi
    sleep 0.5
  done
fi

# 2. Run automated pytest security & T01-T12 Red-Team suite
echo ""
echo "[2/4] Running Pytest Security & T01-T12 Red-Team Suite..."
python3 -m pytest -v

# 3. Run 40-Scenario Evaluation Benchmark
echo ""
echo "[3/4] Running 40-Scenario Cloud Safety Evaluation Benchmark..."
python3 eval/run_eval.py

# 4. Print executive summary & open browser
echo "[4/4] Demo Ready!"
echo "------------------------------------------------------------------------------"
echo "  Operations Console : ${URL}"
echo "  Swagger API Docs   : ${URL}/docs"
echo "  Audit Ledger JSONL : ${ROOT_DIR}/logs/audit.jsonl"
echo "------------------------------------------------------------------------------"

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "${URL}" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "${URL}" >/dev/null 2>&1 || true
fi
