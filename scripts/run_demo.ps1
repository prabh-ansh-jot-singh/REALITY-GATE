<#
.SYNOPSIS
  REALITY-GATE v2.0 — One-Command Enterprise Demo Launcher (Windows PowerShell)
  Launches FastAPI, runs pytest + 40-scenario eval/run_eval.py benchmark,
  prints a clean terminal summary, and opens http://127.0.0.1:8000.
#>

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

$Port = if ($env:REALITY_GATE_PORT) { $env:REALITY_GATE_PORT } else { "8000" }
$Url = "http://127.0.0.1:$Port"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  REALITY-GATE v2.0 — One-Command Enterprise Demo Launcher" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# 1. Start FastAPI server if not already listening
$ServerHealthy = $false
try {
    $null = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 2
    $ServerHealthy = $true
    Write-Host "[OK] REALITY-GATE server already running at $Url" -ForegroundColor Green
} catch {
    Write-Host "[1/4] Launching FastAPI server on $Url ..." -ForegroundColor Yellow
    if (!(Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }
    $Proc = Start-Process -FilePath "python" -ArgumentList "main.py" -WorkingDirectory $RootDir -RedirectStandardOutput "logs\server.out.log" -RedirectStandardError "logs\server.err.log" -PassThru
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $null = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 2
            $ServerHealthy = $true
            Write-Host "[OK] Server ready (PID $($Proc.Id)) at $Url" -ForegroundColor Green
            break
        } catch {}
    }
    if (-not $ServerHealthy) {
        throw "Server failed to become healthy at $Url/api/health. Check logs\server.err.log."
    }
}

# 2. Run automated pytest suite
Write-Host ""
Write-Host "[2/4] Running Pytest Security & T01-T12 Red-Team Suite..." -ForegroundColor Cyan
python -m pytest -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Run 40-Scenario Evaluation Benchmark
Write-Host ""
Write-Host "[3/4] Running 40-Scenario Cloud Safety Evaluation Benchmark..." -ForegroundColor Cyan
python eval/run_eval.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 4. Executive Summary & Launch Browser
Write-Host "[4/4] All Verifications Passed — Launching Console!" -ForegroundColor Green
Write-Host "------------------------------------------------------------------------------"
Write-Host "  Operations Console : $Url"
Write-Host "  Swagger API Docs   : $Url/docs"
Write-Host "  Audit Ledger JSONL : $RootDir\logs\audit.jsonl"
Write-Host "------------------------------------------------------------------------------"

Start-Process $Url
