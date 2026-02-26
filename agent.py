#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner & Payer

Routes ALL calls through ArkForge Trust Layer (certifying proxy).
Every transaction gets a SHA-256 proof chain + RFC 3161 certified timestamp.

Modes:
  scan <repo_url>   — Pay 0.50 EUR + scan repo via Trust Layer
  pay               — Pay 0.50 EUR, no scan (payment proof only)
  verify <proof_id> — Verify an existing proof

Prerequisites:
    pip install requests
    export TRUST_LAYER_API_KEY="mcp_pro_..."

TRANSPARENCY NOTICE:
Both this agent (buyer) and the ArkForge scan API (seller) are built and
controlled by the same team (ArkForge). This is a proof-of-concept for
autonomous agent-to-agent paid transactions.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

TRUST_LAYER_BASE = os.environ.get("TRUST_LAYER_BASE", "https://arkforge.fr/trust")
SCAN_API_TARGET = os.environ.get("SCAN_API_TARGET", "https://arkforge.fr/api/v1/scan-repo")
API_KEY = os.environ.get("TRUST_LAYER_API_KEY", "").strip()
# Fallback to old env var for backwards compat
if not API_KEY:
    API_KEY = os.environ.get("ARKFORGE_SCAN_API_KEY", "").strip()
TIMEOUT_SECONDS = 130
LOG_DIR = Path(__file__).parent / "logs"
PROOF_DIR = Path(__file__).parent / "proofs"


def _headers() -> dict:
    return {
        "X-Api-Key": API_KEY,
        "Content-Type": "application/json",
    }


def _call_proxy(target: str, amount: float, payload: dict, description: str = "", method: str = "POST") -> dict:
    """Call Trust Layer /v1/proxy — charge, forward, prove."""
    resp = requests.post(
        f"{TRUST_LAYER_BASE}/v1/proxy",
        headers=_headers(),
        json={
            "target": target,
            "amount": amount,
            "currency": "eur",
            "payload": payload,
            "method": method,
            "description": description,
        },
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        return {"error": f"HTTP {resp.status_code}", "detail": detail}

    return resp.json()


def pay() -> dict:
    """Pay 0.50 EUR through Trust Layer. No upstream call — payment proof only."""
    if not API_KEY:
        return {"error": "TRUST_LAYER_API_KEY not set"}

    # Target the pricing endpoint (lightweight, always available)
    return _call_proxy(
        target="https://arkforge.fr/trust/v1/pricing",
        amount=0.50,
        payload={},
        description="Agent payment — proof of concept",
        method="GET",
    )


def scan_repo(repo_url: str) -> dict:
    """Pay 0.50 EUR + scan a repository for EU AI Act compliance."""
    if not API_KEY:
        return {"error": "TRUST_LAYER_API_KEY not set"}

    return _call_proxy(
        target=SCAN_API_TARGET,
        amount=0.50,
        payload={"repo_url": repo_url},
        description=f"EU AI Act compliance scan: {repo_url}",
    )


def verify_proof(proof_id: str) -> dict:
    """Verify an existing proof via Trust Layer."""
    resp = requests.get(
        f"{TRUST_LAYER_BASE}/v1/proof/{proof_id}",
        timeout=30,
    )
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text[:500]}
    return resp.json()


def _print_proof(result: dict):
    """Print proof details from Trust Layer response."""
    proof = result.get("proof", {})
    if not proof:
        return
    hashes = proof.get("hashes", {})
    ots = proof.get("timestamp_authority") or {}
    print("[PROOF — Trust Layer]")
    print(f"  ID:           {proof.get('proof_id', 'N/A')}")
    print(f"  Chain Hash:   {hashes.get('chain', 'N/A')[:48]}...")
    print(f"  Request Hash: {hashes.get('request', 'N/A')[:48]}...")
    print(f"  Verify URL:   {proof.get('verification_url', 'N/A')}")
    print(f"  Timestamp:    {proof.get('timestamp', 'N/A')}")
    if ots:
        print(f"  TSA:          {ots.get('status', 'N/A')}")
    print()


def _save_log(command: str, result: dict, extra: dict = None):
    """Save transaction log and proof."""
    now = datetime.now(timezone.utc)
    LOG_DIR.mkdir(exist_ok=True)
    PROOF_DIR.mkdir(exist_ok=True)

    log_entry = {
        "command": command,
        "timestamp": now.isoformat(),
        "trust_layer": TRUST_LAYER_BASE,
        "result": result,
        "transparency": "Both agents built and controlled by ArkForge (PoC)",
    }
    if extra:
        log_entry.update(extra)

    prefix = "scan" if command == "scan" else "pay"
    log_file = LOG_DIR / f"{prefix}_{now.strftime('%Y%m%d_%H%M%S')}.json"
    log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
    (LOG_DIR / "latest_transaction.json").write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))

    # Save proof separately
    proof = result.get("proof", {})
    if proof.get("proof_id"):
        proof_file = PROOF_DIR / f"{proof['proof_id']}.json"
        proof_file.write_text(json.dumps(proof, indent=2, ensure_ascii=False))

    print(f"[SAVED] {log_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 agent.py scan <repo_url>    # Pay 0.50 EUR + scan (via Trust Layer)")
        print("  python3 agent.py pay                # Pay 0.50 EUR (proof only)")
        print("  python3 agent.py verify <proof_id>  # Verify a proof")
        print()
        print("Setup:")
        print("  export TRUST_LAYER_API_KEY='mcp_pro_...'")
        sys.exit(1)

    command = sys.argv[1]
    ts = datetime.now(timezone.utc).isoformat()

    if command == "pay":
        print("=" * 60)
        print("AGENT PAYMENT — 0.50 EUR via Trust Layer")
        print("=" * 60)
        print(f"Timestamp:   {ts}")
        print(f"Trust Layer: {TRUST_LAYER_BASE}/v1/proxy")
        print(f"API Key:     {API_KEY[:12]}..." if API_KEY else "API Key:     NOT SET")
        print()

        result = pay()

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {json.dumps(result['detail'], indent=2)[:500]}")
            sys.exit(1)

        payment = result.get("proof", {}).get("payment", {})
        print("[PAYMENT]")
        print(f"  Amount:    {payment.get('amount', 'N/A')} {payment.get('currency', 'EUR')}")
        print(f"  Status:    {payment.get('status', 'N/A')}")
        print(f"  Stripe ID: {payment.get('transaction_id', 'N/A')}")
        print(f"  Receipt:   {payment.get('receipt_url', 'N/A')}")
        print()
        _print_proof(result)
        _save_log("pay", result)
        print("=" * 60)

    elif command == "scan":
        if len(sys.argv) < 3:
            print("Usage: python3 agent.py scan <repo_url>")
            sys.exit(1)

        repo_url = sys.argv[2]

        print("=" * 60)
        print("EU AI ACT COMPLIANCE SCAN — via Trust Layer")
        print("=" * 60)
        print(f"Timestamp:   {ts}")
        print(f"Target:      {repo_url}")
        print(f"Price:       0.50 EUR")
        print(f"Trust Layer: {TRUST_LAYER_BASE}/v1/proxy")
        print(f"Scan API:    {SCAN_API_TARGET}")
        print(f"API Key:     {API_KEY[:12]}..." if API_KEY else "API Key:     NOT SET")
        print()

        result = scan_repo(repo_url)

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {json.dumps(result['detail'], indent=2)[:500]}")
            sys.exit(1)

        # Payment
        payment = result.get("proof", {}).get("payment", {})
        print("[PAYMENT]")
        print(f"  Amount:    {payment.get('amount', 'N/A')} {payment.get('currency', 'EUR')}")
        print(f"  Status:    {payment.get('status', 'N/A')}")
        print(f"  Stripe ID: {payment.get('transaction_id', 'N/A')}")
        print(f"  Receipt:   {payment.get('receipt_url', 'N/A')}")
        print()

        # Scan results (from upstream response)
        svc = result.get("service_response", {})
        upstream = svc.get("body", svc)
        scan = upstream.get("scan_result", upstream)
        report = scan.get("report", scan)
        compliance = report.get("compliance_summary", {})
        detected = scan.get("detected_models", report.get("detected_models", {}))
        frameworks = list(detected.keys()) if isinstance(detected, dict) else []

        print("[SCAN RESULT]")
        score = compliance.get("compliance_score", "N/A")
        pct = compliance.get("compliance_percentage", "N/A")
        print(f"  Compliance:  {score} ({pct}%)" if pct != "N/A" else f"  Compliance:  {score}")
        print(f"  Risk Cat:    {compliance.get('risk_category', 'N/A')}")
        print(f"  Frameworks:  {', '.join(frameworks) if frameworks else 'none detected'}")
        print()

        _print_proof(result)
        _save_log("scan", result, {"repo_url": repo_url})
        print("=" * 60)

    elif command == "verify":
        if len(sys.argv) < 3:
            print("Usage: python3 agent.py verify <proof_id>")
            sys.exit(1)

        proof_id = sys.argv[2]
        print(f"Verifying proof: {proof_id}")
        result = verify_proof(proof_id)

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            sys.exit(1)

        print(json.dumps(result, indent=2))

    else:
        print(f"Unknown command: {command}")
        print("Use 'scan', 'pay', or 'verify'")
        sys.exit(1)


if __name__ == "__main__":
    main()
