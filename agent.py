#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner & Payer

Two modes:
  pay               — Pay 0.50 EUR via /agent-pay (direct charge with saved card)
  scan <repo_url>   — Pay 0.50 EUR + scan repo via /api/v1/paid-scan

Prerequisites:
    pip install requests
    export ARKFORGE_SCAN_API_KEY="mcp_pro_..."

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

API_BASE = os.environ.get("ARKFORGE_API_BASE", "https://arkforge.fr")
API_KEY = os.environ.get("ARKFORGE_SCAN_API_KEY", "").strip()
TIMEOUT_SECONDS = 120
LOG_DIR = Path(__file__).parent / "logs"


def pay() -> dict:
    """Call /agent-pay to charge 0.50 EUR on saved card. No scan, payment only."""
    if not API_KEY:
        return {"error": "ARKFORGE_SCAN_API_KEY not set. Run: export ARKFORGE_SCAN_API_KEY='mcp_pro_...'"}

    resp = requests.post(
        f"{API_BASE}/agent-pay",
        headers={
            "X-Api-Key": API_KEY,
            "Content-Type": "application/json",
        },
        json={},
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        return {"error": f"HTTP {resp.status_code}", "detail": detail}

    return resp.json()


def scan_repo(repo_url: str) -> dict:
    """Call /api/v1/paid-scan to pay 0.50 EUR + scan a repository."""
    if not API_KEY:
        return {"error": "ARKFORGE_SCAN_API_KEY not set. Run: export ARKFORGE_SCAN_API_KEY='mcp_pro_...'"}

    resp = requests.post(
        f"{API_BASE}/api/v1/paid-scan",
        headers={
            "X-Api-Key": API_KEY,
            "Content-Type": "application/json",
        },
        json={"repo_url": repo_url},
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        return {"error": f"HTTP {resp.status_code}", "detail": detail}

    return resp.json()


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 agent.py pay                           # Pay 0.50 EUR (no scan)")
        print("  python3 agent.py scan <repo_url>               # Pay + scan repo")
        print()
        print("Setup:")
        print("  export ARKFORGE_SCAN_API_KEY='mcp_pro_...'")
        sys.exit(1)

    command = sys.argv[1]
    now = datetime.now(timezone.utc)
    ts = now.isoformat()

    if command == "pay":
        print("=" * 60)
        print("AGENT PAYMENT — 0.50 EUR via /agent-pay")
        print("=" * 60)
        print(f"Timestamp: {ts}")
        print(f"Endpoint:  {API_BASE}/agent-pay")
        print(f"API Key:   {API_KEY[:12]}..." if API_KEY else "API Key:   NOT SET")
        print()

        result = pay()

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {str(result['detail'])[:500]}")
            sys.exit(1)

        payment = result.get("payment_proof", {})
        print(f"[MODE]     {result.get('mode', 'unknown')}")
        print(f"[PAYMENT]")
        print(f"  Intent:    {payment.get('payment_intent_id', 'N/A')}")
        print(f"  Amount:    {payment.get('amount_eur', 'N/A')} EUR")
        print(f"  Status:    {payment.get('status', 'N/A')}")
        print(f"  Receipt:   {payment.get('receipt_url', 'N/A')}")
        print(f"  Customer:  {payment.get('customer_id', 'N/A')}")
        print(f"  Timestamp: {payment.get('timestamp', 'N/A')}")
        print()

        # Save log
        LOG_DIR.mkdir(exist_ok=True)
        log_entry = {
            "command": "pay",
            "timestamp": ts,
            "endpoint": f"{API_BASE}/agent-pay",
            "result": result,
            "transparency": "Both agents built and controlled by ArkForge (PoC)",
        }
        log_file = LOG_DIR / f"pay_{now.strftime('%Y%m%d_%H%M%S')}.json"
        log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
        (LOG_DIR / "latest_transaction.json").write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
        print(f"[SAVED] {log_file}")
        print("=" * 60)
        return result

    elif command == "scan":
        if len(sys.argv) < 3:
            print("Usage: python3 agent.py scan <repo_url>")
            sys.exit(1)

        repo_url = sys.argv[2]

        print("=" * 60)
        print("EU AI ACT COMPLIANCE SCAN")
        print("=" * 60)
        print(f"Timestamp: {ts}")
        print(f"Target:    {repo_url}")
        print(f"Price:     0.50 EUR")
        print(f"API Key:   {API_KEY[:12]}..." if API_KEY else "API Key:   NOT SET")
        print()

        result = scan_repo(repo_url)

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {str(result['detail'])[:500]}")
            sys.exit(1)

        # Payment proof
        payment = result.get("payment_proof", {})
        print("[PAYMENT]")
        print(f"  Intent:  {payment.get('payment_intent_id', 'N/A')}")
        print(f"  Amount:  {payment.get('amount_eur', 'N/A')} EUR")
        print(f"  Status:  {payment.get('status', 'N/A')}")
        print(f"  Receipt: {payment.get('receipt_url', 'N/A')}")
        print()

        # Scan results
        scan = result.get("scan_result", {})
        report = scan.get("report", {})
        compliance = report.get("compliance_summary", {})
        detected = scan.get("detected_models", {})
        frameworks = list(detected.keys()) if isinstance(detected, dict) else []
        files_scanned = scan.get("files_scanned", 0)
        score = compliance.get("compliance_score", "N/A")
        pct = compliance.get("compliance_percentage", "N/A")

        print("[SCAN RESULT]")
        print(f"  Compliance:  {score} ({pct}%)" if pct != "N/A" else f"  Compliance:  {score}")
        print(f"  Risk Cat:    {compliance.get('risk_category', 'N/A')}")
        print(f"  Frameworks:  {', '.join(frameworks) if frameworks else 'none detected'}")
        print(f"  Files:       {files_scanned}")
        print()

        # Save log
        LOG_DIR.mkdir(exist_ok=True)
        log_entry = {
            "command": "scan",
            "timestamp": ts,
            "repo_url": repo_url,
            "payment_proof": payment,
            "scan_summary": {
                "compliance_score": score,
                "compliance_percentage": pct,
                "risk_category": compliance.get("risk_category"),
                "frameworks_detected": frameworks,
                "files_scanned": files_scanned,
            },
            "full_result": result,
            "transparency": "Both agents built and controlled by ArkForge (PoC)",
        }
        log_file = LOG_DIR / f"tx_{now.strftime('%Y%m%d_%H%M%S')}.json"
        log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
        (LOG_DIR / "latest_transaction.json").write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
        print(f"[SAVED] {log_file}")
        print("=" * 60)
        return result

    else:
        print(f"Unknown command: {command}")
        print("Use 'pay' or 'scan'")
        sys.exit(1)


if __name__ == "__main__":
    main()
