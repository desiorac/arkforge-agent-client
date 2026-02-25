#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner

Scans code repositories for EU AI Act compliance using ArkForge's paid API.
Each scan costs 0.50 EUR, charged automatically to a saved card via Stripe.

Prerequisites:
    pip install requests
    export ARKFORGE_SCAN_API_KEY="mcp_pro_..."

Usage:
    python3 agent.py https://github.com/owner/repo

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
API_KEY = os.environ.get("ARKFORGE_SCAN_API_KEY", "")
TIMEOUT_SECONDS = 120
LOG_DIR = Path(__file__).parent / "logs"


def scan_repo(repo_url: str) -> dict:
    """Call ArkForge paid scan API. Charges 0.50 EUR per scan."""
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
        print("Usage: python3 agent.py <repo_url>")
        print()
        print("Example:")
        print("  export ARKFORGE_SCAN_API_KEY='mcp_pro_...'")
        print("  python3 agent.py https://github.com/langchain-ai/langchain")
        sys.exit(1)

    repo_url = sys.argv[1]
    now = datetime.now(timezone.utc)
    ts = now.isoformat()

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
    detected = scan.get("scan", {}).get("detected_models", {})
    frameworks = list(detected.keys()) if isinstance(detected, dict) else []

    print("[SCAN RESULT]")
    print(f"  Risk Score:  {report.get('risk_score', scan.get('risk_score', 'N/A'))}")
    print(f"  Frameworks:  {', '.join(frameworks) if frameworks else 'none detected'}")
    print(f"  Files:       {scan.get('scan', {}).get('files_scanned', 'N/A')}")
    print()

    # Save transaction log locally
    LOG_DIR.mkdir(exist_ok=True)
    log_entry = {
        "timestamp": ts,
        "repo_url": repo_url,
        "payment_proof": payment,
        "scan_summary": {
            "risk_score": report.get("risk_score", scan.get("risk_score")),
            "frameworks_detected": frameworks,
            "files_scanned": scan.get("scan", {}).get("files_scanned", 0),
        },
        "transparency": "Both agents built and controlled by ArkForge (PoC)",
    }

    log_file = LOG_DIR / f"tx_{now.strftime('%Y%m%d_%H%M%S')}.json"
    log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))

    print(f"[SAVED] {log_file}")
    print("=" * 60)

    return result


if __name__ == "__main__":
    main()
