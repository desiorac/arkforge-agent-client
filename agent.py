#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner

This agent autonomously scans code repositories for EU AI Act compliance
using ArkForge's paid scan API. Each scan costs 0.50 EUR, charged
automatically to a pre-configured payment method via Stripe.

Two modes:
  1. With API key (saved card): automatic charge via /api/v1/paid-scan
  2. Without API key: calls /agent-pay for Checkout Session URL

TRANSPARENCY NOTICE:
This agent and the ArkForge scan API are both built and controlled by
the same developer (David Desiorac). This is a proof-of-concept
demonstrating autonomous agent-to-agent paid transactions, not an
attempt to simulate independent entities.

Usage:
    # Mode 1: Automatic with saved card
    export ARKFORGE_SCAN_API_KEY="mcp_scan_..."
    python3 agent.py https://github.com/owner/repo

    # Mode 2: Get checkout URL
    python3 agent.py --checkout
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


def request_checkout() -> dict:
    """Call /agent-pay to get a Stripe Checkout Session URL."""
    resp = requests.post(
        f"{API_BASE}/agent-pay",
        timeout=30,
    )
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text}
    return resp.json()


def scan_repo(repo_url: str) -> dict:
    """Call ArkForge paid scan API. Charges 0.50 EUR per scan."""
    if not API_KEY:
        return {"error": "ARKFORGE_SCAN_API_KEY not set"}

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
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text}

    return resp.json()


def main():
    now = datetime.now(timezone.utc)
    ts = now.isoformat()

    # Mode: checkout only (no scan)
    if "--checkout" in sys.argv:
        print(f"[{ts}] Requesting Stripe Checkout Session...")
        result = request_checkout()
        if "error" in result:
            print(f"[ERROR] {result['error']}")
            sys.exit(1)
        print(f"  Checkout URL: {result.get('url', 'N/A')}")
        print(f"  Payment Link: {result.get('payment_link', 'N/A')}")
        print(f"  Session ID: {result.get('session_id', 'N/A')}")
        print(f"  Amount: {result.get('amount_eur', '0.50')} EUR")
        LOG_DIR.mkdir(exist_ok=True)
        log_file = LOG_DIR / f"checkout_{now.strftime('%Y%m%d_%H%M%S')}.json"
        log_file.write_text(json.dumps({"timestamp": ts, **result}, indent=2))
        print(f"\n  Log saved: {log_file}")
        return result

    # Mode: paid scan (requires API key + saved card)
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 agent.py <repo_url>        # scan with saved card")
        print("  python3 agent.py --checkout         # get checkout URL")
        sys.exit(1)

    repo_url = sys.argv[1]

    print(f"[{ts}] EU AI Act Compliance Agent")
    print(f"[{ts}] Scanning: {repo_url}")
    print(f"[{ts}] Payment: 0.50 EUR (automatic via Stripe)")
    print()

    result = scan_repo(repo_url)

    if "error" in result:
        print(f"[ERROR] {result['error']}")
        if "detail" in result:
            print(f"  Detail: {result['detail'][:500]}")
        sys.exit(1)

    payment = result.get("payment_proof", {})
    scan = result.get("scan_result", {})

    print(f"[{ts}] Transaction successful!")
    print(f"  Payment Intent: {payment.get('payment_intent_id', 'N/A')}")
    print(f"  Amount: {payment.get('amount_eur', 'N/A')} EUR")
    print(f"  Status: {payment.get('status', 'N/A')}")
    print(f"  Receipt: {payment.get('receipt_url', 'N/A')}")
    print()

    risk = scan.get("risk_score", scan.get("report", {}).get("risk_score", "N/A"))
    detected = scan.get("scan", {}).get("detected_models", {})
    frameworks = list(detected.keys()) if isinstance(detected, dict) else []
    print(f"  Risk Score: {risk}")
    print(f"  Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}")

    # Save transaction log
    LOG_DIR.mkdir(exist_ok=True)
    log_file = LOG_DIR / f"tx_{now.strftime('%Y%m%d_%H%M%S')}.json"
    log_entry = {
        "timestamp": ts,
        "agent": "eu-ai-act-compliance-agent",
        "service": "arkforge-mcp-eu-ai-act",
        "repo_url": repo_url,
        "payment_proof": payment,
        "scan_summary": {
            "risk_score": risk,
            "frameworks_detected": frameworks,
            "files_scanned": scan.get("scan", {}).get("files_scanned", 0),
        },
        "transparency": "Both agents built and controlled by the same developer",
    }
    log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
    print(f"\n  Log saved: {log_file}")

    # Also write to a stable path for proof capture
    latest = LOG_DIR / "latest_transaction.json"
    latest.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))

    return result


if __name__ == "__main__":
    main()
