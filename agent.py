#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner & Payer

Routes ALL calls through ArkForge Trust Layer (certifying proxy).
Every transaction gets a SHA-256 proof chain + RFC 3161 certified timestamp.

Modes:
  scan <repo_url>   — Scan repo via Trust Layer (0.10 EUR/proof)
  pay               — Payment proof only (0.10 EUR from credits)
  credits <amount>  — Buy prepaid credits (min 1 EUR, max 100 EUR)
  verify <proof_id> — Verify an existing proof

Receipt auto-attach:
  After 'credits', the Stripe receipt URL is saved locally.
  Subsequent 'scan' and 'pay' calls auto-attach it as payment evidence.
  --receipt-url URL   Override with a specific receipt URL
  --no-receipt        Skip auto-attach for this call

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
RECEIPT_FILE = Path(__file__).parent / ".last_receipt.json"


AGENT_IDENTITY = "arkforge-agent-client"
AGENT_VERSION = "1.4.0"


def _save_receipt(receipt_url: str, amount: float = 0):
    """Save last Stripe receipt URL for auto-attach on future calls."""
    RECEIPT_FILE.write_text(json.dumps({
        "receipt_url": receipt_url,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "amount": amount,
    }, indent=2))


def _load_receipt() -> str:
    """Load last saved receipt URL. Returns empty string if none."""
    if not RECEIPT_FILE.exists():
        return ""
    try:
        data = json.loads(RECEIPT_FILE.read_text())
        return data.get("receipt_url", "")
    except (json.JSONDecodeError, OSError):
        return ""


def _headers() -> dict:
    return {
        "X-Api-Key": API_KEY,
        "Content-Type": "application/json",
        "X-Agent-Identity": AGENT_IDENTITY,
        "X-Agent-Version": AGENT_VERSION,
    }


def _call_proxy(target: str, payload: dict, description: str = "", method: str = "POST",
                receipt_url: str = "") -> dict:
    """Call Trust Layer /v1/proxy — debit credits, forward, prove."""
    body = {
        "target": target,
        "payload": payload,
        "method": method,
        "description": description,
    }
    if receipt_url:
        body["payment_evidence"] = {
            "type": "stripe",
            "receipt_url": receipt_url,
        }
    resp = requests.post(
        f"{TRUST_LAYER_BASE}/v1/proxy",
        headers=_headers(),
        json=body,
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        return {"error": f"HTTP {resp.status_code}", "detail": detail}

    result = resp.json()
    # Capture Ghost Stamp headers for display
    result["_response_headers"] = {
        k: v for k, v in resp.headers.items() if k.startswith("X-ArkForge-")
    }
    return result


def pay(receipt_url: str = "") -> dict:
    """Pay 0.10 EUR from prepaid credits. No upstream call — payment proof only."""
    if not API_KEY:
        return {"error": "TRUST_LAYER_API_KEY not set"}

    # Target the pricing endpoint (lightweight, always available)
    return _call_proxy(
        target="https://arkforge.fr/trust/v1/pricing",
        payload={},
        description="Agent payment — proof of concept",
        method="GET",
        receipt_url=receipt_url,
    )


def scan_repo(repo_url: str, receipt_url: str = "") -> dict:
    """Scan a repository for EU AI Act compliance (0.10 EUR from prepaid credits)."""
    if not API_KEY:
        return {"error": "TRUST_LAYER_API_KEY not set"}

    return _call_proxy(
        target=SCAN_API_TARGET,
        payload={"repo_url": repo_url},
        description=f"EU AI Act compliance scan: {repo_url}",
        receipt_url=receipt_url,
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


def buy_credits(amount: float) -> dict:
    """Buy prepaid credits via Trust Layer (charges saved Stripe card)."""
    if not API_KEY:
        return {"error": "TRUST_LAYER_API_KEY not set"}

    resp = requests.post(
        f"{TRUST_LAYER_BASE}/v1/credits/buy",
        headers=_headers(),
        json={"amount": amount},
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code != 200:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        return {"error": f"HTTP {resp.status_code}", "detail": detail}

    return resp.json()


def _extract_receipt_url(args: list) -> str:
    """Extract --receipt-url value from CLI arguments."""
    for i, arg in enumerate(args):
        if arg == "--receipt-url" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--receipt-url="):
            return arg.split("=", 1)[1]
    return ""


def _print_payment_evidence(result: dict):
    """Print external payment evidence from proof."""
    proof = result if "payment_evidence" in result else result.get("proof", {})
    pe = proof.get("payment_evidence")
    if not pe:
        return
    print("[PAYMENT EVIDENCE — External Receipt]")
    status = pe.get("receipt_fetch_status", "N/A")
    icon = "OK" if status == "fetched" else "FAILED"
    print(f"  Fetch:     {icon} ({status})")
    if pe.get("receipt_content_hash"):
        print(f"  Hash:      {pe['receipt_content_hash'][:48]}...")
    if pe.get("parsing_status"):
        print(f"  Parsing:   {pe['parsing_status']}")
    parsed = pe.get("parsed_fields")
    if parsed and isinstance(parsed, dict):
        if parsed.get("amount") is not None:
            print(f"  Amount:    {parsed['amount']} {parsed.get('currency', '')}")
        if parsed.get("status"):
            print(f"  Status:    {parsed['status']}")
        if parsed.get("date"):
            print(f"  Date:      {parsed['date']}")
    verification = pe.get("payment_verification", "N/A")
    print(f"  Verified:  {verification}")
    if pe.get("receipt_fetch_error"):
        print(f"  Error:     {pe['receipt_fetch_error']}")
    print()


def _print_proof(result: dict):
    """Print proof details from Trust Layer response."""
    proof = result.get("proof", {})
    if not proof:
        return
    hashes = proof.get("hashes", {})
    tsa = proof.get("timestamp_authority") or {}

    print("[PROOF — Trust Layer]")
    print(f"  ID:           {proof.get('proof_id', 'N/A')}")
    if proof.get("spec_version"):
        print(f"  Spec:         {proof['spec_version']}")
    print(f"  Chain Hash:   {hashes.get('chain', 'N/A')[:48]}...")
    print(f"  Request Hash: {hashes.get('request', 'N/A')[:48]}...")
    if proof.get("arkforge_signature"):
        sig = proof["arkforge_signature"]
        print(f"  Signature:    {sig[:20]}...(verified)")
    print(f"  Verify URL:   {proof.get('verification_url', 'N/A')}")
    share_url = proof.get("verification_url", "").replace("/v1/proof/", "/v/")
    if share_url:
        print(f"  Share URL:    {share_url}")
    print(f"  Timestamp:    {proof.get('timestamp', 'N/A')}")
    if proof.get("upstream_timestamp"):
        print(f"  Upstream:     {proof['upstream_timestamp']}")
    if tsa:
        print(f"  TSA:          {tsa.get('status', 'N/A')}")
    print()


def _print_attestation(result: dict):
    """Print Digital Stamp (Level 1) from service response."""
    svc = result.get("service_response", {})
    body = svc.get("body", {}) if isinstance(svc, dict) else {}
    attestation = body.get("_arkforge_attestation") if isinstance(body, dict) else None
    if attestation:
        print("[ATTESTATION — Digital Stamp]")
        print(f"  Embedded in scan result body as _arkforge_attestation")
        print(f"  Status:       {attestation.get('status', 'N/A')}")
        print()


def _print_ghost_stamp(result: dict):
    """Print Ghost Stamp (Level 2) from response headers."""
    headers = result.get("_response_headers", {})
    if headers:
        print("[RESPONSE HEADERS — Ghost Stamp]")
        for key in ("X-ArkForge-Verified", "X-ArkForge-Proof-ID", "X-ArkForge-Trust-Link"):
            if key in headers:
                print(f"  {key}: {headers[key]}")
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

    prefix = command if command in ("scan", "pay", "credits") else "pay"
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
        print("  python3 agent.py scan <repo_url>       # Scan repo (0.10 EUR)")
        print("  python3 agent.py pay                    # Payment proof (0.10 EUR)")
        print("  python3 agent.py credits <amount_eur>   # Buy credits (1-100 EUR)")
        print("  python3 agent.py verify <proof_id>      # Verify a proof")
        print()
        print("Receipt auto-attach (after buying credits):")
        print("  --receipt-url URL   Override with a specific receipt")
        print("  --no-receipt        Skip auto-attach for this call")
        print()
        print("Setup:")
        print("  export TRUST_LAYER_API_KEY='mcp_pro_...'")
        sys.exit(1)

    command = sys.argv[1]
    ts = datetime.now(timezone.utc).isoformat()

    no_receipt = "--no-receipt" in sys.argv
    receipt_url = _extract_receipt_url(sys.argv)
    if not receipt_url and not no_receipt:
        receipt_url = _load_receipt()
        if receipt_url:
            print(f"[AUTO] Using saved receipt: {receipt_url[:60]}...")
            print()

    if command == "pay":
        print("=" * 60)
        print("AGENT PAYMENT — 0.10 EUR from prepaid credits")
        print("=" * 60)
        print(f"Timestamp:   {ts}")
        print(f"Trust Layer: {TRUST_LAYER_BASE}/v1/proxy")
        print(f"API Key:     {API_KEY[:12]}..." if API_KEY else "API Key:     NOT SET")
        if receipt_url:
            print(f"Receipt URL: {receipt_url[:60]}...")
        print()

        result = pay(receipt_url=receipt_url)

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {json.dumps(result['detail'], indent=2)[:500]}")
            sys.exit(1)

        payment = result.get("proof", {}).get("payment", {})
        print("[PAYMENT]")
        print(f"  Amount:    {payment.get('amount', 'N/A')} {payment.get('currency', 'EUR')}")
        print(f"  Status:    {payment.get('status', 'N/A')}")
        print(f"  Txn ID:    {payment.get('transaction_id', 'N/A')}")
        if payment.get("receipt_url"):
            print(f"  Receipt:   {payment['receipt_url']}")
        print()
        _print_proof(result)
        _print_payment_evidence(result)
        _print_attestation(result)
        _print_ghost_stamp(result)
        _save_log("pay", result)
        print("=" * 60)

    elif command == "credits":
        if len(sys.argv) < 3:
            print("Usage: python3 agent.py credits <amount_eur>")
            print("  Min: 1.00 EUR (= 10 proofs)")
            print("  Max: 100.00 EUR (= 1000 proofs)")
            sys.exit(1)

        amount = float(sys.argv[2])
        print("=" * 60)
        print(f"BUY CREDITS — {amount:.2f} EUR")
        print("=" * 60)
        print(f"Timestamp:   {ts}")
        print(f"Trust Layer: {TRUST_LAYER_BASE}/v1/credits/buy")
        print(f"API Key:     {API_KEY[:12]}..." if API_KEY else "API Key:     NOT SET")
        print()

        result = buy_credits(amount)

        if "error" in result:
            print(f"[FAILED] {result['error']}")
            if "detail" in result:
                print(f"  {json.dumps(result['detail'], indent=2)[:500]}")
            sys.exit(1)

        print("[CREDITS PURCHASED]")
        print(f"  Added:     {result.get('credits_added', 'N/A')} EUR")
        print(f"  Balance:   {result.get('balance', 'N/A')} EUR")
        print(f"  Proofs:    {result.get('proofs_available', 'N/A')} available")
        if result.get("receipt_url"):
            print(f"  Receipt:   {result['receipt_url']}")
            _save_receipt(result["receipt_url"], amount)
            print(f"  [AUTO] Receipt saved — will be attached to future scan/pay calls")
        print()
        _save_log("credits", result, {"amount": amount})
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
        print(f"Price:       0.10 EUR (from prepaid credits)")
        print(f"Trust Layer: {TRUST_LAYER_BASE}/v1/proxy")
        print(f"Scan API:    {SCAN_API_TARGET}")
        print(f"API Key:     {API_KEY[:12]}..." if API_KEY else "API Key:     NOT SET")
        if receipt_url:
            print(f"Receipt URL: {receipt_url[:60]}...")
        print()

        result = scan_repo(repo_url, receipt_url=receipt_url)

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
        print(f"  Txn ID:    {payment.get('transaction_id', 'N/A')}")
        if payment.get("receipt_url"):
            print(f"  Receipt:   {payment['receipt_url']}")
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
        _print_payment_evidence(result)
        _print_attestation(result)
        _print_ghost_stamp(result)
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
        # Show payment evidence summary if present
        _print_payment_evidence(result)

    else:
        print(f"Unknown command: {command}")
        print("Use 'scan', 'pay', 'credits', or 'verify'")
        sys.exit(1)


if __name__ == "__main__":
    main()
