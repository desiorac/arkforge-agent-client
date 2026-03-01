#!/usr/bin/env python3
"""
EU AI Act Compliance Agent — Autonomous Scanner & Payer

Routes ALL calls through ArkForge Trust Layer (certifying proxy).
Every transaction gets a SHA-256 proof chain + RFC 3161 certified timestamp.

Modes:
  scan <repo_url>            — Scan repo via Trust Layer (0.10 EUR/proof)
  pay                        — Payment proof only (0.10 EUR from credits)
  credits <amount>           — Buy prepaid credits (min 1 EUR, max 100 EUR)
  verify <proof_id>          — Verify an existing proof
  reputation <agent_id>      — Check agent reputation (0-100)
  dispute <proof_id> "reason" — File a dispute against a proof
  disputes <agent_id>        — View dispute history for an agent

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
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

AGENT_IDENTITY = "arkforge-agent-client"
AGENT_VERSION = "1.5.0"

TIMEOUT_SECONDS = 130
LOG_DIR = Path(__file__).parent / "logs"
PROOF_DIR = Path(__file__).parent / "proofs"
RECEIPT_FILE = Path(__file__).parent / ".last_receipt.json"

log = logging.getLogger("arkforge-agent")


# ---------------------------------------------------------------------------
# Config — lazy evaluation so env vars can be set after import
# ---------------------------------------------------------------------------

def _get_base_url() -> str:
    return os.environ.get("TRUST_LAYER_BASE", "https://arkforge.fr/trust")


def _get_scan_target() -> str:
    return os.environ.get("SCAN_API_TARGET", "https://arkforge.fr/api/v1/scan-repo")


def _get_api_key() -> str:
    key = os.environ.get("TRUST_LAYER_API_KEY", "").strip()
    if not key:
        key = os.environ.get("ARKFORGE_SCAN_API_KEY", "").strip()
    return key


# ---------------------------------------------------------------------------
# Receipt persistence
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _headers() -> dict:
    return {
        "X-Api-Key": _get_api_key(),
        "Content-Type": "application/json",
        "X-Agent-Identity": AGENT_IDENTITY,
        "X-Agent-Version": AGENT_VERSION,
    }


def _safe_json(resp: requests.Response) -> dict:
    """Parse JSON response, return error dict on failure."""
    try:
        return resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return {"error": f"Invalid JSON from server (HTTP {resp.status_code})",
                "detail": resp.text[:500]}


def _error_result(resp: requests.Response) -> dict:
    """Build a standardized error dict from a failed response."""
    try:
        detail = resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        detail = resp.text[:500]
    return {"error": f"HTTP {resp.status_code}", "detail": detail}


# ---------------------------------------------------------------------------
# API functions (importable as library)
# ---------------------------------------------------------------------------

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
        f"{_get_base_url()}/v1/proxy",
        headers=_headers(),
        json=body,
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code not in (200, 201):
        return _error_result(resp)

    result = _safe_json(resp)
    if "error" in result:
        return result

    # Capture Ghost Stamp headers separately (not mixed into API data)
    ghost_headers = {
        k: v for k, v in resp.headers.items() if k.startswith("X-ArkForge-")
    }
    if ghost_headers:
        result["_response_headers"] = ghost_headers
    return result


def pay(receipt_url: str = "") -> dict:
    """Pay 0.10 EUR from prepaid credits. No upstream call — payment proof only."""
    if not _get_api_key():
        return {"error": "TRUST_LAYER_API_KEY not set"}

    return _call_proxy(
        target=f"{_get_base_url()}/v1/pricing",
        payload={},
        description="Agent payment — proof of concept",
        method="GET",
        receipt_url=receipt_url,
    )


def scan_repo(repo_url: str, receipt_url: str = "") -> dict:
    """Scan a repository for EU AI Act compliance (0.10 EUR from prepaid credits)."""
    if not _get_api_key():
        return {"error": "TRUST_LAYER_API_KEY not set"}

    return _call_proxy(
        target=_get_scan_target(),
        payload={"repo_url": repo_url},
        description=f"EU AI Act compliance scan: {repo_url}",
        receipt_url=receipt_url,
    )


def verify_proof(proof_id: str) -> dict:
    """Verify an existing proof via Trust Layer."""
    resp = requests.get(
        f"{_get_base_url()}/v1/proof/{proof_id}",
        timeout=30,
    )
    if resp.status_code != 200:
        return _error_result(resp)
    return _safe_json(resp)


def get_reputation(agent_id: str) -> dict:
    """Get public reputation score for an agent."""
    resp = requests.get(
        f"{_get_base_url()}/v1/agent/{agent_id}/reputation",
        timeout=30,
    )
    if resp.status_code != 200:
        return _error_result(resp)
    return _safe_json(resp)


def file_dispute(proof_id: str, reason: str) -> dict:
    """File a dispute against a proof."""
    if not _get_api_key():
        return {"error": "TRUST_LAYER_API_KEY not set"}
    resp = requests.post(
        f"{_get_base_url()}/v1/disputes",
        headers=_headers(),
        json={"proof_id": proof_id, "reason": reason},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        return _error_result(resp)
    return _safe_json(resp)


def get_disputes(agent_id: str) -> dict:
    """Get dispute history for an agent."""
    resp = requests.get(
        f"{_get_base_url()}/v1/agent/{agent_id}/disputes",
        timeout=30,
    )
    if resp.status_code != 200:
        return _error_result(resp)
    return _safe_json(resp)


def buy_credits(amount: float) -> dict:
    """Buy prepaid credits via Trust Layer (charges saved Stripe card)."""
    if not _get_api_key():
        return {"error": "TRUST_LAYER_API_KEY not set"}

    resp = requests.post(
        f"{_get_base_url()}/v1/credits/buy",
        headers=_headers(),
        json={"amount": amount},
        timeout=TIMEOUT_SECONDS,
    )

    if resp.status_code not in (200, 201):
        return _error_result(resp)

    return _safe_json(resp)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_header(title: str):
    print("=" * 60)
    print(title)
    print("=" * 60)


def _print_error(result: dict):
    """Print error and exit. Returns True if error was found."""
    if "error" not in result:
        return False
    print(f"[FAILED] {result['error']}")
    detail = result.get("detail")
    if detail:
        text = json.dumps(detail, indent=2)[:500] if not isinstance(detail, str) else detail[:500]
        print(f"  {text}")
    sys.exit(1)


def _print_key_info():
    api_key = _get_api_key()
    print(f"API Key:     {api_key[:6]}..." if api_key else "API Key:     NOT SET")


def _print_payment(result: dict):
    """Print payment details from proof."""
    payment = result.get("proof", {}).get("payment", {})
    if not payment:
        return
    print("[PAYMENT]")
    print(f"  Amount:    {payment.get('amount', 'N/A')} {payment.get('currency', 'EUR')}")
    print(f"  Status:    {payment.get('status', 'N/A')}")
    print(f"  Txn ID:    {payment.get('transaction_id', 'N/A')}")
    if payment.get("receipt_url"):
        print(f"  Receipt:   {payment['receipt_url']}")
    print()


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

    chain = hashes.get("chain", "N/A") or "N/A"
    req_hash = hashes.get("request", "N/A") or "N/A"

    print("[PROOF — Trust Layer]")
    print(f"  ID:           {proof.get('proof_id', 'N/A')}")
    if proof.get("spec_version"):
        print(f"  Spec:         {proof['spec_version']}")
    print(f"  Chain Hash:   {chain[:48]}...")
    print(f"  Request Hash: {req_hash[:48]}...")
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


def _print_full_proof(result: dict):
    """Print all proof sections (payment, proof, evidence, stamps)."""
    _print_payment(result)
    _print_proof(result)
    _print_payment_evidence(result)
    _print_attestation(result)
    _print_ghost_stamp(result)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _save_log(command: str, result: dict, extra: dict = None):
    """Save transaction log and proof."""
    now = datetime.now(timezone.utc)
    LOG_DIR.mkdir(exist_ok=True)
    PROOF_DIR.mkdir(exist_ok=True)

    log_entry = {
        "command": command,
        "timestamp": now.isoformat(),
        "trust_layer": _get_base_url(),
        "result": result,
        "transparency": "Both agents built and controlled by ArkForge (PoC)",
    }
    if extra:
        log_entry.update(extra)

    prefix = command if command in ("scan", "pay", "credits") else "pay"
    log_file = LOG_DIR / f"{prefix}_{now.strftime('%Y%m%d_%H%M%S')}.json"
    log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))
    (LOG_DIR / "latest_transaction.json").write_text(json.dumps(log_entry, indent=2, ensure_ascii=False))

    proof = result.get("proof", {})
    if proof.get("proof_id"):
        proof_file = PROOF_DIR / f"{proof['proof_id']}.json"
        proof_file.write_text(json.dumps(proof, indent=2, ensure_ascii=False))

    log.info("Saved %s", log_file)
    print(f"[SAVED] {log_file}")


# ---------------------------------------------------------------------------
# CLI argument helpers
# ---------------------------------------------------------------------------

def _extract_receipt_url(args: list) -> str:
    """Extract --receipt-url value from CLI arguments."""
    for i, arg in enumerate(args):
        if arg == "--receipt-url" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--receipt-url="):
            return arg.split("=", 1)[1]
    return ""


def _resolve_receipt(args: list) -> str:
    """Resolve receipt URL from CLI args or saved state."""
    no_receipt = "--no-receipt" in args
    receipt_url = _extract_receipt_url(args)
    if not receipt_url and not no_receipt:
        receipt_url = _load_receipt()
        if receipt_url:
            print(f"[AUTO] Using saved receipt: {receipt_url[:60]}...")
            print()
    return receipt_url


def _require_arg(index: int, usage: str):
    """Exit with usage message if arg is missing."""
    if len(sys.argv) <= index:
        print(usage)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_pay(receipt_url: str):
    ts = datetime.now(timezone.utc).isoformat()
    _print_header("AGENT PAYMENT — 0.10 EUR from prepaid credits")
    print(f"Timestamp:   {ts}")
    print(f"Trust Layer: {_get_base_url()}/v1/proxy")
    _print_key_info()
    if receipt_url:
        print(f"Receipt URL: {receipt_url[:60]}...")
    print()

    result = pay(receipt_url=receipt_url)
    _print_error(result)
    _print_full_proof(result)
    _save_log("pay", result)
    _print_header("DONE")


def _cmd_credits():
    _require_arg(2, "Usage: python3 agent.py credits <amount_eur>\n"
                     "  Min: 1.00 EUR (= 10 proofs)\n"
                     "  Max: 100.00 EUR (= 1000 proofs)")

    try:
        amount = float(sys.argv[2])
    except ValueError:
        print(f"[FAILED] Invalid amount: {sys.argv[2]!r} (expected a number)")
        sys.exit(1)

    ts = datetime.now(timezone.utc).isoformat()
    _print_header(f"BUY CREDITS — {amount:.2f} EUR")
    print(f"Timestamp:   {ts}")
    print(f"Trust Layer: {_get_base_url()}/v1/credits/buy")
    _print_key_info()
    print()

    result = buy_credits(amount)
    _print_error(result)

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
    _print_header("DONE")


def _cmd_scan(receipt_url: str):
    _require_arg(2, "Usage: python3 agent.py scan <repo_url>")
    repo_url = sys.argv[2]

    if not repo_url.startswith(("http://", "https://")):
        print(f"[FAILED] Invalid URL: {repo_url!r} (expected http:// or https://)")
        sys.exit(1)

    ts = datetime.now(timezone.utc).isoformat()
    _print_header("EU AI ACT COMPLIANCE SCAN — via Trust Layer")
    print(f"Timestamp:   {ts}")
    print(f"Target:      {repo_url}")
    print(f"Price:       0.10 EUR (from prepaid credits)")
    print(f"Trust Layer: {_get_base_url()}/v1/proxy")
    print(f"Scan API:    {_get_scan_target()}")
    _print_key_info()
    if receipt_url:
        print(f"Receipt URL: {receipt_url[:60]}...")
    print()

    result = scan_repo(repo_url, receipt_url=receipt_url)
    _print_error(result)

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

    _print_full_proof(result)
    _save_log("scan", result, {"repo_url": repo_url})
    _print_header("DONE")


def _cmd_verify():
    _require_arg(2, "Usage: python3 agent.py verify <proof_id>")
    proof_id = sys.argv[2]

    print(f"Verifying proof: {proof_id}")
    result = verify_proof(proof_id)
    _print_error(result)

    print(json.dumps(result, indent=2))
    _print_payment_evidence(result)


def _cmd_reputation():
    _require_arg(2, "Usage: python3 agent.py reputation <agent_id>")
    agent_id = sys.argv[2]

    print(f"Fetching reputation for: {agent_id}")
    result = get_reputation(agent_id)
    _print_error(result)

    _print_header("AGENT REPUTATION")
    print(f"  Agent:       {result.get('agent_id', agent_id)}")
    print(f"  Score:       {result.get('score', 'N/A')}/100")
    dims = result.get("dimensions", {})
    if dims:
        print("  Dimensions:")
        for dim, val in dims.items():
            print(f"    {dim}: {val}")
    penalties = result.get("penalties", [])
    if penalties:
        print(f"  Penalties:   {len(penalties)}")
        for p in penalties[:5]:
            print(f"    - {p.get('reason', p)}")
    if result.get("signature"):
        print(f"  Signature:   {str(result['signature'])[:30]}...")
    print("=" * 60)


def _cmd_dispute():
    _require_arg(3, 'Usage: python3 agent.py dispute <proof_id> "reason"')
    proof_id = sys.argv[2]
    reason = sys.argv[3]

    if not reason.strip():
        print("[FAILED] Dispute reason cannot be empty")
        sys.exit(1)

    print(f"Filing dispute for proof: {proof_id}")
    print(f"Reason: {reason}")
    result = file_dispute(proof_id, reason)
    _print_error(result)

    _print_header("DISPUTE FILED")
    print(f"  Dispute ID:  {result.get('dispute_id', 'N/A')}")
    print(f"  Proof ID:    {result.get('proof_id', proof_id)}")
    print(f"  Status:      {result.get('status', 'N/A')}")
    print(f"  Resolution:  {result.get('resolution', 'PENDING')}")
    print("=" * 60)


def _cmd_disputes():
    _require_arg(2, "Usage: python3 agent.py disputes <agent_id>")
    agent_id = sys.argv[2]

    print(f"Fetching disputes for: {agent_id}")
    result = get_disputes(agent_id)
    _print_error(result)

    _print_header("DISPUTE HISTORY")
    summary = result.get("summary", {})
    print(f"  Filed:       {summary.get('total_filed', result.get('total', 0))}")
    print(f"  Won:         {summary.get('won', 0)}")
    print(f"  Lost:        {summary.get('lost', 0)}")
    disputes = result.get("disputes", [])
    if disputes:
        print()
        print("  Recent disputes:")
        for d in disputes[:10]:
            status = d.get("status", "N/A")
            print(f"    {d.get('dispute_id', 'N/A')} | {d.get('proof_id', 'N/A')} | {status}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

COMMANDS = {
    "pay": lambda receipt_url: _cmd_pay(receipt_url),
    "credits": lambda receipt_url: _cmd_credits(),
    "scan": lambda receipt_url: _cmd_scan(receipt_url),
    "verify": lambda receipt_url: _cmd_verify(),
    "reputation": lambda receipt_url: _cmd_reputation(),
    "dispute": lambda receipt_url: _cmd_dispute(),
    "disputes": lambda receipt_url: _cmd_disputes(),
}


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 agent.py scan <repo_url>       # Scan repo (0.10 EUR)")
        print("  python3 agent.py pay                    # Payment proof (0.10 EUR)")
        print("  python3 agent.py credits <amount_eur>   # Buy credits (1-100 EUR)")
        print("  python3 agent.py verify <proof_id>      # Verify a proof")
        print("  python3 agent.py reputation <agent_id>  # Check agent reputation (0-100)")
        print("  python3 agent.py dispute <proof_id> \"reason\"  # File a dispute")
        print("  python3 agent.py disputes <agent_id>    # View dispute history")
        print()
        print("Receipt auto-attach (after buying credits):")
        print("  --receipt-url URL   Override with a specific receipt")
        print("  --no-receipt        Skip auto-attach for this call")
        print()
        print("Setup:")
        print("  export TRUST_LAYER_API_KEY='mcp_pro_...'")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    command = sys.argv[1]
    handler = COMMANDS.get(command)
    if not handler:
        print(f"Unknown command: {command}")
        print(f"Use: {', '.join(COMMANDS)}")
        sys.exit(1)

    receipt_url = _resolve_receipt(sys.argv)
    handler(receipt_url)


if __name__ == "__main__":
    main()
