#!/usr/bin/env python3
"""
Execute Full Agent-to-Agent Transaction

One-command execution:
1. Agent scans a repo via ArkForge paid API (0.50 EUR)
2. Captures 5 infalsifiable proofs
3. Pushes to public GitHub repo

Prerequisites:
    export ARKFORGE_SCAN_API_KEY="mcp_scan_..."

TRANSPARENCY: Both agents are built and controlled by the same developer.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent))

from agent import scan_repo
from capture_proofs import (
    proof_1_stripe,
    proof_2_git_commit,
    proof_3_opentimestamps,
    proof_4_archive_org,
    proof_5_email,
    LOG_DIR,
    PROOFS_DIR,
)

DEFAULT_REPO = "https://github.com/langchain-ai/langchain"


def execute():
    repo_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPO
    now = datetime.now(timezone.utc)
    ts = now.isoformat()

    api_key = os.environ.get("ARKFORGE_SCAN_API_KEY", "")
    if not api_key:
        print("[ERROR] ARKFORGE_SCAN_API_KEY not set.")
        print("  Run: export ARKFORGE_SCAN_API_KEY='mcp_scan_...'")
        sys.exit(1)

    print("=" * 60)
    print("AGENT-TO-AGENT TRANSACTION EXECUTION")
    print("=" * 60)
    print(f"Timestamp: {ts}")
    print(f"Target: {repo_url}")
    print(f"Price: 0.50 EUR")
    print(f"API Key: {api_key[:12]}...")
    print()

    # Step 1: Execute the scan (triggers payment)
    print("[STEP 1] Executing paid scan...")
    result = scan_repo(repo_url)

    if "error" in result:
        print(f"[FAILED] {result['error']}")
        if "detail" in result:
            print(f"  {result['detail'][:500]}")
        sys.exit(1)

    payment = result.get("payment_proof", {})
    scan = result.get("scan_result", {})
    print(f"  Payment Intent: {payment.get('payment_intent_id', 'N/A')}")
    print(f"  Amount: {payment.get('amount_eur', 'N/A')} EUR")
    print(f"  Status: {payment.get('status', 'N/A')}")
    print(f"  Receipt: {payment.get('receipt_url', 'N/A')}")

    # Save transaction log
    LOG_DIR.mkdir(exist_ok=True)
    PROOFS_DIR.mkdir(exist_ok=True)

    tx = {
        "timestamp": ts,
        "agent": "eu-ai-act-compliance-agent",
        "service": "arkforge-mcp-eu-ai-act",
        "repo_url": repo_url,
        "payment_proof": payment,
        "scan_summary": {
            "risk_score": scan.get("risk_score", scan.get("report", {}).get("risk_score", "N/A")),
            "frameworks_detected": list(scan.get("scan", {}).get("detected_models", {}).keys())
            if isinstance(scan.get("scan", {}).get("detected_models"), dict) else [],
            "files_scanned": scan.get("scan", {}).get("files_scanned", 0),
        },
        "full_result": result,
        "transparency": "Both agents built and controlled by the same developer (David Desiorac)",
    }

    log_file = LOG_DIR / f"tx_{now.strftime('%Y%m%d_%H%M%S')}.json"
    log_file.write_text(json.dumps(tx, indent=2, ensure_ascii=False))
    latest = LOG_DIR / "latest_transaction.json"
    latest.write_text(json.dumps(tx, indent=2, ensure_ascii=False))

    # Step 2: Capture proofs
    print("\n[STEP 2] Capturing proofs...")
    proofs = {}

    print("  [1/5] Stripe payment...")
    proofs["stripe"] = proof_1_stripe(tx)
    print(f"    → {proofs['stripe']['status']}")

    print("  [2/5] Git commit...")
    # Write proof file first
    proof_file = PROOFS_DIR / "transaction_proof.json"
    proof_file.write_text(json.dumps(tx, indent=2, ensure_ascii=False))
    proofs["git_commit"] = proof_2_git_commit(tx)
    print(f"    → {proofs['git_commit']['status']}")

    print("  [3/5] OpenTimestamps...")
    proofs["opentimestamps"] = proof_3_opentimestamps(tx)
    print(f"    → {proofs['opentimestamps']['status']}")

    print("  [4/5] Archive.org...")
    proofs["archive_org"] = proof_4_archive_org()
    print(f"    → {proofs['archive_org']['status']}")

    print("  [5/5] Email to shareholder...")
    proofs["email"] = proof_5_email(tx, proofs)
    print(f"    → {proofs['email']['status']}")

    # Save proofs
    proofs["captured_at"] = datetime.now(timezone.utc).isoformat()
    proofs["transaction_ref"] = payment.get("payment_intent_id", "unknown")
    all_proofs = PROOFS_DIR / "all_proofs.json"
    all_proofs.write_text(json.dumps(proofs, indent=2, ensure_ascii=False))

    # Step 3: Push to GitHub
    print("\n[STEP 3] Pushing to GitHub...")
    try:
        subprocess.run(["git", "add", "-A"], capture_output=True, cwd=Path(__file__).parent)
        subprocess.run(
            ["git", "commit", "-m", f"proof: agent-to-agent transaction {ts}"],
            capture_output=True, text=True, cwd=Path(__file__).parent,
        )
        push_result = subprocess.run(
            ["git", "push"], capture_output=True, text=True, cwd=Path(__file__).parent,
        )
        if push_result.returncode == 0:
            print("  → Pushed to public repo")
        else:
            print(f"  → Push failed: {push_result.stderr[:200]}")
    except Exception as e:
        print(f"  → Git error: {e}")

    # Summary
    verified = sum(1 for k in ["stripe", "git_commit", "opentimestamps", "archive_org", "email"]
                   if proofs.get(k, {}).get("status") in ("verified", "committed", "stamped", "saved", "sent"))
    print(f"\n{'=' * 60}")
    print(f"TRANSACTION COMPLETE")
    print(f"  Payment Intent: {payment.get('payment_intent_id', 'N/A')}")
    print(f"  Amount: 0.50 EUR")
    print(f"  Proofs: {verified}/5 verified")
    print(f"  Logs: {log_file}")
    print(f"  Proofs: {all_proofs}")
    print(f"{'=' * 60}")

    return tx, proofs


if __name__ == "__main__":
    execute()
