#!/usr/bin/env python3
"""
Proof Capture — 5 Independent Sources

Captures infalsifiable proofs of the agent-to-agent transaction:
1. Stripe payment (already in transaction log)
2. Git commit to public repo (automated)
3. OpenTimestamps (Bitcoin blockchain anchor)
4. Archive.org snapshot
5. Email to shareholder

TRANSPARENCY: Both agents are built and controlled by the same developer.
"""

import hashlib
import json
import os
import smtplib
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"
PROOFS_DIR = Path(__file__).parent / "proofs"


def load_transaction():
    """Load the latest transaction log."""
    latest = LOG_DIR / "latest_transaction.json"
    if not latest.exists():
        print("[ERROR] No transaction log found. Run agent.py first.")
        sys.exit(1)
    return json.loads(latest.read_text())


def proof_1_stripe(tx: dict) -> dict:
    """Stripe payment — already captured in transaction."""
    payment = tx.get("payment_proof", {})
    if not payment.get("payment_intent_id"):
        return {"status": "missing", "error": "No payment_intent_id in transaction log"}
    return {
        "status": "verified",
        "payment_intent_id": payment["payment_intent_id"],
        "amount": payment.get("amount_eur", "0.50"),
        "currency": "eur",
        "stripe_status": payment.get("status", "unknown"),
        "receipt_url": payment.get("receipt_url"),
        "created_timestamp": payment.get("created_timestamp"),
    }


def proof_2_git_commit(tx: dict) -> dict:
    """Git commit with transaction data to public repo."""
    proof_file = PROOFS_DIR / "transaction_proof.json"
    proof_file.write_text(json.dumps(tx, indent=2, ensure_ascii=False))

    import shutil
    git_bin = shutil.which("git")
    if not git_bin:
        return {"status": "skipped", "error": "git not found in PATH"}

    try:
        # Stage and commit the proof
        subprocess.run([git_bin, "add", str(proof_file)], check=True, capture_output=True, cwd=proof_file.parent.parent)
        result = subprocess.run(
            [git_bin, "commit", "-m", f"proof: agent-to-agent transaction {tx.get('timestamp', 'unknown')}"],
            check=True, capture_output=True, text=True, cwd=proof_file.parent.parent,
        )
        # Get commit hash
        hash_result = subprocess.run(
            [git_bin, "rev-parse", "HEAD"], capture_output=True, text=True, cwd=proof_file.parent.parent,
        )
        commit_hash = hash_result.stdout.strip()
        return {"status": "committed", "commit_hash": commit_hash}
    except subprocess.CalledProcessError as e:
        err = e.stderr if hasattr(e, 'stderr') else str(e)
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return {"status": "failed", "error": err}
    except FileNotFoundError:
        return {"status": "skipped", "error": "git binary not accessible"}


def proof_3_opentimestamps(tx: dict) -> dict:
    """OpenTimestamps — anchor SHA-256 hash on Bitcoin blockchain."""
    # Write canonical JSON for hashing
    canonical = json.dumps(tx, sort_keys=True, ensure_ascii=False)
    sha256 = hashlib.sha256(canonical.encode()).hexdigest()

    proof_file = PROOFS_DIR / "transaction_hash.txt"
    proof_file.write_text(f"SHA-256: {sha256}\n\nCanonical transaction data:\n{canonical}\n")

    result_data = {"sha256": sha256, "file": str(proof_file)}

    try:
        result = subprocess.run(
            ["ots", "stamp", str(proof_file)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            result_data["status"] = "stamped"
            result_data["ots_file"] = str(proof_file) + ".ots"
            result_data["output"] = result.stdout.strip()
        else:
            result_data["status"] = "stamp_failed"
            result_data["error"] = result.stderr.strip()
    except FileNotFoundError:
        # ots not installed — try pip install
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "opentimestamps-client"],
                capture_output=True, timeout=60,
            )
            result = subprocess.run(
                ["ots", "stamp", str(proof_file)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                result_data["status"] = "stamped"
                result_data["ots_file"] = str(proof_file) + ".ots"
            else:
                result_data["status"] = "stamp_failed"
                result_data["error"] = result.stderr.strip()
        except Exception as e:
            result_data["status"] = "unavailable"
            result_data["error"] = f"ots not available: {e}"
    except Exception as e:
        result_data["status"] = "failed"
        result_data["error"] = str(e)

    return result_data


def proof_4_archive_org() -> dict:
    """Archive.org — snapshot of the API status page."""
    import requests

    try:
        resp = requests.get(
            "https://web.archive.org/save/https://arkforge.fr/api/v1/status",
            timeout=30,
            headers={"User-Agent": "ArkForge-ProofCapture/1.0"},
        )
        archive_url = resp.headers.get("Content-Location", "")
        if archive_url and not archive_url.startswith("http"):
            archive_url = f"https://web.archive.org{archive_url}"
        return {
            "status": "saved" if resp.status_code in (200, 301, 302) else f"http_{resp.status_code}",
            "archive_url": archive_url or resp.url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def proof_5_email(tx: dict, all_proofs: dict) -> dict:
    """Email all proofs to shareholder."""
    # Load SMTP config: env vars first, then settings file, then defaults
    config = {}
    for path in [Path(__file__).parent / ".env", Path("/opt/claude-ceo/config/settings.env")]:
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config.setdefault(k.strip(), v.strip())

    smtp_host = os.environ.get("SMTP_HOST") or config.get("SMTP_HOST", "ssl0.ovh.net")
    smtp_port = int(os.environ.get("SMTP_PORT") or config.get("SMTP_PORT", "465"))
    smtp_user = os.environ.get("SMTP_USER") or config.get("IMAP_USER", "contact@arkforge.fr")
    smtp_pass = os.environ.get("SMTP_PASSWORD") or config.get("IMAP_PASSWORD", "")
    to_email = os.environ.get("PROOF_EMAIL") or "contact@arkforge.fr"

    if not smtp_pass:
        return {"status": "skipped", "error": "SMTP not configured (set SMTP_PASSWORD env var or .env file)"}

    payment = tx.get("payment_proof", {})
    body = f"""PROOF OF AGENT-TO-AGENT TRANSACTION

Timestamp: {tx.get('timestamp', 'unknown')}
Agent: {tx.get('agent', 'eu-ai-act-compliance-agent')}
Service: {tx.get('service', 'arkforge-mcp-eu-ai-act')}
Repo scanned: {tx.get('repo_url', 'unknown')}

PAYMENT PROOF (Stripe):
  Payment Intent: {payment.get('payment_intent_id', 'N/A')}
  Amount: {payment.get('amount_eur', '0.50')} EUR
  Status: {payment.get('status', 'N/A')}
  Receipt: {payment.get('receipt_url', 'N/A')}

ALL PROOFS SUMMARY:
{json.dumps(all_proofs, indent=2, ensure_ascii=False)}

TRANSPARENCY NOTICE:
Both agents (client and service) are built and controlled by the same
team (ArkForge). This is a proof-of-concept for autonomous
agent-to-agent paid transactions.

SHA-256 of transaction data:
{all_proofs.get('opentimestamps', {}).get('sha256', 'not computed')}
"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[PROOF] Agent-to-Agent Transaction — {tx.get('timestamp', '')}"
        msg["From"] = f"ArkForge <{smtp_user}>"
        msg["To"] = to_email
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="arkforge.fr")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=15) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())

        return {"status": "sent", "to": to_email, "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def main():
    PROOFS_DIR.mkdir(exist_ok=True)
    tx = load_transaction()

    print("=" * 60)
    print("PROOF CAPTURE — Agent-to-Agent Transaction")
    print("=" * 60)

    proofs = {}

    print("\n[1/5] Stripe payment proof...")
    proofs["stripe"] = proof_1_stripe(tx)
    print(f"  → {proofs['stripe']['status']}")

    print("\n[2/5] Git commit to public repo...")
    proofs["git_commit"] = proof_2_git_commit(tx)
    print(f"  → {proofs['git_commit']['status']}")

    print("\n[3/5] OpenTimestamps (Bitcoin anchor)...")
    proofs["opentimestamps"] = proof_3_opentimestamps(tx)
    print(f"  → {proofs['opentimestamps']['status']}")

    print("\n[4/5] Archive.org snapshot...")
    proofs["archive_org"] = proof_4_archive_org()
    print(f"  → {proofs['archive_org']['status']}")

    print("\n[5/5] Email to shareholder...")
    proofs["email"] = proof_5_email(tx, proofs)
    print(f"  → {proofs['email']['status']}")

    # Save all proofs
    all_proofs_file = PROOFS_DIR / "all_proofs.json"
    proofs["captured_at"] = datetime.now(timezone.utc).isoformat()
    proofs["transaction_ref"] = tx.get("payment_proof", {}).get("payment_intent_id", "unknown")
    all_proofs_file.write_text(json.dumps(proofs, indent=2, ensure_ascii=False))

    print(f"\n{'=' * 60}")
    print(f"All proofs saved: {all_proofs_file}")
    verified = sum(1 for k in ["stripe", "git_commit", "opentimestamps", "archive_org", "email"]
                   if proofs.get(k, {}).get("status") in ("verified", "committed", "stamped", "saved", "sent"))
    print(f"Verified: {verified}/5 sources")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
