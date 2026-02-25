#!/usr/bin/env python3
"""
Check Setup Status & Create API Key

After the shareholder enters their card via Stripe Checkout,
this script checks the session status and creates the API key
if the webhook didn't fire.

Usage:
    python3 check_setup.py <checkout_session_id>
"""

import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

# Load Stripe key from settings
SETTINGS_ENV = Path("/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/config/settings.env")
API_KEYS_FILE = Path("/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/data/api_keys.json")


def load_stripe_key():
    """Load Stripe secret key from settings."""
    if not SETTINGS_ENV.exists():
        return None
    for line in SETTINGS_ENV.read_text().splitlines():
        line = line.strip()
        if line.startswith("STRIPE_LIVE_SECRET_KEY="):
            return line.split("=", 1)[1].strip()
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 check_setup.py <checkout_session_id>")
        sys.exit(1)

    session_id = sys.argv[1]
    stripe_key = load_stripe_key()
    if not stripe_key:
        print("[ERROR] Stripe key not found in settings.env")
        sys.exit(1)

    import stripe
    stripe.api_key = stripe_key

    print(f"Checking session: {session_id}")

    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print(f"  Status: {session.status}")
    print(f"  Mode: {session.mode}")
    print(f"  Customer: {session.customer}")
    print(f"  Email: {session.customer_email or session.customer_details.get('email', 'N/A') if session.customer_details else 'N/A'}")

    if session.status != "complete":
        print(f"\n[WAITING] Session not yet completed. Status: {session.status}")
        print("  The shareholder needs to enter their card at the Checkout URL.")
        sys.exit(0)

    # Session is complete — get the setup intent and payment method
    setup_intent_id = session.setup_intent
    if not setup_intent_id:
        print("[ERROR] No setup intent found in completed session")
        sys.exit(1)

    setup_intent = stripe.SetupIntent.retrieve(setup_intent_id)
    payment_method_id = setup_intent.payment_method
    customer_id = session.customer

    print(f"  Setup Intent: {setup_intent_id}")
    print(f"  Payment Method: {payment_method_id}")

    # Check if API key already exists for this customer
    keys = {}
    if API_KEYS_FILE.exists():
        keys = json.loads(API_KEYS_FILE.read_text())

    existing = [k for k, v in keys.items() if v.get("stripe_customer_id") == customer_id and v.get("plan") == "paid_scan"]
    if existing:
        print(f"\n[OK] API key already exists: {existing[0]}")
        print(f"  export ARKFORGE_SCAN_API_KEY='{existing[0]}'")
        return

    # Create new API key
    email = session.customer_email or ""
    if session.customer_details:
        email = email or session.customer_details.get("email", "")

    api_key = f"mcp_scan_{secrets.token_hex(12)}"
    keys[api_key] = {
        "plan": "paid_scan",
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "email": email,
        "stripe_customer_id": customer_id,
        "stripe_payment_method_id": payment_method_id,
        "scans_total": 0,
        "total_charged_cents": 0,
        "note": "Agent client — carte tierce (agent-to-agent PoC)",
    }
    API_KEYS_FILE.write_text(json.dumps(keys, indent=2, ensure_ascii=False))

    # Set customer default payment method
    stripe.Customer.modify(
        customer_id,
        invoice_settings={"default_payment_method": payment_method_id},
    )

    print(f"\n[OK] API key created: {api_key}")
    print(f"\nTo execute the transaction:")
    print(f"  export ARKFORGE_SCAN_API_KEY='{api_key}'")
    print(f"  python3 execute_transaction.py")


if __name__ == "__main__":
    main()
