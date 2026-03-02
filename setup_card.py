#!/usr/bin/env python3
"""
Setup Pro Account — Buy initial credits and save card via Stripe Checkout.

The initial purchase (minimum 10 EUR = 100 proofs) is charged immediately.
Your card is saved for future top-ups (no browser required next time).
Your API key and credits are set up automatically after payment.

Usage:
    python3 setup_card.py your@email.com               # Live mode (real charges)
    python3 setup_card.py your@email.com --test        # Test mode (Stripe test card)
    python3 setup_card.py your@email.com --amount 20   # Buy 20 EUR = 200 proofs
"""

import os
import sys

import requests

API_BASE = os.environ.get("ARKFORGE_API_BASE", "https://arkforge.fr")
MIN_AMOUNT = 10.0


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 setup_card.py <email> [--test] [--amount EUR]")
        print()
        print("Options:")
        print("  --test          Use Stripe test mode (no real charges)")
        print("  --amount EUR    Credits to buy (default: 10 EUR = 100 proofs)")
        print()
        print("Examples:")
        print("  python3 setup_card.py user@example.com")
        print("  python3 setup_card.py user@example.com --test")
        print("  python3 setup_card.py user@example.com --amount 20")
        sys.exit(1)

    email = sys.argv[1]
    test_mode = "--test" in sys.argv

    amount = MIN_AMOUNT
    if "--amount" in sys.argv:
        idx = sys.argv.index("--amount")
        try:
            amount = float(sys.argv[idx + 1])
        except (IndexError, ValueError):
            print("[ERROR] --amount requires a number (e.g. --amount 20)")
            sys.exit(1)

    if amount < MIN_AMOUNT:
        print(f"[ERROR] Minimum amount is {MIN_AMOUNT:.0f} EUR ({int(MIN_AMOUNT / 0.10)} proofs)")
        sys.exit(1)

    mode_label = "TEST" if test_mode else "LIVE"
    key_prefix = "mcp_test_" if test_mode else "mcp_pro_"
    proofs = int(amount / 0.10)

    print("=" * 60)
    print("ARKFORGE TRUST LAYER — PRO SETUP")
    print("=" * 60)
    print(f"Email:   {email}")
    print(f"Mode:    {mode_label}")
    print(f"Amount:  {amount:.0f} EUR ({proofs} proofs)")
    print()

    body = {"email": email, "amount": amount}
    if test_mode:
        body["mode"] = "test"

    resp = requests.post(
        f"{API_BASE}/trust/v1/keys/setup",
        json=body,
        timeout=30,
    )

    if resp.status_code != 200:
        print(f"[ERROR] HTTP {resp.status_code}: {resp.text}")
        sys.exit(1)

    result = resp.json()

    print("Open this URL to complete payment:")
    print()
    print(f"  {result['checkout_url']}")
    print()
    if test_mode:
        print("Test card: 4242 4242 4242 4242 (any future expiry, any CVC)")
        print()
    print("After payment:")
    print(f"  1. Your API key ({key_prefix}...) will be sent by email")
    print(f"  2. {proofs} proofs will be credited automatically")
    print(f"  3. Set it: export TRUST_LAYER_API_KEY='{key_prefix}...'")
    print("  4. Run:    python3 agent.py scan https://github.com/owner/repo")
    print()
    print(f"Session ID:      {result.get('session_id', 'N/A')}")
    print(f"Proofs included: {result.get('proofs_included', proofs)}")
    print(f"Mode:            {result.get('mode', 'live').upper()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
