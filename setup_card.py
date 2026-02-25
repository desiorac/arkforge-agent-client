#!/usr/bin/env python3
"""
Setup Payment Method for Agent Client

Creates a Stripe Checkout Session (setup mode) so the shareholder
can add their separate card for the agent client.

After card is added:
1. Stripe webhook creates an API key automatically
2. OR run check_setup.py to create it manually

Usage:
    python3 setup_card.py [email]
"""

import json
import sys

import requests

API_BASE = "https://arkforge.fr"
DEFAULT_EMAIL = "agent-client@arkforge.fr"


def create_setup_session(email: str) -> dict:
    """Create a Stripe Checkout Session to save a payment method."""
    resp = requests.post(
        f"{API_BASE}/api/v1/setup-payment-method",
        json={"email": email},
        timeout=30,
    )
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    return resp.json()


def main():
    email = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EMAIL

    print("=" * 60)
    print("SETUP PAYMENT METHOD — Agent Client")
    print("=" * 60)
    print(f"Email: {email}")
    print()

    result = create_setup_session(email)

    if "error" in result:
        print(f"[ERROR] {result['error']}")
        sys.exit(1)

    print("Checkout URL (enter card here):")
    print(f"  {result['checkout_url']}")
    print()
    print(f"Session ID: {result['session_id']}")
    print()
    print("NEXT STEPS:")
    print("  1. Open the Checkout URL in a browser")
    print("  2. Enter the SEPARATE card (carte tierce)")
    print("  3. Complete the setup")
    print("  4. An API key will be created automatically (webhook)")
    print("  5. OR run: python3 check_setup.py <session_id>")
    print()
    print("Then set the API key:")
    print("  export ARKFORGE_SCAN_API_KEY='mcp_scan_...'")
    print("  python3 execute_transaction.py")


if __name__ == "__main__":
    main()
