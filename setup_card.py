#!/usr/bin/env python3
"""
Setup Payment Method — Save a card for paid scans.

Creates a Stripe Checkout Session (setup mode) to save a card.
After setup, the webhook automatically creates your API key.

Usage:
    python3 setup_card.py your@email.com
"""

import json
import os
import sys

import requests

API_BASE = os.environ.get("ARKFORGE_API_BASE", "https://arkforge.fr")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 setup_card.py <email>")
        print()
        print("Example:")
        print("  python3 setup_card.py user@example.com")
        sys.exit(1)

    email = sys.argv[1]

    print("=" * 60)
    print("SETUP PAYMENT METHOD")
    print("=" * 60)
    print(f"Email: {email}")
    print()

    resp = requests.post(
        f"{API_BASE}/api/v1/setup-payment-method",
        json={"email": email},
        timeout=30,
    )

    if resp.status_code != 200:
        print(f"[ERROR] HTTP {resp.status_code}: {resp.text}")
        sys.exit(1)

    result = resp.json()

    print("Open this URL to enter your card:")
    print()
    print(f"  {result['checkout_url']}")
    print()
    print("After completing checkout:")
    print("  1. Your API key will be sent by email automatically")
    print("  2. Set it: export ARKFORGE_SCAN_API_KEY='mcp_pro_...'")
    print("  3. Run:    python3 agent.py https://github.com/owner/repo")
    print()
    print(f"Session ID: {result.get('session_id', 'N/A')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
