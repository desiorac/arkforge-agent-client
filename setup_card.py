#!/usr/bin/env python3
"""
Setup Payment Method — Save a card for paid scans.

Creates a Stripe Checkout Session (setup mode) to save a card.
After setup, the webhook automatically creates your API key.

Usage:
    python3 setup_card.py your@email.com          # Live mode (real charges)
    python3 setup_card.py your@email.com --test    # Test mode (no charges)
"""

import json
import os
import sys

import requests

API_BASE = os.environ.get("ARKFORGE_API_BASE", "https://arkforge.fr")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 setup_card.py <email> [--test]")
        print()
        print("Options:")
        print("  --test    Use Stripe test mode (no real charges)")
        print()
        print("Examples:")
        print("  python3 setup_card.py user@example.com          # Live")
        print("  python3 setup_card.py user@example.com --test   # Test")
        sys.exit(1)

    email = sys.argv[1]
    test_mode = "--test" in sys.argv

    mode_label = "TEST" if test_mode else "LIVE"
    key_prefix = "mcp_test_" if test_mode else "mcp_pro_"

    print("=" * 60)
    print("SETUP PAYMENT METHOD")
    print("=" * 60)
    print(f"Email: {email}")
    print(f"Mode:  {mode_label}")
    print()

    body = {"email": email}
    if test_mode:
        body["mode"] = "test"

    resp = requests.post(
        f"{API_BASE}/api/v1/setup-payment-method",
        json=body,
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
    if test_mode:
        print("Test card: 4242 4242 4242 4242 (any expiry, any CVC)")
        print()
    print("After completing checkout:")
    print("  1. Your API key will be sent by email automatically")
    print(f"  2. Set it: export ARKFORGE_SCAN_API_KEY='{key_prefix}...'")
    print("  3. Run:    python3 agent.py https://github.com/owner/repo")
    print()
    print(f"Session ID: {result.get('session_id', 'N/A')}")
    print(f"Mode:       {result.get('mode', 'live').upper()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
