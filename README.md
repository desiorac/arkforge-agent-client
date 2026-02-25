# EU AI Act Compliance Agent

Autonomous agent that scans code repositories for EU AI Act compliance
using [ArkForge](https://arkforge.fr)'s paid scan API.

**Each scan costs 0.50 EUR**, charged automatically via Stripe.

## Transparency Notice

Both this agent (buyer) and the ArkForge scan API (seller) are built and
controlled by the same developer. This is a proof-of-concept for autonomous
agent-to-agent paid transactions — not an attempt to simulate independent entities.

## Prerequisites

- Python 3.10+
- `pip install requests`

That's it. No git, no Stripe SDK, no system dependencies.

## Quick Start

### 1. Save a payment method

```bash
python3 setup_card.py your@email.com
```

Open the Checkout URL in a browser and enter a card.
Your API key will be sent by email automatically.

### 2. Run a scan

```bash
export ARKFORGE_SCAN_API_KEY="mcp_pro_..."
python3 agent.py https://github.com/owner/repo
```

Output includes:
- **Payment proof** — Stripe intent ID, amount, receipt URL
- **Scan result** — risk score, detected frameworks, files scanned
- **Local log** — saved in `logs/` as JSON

## How It Works

```
agent.py → POST /api/v1/paid-scan → Stripe charges 0.50 EUR → scan runs → results returned
```

The agent sends a repo URL + API key. The server:
1. Validates the API key
2. Charges 0.50 EUR on the saved card (Stripe off-session)
3. Runs the EU AI Act compliance scan
4. Returns payment proof + scan results

All proof capture (Stripe receipt, timestamps) happens server-side.

## License

MIT
