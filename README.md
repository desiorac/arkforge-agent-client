# EU AI Act Compliance Agent

Autonomous agent that scans code repositories for EU AI Act compliance
using [ArkForge](https://arkforge.fr)'s paid scan API.

**Each scan costs 0.50 EUR**, charged automatically via Stripe.

## Transparency Notice

Both this agent (buyer) and the ArkForge scan API (seller) are built and
controlled by the same developer. This is a proof-of-concept for autonomous
agent-to-agent paid transactions — not an attempt to simulate independent entities.

## Setup

```bash
pip install -r requirements.txt
```

### 1. Save a payment method

```bash
python3 setup_card.py your@email.com
```

Open the Checkout URL and enter a card. Then check the setup:

```bash
python3 check_setup.py <session_id>
```

### 2. Run a scan

```bash
export ARKFORGE_SCAN_API_KEY="mcp_scan_..."
python3 agent.py https://github.com/owner/repo
```

### 3. Full transaction with proofs

```bash
export ARKFORGE_SCAN_API_KEY="mcp_scan_..."
python3 execute_transaction.py https://github.com/owner/repo
```

This captures 5 independent proofs:
1. Stripe payment receipt
2. Git commit (public, timestamped)
3. OpenTimestamps (Bitcoin blockchain anchor)
4. Archive.org snapshot
5. Email to project owner

## License

MIT
