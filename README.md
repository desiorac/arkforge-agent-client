# ArkForge Agent Client

## What is this?

A proof-of-concept demonstrating **autonomous agent-to-agent paid transactions** with a built-in trust layer.

One agent (this client) pays another agent (the [ArkForge MCP EU AI Act](https://github.com/ark-forge/mcp-eu-ai-act) server) to scan a code repository for EU AI Act compliance. The transaction happens programmatically — no human clicks, no browser, no manual approval. The agent decides to scan, pays 0.50 EUR via Stripe, receives the compliance report, and logs everything with verifiable proofs.

## Why does this matter?

AI agents are starting to act on behalf of humans — browsing, coding, deploying. The next step is agents **paying for services autonomously**. But autonomous payments create a trust problem:

- How does the buyer agent know it got what it paid for?
- How does the seller agent prove it delivered?
- How does the human owner verify what happened?

## The Trust Layer

Every transaction produces a chain of verifiable proofs, without requiring trust between parties:

```
Agent sends API key + repo URL
    |
    v
Server validates key, finds saved card
    |
    v
Stripe charges 0.50 EUR off-session (no human interaction)
    |
    v
Server clones repo, runs EU AI Act compliance scan
    |
    v
Server returns to agent:
  - Payment proof (Stripe intent ID, receipt URL, amount)
  - Scan result (compliance score, frameworks, recommendations)
    |
    v
Server emails full proof to card owner (async, best-effort)
    |
    v
Agent saves transaction log locally (logs/*.json)
```

**Each layer is independently verifiable:**

| Proof | Verified by | Can be faked? |
|---|---|---|
| Stripe Payment Intent | Stripe dashboard, receipt URL | No (Stripe is the source of truth) |
| Receipt URL | Anyone with the link | No (hosted by Stripe) |
| Scan result | Re-running the scan on same repo | No (deterministic) |
| Email proof | Card owner's inbox | No (SMTP headers + timestamp) |
| Local log | `logs/tx_*.json` with full response | Tamper-evident (contains Stripe IDs) |

The trust layer works because **no single party controls all the proofs**. Stripe is a third party. The email goes to the human owner. The scan is deterministic and reproducible.

## Transparency Notice

Both this agent (buyer) and the ArkForge scan API (seller) are built and controlled by the same developer. This is a proof-of-concept — not an attempt to simulate independent entities. The architecture is designed so that it **would work identically** between independent parties.

## Prerequisites

- Python 3.10+
- `pip install requests`

That's it. No git, no Stripe SDK, no system dependencies.

## Quick Start

### 1. Register a payment card (once)

```bash
python3 setup_card.py your@email.com --test    # Test mode (no charges)
python3 setup_card.py your@email.com           # Live mode (real charges)
```

Open the Checkout URL in a browser and enter a card. No Stripe account needed — just a card. Your API key will be sent by email automatically.

For test mode, use Stripe test card `4242 4242 4242 4242` (any future expiry, any CVC).

### 2. Run a scan

```bash
export ARKFORGE_SCAN_API_KEY="mcp_test_..."    # or mcp_pro_... for live
python3 agent.py scan https://github.com/owner/repo
```

### Example output

```
============================================================
EU AI ACT COMPLIANCE SCAN
============================================================
Timestamp: 2026-02-25T15:11:42.802488+00:00
Target:    https://github.com/openai/openai-quickstart-python
Price:     0.50 EUR
API Key:   mcp_test_082...

[PAYMENT]
  Intent:  pi_3T4jGK6iihEhp9U91SHFGoGZ
  Amount:  0.5 EUR
  Status:  succeeded
  Receipt: https://pay.stripe.com/receipts/payment/CAcaFwo...

[SCAN RESULT]
  Compliance:  2/3 (66.7%)
  Risk Cat:    limited
  Frameworks:  openai, anthropic
  Files:       5

[RECOMMENDATIONS]
  - content_marking: Mark AI-generated content so users can distinguish it from human content

[SAVED] logs/tx_20260225_144028.json
============================================================
```

## Test mode vs Live mode

Both modes work simultaneously on the same server. No configuration needed — the API key prefix determines everything:

| Key prefix | Stripe mode | Real charges? |
|---|---|---|
| `mcp_test_*` | Test | No |
| `mcp_pro_*` | Live | Yes (0.50 EUR) |

### Getting a test key (recommended first)

```bash
python3 setup_card.py your@email.com --test
```

Use Stripe test card `4242 4242 4242 4242` (any future expiry, any CVC). Your test API key (`mcp_test_...`) will be emailed automatically.

### Getting a live key

```bash
python3 setup_card.py your@email.com
```

Enter a real credit/debit card. No Stripe account needed — just a card. Your live API key (`mcp_pro_...`) will be emailed automatically.

### Switching between modes

Just change the API key. Both keys can coexist — same email, same server:

```bash
export ARKFORGE_SCAN_API_KEY="mcp_test_..."   # Free scans (test mode)
export ARKFORGE_SCAN_API_KEY="mcp_pro_..."    # Paid scans (0.50 EUR each)
```

## What the scan returns

The paid scan runs three analyses on the target repository:

1. **Framework detection** — identifies AI/ML libraries (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain, Gemini, Mistral, and 14 others)
2. **Compliance check** — evaluates against EU AI Act requirements for the detected risk category (transparency, user disclosure, content marking, technical docs, risk management, etc.)
3. **Report with recommendations** — actionable steps for each failing check, with references to specific EU AI Act articles

## Architecture

```
arkforge-agent-client/
  setup_card.py      # One-time: save payment method (--test for test mode)
  agent.py           # Two modes: "scan <url>" (pay+scan) or "pay" (payment only)
  logs/              # Transaction logs (JSON, one per scan)
  requirements.txt   # Only: requests
```

The client is intentionally minimal. All complexity lives server-side:
- Stripe payment processing
- Git clone + repo scanning
- Compliance analysis + report generation
- Proof email delivery

## API Reference

### `POST /api/v1/setup-payment-method`

Save a card for future off-session payments.

```json
// Request (live mode)
{"email": "user@example.com"}

// Request (test mode)
{"email": "user@example.com", "mode": "test"}

// Response
{"checkout_url": "https://checkout.stripe.com/...", "session_id": "cs_...", "customer_id": "cus_...", "mode": "live"}
```

### `POST /api/v1/paid-scan`

Execute a paid scan. Requires `X-Api-Key` header.

```json
// Request
{"repo_url": "https://github.com/owner/repo"}

// Response
{
  "payment_proof": {
    "payment_intent_id": "pi_...",
    "amount_eur": 0.5,
    "status": "succeeded",
    "receipt_url": "https://pay.stripe.com/receipts/..."
  },
  "scan_result": {
    "files_scanned": 5,
    "detected_models": {"openai": ["app.py"], "anthropic": ["utils.py"]},
    "report": {
      "compliance_summary": {"compliance_score": "2/3", "compliance_percentage": 66.7},
      "recommendations": [{"check": "content_marking", "status": "FAIL", "what": "..."}]
    }
  }
}
```

## License

MIT
