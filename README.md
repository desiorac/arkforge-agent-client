# ArkForge Agent Client

## What is this?

A proof-of-concept demonstrating **autonomous agent-to-agent paid transactions** through the [ArkForge Trust Layer](https://github.com/ark-forge/trust-layer).

One agent (this client) pays another agent (the [ArkForge MCP EU AI Act](https://github.com/ark-forge/mcp-eu-ai-act) scanner) to scan a code repository for EU AI Act compliance. Every transaction flows through the Trust Layer, which handles billing via Stripe and produces a tamper-proof cryptographic proof (SHA-256 chain + RFC 3161 certified timestamp).

No human clicks, no browser, no manual approval.

## Why does this matter?

AI agents are starting to act on behalf of humans — browsing, coding, deploying. The next step is agents **paying for services autonomously**. But autonomous payments create a trust problem:

- How does the buyer agent know it got what it paid for?
- How does the seller agent prove it delivered?
- How does the human owner verify what happened?

## The Trust Layer

Every transaction produces a chain of verifiable proofs:

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- Validates API key
    |--- Charges 0.50 EUR via Stripe (off-session)
    |--- Forwards scan request to upstream API
    |--- Hashes request + response (SHA-256 chain)
    |--- Submits to RFC 3161 TSA (certified timestamp)
    |--- Returns proof + scan result
    |
    v
Agent receives: payment receipt + scan report + cryptographic proof
```

**Each layer is independently verifiable:**

| Proof | Verified by | Can be faked? |
|---|---|---|
| Stripe Payment Intent | Stripe dashboard, receipt URL | No (Stripe is source of truth) |
| SHA-256 hash chain | Trust Layer verification URL | No (deterministic) |
| RFC 3161 TSA | `openssl ts -verify` | No (certified by trusted TSA) |
| Scan result | Re-running scan on same repo | No (deterministic) |
| Local log | `logs/*.json` + `proofs/*.json` | Tamper-evident (contains Stripe IDs + hashes) |

### Triptyque de la Preuve

Every transaction carries the ArkForge mark at 3 levels:

| Level | Where | For whom | What |
|-------|-------|----------|------|
| **1 — Digital Stamp** | `service_response.body._arkforge_attestation` | Agents (JSON consumers) | Proof ID, seal URL, verification status |
| **2 — Ghost Stamp** | HTTP response headers | Infra / monitoring | `X-ArkForge-Proof`, `X-ArkForge-Verified`, `X-ArkForge-Proof-ID`, `X-ArkForge-Trust-Link` |
| **3 — Visual Stamp** | HTML proof page | Humans / legal | Colored badge (green/orange/red), full proof details |

Open any proof in a browser: `https://arkforge.fr/trust/v/prf_...` — the short URL redirects to a self-contained HTML page with all verification details.

## Transparency Notice

Both this agent (buyer) and the ArkForge scan API (seller) are built and controlled by the same team (ArkForge). This is a proof-of-concept — not an attempt to simulate independent entities. The architecture is designed so that it **would work identically** between independent parties.

## Prerequisites

- Python 3.10+
- `pip install requests`

## Quick Start

### 1. Register a payment card (once)

**Option A — via setup_card.py:**

```bash
python3 setup_card.py your@email.com --test    # Test mode (no real charges)
python3 setup_card.py your@email.com           # Live mode (real charges)
```

**Option B — via curl:**

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "mode": "test"}'
```

Open the returned `checkout_url` in a browser and enter a card. For test mode, use Stripe test card `4242 4242 4242 4242` (any future expiry, any CVC). Your API key will be emailed automatically.

### 2. Run a scan

```bash
export TRUST_LAYER_API_KEY="mcp_test_..."    # or mcp_pro_... for live
python3 agent.py scan https://github.com/owner/repo
```

### 3. Just pay (no scan)

```bash
python3 agent.py pay
```

### 4. Verify a proof

```bash
python3 agent.py verify prf_20260225_171714_4ebb28
```

### Example output

```
============================================================
EU AI ACT COMPLIANCE SCAN — via Trust Layer
============================================================
Timestamp:   2026-02-25T17:17:12.560154+00:00
Target:      https://github.com/openai/openai-quickstart-python
Price:       0.50 EUR
Trust Layer: https://arkforge.fr/trust/v1/proxy
Scan API:    https://arkforge.fr/api/v1/scan-repo
API Key:     mcp_test_93f...

[PAYMENT]
  Amount:    0.5 eur
  Status:    succeeded
  Stripe ID: pi_3T4li16iihEhp9U90qMPez14
  Receipt:   https://pay.stripe.com/receipts/payment/CAcaFwo...

[SCAN RESULT]
  Compliance:  2/3 (66.7%)
  Risk Cat:    limited
  Frameworks:  openai, anthropic

[PROOF — Trust Layer]
  ID:           prf_20260225_171714_4ebb28
  Chain Hash:   sha256:5319f160352fea2c1889cf6dcbb9d1b431...
  Request Hash: sha256:0b801bccb76376504cb2c5f92c55cd7cfd...
  Verify URL:   https://arkforge.fr/trust/v1/proof/prf_20260225_171714_4ebb28
  Share URL:    https://arkforge.fr/trust/v/prf_20260225_171714_4ebb28
  Timestamp:    2026-02-25T17:17:12Z
  OTS:          pending

[ATTESTATION — Digital Stamp]
  Embedded in scan result body as _arkforge_attestation
  Status:       VERIFIED_TRANSACTION

[RESPONSE HEADERS — Ghost Stamp]
  X-ArkForge-Verified: true
  X-ArkForge-Proof-ID: prf_20260225_171714_4ebb28
  X-ArkForge-Trust-Link: https://arkforge.fr/trust/v/prf_20260225_171714_4ebb28

[SAVED] logs/scan_20260225_171715.json
============================================================
```

## Commands

| Command | Description |
|---------|-------------|
| `python3 agent.py scan <repo_url>` | Pay 0.50 EUR + scan repo via Trust Layer |
| `python3 agent.py pay` | Pay 0.50 EUR (proof only, no scan) |
| `python3 agent.py verify <proof_id>` | Verify an existing proof |

## Test mode vs Live mode

| Key prefix | Stripe mode | Real charges? |
|---|---|---|
| `mcp_test_*` | Test | No |
| `mcp_pro_*` | Live | Yes (0.50 EUR) |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_LAYER_API_KEY` | — | API key (required) |
| `TRUST_LAYER_BASE` | `https://arkforge.fr/trust` | Trust Layer URL |
| `SCAN_API_TARGET` | `https://arkforge.fr/api/v1/scan-repo` | Upstream scan endpoint |

## Architecture

```
arkforge-agent-client/
  setup_card.py      # One-time: save payment method
  agent.py           # scan / pay / verify — all via Trust Layer
  logs/              # Transaction logs (JSON)
  proofs/            # Cryptographic proofs (JSON)
  requirements.txt   # Only: requests
```

## License

MIT
