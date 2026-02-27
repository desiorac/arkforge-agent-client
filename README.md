# ArkForge Agent Client

## What is this?

A proof-of-concept demonstrating **autonomous agent-to-agent paid transactions** through the [ArkForge Trust Layer](https://github.com/ark-forge/trust-layer).

One agent (this client) calls another agent (the [ArkForge MCP EU AI Act](https://github.com/ark-forge/mcp-eu-ai-act) scanner) to scan a code repository for EU AI Act compliance. Every transaction flows through the Trust Layer, which produces a tamper-proof cryptographic proof (SHA-256 chain + Ed25519 signature + RFC 3161 certified timestamp). Pro plan adds Stripe payment as a 4th witness.

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
    |--- Charges via Stripe (Pro only — Free skips this)
    |--- Forwards scan request to upstream API
    |--- Hashes request + response (SHA-256 chain)
    |--- Signs with Ed25519
    |--- Submits to RFC 3161 TSA (certified timestamp)
    |--- Returns proof + scan result
    |
    v
Agent receives: scan report + cryptographic proof (+ payment receipt on Pro)
```

**Each layer is independently verifiable:**

| Proof | Verified by | Can be faked? | Plan |
|---|---|---|---|
| Ed25519 signature | Verify with ArkForge public key | No (cryptographic) | All |
| SHA-256 hash chain | Trust Layer verification URL | No (deterministic) | All |
| RFC 3161 TSA | `openssl ts -verify` | No (certified by trusted TSA) | All |
| Stripe Payment Intent | Stripe dashboard, receipt URL | No (Stripe is source of truth) | Pro only |
| Scan result | Re-running scan on same repo | No (deterministic) | All |
| Local log | `logs/*.json` + `proofs/*.json` | Tamper-evident (contains hashes) | All |

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

### 1. Get an API key

**Free plan** — no card required:

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "plan": "free"}'
```

Your `mcp_free_*` API key will be emailed automatically. 100 calls/month, 3 witnesses (no Stripe).

**Pro plan** — register a payment card (once):

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
  Spec:         1.0
  Chain Hash:   sha256:5319f160352fea2c1889cf6dcbb9d1b431...
  Request Hash: sha256:0b801bccb76376504cb2c5f92c55cd7cfd...
  Signature:    ed25519:T3hY8k...(verified)
  Verify URL:   https://arkforge.fr/trust/v1/proof/prf_20260225_171714_4ebb28
  Share URL:    https://arkforge.fr/trust/v/prf_20260225_171714_4ebb28
  Timestamp:    2026-02-25T17:17:12Z
  Upstream:     Wed, 25 Feb 2026 17:17:13 GMT
  TSA:          pending

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

### New fields (additive, no client changes required)

The Trust Layer now includes additional fields in proof responses. These are purely additive — no changes needed on the agent client side:

| Field | Description |
|-------|-------------|
| `proof.spec_version` | Proof format version (see [proof-spec](https://github.com/ark-forge/proof-spec)) |
| `proof.arkforge_signature` | Ed25519 signature of the chain hash |
| `proof.arkforge_pubkey` | ArkForge's public key for verification |
| `proof.upstream_timestamp` | Upstream service's `Date` header |
| `proof.timestamp_authority.tsr_base64` | Embedded TSR file (base64, available after background processing) |

## Commands

| Command | Description |
|---------|-------------|
| `python3 agent.py scan <repo_url>` | Scan repo via Trust Layer (0.50 EUR on Pro, free on Free) |
| `python3 agent.py pay` | Payment + proof only, no scan (Pro keys only) |
| `python3 agent.py verify <proof_id>` | Verify an existing proof |

## Plans

| Key prefix | Plan | Stripe | Witnesses | Limits |
|---|---|---|---|---|
| `mcp_free_*` | Free | No | 3 (Ed25519, TSA, Archive.org) | 100/month |
| `mcp_test_*` | Test | Test mode (no real charges) | 4 | Unlimited |
| `mcp_pro_*` | Pro | Live (0.50 EUR/call) | 4 (+ Stripe receipt) | 100/day |

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
