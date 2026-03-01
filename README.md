# ArkForge Agent Client

[![GitHub Stars](https://img.shields.io/github/stars/ark-forge/arkforge-agent-client?style=flat&label=Star)](https://github.com/ark-forge/arkforge-agent-client/stargazers)

A proof-of-concept demonstrating **autonomous agent-to-agent paid transactions** through the [ArkForge Trust Layer](https://github.com/ark-forge/trust-layer).

One agent (this client) calls another agent (the [ArkForge MCP EU AI Act](https://github.com/ark-forge/mcp-eu-ai-act) scanner) to scan a code repository for EU AI Act compliance. Every transaction flows through the Trust Layer, which produces a tamper-proof cryptographic proof (SHA-256 chain + Ed25519 signature + RFC 3161 certified timestamp).

No human clicks, no browser, no manual approval.

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

### 2. Buy credits (Pro plan)

Before using the proxy, purchase prepaid credits. The Stripe receipt URL is **automatically saved** for future calls.

**Via agent.py:**

```bash
pip install requests
export TRUST_LAYER_API_KEY="mcp_pro_..."
python3 agent.py credits 10    # Buy 10 EUR = 100 proofs — receipt auto-saved
```

**Via curl:**

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: mcp_pro_..." \
  -d '{"amount": 10}'
```

Each proof costs 0.10 EUR. Min 1 EUR, max 100 EUR. Credits are deducted automatically on each proxy call.

### 3. Run a scan

```bash
export TRUST_LAYER_API_KEY="mcp_test_..."    # or mcp_pro_... for live
python3 agent.py scan https://github.com/owner/repo
```

If you purchased credits earlier, the saved receipt is **auto-attached** as payment evidence. You can also provide one manually:

```bash
python3 agent.py scan https://github.com/owner/repo \
  --receipt-url "https://pay.stripe.com/receipts/payment/CAcaFwoV..."
```

To skip auto-attach for a single call:

```bash
python3 agent.py scan https://github.com/owner/repo --no-receipt
```

### 4. Just pay (no scan)

```bash
python3 agent.py pay                     # auto-attaches saved receipt if any
python3 agent.py pay --no-receipt        # skip auto-attach
python3 agent.py pay --receipt-url "https://pay.stripe.com/receipts/payment/..."
```

### 5. Verify a proof

```bash
python3 agent.py verify prf_20260225_171714_4ebb28
```

### 6. Check reputation

```bash
python3 agent.py reputation <agent_id>
```

```
============================================================
AGENT REPUTATION
============================================================
  Agent:       buyer_abc123
  Score:       85/100
  Dimensions:
    reliability: 90
    dispute_rate: 95
    volume: 70
    consistency: 85
    longevity: 80
  Penalties:   0
  Signature:   ed25519:T3hY8kLm9nPq...(verified)
============================================================
```

### 7. File a dispute

```bash
python3 agent.py dispute prf_20260301_120000_abc123 "Response was empty"
```

```
============================================================
DISPUTE FILED
============================================================
  Dispute ID:  disp_a1b2c3d4
  Proof ID:    prf_20260301_120000_abc123
  Status:      open
  Resolution:  PENDING
============================================================
```

### 8. View dispute history

```bash
python3 agent.py disputes <agent_id>
```

```
============================================================
DISPUTE HISTORY
============================================================
  Filed:       3
  Won:         2
  Lost:        1

  Recent disputes:
    disp_a1b2c3d4 | prf_20260301_120000_abc123 | UPHELD
    disp_e5f6g7h8 | prf_20260228_090000_def456 | DENIED
    disp_i9j0k1l2 | prf_20260227_150000_ghi789 | UPHELD
============================================================
```

### Example scan output

```
============================================================
EU AI ACT COMPLIANCE SCAN — via Trust Layer
============================================================
Timestamp:   2026-02-25T17:17:12.560154+00:00
Target:      https://github.com/openai/openai-quickstart-python
Price:       0.10 EUR (from prepaid credits)
Trust Layer: https://arkforge.fr/trust/v1/proxy
Scan API:    https://arkforge.fr/api/v1/scan-repo
API Key:     mcp_te...

[PAYMENT]
  Amount:    0.1 eur
  Status:    succeeded
  Txn ID:    crd_20260227_143012_a1b2c3

[SCAN RESULT]
  Compliance:  2/3 (66.7%)
  Risk Cat:    limited
  Frameworks:  openai, anthropic

[PROOF — Trust Layer]
  ID:           prf_20260225_171714_4ebb28
  Spec:         1.1
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

With `--receipt-url`, an additional section appears:

```
[PAYMENT EVIDENCE — External Receipt]
  Fetch:     OK (fetched)
  Hash:      sha256:af65b75f3901dfd0ed9590a009bf7283e318...
  Parsing:   success
  Amount:    25.0 usd
  Status:    Paid
  Date:      February 28, 2026
  Verified:  fetched
```

## Library usage

`agent.py` can be imported as a Python module:

```python
from agent import scan_repo, verify_proof, get_reputation, file_dispute, get_disputes

# All functions return dicts — check for "error" key on failure
result = scan_repo("https://github.com/owner/repo")
if "error" in result:
    print(result["error"])
else:
    proof = result["proof"]
    print(proof["proof_id"])

# Public endpoints (no API key required)
rep = get_reputation("buyer_abc123")
disputes = get_disputes("buyer_abc123")

# Authenticated endpoints (TRUST_LAYER_API_KEY env var)
result = file_dispute("prf_...", "Response was empty")
```

Config is read from environment variables at call time, so you can set them after import:

```python
import os
os.environ["TRUST_LAYER_API_KEY"] = "mcp_pro_..."
os.environ["TRUST_LAYER_BASE"] = "http://localhost:8100"  # local dev

from agent import scan_repo
result = scan_repo("https://github.com/owner/repo")
```

## Why does this matter?

AI agents are starting to act on behalf of humans — browsing, coding, deploying. The next step is agents **paying for services autonomously**. But autonomous payments create a trust problem:

- How does the buyer agent know it got what it paid for?
- How does the seller agent prove it delivered?
- How does the human owner verify what happened?

## How the Trust Layer works

Every transaction produces a chain of verifiable proofs:

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- Validates API key
    |--- Debits prepaid credits (Pro only — Free skips this)
    |--- Fetches external receipt if --receipt-url provided (optional)
    |--- Forwards scan request to upstream API
    |--- Hashes request + response (SHA-256 chain)
    |--- Binds receipt content hash to chain (if present)
    |--- Signs with Ed25519
    |--- Submits to RFC 3161 TSA (certified timestamp)
    |--- Returns proof + scan result
    |
    v
Agent receives: scan report + cryptographic proof [+ payment evidence]
```

**Each layer is independently verifiable:**

| Proof | Verified by | Can be faked? | Plan |
|---|---|---|---|
| Ed25519 signature | Verify with ArkForge public key | No (cryptographic) | All |
| SHA-256 hash chain | Trust Layer verification URL | No (deterministic) | All |
| RFC 3161 TSA | `openssl ts -verify` | No (certified by trusted TSA) | All |
| Stripe receipt | Stripe dashboard (for credit purchase) | No (Stripe is source of truth) | Pro only |
| External receipt | `--receipt-url` — fetched, hashed, bound to proof | No (SHA-256 of raw content) | All (optional) |
| Scan result | Re-running scan on same repo | No (deterministic) | All |
| Local log | `logs/*.json` + `proofs/*.json` | Tamper-evident (contains hashes) | All |

### Three-layer proof system

Every transaction carries the ArkForge mark at 3 levels:

| Level | Where | For whom | What |
|-------|-------|----------|------|
| **1 — Digital Stamp** | `service_response.body._arkforge_attestation` | Agents (JSON consumers) | Proof ID, seal URL, verification status |
| **2 — Ghost Stamp** | HTTP response headers | Infra / monitoring | `X-ArkForge-Verified`, `X-ArkForge-Proof-ID`, `X-ArkForge-Trust-Link` |
| **3 — Visual Stamp** | HTML proof page | Humans / legal | Colored badge (green/orange/red), full proof details |

Open any proof in a browser: `https://arkforge.fr/trust/v/prf_...` — the short URL redirects to a self-contained HTML page with all verification details.

## Transparency Notice

Both this agent (buyer) and the ArkForge scan API (seller) are built and controlled by the same team (ArkForge). This is a proof-of-concept — not an attempt to simulate independent entities. The architecture is designed so that it **would work identically** between independent parties.

## Proof fields

| Field | Description |
|-------|-------------|
| `proof.spec_version` | Proof format version: `1.1` (standard) or `2.0` (with receipt). See [proof-spec](https://github.com/ark-forge/proof-spec) |
| `proof.arkforge_signature` | Ed25519 signature of the chain hash |
| `proof.arkforge_pubkey` | ArkForge's public key for verification |
| `proof.upstream_timestamp` | Upstream service's `Date` header |
| `proof.timestamp_authority.tsr_base64` | Embedded TSR file (base64, available after background processing) |
| `proof.payment_evidence` | External receipt verification result (when `--receipt-url` was provided) |
| `proof.payment_evidence.receipt_content_hash` | SHA-256 of raw receipt bytes — bound to chain hash |
| `proof.payment_evidence.parsed_fields` | Extracted amount, currency, status, date (best-effort) |
| `proof.transaction_success` | Whether the upstream service returned a success response (HTTP status < 400) |
| `proof.upstream_status_code` | HTTP status code returned by the upstream service |
| `proof.disputed` | Whether this proof has been disputed |
| `proof.dispute_id` | Reference to the dispute record (e.g. `disp_a1b2c3d4`) |

## Commands

| Command | Description |
|---------|-------------|
| `python3 agent.py scan <repo_url> [--receipt-url URL] [--no-receipt]` | Scan repo via Trust Layer (auto-attaches saved receipt) |
| `python3 agent.py pay [--receipt-url URL] [--no-receipt]` | Payment + proof only (auto-attaches saved receipt) |
| `python3 agent.py credits <amount>` | Buy prepaid credits — **saves receipt URL** for future calls |
| `python3 agent.py verify <proof_id>` | Verify an existing proof (shows payment evidence if present) |
| `python3 agent.py reputation <agent_id>` | Check agent reputation score (0-100) |
| `python3 agent.py dispute <proof_id> "reason"` | File a dispute against a proof |
| `python3 agent.py disputes <agent_id>` | View dispute history for an agent |

## Plans

| Key prefix | Plan | Stripe | Witnesses | Limits |
|---|---|---|---|---|
| `mcp_free_*` | Free | No | 3 (Ed25519, TSA, Archive.org) + optional external receipt | 100/month |
| `mcp_test_*` | Test | Test mode (no real charges) | 3 + optional external receipt | Dev only |
| `mcp_pro_*` | Pro | Prepaid credits (0.10 EUR/proof) | 3 (+ Stripe receipt) + optional external receipt | 100/day |

## Prerequisites

- Python 3.10+
- `pip install requests`

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_LAYER_API_KEY` | — | API key (required) |
| `TRUST_LAYER_BASE` | `https://arkforge.fr/trust` | Trust Layer URL |
| `SCAN_API_TARGET` | `https://arkforge.fr/api/v1/scan-repo` | Upstream scan endpoint |

## Architecture

```
arkforge-agent-client/
  agent.py               # CLI + importable library (7 commands)
  setup_card.py          # One-time: save payment method
  requirements.txt       # Only: requests
  .last_receipt.json     # Auto-saved Stripe receipt URL (gitignored)
  logs/                  # Transaction logs (JSON, gitignored)
  proofs/                # Cryptographic proofs (JSON, gitignored)
```

## Roadmap

Third-party provider support and multi-PSP payment verification are coming. See the [Trust Layer roadmap](https://github.com/ark-forge/trust-layer/blob/main/ROADMAP.md).

## License

MIT

---

Questions or feedback? Open an [issue](https://github.com/ark-forge/arkforge-agent-client/issues).
