# Changelog

## [1.8.1] - 2026-03-16

### Changed (no code change — Trust Layer v1.3.0 API update)
- `verify_proof(proof_id)` — `GET /v1/proof/{id}` now returns a privacy-filtered response. The following fields are no longer visible publicly: `parties` (buyer/seller identity), `certification_fee` amounts, `provider_payment.receipt_url`, `provider_payment.parsed_fields` (amount, status, date), `buyer_reputation_score`, `buyer_profile_url`. `_print_provider_payment()` and `_print_payment()` will silently skip these fields when called on a verified proof.
- To access the full proof (including payment details), use `GET /v1/proof/{id}/full` with your API key (owner only). No client helper added yet — use `requests.get()` directly with `headers={"X-Api-Key": YOUR_KEY}`.

## [1.8.0] - 2026-03-03

### Added
- Display Sigstore Rekor entry in `_print_proof()` output
  - `Rekor: verified (logIndex=<N>)` when transparency log is present
  - `Rekor URL: https://search.sigstore.dev/?logIndex=<N>` for direct public verification

## [1.7.0] - 2026-03-03

### Changed
- `reputation` command updated to match new Trust Layer scoring model
  - Displays `reputation_score`, `success_rate`, `confidence`, and `formula`
  - Previous 5-dimension display (reliability, volume, etc.) removed — replaced by transparent formula
  - Formula: `score = floor(success_rate × confidence) − penalties`

## [1.6.0] - 2026-03-01

### Added
- `reputation <agent_id>` command — check public reputation score (0-100) for any agent
- `dispute <proof_id> "reason"` command — flag a proof as contested
- `disputes <agent_id>` command — view dispute history for an agent

### Changed
- Auto-save receipt after `credits` command (receipt URL logged for Mode B reference)
- Auto-attach receipt on `scan`/`pay` if `--receipt-url` provided

## [1.5.0] - 2026-02-28

### Added
- Mode B — payment evidence: `--receipt-url URL` attaches a direct provider payment receipt
- `--pay-provider` flag: pays the scan provider directly via Stripe and auto-attaches the receipt
- Ghost Stamp (Level 2): `X-ArkForge-*` response headers captured and displayed
- `--no-receipt` flag to skip receipt attachment

## [1.4.0] - 2026-02-26

### Added
- `credits <amount>` command — buy prepaid credits via Stripe Checkout (1–100 EUR)
- `verify <proof_id>` command — verify an existing proof
- Proof files saved to `proofs/` directory alongside transaction logs

### Changed
- `scan` and `pay` now debit prepaid credits (0.10 EUR/proof) instead of per-call Stripe charges
- Free tier support (100 proofs/month, no card required)

## [1.0.0] - 2026-02-17

### Added
- Initial release: `scan <repo_url>` and `pay` commands
- Trust Layer proxy integration (SHA-256 chain + Ed25519 + RFC 3161 TSA)
- Transaction logging to `logs/` directory
