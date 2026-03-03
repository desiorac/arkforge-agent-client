# Changelog

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
