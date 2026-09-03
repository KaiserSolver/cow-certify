# Roadmap

Direction set by the 2026-08-17 independent audit: keep the forensic engine,
build the assurance product on top. Every number the tool emits should answer
two questions — *how exact is it* (exact / protocol-equivalent / lower-bound /
proxy / incomplete) and *what population is it over*. Ordered by intent, not
by promise dates.

## Trust model (next)
- **Validity × assurance dimensions.** Separate "VALID/INVALID/INCOMPLETE"
  from "HIGH/MODERATE/LIMITED assurance" so a wrapper-routed PASS (API-derived
  binding) never reads identical to a calldata-proven direct PASS.
- **Evidence-strength labels** per conclusion: PRIMARY (on-chain calldata/
  logs) / SECONDARY (public API) / INFERRED (fallbacks, e.g. wrapper owner
  as receiver).
- **Finality model.** Certificates record block hash, confirmations, and
  finality status; fresh settlements are PROVISIONAL, finalized ones FINAL.
  This also upgrades C6: post-finality lateness becomes a policy finding
  ("landed N blocks late — lateness established, not intent"), not UNCERTAIN.
- **Engine provenance** in every certificate: tool version, git commit,
  ruleset identifier, separate from `schema_version`.
- **Request digests** in the evidence ledger (canonical request → response
  provenance; credentials sanitized before hashing).

## Verification depth
- **Differential oracle vs CoW's official circuit-breaker validator** on the
  regression corpus; any disagreement fails CI. Independence gets stronger
  when it is continuously reconciled against the reference implementation.
- **C16 signature authenticity** (EIP-712 / eth_sign / presign / EIP-1271
  with block-state caveats); rename current C12 to order-record-consistency.
- **Hook authorization** (services#2667 criterion 4): executed pre/post
  hooks ⊆ matched orders' declared appData hooks; `--deep` trace mode where
  the RPC allows it.
- **Payout provenance** beyond the C11 sender filter: Vault internal
  balances, native-ETH legs, wrapper receivers via trace attribution.
- **Versioned schema adapters** for API records (auction.orders as strings
  today; adapters make drift a loud SOURCE SCHEMA UNSUPPORTED, not a silent
  misread). Positive JIT classification (surplusCapturingJitOrderOwners)
  instead of absence-based.
- **Buffer accounting** (C15): classify balance deltas against the
  protocol's permitted buffer usages.

## Product
- **Wallet watch / solver watch**: enter an address once, every new
  settlement is verified as it lands; the recurring workflow the one-shot
  certifier lacks.
- **Trader-first presentation**: an execution receipt (what you sold, got,
  authorized, improvement over limit, on-time, solver) with C0-C15 behind
  "technical details".
- **Batch as analytics**: `audit-solver <name> --last 7d` /
  `audit-wallet 0x… --last 90d` with structured per-check fields (no more
  scraping detail strings).
- **Execution-quality layer** (separate from integrity, never mixed):
  quote vs signed limit vs fill vs auction reference; explicit
  VALID-but-poor-execution / INVALID-but-good-price independence.
- Browser: parallel chain auto-detection, response-size bounds, restrictive
  CSP generated from the network registry.

## Engineering
- Signed network registry (chain id, contracts, API segment, explorer,
  verified-deployment provenance) validated against CoW metadata in CI.
- Packaging: dependency ceiling for eth-abi, locked dev environment, signed
  tags (PyPI: shipped since 0.4.0).
- Long-term: single verification core (Rust → WASM + Python bindings) to
  eliminate the dual-implementation risk the parity guards currently manage.
- METHODOLOGY.md / GOVERNANCE.md: identical rules for every solver, public
  correction log, challenge process, maintainer affiliation disclosed.
