# Changelog

## 0.4.0 — 2026-08-17

Correctness batch from an independent line-level audit (external reviewer,
same-day fixes). Verdict-relevant changes first:

- **C3 exact-match discipline.** Executed-vs-scored amount deltas inside the
  old ±2-atom band no longer PASS: exact is the only PASS; a 1-2 atom
  user-deficit lands UNCERTAIN (flagged for review — the old label called it
  "user-favorable" even when the user received less); beyond the band stays
  VIOLATION. Corpus evidence: 0/94 shipped certificates ever exercised the
  band — real settlements match exactly.
- **C11 sender filter (false-PASS fix).** Only ERC-20 transfers sent BY the
  settlement contract count toward receiver delivery; an unrelated
  same-transaction transfer to the same (token, receiver) can no longer
  satisfy the expected amount. Regression test added.
- **C5 never guesses order kind.** A trade whose sell/buy kind cannot be
  established from public data is excluded from the delivered-surplus sum
  and disclosed in the coverage note (previously silently assumed "sell" —
  a buy order valued as a sell produces a wrong surplus).
- **Custom-RPC chain-id validation.** `--rpc-url` endpoints are verified via
  `eth_chainId` against `--network` before any certification (certifying a
  Base settlement against an Arbitrum node now refuses instead of producing
  confident nonsense).
- **Linea support** (chain 59144) — GPv2 presence and canonical authenticator
  verified on-chain before inclusion; CLI + browser. 11 networks now.
- **C14 renamed honestly**: "Execution vs auction reference price" — the
  reference price is a comparison anchor, not a "fair mid" economic judgment.
- **CI workflow added**: Python tests + engine compile + Python/JS decoder
  parity vectors now run on every push/PR (previously the guards existed but
  nothing enforced them on merge).
- Evidence-ledger docstring corrected: entries pin the RESPONSE bytes'
  sha256 + safe origin; the exact request is not yet pinned (roadmap).

Verification of this batch: 33/33 Python tests, 80/80 decoder parity, 14/14
live verdict parity, full self-audit corpus regenerated with **zero verdict
changes**, negative-control corpus unchanged (3 VIOLATION / 1 UNCERTAIN),
end-to-end certification of a live Linea settlement.

## 0.3.0 — 2026-08-15

Initial public release: C0-C15 checks, CLI + browser app (GitHub Pages),
10 networks, evidence ledger, HTML/JSON certificates, batch mode, self-audit
corpus + drift guards, negative-control corpus.
