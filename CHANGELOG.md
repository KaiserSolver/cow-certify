# Changelog

## 0.4.1 — 2026-09-03

Never-accuse batch from a six-lane deep review (verification math, browser
parity, transport/CLI), fixed in both engines with a new hermetic test suite
that reproduces every item offline. Verdict-relevant changes first:

- **A missing receipt is not a revert (both engines).** A node answering
  `null` for `eth_getTransactionReceipt` — a pending transaction, or a lagging
  or pruning endpoint (observed live: the two reads were served by different
  nodes) — produced `C8 VIOLATION "transaction REVERTED"` on a valid
  settlement. Anything other than an explicit `status: 0x1` is now confirmed
  across every endpoint known for the network (the custom `--rpc-url` AND the
  built-in defaults, so a single endpoint is never the only witness); a
  receipt that is still missing lands `C8 UNCERTAIN`, and VIOLATION requires
  an explicit `0x0` from every witness. A receipt without a `status` field is
  treated the same way.
- **Browser C1 canonicity (browser only).** The JS decoder read the auction
  id whenever the calldata length was 8 mod 32, where Python required the
  blob to re-encode canonically. Non-canonical calldata with a wrong tail was
  accused by the browser and (correctly) not by Python. The JS decoder now
  tracks canonical layout while decoding; both engines read an auction id
  only from a canonical blob with EXACTLY an 8-byte tail. A tail of any other
  length is reported as a non-standard tail (`C1 UNCERTAIN`), never compared,
  never accused — the autopilot appends exactly 8 bytes, a custom driver may
  append anything.
- **Browser decoder no longer zero-fills truncated calldata (browser only).**
  A short read decoded as zero, which fabricated a signed limit of 0 and
  certified a genuinely limit-breaking trade as `C4 PASS`. The reader now
  throws on any out-of-range word (and validates ABI padding as eth_abi's
  strict decoder does), so decoding fails loudly into the existing
  orderbook-limit fallback and C4 reaches the same VIOLATION as Python.
- **C9 accuses only from a block-pinned reading.** On a reverted transaction
  against a non-archive RPC, the `latest` fallback could produce
  `C9 VIOLATION "not a registered solver"` for a solver de-registered since.
  A reading taken at `latest` may corroborate (PASS) but never accuse; with
  no receipt the execution status is unknown and C9 never accuses.
- **C3 liquidity carve-out.** A settled order that is in neither the winning
  solution's order list nor the auction's user-order set is most likely a
  JIT / CoW-AMM leg the public record did not list: `UNCERTAIN`, flagged for
  review. An unlisted settled order that IS an auction user order remains a
  VIOLATION.
- **Context checks never move the overall verdict.** C5, C13 and C14 had
  reachable UNCERTAIN branches (C14 fired on any missing reference price, a
  routine case on long-tail pairs), which turned valid settlements UNCERTAIN
  with exit code 2. They now report INFO with the reason. The README's
  "always INFO" description is now true.
- **Malformed API values never abort a certificate.** Reference prices,
  order limits and other API-sourced integers are parsed with guards; a bad
  value skips that datum instead of raising out of the certificate.

Transport, credential safety and CLI contract:

- A custom RPC key can no longer reach a certificate through an error
  string: every URL in an error message is reduced to scheme://host (port
  kept, userinfo dropped) before it can land in a check detail.
- A `200` with a non-JSON body (a rate-limit interstitial) now rotates to
  the next endpoint instead of ending the RPC fallback chain; `--rpc-url`
  gets bounded retries of its own; a deterministic JSON-RPC error rotates
  but never re-rounds (browser: a `400` from api.cow.fi is no longer retried
  three times).
- Bad input (typo'd hash, bad order uid, unknown network) exits **3**
  (operational) as documented, not argparse's 2 (which is the UNCERTAIN
  verdict). `--json` prints only the certificate on stdout; status lines
  from `--out`, `--html` and `--order` go to stderr. `cow-certify-batch`
  exits 1 on any VIOLATION, 3 on any error, 0 otherwise (was always 0).
- The `--order` path's trades lookup is now part of the certificate's
  evidence ledger. Calldata is lower-cased before the selector match.
  Output files are written as UTF-8 and the human render degrades its
  glyphs under a C locale instead of crashing. GPv2 non-`settle()` entry
  points (e.g. `swap()`) are labelled as such instead of "not the GPv2
  contract".
- Browser: custom `rpcUrl` is chain-id-validated like the CLI; token symbols
  carrying control or bidi-override characters are rejected like Python's
  `isprintable()`; the ledger cites the full (keyless) api.cow.fi URL so a
  reader can re-fetch it; Base endpoint order matches the CLI.
- Dead default RPCs dropped (`eth.llamarpc.com`, `polygon-rpc.com`,
  `binance.llamarpc.com`); `bsc-dataseed.bnbchain.org` restored.

Tests and CI:

- `tests/test_hermetic.py` (Python, 33 cases) and `web/test_hermetic.mjs`
  (browser, 21 cases) stub the transport with a recorded real Base
  settlement (`tests/fixtures/base_0x859d015d.json`) and mutate one thing at
  a time — null receipt, split reads, bad status, missing status field,
  single custom endpoint, non-archive C9, keyed RPC error, non-JSON 200,
  truncated / non-canonical / odd-tail calldata, unlisted uids, malformed
  prices, exit codes, JSON purity, batch exit codes. They run in CI; no
  network. The shipped corpora are all-PASS, so they could never have
  caught any of this.
- CI also runs on Python 3.9 (the declared floor), builds and installs the
  package, and runs ruff (a lint config now exists); the Pages deploy runs
  the offline JS tests first.
- Fixture corpora regenerated with 0.4.1: zero verdict changes on the 80
  self-audit and 14 parity certificates; the 4 negatives unchanged.

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
