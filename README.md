# cow-certify

[![PyPI](https://img.shields.io/pypi/v/cow-certify)](https://pypi.org/project/cow-certify/)

Independent verification for CoW Protocol settlements. Paste a settlement
transaction (or your order id) and get a reproducible verdict on whether that
settlement faithfully executed the auction it claims — with the evidence to
re-run the check yourself.

Built and maintained by [kaisersolver](https://github.com/KaiserSolver), a live
CoW solver on Arbitrum and Base. Not affiliated with the CoW Protocol core
team. Everything here works from public data only: chain RPC, the public
competition API, and the public orderbook. No keys, no accounts, no privileged
access. That is the point: anyone can re-run any certificate and get the same
answer.

## The one rule: it never accuses from ambiguity

A verification tool run by an *active solver* has an obvious conflict of
interest, so this one is built to resolve every ambiguity against itself.
A check emits `VIOLATION` only when public data proves misbehavior — and where
the data proves anything else, it says exactly what it cannot conclude instead
of guessing. A missing competition record, a rate-limited RPC, an amount it
cannot reconstruct: all `UNCERTAIN`, never an accusation. When something looks
off but has legitimate explanations the public data can't rule out, it stays
`UNCERTAIN` — still never `VIOLATION`. For example, a
*successful* `settle()` provably passed the on-chain solver check, so a negative
authenticator read must be our own artifact, and the tool reports it as
`UNCERTAIN` rather than accusing. That discipline is the reason a
competitor-built watchdog can be trusted at all, and it holds across every
check.

## For traders — no install

There's a browser app in [`web/`](web/): open the page, paste your settlement
transaction or order id, and it verifies the trade **in your own browser** from
public data — no install, no account, nothing sent anywhere but the same public
RPCs and CoW API the CLI uses. It's a static site (host it on GitHub Pages or
IPFS). It runs the same checks as the CLI, and a drift-guard forces the two to
agree verdict-for-verdict (see [The drift guard](#the-drift-guard)), so the
in-browser answer is exactly as trustworthy as the command line.
See [`web/README.md`](https://github.com/KaiserSolver/cow-certify/blob/main/web/README.md).

## Install (CLI)

```
pip install cow-certify
cow-certify --network base 0x<settlement_tx_hash>
```

Or from a clone, with no install at all:

```
git clone https://github.com/KaiserSolver/cow-certify
cd cow-certify
python3 -m cow_certify --network base 0x<settlement_tx_hash>
```

The only third-party dependency is `eth-abi`; public RPCs and API endpoints for
every chain are built in.

## Quickstart

```
# certify a settlement transaction
cow-certify --network base 0x<settlement_tx_hash>

# traders: certify your own trade straight from its order id on CoW Explorer
cow-certify --network mainnet --order 0x<order_uid>

# write a shareable HTML certificate (for anyone, not just the terminal)
cow-certify --network base 0x<tx> --html cert.html

# machine-readable certificate JSON (JSON only — pipeable to jq / CI)
cow-certify --network arbitrum 0x<tx> --json

# batch mode + aggregate summary
python3 -m cow_certify.batch corpus.csv --out certs/
```

(`python3 -m cow_certify` works identically from a source checkout.)

Supported networks: mainnet, arbitrum, base, gnosis, polygon, avalanche, bnb,
ink, linea, plasma, sepolia. Default public RPCs are built in (with fallback rotation
and retry/backoff); pass `--rpc-url` for your own endpoint — recommended for
mainnet, whose public RPCs rate-limit hard.

### Reading the result

The output leads with the overall verdict, then a scannable line per check:
green `✓` PASS, red `✗` VIOLATION, yellow `?` UNCERTAIN, dim `·` for context. Colors turn off
automatically when piped or under `NO_COLOR` (or `--no-color`). The exit code
carries the outcome so it drops into CI: **`0`** pass · **`1`** violation ·
**`2`** uncertain · **`3`** operational error (bad input, RPC/API
unreachable) — so a real violation (`1`) is never confused with a typo'd hash
(`3`). Add `-v` for the per-order ledger, `--json` for the certificate.

## What gets checked

| check | question it answers |
|---|---|
| C0 settlement shape | Is this a direct settle() call, a solver-owned wrapper route, or not a CoW settlement at all? |
| C1 auction binding | Does the auction id embedded in the calldata match the stored competition record? |
| C2 winner legitimacy | Was the settlement executed by the solver that actually won the auction? |
| C3 solution fidelity | Did exactly the winning solution's orders settle, at the scored amounts? |
| C4 limit compliance | Does every trade respect the user's signed limit price? |
| C5 surplus delivered | The user surplus actually delivered on-chain (context — see below). |
| C6 timeliness | Did the settlement land within the auction deadline? |
| C7 competition context | How contested was this win (solvers, solutions, margin)? |
| C8 execution status | Emitted only when a settlement reverted on-chain (→ VIOLATION). |
| C9 solver authorization | Was the settle() caller a registered solver in the on-chain GPv2 authenticator? |
| C10 order ledger | The full per-order record: tokens, amounts, prices, fees, fill fraction, surplus, validity. |
| C11 receiver delivery | Did each order's buy tokens actually reach the recorded receiver on-chain? |
| C12 order authenticity | Does each settled order match a real signed order in the public orderbook? |
| C13 interactions | What external calls (pre/intra/post targets, values, selectors) did the settlement make? |
| C14 price vs mid | How did execution compare to the auction's reference mid? (a best-execution *signal*, not full EBBO) |
| C15 protocol buffer | Did the settlement draw from CoW's accumulated-fee buffer (ERC-20 net delta)? |

Verdicts are **PASS**, **VIOLATION**, **UNCERTAIN**, or **INFO**.
C7, C10, C13, C14, and C15 are always INFO — context and signal rather than a
pass/fail judgment. C5 is INFO too, and deliberately so (see below).

Checks C1–C3 implement verification criteria the CoW core team described for
their own internal watchdog in
[cowprotocol/services#2667](https://github.com/cowprotocol/services/issues/2667),
which also notes that "having multiple independent implementations of this
crucial logic is important." This is one such independent implementation.
(C4 is the GPv2 signed-limit guarantee, adjacent to but not one of the #2667
criteria; criterion 4 — settled interactions being a subset of the matched
orders' hooks — is on the roadmap.)

## What it cannot check, honestly

- **C5 does not confirm the competition score.** The reported score folds in
  protocol fee policy and the CIP-38 objective, none of which are exposed in
  public data, so a legitimate fee-bearing settlement has a score well above the
  user surplus. C5 therefore *reports* the surplus actually delivered on-chain —
  computed from the executed Trade-event amounts against the signed limits, so
  it **cannot be inflated by the settlement's clearing prices** — and states
  plainly that it does not independently confirm the score. It is context, never
  a verdict.
- **Best-execution / EBBO** (whether a better price was available elsewhere) is
  out of scope by design. This tool verifies a settlement's *validity*, not its
  *optimality*. It does not detect, or claim to detect, EBBO violations. C14 is
  a reference-*price* comparison, not an executable-elsewhere verdict.
- **Declines** (a solver wins but never submits) leave no transaction and no
  public record; nobody outside the core team can measure them.
- On **wrapper-routed** settlements the calldata auction id is not accessible at
  the top level, so auction binding relies on the API record alone (marked on
  the certificate).

## Verify our work

You do not have to trust any of this — re-run it:

```
# 1. the test suite (offline, no network)
python3 -m unittest discover -s tests

# 2. regenerate our 80-settlement self-audit and diff against what we shipped
python3 -m cow_certify.batch self_audit_corpus.csv --out /tmp/reaudit
diff <(ls certs_self_audit) <(ls /tmp/reaudit)

# 3. the drift guards (Node) — see below
node web/test_decode.mjs        # decoder parity, offline
node web/test_certify.mjs       # verdict parity, live
```

And inspect any certificate's evidence trail — every fetch it relied on, pinned
by hash:

```
python3 -m cow_certify --network base 0x<tx> --json \
  | jq '.evidence[] | {kind, ref, sha256}'
```

## The drift guard

The browser app re-implements every check in JavaScript, which raises the
obvious question: does it actually agree with the Python tool? Two guards force
it to, over two corpora:

- **`web/test_decode.mjs`** checks the hand-rolled browser ABI decoder decodes
  `settle()` calldata **byte-identically** to the Python decoder, over 80 real
  settlements. Its baseline is reproducible with
  `python3 tools/make_decode_truth.py`.
- **`web/test_certify.mjs`** checks the browser produces the **same verdict for
  every check** as the Python certificate — by default over the 80-settlement
  self-audit corpus, and with `CERTS=../certs_parity/` over the deliberately
  adversarial one (wrapper routes, five chains, other solvers' settlements —
  the branches our own all-PASS self-audit misses).

So "the browser gives the same answer as the CLI" is enforced, not hoped.

## Evidence and reproducibility

Every certificate embeds an evidence ledger: each external fetch with its URL
(any RPC API key stripped), a sha256 of the raw response, a byte count, and a
timestamp — plus the exact command to reproduce the run. Certificates are plain
JSON; the human-readable and HTML renderings are derived from them, never the
other way around. (The hashes pin the exact bytes *this* run saw; different RPC
providers serialize JSON differently, so a re-run's hashes need not match
byte-for-byte — the ledger is tamper-evidence for a published certificate, not a
universal fingerprint.)

We certify our own settlements first and continuously, under the same checks and
the same rules as anyone else's — `certs_self_audit/` holds 80 of them, and
`certs_negative/` holds real settlements that must *not* read as a clean PASS
(a reverted settle(), a non-settlement transaction), so you can see the tool
discriminate rather than only rubber-stamp.

## Status

v0.3. Runs on ten CoW chains — Ethereum, Gnosis, Arbitrum, Base, Polygon,
Avalanche, BNB, Ink, Plasma, Sepolia — self-audited on 80 of our own
settlements. Scope is settlement *verification only*; best-execution / EBBO is
intentionally out of scope. Roadmap: services#2667 criterion 4 (settled
interactions ⊆ matched-order hooks, from public `fullAppData`), a JIT/liquidity-
order classification, and revert-reason forensics. Issues and corrections are
welcome — especially anywhere our accounting diverges from how the protocol
actually scores things.

MIT license.
