# cow-certify

[![PyPI](https://img.shields.io/pypi/v/cow-certify)](https://pypi.org/project/cow-certify/)

Independent verification for CoW Protocol settlements. Paste a settlement
transaction (or your order id) and get a reproducible verdict on whether that
settlement faithfully executed the auction it claims — with the evidence to
re-run the check yourself.

Built and maintained by [kaisersolver](https://github.com/KaiserSolver), a live
CoW solver on Arbitrum, Base and BNB Chain. Not affiliated with the CoW Protocol core
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

# CIP-87: recompute every order's penalty cap in a public auction body and diff
# it against the autopilot's published penaltyCapNative (see below)
cow-certify --network base --penalty-cap 153714586 --env staging

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
pass/fail judgment, and they never move the overall verdict (a context check
that cannot be computed says so as INFO, it does not make a valid settlement
UNCERTAIN). C5 is INFO too, and deliberately so (see below).

Checks C1–C3 implement verification criteria the CoW core team described for
their own internal watchdog in
[cowprotocol/services#2667](https://github.com/cowprotocol/services/issues/2667),
which also notes that "having multiple independent implementations of this
crucial logic is important." This is one such independent implementation.
(C4 is the GPv2 signed-limit guarantee, adjacent to but not one of the #2667
criteria; criterion 4 — settled interactions being a subset of the matched
orders' hooks — is on the roadmap.)

## CIP-87 penalty-cap replay

[CIP-87](https://forum.cow.fi/t/3520) replaces the flat penalty cap with a
per-order cap, `min(factor × volume, $20)`, that the autopilot computes and
writes into every order of the auction it hands to solvers as
`penaltyCapNative`. That auction body is public — one gzipped object per
auction in the solver-instances bucket
(`solver-instances.s3.eu-central-1.amazonaws.com/<env>/<chain>/auction/<id>.json`,
kept about 30 days: on 2026-09-07 the oldest prod objects were dated
2026-08-08 and the oldest staging objects between 2026-08-07 and 2026-08-11
depending on the chain) — and it also carries every input the calculation
consumes: the signed order amounts and the per-token native reference
prices. So the cap can be recomputed from scratch and diffed against the
number the autopilot published. Two implementations of one formula, from
public data:

```
cow-certify --network base --penalty-cap 153714586 --env staging
cow-certify --network mainnet --penalty-cap 16356147 --env staging --json | jq .summary
python3 -m cow_certify.penalty_cap_batch penalty_cap_corpus.csv --out certs_penalty_cap/
```

What is mirrored, against
[`crates/autopilot/src/domain/penalty_cap.rs`](https://github.com/cowprotocol/services/blob/d4bc7947eb49992ed1d71bb93514211f546c7ca9/crates/autopilot/src/domain/penalty_cap.rs)
at services commit `d4bc794` (main, 2026-09-07; the `PenaltyFactor` in
`crates/configs`, the call site in `solvable_orders.rs` and the driver's body
mapping in `crates/driver/src/infra/solver/dto/auction.rs` were read at the
same commit): volume is the **signed** amount (sell amount for sell orders,
buy amount for buy orders — `fullSellAmount`/`fullBuyAmount` in the body,
which the driver fills from the signed amounts, not the remaining part of a
partial fill) times that token's reference price over 1e18, with the
native-ETH placeholder mapped to the wrapped token; the factor is the first
configured override whose token set contains both the sell token and the
wrapped buy token, else the chain default (CIP-87's initial values: mainnet
4, Gnosis 3, Arbitrum 1, Base 2, Avalanche 2, Polygon 3, BNB 1, Linea 2,
Ink 1, Plasma 1 bps; correlated pairs 0.1 bps — the core team may retune
within 0–10 bps with notice, and every report states whether the chain's
default has been confirmed by a published cap); factors are applied as
parts-per-million with floor division; the $20 bound is
`20 × 10^dec × price(reference token) / 1e18`. The fallbacks are mirrored
deliberately because they are the branches a re-implementation gets wrong:
no price for the volume token, or a multiplication overflow, makes the cap
the **bound** (not zero); an overflow converting the bound makes it
`U256::MAX` (uncapped).

Two places where the CIP text and the code differ, stated so nobody "fixes"
the replay toward the text: CIP-87 defines the basis as the order's *quote*
(buy amount net of volume fees for sell orders, sell amount plus fees for buy
orders); the implementation values the order's own sell side (sell orders)
or buy side (buy orders) at the auction's reference prices. And the CIP's
scaling of a partially fillable order's cap to its executed fraction happens
at penalty time, not in the published per-order cap: the body carries the
cap for the full signed amount, and that is what is replayed. The published
number is the implementation's, so the replay follows the code. What the
replay verifies is the per-order cap the autopilot published — not the
penalty actually applied to a solver, which is rewards accounting outside
public data.

Per order the report says `MATCH`, `DIFFERENCE`, `NO_PUBLISHED_CAP` or
`NOT_COMPUTABLE`, with the volume, the factor and its source, the volume
cap, the bound and every input behind it (`absolute_bound_inputs`: the usd
reference token, its decimals and its price in this body), the regime that
produced the expected value (`volume_factor`, `absolute_bound`,
`no_price_fallback`), every candidate value the replay could derive from the
body, and — on a match — `matched_by`, the regime, factor and value that
actually reproduced the published number (for an inferred match that is not
the stated config's `expected_cap`). A matched order also carries a
`vector`: its signed order fields, the prices the formula consumed, the
configuration that reproduces the published value, and `expected_cap`.
Inferred regimes are made explicit in the vector's config, so a literal
implementation of the formula — in any language — reproduces every vector
without knowing about inference. `python3 -m cow_certify.penalty_cap_vectors
certs_penalty_cap/ certs_penalty_cap_heldout/ --out penalty_cap_vectors.json
--check` collects them into one file (schema
`cow-certify/penalty-cap-vectors/2`) and `--check` recomputes each vector
from its own fields, failing on any mismatch; the shipped
`penalty_cap_vectors.json` is that file for the corpus and held-out set.
Every vector states the usd reference price the calculator must be
constructed with (`usd_reference_price`) and where it came from
(`usd_reference_price_source`: `auction` — this body carried it;
`retained:<id>` — recovered from the most recent prior body that carried
one, the value the autopilot keeps when a cycle brings none; `unpublished` —
the body lists the token with a null price and no prior body within
`--retained-lookback` had one; `absent`). For a volume-side cap it also
states `min_usd_reference_price`, the smallest reference price at which the
bound still exceeds the published cap: constructed with any price at or
above it a literal implementation returns `expected_cap`, one wei below it
the bound binds — and `--check` proves both. On Gnosis staging the reference
token is listed in every body with a null price (the autopilot's native
price estimator fails for it there), so its retained value is the startup
fetch and never public; those vectors carry the threshold instead. A
`DIFFERENCE` is a finding to take to the core team, never a "violation" —
this is rewards accounting, and the tool has no standing to call it anything
else. The auction's overall verdict is the *worst* order verdict, so exit 0
means every order matched: 0 all matched, 2 any order that differs, carries
no published cap or could not be replayed, 3 operational. (The batch runner
exits 0 unless a `DIFFERENCE` occurs, because a corpus deliberately spans
the rollout; its summary counts the unverified orders.)

Two inputs are **not public** and the report says so every time. The
correlated-token override sets and the usd reference token are autopilot
deployment config. The replay ships CIP-87's numbers plus a per-chain USDC
default; when a published value is only reproducible under the 0.1 bps
correlated factor, or as the $20 bound converted through a different token,
the order is a `MATCH` marked `inferred: true` with the regime it needed.
`--strict` disables inference (those become `DIFFERENCE`), and overrides can
be declared in code (`penalty_cap.cip87_config(network, overrides=[...])`) so
they count as stated matches. The mainnet reference token (USDC) is
confirmed from published bound-binding caps; elsewhere the report prints
`assumed` until a bound-binding order confirms it — with one public hint the
report records: the autopilot lists its reference token in every body even
when no order uses it (`config.usd_reference.token_in_body`), which is how
the BNB and Gnosis assumptions were corroborated. A stale reference price
(the autopilot keeps its last value when the reference token has no price in
a cycle) is not observable from outside; the replay uses the price in the
auction. This mode is CLI-only (not in the browser app) and, as of this
release, only the **staging** autopilots publish the cap — prod bodies carry
no `penaltyCapNative` yet, so `--env prod` reports `NO_PUBLISHED_CAP` with
the expected values until the field ships.

The shipped corpus, `penalty_cap_corpus.csv` → `certs_penalty_cap/`, is a
sample of staging auctions spread across the bucket's retention window on
every chain with a staging prefix (`tools/make_penalty_cap_corpus.py`). The
staging bots repeat a handful of orders across many auctions, so the honest
count is *distinct orders*, re-priced per auction; each report embeds its
inputs, so the corpus stays a hermetic vector set after the bodies expire.

Result on 2026-09-07 (188 auctions, 0 fetch errors), unchanged when regenerated
on 2026-09-08 with `--retained-lookback 20` (186 bodies still in the bucket; two
pre-rollout bodies without published caps had expired and their 09-07 reports
are kept as they were): every one of the 171
order instances that carries a published cap is reproduced exactly — 0
differences — across 19 distinct orders on six chains. The other 77 auctions
carry no cap: older than the rollout on their chain, or on a chain that is
not publishing yet. Incidentally that brackets each staging rollout (the
last *sampled* auction without a cap and the first with one). A held-out
set — `penalty_cap_heldout.csv` → `certs_penalty_cap_heldout/`, the newest
12 auctions per chain on Base, mainnet and Gnosis on 2026-09-07, none of
them in the corpus (`tools/make_penalty_cap_heldout.py`; Arbitrum, BNB and
Avalanche staging had no bodies in the last 400 auction ids) — reproduced
85 of 85 order instances across 36 auctions, 8 distinct orders.

| chain | auctions | with cap | matched / instances | distinct orders | regimes seen | rollout between |
|---|---|---|---|---|---|---|
| mainnet | 55 | 35 | 63 / 63 | 2 | correlated 0.1 bps (inferred) ×35, $20 bound via USDC ×28 | 16303571 – 16312348 |
| base | 38 | 29 | 61 / 61 | 5 | 2 bps, all partially fillable (signed amount) | 153435843 – 153482354 |
| gnosis | 55 | 35 | 35 / 35 | 1 | 3 bps | 180083448 – 180104309 |
| bnb | 11 | 5 | 5 / 5 | 5 | 1 bps ×2, correlated (inferred) ×3 | 106062285 – 106268758 |
| arbitrum | 12 | 4 | 4 / 4 | 4 | 1 bps ×2, correlated (inferred) ×2 | 209545720 – 209984826 |
| avalanche | 6 | 3 | 3 / 3 | 2 | 2 bps ×2, correlated (inferred) ×1 | 258141041 – 258401616 |
| polygon, linea, plasma | 11 | 0 | – | – | no `penaltyCapNative` in staging bodies yet | – |
| ink | 0 | – | – | – | one auction body in the whole window | – |

What the corpus does **not** exercise, so you know where the replay rests on
code reading alone: a buy order below the bound (the only buy orders are the
mainnet 10,000 WETH ones, where the bound binds regardless of the volume
formula); a bound-binding order on any chain but mainnet (so the usd
reference token is confirmed only there); mainnet's own 4 bps default (every
mainnet cap in the corpus was correlated or bound-bound, so the confirmed
defaults are Base, Gnosis, Arbitrum, BNB and Avalanche — the report says so
per chain); and the four chains above with no published cap. The Gnosis
matches carry a further caveat the report prints: the assumed usd reference
token has no price in those bodies, so the bound is not computable there and
the match rests on `published == volume cap` alone (which is consistent only
if the bound was at least that). On 2026-09-07 we did not find the factor
values on docs.cow.fi's rewards or competition-rules pages, so CIP-87's text
is the only published source for them we know of. Regenerate and extend it
any time (the batch prints instances, distinct orders, and distinct orders
that carried a cap and matched — the 19 above — so every number in this
section is one command away):

```
python3 tools/make_penalty_cap_corpus.py --per-chain 25 --out penalty_cap_corpus.csv
python3 -m cow_certify.penalty_cap_batch penalty_cap_corpus.csv --out /tmp/replay
python3 tools/make_penalty_cap_heldout.py --per-chain 12 --out penalty_cap_heldout.csv
python3 -m cow_certify.penalty_cap_batch penalty_cap_heldout.csv --out /tmp/replay_heldout
```

## What it cannot check, honestly

- **C5 does not confirm the competition score.** C5 *reports* the surplus
  actually delivered on-chain — computed from the executed Trade-event amounts
  against the signed limits, so it **cannot be inflated by the settlement's
  clearing prices** — and states plainly that it does not independently confirm
  the score. The score also includes protocol fees, so a legitimate fee-bearing
  settlement shows a score above the delivered surplus; that gap is expected,
  not a finding. It is context, never a verdict.
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
# 1. the test suites (offline, no network) — unit tests plus the hermetic
#    suite, which replays a recorded real settlement through a stubbed network
#    and mutates one thing at a time (null receipt, split reads, truncated
#    calldata, keyed RPC error, ...) asserting a valid settlement is never accused
python3 -m pytest tests/ -q          # or: python3 -m unittest discover -s tests
node web/test_hermetic.mjs           # the same scenarios against the browser engine

# 2. regenerate our 80-settlement self-audit and diff against what we shipped
python3 -m cow_certify.batch self_audit_corpus.csv --out /tmp/reaudit
diff <(ls certs_self_audit) <(ls /tmp/reaudit)

# 3. the drift guards (Node) — see below
node web/test_decode.mjs        # decoder parity, offline
node web/test_certify.mjs       # verdict parity, live
```

The shipped corpora are all-PASS by construction (real, clean settlements), so
they can only prove the engines agree — not that either one refuses to accuse
when the data is bad. That is what the hermetic suites are for: they are the
regression tests for every never-accuse fix in the changelog.

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
  settlements. Its baseline is reproducible (needs RPC access) with
  `python3 tools/make_decode_truth.py self_audit_corpus.csv web/testdata/decode_truth.json`.
- **`web/test_hermetic.mjs`** and **`tests/test_hermetic.py`** run the same
  adversarial scenarios through both engines with no network at all, from a
  recorded settlement in `tests/fixtures/`. These are the guards that the
  all-PASS corpora structurally cannot provide.
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

v0.5.2. Sixteen checks (C0–C15) on ten production CoW chains — Ethereum, Gnosis,
Arbitrum, Base, Polygon, Avalanche, BNB, Ink, Linea, Plasma — plus Sepolia,
self-audited on 80 of our own settlements, with a hermetic adversarial suite on
both engines, plus the CIP-87 penalty-cap replay (CLI only) with its own staging
corpus: 171 / 171 published caps reproduced. Since 0.5.1 every penalty-cap
report keeps the inputs behind the absolute bound (`absolute_bound_inputs`) and
the corpus ships as one vector file, `penalty_cap_vectors.json`; since 0.5.2
each vector states its `usd_reference_price` and its source, or the proven
`min_usd_reference_price` where the price is not public (vectors schema 2). Scope is
settlement *verification only* (and, for CIP-87, accounting *replay*);
best-execution / EBBO is intentionally out of scope. Roadmap: services#2667 criterion 4 (settled interactions ⊆ matched-order
hooks, from public `fullAppData`), a finality model (so a late landing can be
more than UNCERTAIN), and revert-reason forensics. Issues and corrections are
welcome — especially anywhere our accounting diverges from how the protocol
actually scores things. See `CHANGELOG.md` for what each release changed in the
verdicts.

MIT license.
