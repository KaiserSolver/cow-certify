# cow-certify — browser app

A fully client-side verifier for non-technical users: open the page, paste a
CoW Protocol settlement tx (or your order id), and get the same certificate the
CLI produces — computed entirely in your browser from public data. No backend,
no account, no keys.

## Run it

It's static files. Any static host works:

```
# locally
python3 -m http.server -d web 8000     # then open http://localhost:8000

# GitHub Pages: serve the web/ directory
# IPFS: `ipfs add -r web` and pin the CID
```

The page calls public RPCs and the public CoW API directly from the browser
(both send `access-control-allow-origin: *`), so nothing else is required.

## Files

- `index.html` — the page (input form + styles)
- `app.js` — input handling, chain auto-detect, order→settlement resolution
- `checks.js` — the C0–C15 verification pipeline
- `gpv2.js` — a dependency-free ABI decoder for GPv2 `settle()` calldata
- `sources.js` — public RPC / CoW API / token-metadata fetchers
- `render.js` — the certificate view

The UI embeds **IBM Plex Mono** (SIL Open Font License) as its identity/data
face, base64-inlined — no CDN, fully self-contained.

## Parity with the CLI — enforced, not hoped

The browser build is a second implementation of the same checks, so it is held
to the Python reference by two drift-guards. The default corpus is the
80-settlement self-audit (our own, direct, all-PASS):

```
node web/test_decode.mjs     # decoder decodes byte-identically to Python  (80/80)
node web/test_certify.mjs    # every overall + per-check verdict matches   (80/80)
```

A second, deliberately diverse corpus (`web/testdata/parity_corpus.csv`) covers
the branches the self-audit misses — wrapper (solver-contract) routes, mainnet,
Gnosis/Polygon, and other solvers' settlements:

```
TRUTH=./testdata/parity_decode_truth.json node web/test_decode.mjs   # 12/12 (direct-decodable entries; wrapper routes excluded)
CERTS=../certs_parity/ node web/test_certify.mjs                     # 14/14 verdict parity (rate-limit skips possible on mainnet)
```

If the browser ever disagreed with the CLI, these fail. They are the contract
that lets a trader trust the in-browser answer as much as the command line.
