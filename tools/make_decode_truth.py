#!/usr/bin/env python3
"""Regenerate a decode-truth file for the JS↔Python decoder drift guard.

The guard (web/test_decode.mjs) checks that the hand-rolled browser decoder
(web/gpv2.js) decodes settle() calldata byte-identically to the vendored Python
decoder (cow_certify/gpv2.py). Its baseline — web/testdata/decode_truth.json —
is the Python decoder's output for a corpus of real settlements. This script
produces that baseline reproducibly (previously it had no generator, which made
the guard's ground truth un-auditable).

Usage:
  python3 tools/make_decode_truth.py self_audit_corpus.csv web/testdata/decode_truth.json
  python3 tools/make_decode_truth.py web/testdata/parity_corpus.csv \
      web/testdata/parity_decode_truth.json

Each output row is {network, tx, calldata, decoded} where `decoded` is the
JSON-safe projection of gpv2.decode_settlement the JS mirrors.
"""
import json
import os
import sys

# Runnable directly from a clone (`python3 tools/make_decode_truth.py`): put the
# repo root on the path so the package imports without PYTHONPATH.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cow_certify import gpv2, sources  # noqa: E402


def _addr(x):
    return (x if isinstance(x, str) else "0x" + bytes(x).hex()).lower()


def _selector(callbytes):
    h = callbytes.hex() if isinstance(callbytes, (bytes, bytearray)) else ""
    return "0x" + h[:8] if len(h) >= 8 else "0x"


def _decoded_projection(calldata):
    d = gpv2.decode_settlement(calldata)
    # Exactly the shape web/test_decode.mjs compares against (see eqTrades):
    # camelCase, amounts as strings, flags/validTo as numbers, auctionId as
    # string-or-null.
    trades = [{
        "sellTokenIndex": int(t[0]),
        "buyTokenIndex": int(t[1]),
        "receiver": _addr(t[2]),
        "sellAmount": str(t[3]),
        "buyAmount": str(t[4]),
        "validTo": int(t[5]),
        "appData": "0x" + bytes(t[6]).hex(),
        "feeAmount": str(t[7]),
        "flags": int(t[8]),
        "executedAmount": str(t[9]),
    } for t in d["trades"]]
    interactions = [
        [{"target": _addr(it[0]), "value": str(it[1]), "selector": _selector(it[2])}
         for it in stage]
        for stage in d["interactions"]
    ]
    return {
        "tokens": d["tokens"],
        "clearingPrices": [str(p) for p in d["clearing_prices"]],
        "trades": trades,
        "interactions": interactions,
        "auctionId": None if d["auction_id"] is None else str(d["auction_id"]),
    }


def main(argv):
    if len(argv) != 3:
        sys.exit(f"usage: {argv[0]} <corpus.csv> <out.json>")
    corpus, out_path = argv[1], argv[2]
    rows = []
    with open(corpus, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            network, tx = (p.strip() for p in line.split(",", 1))
            ev = sources.Evidence()
            rpc = sources.DEFAULT_RPC[network]
            txd = sources.rpc(rpc, "eth_getTransactionByHash", [tx], ev)
            calldata = (txd or {}).get("input") or ""
            try:
                decoded = _decoded_projection(calldata)
            except Exception as e:
                print(f"  skip {network} {tx[:12]}…: {e}", file=sys.stderr)
                continue
            rows.append({"network": network, "tx": tx,
                         "calldata": calldata, "decoded": decoded})
            print(f"  {network} {tx[:12]}… ok", file=sys.stderr)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(f"wrote {len(rows)} rows → {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
