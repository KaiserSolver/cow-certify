"""Collect CIP-87 penalty-cap vectors from replay reports into ONE file that a
second implementation can consume, and self-check them.

  python3 -m cow_certify.penalty_cap_vectors certs_penalty_cap/ certs_penalty_cap_heldout/ \
      --out penalty_cap_vectors.json --check

A vector is one MATCHed order: the signed order fields, the native prices the
formula consumed (volume token and usd reference token), the configuration
that reproduces the published value (default factor in ppm, any override
needed, the $ bound, the usd reference token and decimals, the wrapped native
token) and `expected_cap` = the autopilot's published penaltyCapNative. Amounts
and prices are decimal strings (U256-safe). Inferred regimes are made
explicit in `config` so a literal implementation of the formula reproduces
`expected_cap` with no knowledge of inference; `inferred` says which ones.

Every vector also states the usd reference price the calculator must be
constructed with (`usd_reference_price`, with `usd_reference_price_source` =
`auction` when this body carried it, `retained:<auction id>` when it was
recovered from the most recent prior body that carried one, `unpublished`
when the body lists the token with no price and no prior body within the
lookback had one, `absent` when the body does not list the token) and, for
volume-side caps, `min_usd_reference_price`: the smallest reference price at
which the absolute bound still exceeds the published cap - a literal
implementation constructed with any price at or above it returns
`expected_cap`; one wei below it the bound binds. `usd_reference_token_in_body`
records whether the assumed reference token was listed in the body at all
(listed without any order using it is public evidence that it is the deployed
reference token).

`--check` recomputes every vector from its own fields with cow-certify's
arithmetic (cap_from_vector) and fails if any differs from expected_cap - the
same check a foreign implementation should run against this file. For a vector
without an exact price it also proves the threshold: constructed at
`min_usd_reference_price` the vector reproduces `expected_cap`, one wei below
it does not.

Schema: cow-certify/penalty-cap-vectors/2 (top-level `schema`, `reference_commit`,
`generated_at`, `count`, `regimes`, `inferred`, `reference_prices`, `vectors`).
"""
import argparse
import glob
import json
import os
import sys
import time

from . import __version__
from .penalty_cap import VECTOR_SCHEMA, cap_from_vector


def collect(dirs):
    vectors, ids = [], set()
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            with open(path, encoding="utf-8") as f:
                rep = json.load(f)
            if rep.get("kind") != "penalty_cap_replay":
                continue
            for o in rep.get("orders", []):
                v = o.get("vector")
                if v and v["id"] not in ids:
                    ids.add(v["id"])
                    vectors.append(v)
    return vectors


def check(vectors):
    bad = []
    for v in vectors:
        got = cap_from_vector(v)
        if got is None or str(got) != v["expected_cap"]:
            bad.append((v["id"], v["expected_cap"], got))
            continue
        # Threshold proof for vectors that carry no exact reference price: at the
        # stated minimum the cap is reproduced, one wei below it the bound binds.
        tok = (v["config"].get("usd_reference_token") or "").lower()
        has_price = v.get("usd_reference_price") is not None or tok in {k.lower() for k in v["prices"]}
        m = v.get("min_usd_reference_price")
        if m is not None and not has_price:
            at = dict(v, usd_reference_price=str(int(m)))
            below = dict(v, usd_reference_price=str(int(m) - 1)) if int(m) > 0 else None
            if str(cap_from_vector(at)) != v["expected_cap"]:
                bad.append((v["id"], v["expected_cap"], f"at min price {m}: {cap_from_vector(at)}"))
            elif below is not None and str(cap_from_vector(below)) == v["expected_cap"]:
                bad.append((v["id"], v["expected_cap"], f"min price {m} is not tight"))
    return bad


def main():
    ap = argparse.ArgumentParser(prog="cow-certify-penalty-cap-vectors")
    ap.add_argument("dirs", nargs="+", help="report directories (from penalty_cap_batch)")
    ap.add_argument("--out", default="penalty_cap_vectors.json")
    ap.add_argument("--check", action="store_true",
                    help="recompute every vector from its own fields and fail on any mismatch")
    args = ap.parse_args()
    vectors = collect(args.dirs)
    commits = sorted({v.get("reference_commit") for v in vectors if v.get("reference_commit")})
    doc = {
        "schema": VECTOR_SCHEMA,
        "tool_version": __version__,
        "reference_commit": commits[0] if len(commits) == 1 else commits,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(vectors),
        "regimes": {r: sum(1 for v in vectors if v["regime"] == r)
                    for r in sorted({v["regime"] for v in vectors})},
        "inferred": sum(1 for v in vectors if v["inferred"]),
        "reference_prices": {src: sum(1 for v in vectors if v.get("usd_reference_price_source") == src)
                             for src in sorted({v.get("usd_reference_price_source") or "none"
                                                for v in vectors})},
        "vectors": vectors,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print(f"wrote {args.out}: {len(vectors)} vectors, regimes {doc['regimes']}, "
          f"inferred {doc['inferred']}, reference prices {doc['reference_prices']}", flush=True)
    if args.check:
        bad = check(vectors)
        if bad:
            for b in bad[:20]:
                print(f"  MISMATCH {b[0]}: expected {b[1]} recomputed {b[2]}")
            print(f"check FAILED: {len(bad)}/{len(vectors)}")
            return 2
        print(f"check OK: {len(vectors)}/{len(vectors)} vectors reproduce expected_cap from their own fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
