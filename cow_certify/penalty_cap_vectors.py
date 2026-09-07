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

`--check` recomputes every vector from its own fields with cow-certify's
arithmetic (cap_from_vector) and fails if any differs from expected_cap - the
same check a foreign implementation should run against this file.

Schema: cow-certify/penalty-cap-vectors/1 (top-level `schema`, `reference_commit`,
`generated_at`, `count`, `vectors`).
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
        "vectors": vectors,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print(f"wrote {args.out}: {len(vectors)} vectors, regimes {doc['regimes']}, "
          f"inferred {doc['inferred']}", flush=True)
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
