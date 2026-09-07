"""Batch CIP-87 penalty-cap replay: read `network,env,auction_id` lines, replay
each public auction body, write one report per auction, print an aggregate
summary (auctions, order instances, DISTINCT orders, regimes).

  python3 -m cow_certify.penalty_cap_batch penalty_cap_corpus.csv --out certs_penalty_cap/

Exit code: 0 = every auction replayed and no order is a DIFFERENCE;
2 = at least one DIFFERENCE (a finding, not a violation); 3 = at least one
auction could not be fetched/replayed and no DIFFERENCE. Unlike the
single-auction CLI (exit 2 for any unverified order), the batch tolerates
NO_PUBLISHED_CAP / NOT_COMPUTABLE orders because a corpus deliberately spans
the rollout (auctions before the field existed); the summary counts them.
"""
import argparse
import json
import os
import sys
import time

from . import sources
from .penalty_cap import DIFFERENCE, MATCH, replay


def main():
    ap = argparse.ArgumentParser(prog="cow-certify-penalty-cap-batch")
    ap.add_argument("corpus", help="file of `network,env,auction_id` lines (# = comment)")
    ap.add_argument("--out", default="certs_penalty_cap", help="output directory")
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--strict", action="store_true",
                    help="no regime inference; only the stated config counts")
    args = ap.parse_args()

    rows = []
    with open(args.corpus, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3 or not all(parts[:3]):
                print(f"  skipping malformed line: {line[:50]}", flush=True)
                continue
            rows.append((parts[0], parts[1], parts[2]))
    os.makedirs(args.out, exist_ok=True)
    print(f"replaying {len(rows)} auctions -> {args.out}/", flush=True)

    overall, verdicts, regimes = {}, {}, {}
    orders = 0
    distinct = set()
    distinct_matched = set()
    inferred = 0
    errors = 0
    diffs = []
    for i, (network, env, aid) in enumerate(rows):
        if network not in sources.BUCKET_CHAINS or env not in sources.BUCKET_ENVS \
                or not aid.isdigit():
            errors += 1
            print(f"  !! {network} {env} {aid}: bad row (network/env/auction id)", flush=True)
            continue
        try:
            rep = replay(network, int(aid), env=env, strict=args.strict)
        except (Exception, SystemExit) as e:
            errors += 1
            msg = str(e.code) if isinstance(e, SystemExit) else str(e)
            print(f"  !! {network} {env} {aid}: {sources.redact(msg)[:100]}", flush=True)
            continue
        path = os.path.join(args.out, f"{network}-{env}-{aid}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=1)
        overall[rep["overall"]] = overall.get(rep["overall"], 0) + 1
        for o in rep["orders"]:
            orders += 1
            distinct.add((network, o["uid"]))
            verdicts[o["verdict"]] = verdicts.get(o["verdict"], 0) + 1
            if o["verdict"] == MATCH:
                regimes[o["regime"]] = regimes.get(o["regime"], 0) + 1
                inferred += 1 if o.get("inferred") else 0
                distinct_matched.add((network, o["uid"]))
            elif o["verdict"] == DIFFERENCE:
                diffs.append((network, env, aid, o["uid"], o.get("published_cap"),
                              o.get("expected_cap")))
        if (i + 1) % 10 == 0:
            print(f"  ..{i + 1}/{len(rows)} {overall}", flush=True)
        time.sleep(args.sleep)

    print("\n== SUMMARY ==", flush=True)
    print(f"auctions replayed: {sum(overall.values())} | errors: {errors}")
    print(f"auction verdicts: {overall}")
    print(f"order instances: {orders} | distinct orders: {len(distinct)} "
          f"(with a published cap and matched: {len(distinct_matched)})")
    print(f"order verdicts: {verdicts}")
    if regimes:
        print(f"match regimes: {regimes} (inferred: {inferred})")
    for d in diffs[:20]:
        print(f"  DIFFERENCE {d[0]} {d[1]} auction {d[2]} order {d[3][:18]}… published {d[4]} expected {d[5]}")
    if diffs:
        return 2
    if errors:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
