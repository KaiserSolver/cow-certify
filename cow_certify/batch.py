"""Batch certification: read `network,tx_hash` lines, certify each, write
certificates to a directory, print an aggregate summary.

  python3 -m cow_certify.batch corpus.csv --out certs/ [--sleep 0.3]

The summary is the seed of the aggregate view (competition-health reporting):
verdict counts, per-check failure/uncertain tallies, and the C5 gap
distribution in ppm.
"""
import argparse
import json
import os
import sys
import time

from .certify import certify_tx


def main():
    ap = argparse.ArgumentParser(prog="cow-certify-batch")
    ap.add_argument("corpus", help="file of `network,tx_hash` lines (# = comment)")
    ap.add_argument("--out", default="certs", help="output directory")
    ap.add_argument("--sleep", type=float, default=0.3)
    ap.add_argument("--rpc-map", help="per-network RPC override, "
                    "'network=url,network=url' (e.g. for a private archive "
                    "endpoint when self-auditing at volume)")
    args = ap.parse_args()

    rpc_map = {}
    if args.rpc_map:
        for pair in args.rpc_map.split(","):
            net, url = pair.split("=", 1)
            rpc_map[net.strip()] = url.strip()

    os.makedirs(args.out, exist_ok=True)
    rows = []
    for line in open(args.corpus):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            print(f"  skipping malformed line: {line[:50]}", flush=True)
            continue
        network, tx = parts[0], parts[1]
        rows.append((network, tx))
    print(f"certifying {len(rows)} settlements -> {args.out}/", flush=True)

    overall = {}
    check_fail = {}
    c5_ppm = []
    errors = 0
    for i, (network, tx) in enumerate(rows):
        try:
            cert = certify_tx(network, tx, rpc_url=rpc_map.get(network))
        except (Exception, SystemExit) as e:
            # certify.py signals tx-not-found via SystemExit, which is NOT an
            # Exception — without catching it here one unreachable tx (a
            # transient RPC null is enough) kills the whole batch mid-run and
            # breaks the README's re-run-our-self-audit ritual.
            errors += 1
            print(f"  !! {network} {tx[:14]}..: {str(e)[:90]}", flush=True)
            continue
        path = os.path.join(args.out, f"{network}-{tx[:14]}.json")
        with open(path, "w") as f:
            json.dump(cert, f, indent=1)
        overall[cert["overall"]] = overall.get(cert["overall"], 0) + 1
        for c in cert["checks"]:
            if c["verdict"] in ("VIOLATION", "UNCERTAIN"):
                key = f"{c['check']}:{c['verdict']}"
                check_fail[key] = check_fail.get(key, 0) + 1
            if c["check"].startswith("C5") and "gap" in c.get("detail", ""):
                try:
                    ppm = float(c["detail"].split("gap")[1].split("ppm")[0].strip(" (+"))
                    c5_ppm.append(ppm)
                except (IndexError, ValueError):
                    pass
        if (i + 1) % 10 == 0:
            print(f"  ..{i + 1}/{len(rows)} {overall}", flush=True)
        time.sleep(args.sleep)

    print("\n== SUMMARY ==", flush=True)
    print(f"certified: {sum(overall.values())} | fetch errors: {errors}")
    print(f"overall verdicts: {overall}")
    if check_fail:
        print("non-PASS checks:")
        for k, v in sorted(check_fail.items(), key=lambda kv: -kv[1]):
            print(f"  {k}: {v}")
    if c5_ppm:
        c5_ppm.sort()
        n = len(c5_ppm)
        print(f"C5 gap ppm: n={n} min={c5_ppm[0]:+.2f} "
              f"median={c5_ppm[n // 2]:+.2f} max={c5_ppm[-1]:+.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
