"""Batch certification: read `network,tx_hash` lines, certify each, write
certificates to a directory, print an aggregate summary.

  python3 -m cow_certify.batch corpus.csv --out certs/ [--sleep 0.3]

Exit code: 0 = every row certified and none is a VIOLATION; 1 = at least one
VIOLATION certificate; 3 = at least one row could not be certified (bad
network, unreachable tx, RPC/API failure) and no VIOLATION. A batch that
silently exited 0 with fetch errors would defeat the self-audit ritual.
"""
import argparse
import json
import os
import sys
import time

from . import sources
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
    with open(args.corpus, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2 or not parts[0] or not parts[1]:
                print(f"  skipping malformed line: {line[:50]}", flush=True)
                continue
            rows.append((parts[0], parts[1]))
    print(f"certifying {len(rows)} settlements -> {args.out}/", flush=True)

    overall = {}
    check_fail = {}
    errors = 0
    for i, (network, tx) in enumerate(rows):
        if network not in sources.NETWORKS:
            errors += 1
            print(f"  !! {network} {tx[:14]}..: unknown network (known: "
                  f"{', '.join(sources.NETWORKS)})", flush=True)
            continue
        try:
            cert = certify_tx(network, tx, rpc_url=rpc_map.get(network))
        except (Exception, SystemExit) as e:
            # certify.py signals tx-not-found via SystemExit, which is NOT an
            # Exception — without catching it here one unreachable tx (a
            # transient RPC null is enough) kills the whole batch mid-run and
            # breaks the README's re-run-our-self-audit ritual.
            errors += 1
            msg = str(e.code) if isinstance(e, SystemExit) else str(e)
            print(f"  !! {network} {tx[:14]}..: {sources.redact(msg)[:90]}", flush=True)
            continue
        path = os.path.join(args.out, f"{network}-{tx[:14]}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=1)
        overall[cert["overall"]] = overall.get(cert["overall"], 0) + 1
        for c in cert["checks"]:
            if c["verdict"] in ("VIOLATION", "UNCERTAIN"):
                key = f"{c['check']}:{c['verdict']}"
                check_fail[key] = check_fail.get(key, 0) + 1
        if (i + 1) % 10 == 0:
            print(f"  ..{i + 1}/{len(rows)} {overall}", flush=True)
        time.sleep(args.sleep)

    print("\n== SUMMARY ==", flush=True)
    print(f"certified: {sum(overall.values())} | errors: {errors}")
    print(f"overall verdicts: {overall}")
    if check_fail:
        print("non-PASS checks:")
        for k, v in sorted(check_fail.items(), key=lambda kv: -kv[1]):
            print(f"  {k}: {v}")
    if overall.get("VIOLATION"):
        return 1
    if errors:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
