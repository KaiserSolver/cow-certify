"""Build `penalty_cap_heldout.csv`: the NEWEST staging auction bodies per chain
that are NOT in `penalty_cap_corpus.csv`, so the replay can be checked on
auctions it was never tuned on. Same row format as the corpus.

  python3 tools/make_penalty_cap_heldout.py [--per-chain 12] [--corpus penalty_cap_corpus.csv] [--out penalty_cap_heldout.csv]
  python3 -m cow_certify.penalty_cap_batch penalty_cap_heldout.csv --out certs_penalty_cap_heldout/

Walks back from the barn orderbook's current auction id and keeps the first
`--per-chain` ids that have a body in the bucket (up to `--scan` ids per
chain; Arbitrum/BNB/Avalanche staging bodies are sparse and may yield none).
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

BUCKET = "https://solver-instances.s3.eu-central-1.amazonaws.com"
UA = {"user-agent": "curl/8"}
CHAINS = {
    "mainnet": ("mainnet", "mainnet"),
    "arbitrum": ("arbitrum-one", "arbitrum_one"),
    "base": ("base", "base"),
    "gnosis": ("xdai", "xdai"),
    "polygon": ("polygon", "polygon"),
    "avalanche": ("avalanche", "avalanche"),
    "bnb": ("bnb", "bnb"),
    "linea": ("linea", "linea"),
    "ink": ("ink", "ink"),
    "plasma": ("plasma", "plasma"),
}


def _get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()


def _exists(seg, aid):
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{BUCKET}/staging/{seg}/auction/{aid}.json", headers=UA, method="HEAD"), timeout=30)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-chain", type=int, default=12)
    ap.add_argument("--scan", type=int, default=400)
    ap.add_argument("--corpus", default="penalty_cap_corpus.csv")
    ap.add_argument("--out", default="penalty_cap_heldout.csv")
    ap.add_argument("--chains", default=",".join(CHAINS))
    args = ap.parse_args()
    corpus = set()
    with open(args.corpus, encoding="utf-8") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                net, _env, aid = [p.strip() for p in line.split(",")[:3]]
                corpus.add((net, int(aid)))
    rows = ["# network,env,auction_id — the newest staging auction bodies per chain NOT in",
            f"# {args.corpus} (tools/make_penalty_cap_heldout.py); regenerate any time."]
    for network in args.chains.split(","):
        network = network.strip()
        seg, api = CHAINS[network]
        try:
            latest = json.loads(_get(f"https://barn.api.cow.fi/{api}/api/v1/auction"))["id"]
        except Exception as e:
            print(f"  {network}: barn auction id unavailable ({str(e)[:60]})", file=sys.stderr)
            continue
        ids, aid, scanned = [], latest - 1, 0
        while len(ids) < args.per_chain and scanned < args.scan:
            scanned += 1
            if (network, aid) not in corpus and _exists(seg, aid):
                ids.append(aid)
            aid -= 1
        print(f"  {network}: {len(ids)} held-out auctions (scanned {scanned} ids back from {latest})",
              file=sys.stderr)
        rows += [f"{network},staging,{a}" for a in sorted(ids)]
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(rows) + "\n")
    print(f"wrote {args.out}: {sum(1 for r in rows if not r.startswith('#'))} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
