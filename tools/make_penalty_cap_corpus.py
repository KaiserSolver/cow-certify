"""Build `penalty_cap_corpus.csv`: a sample of public STAGING auction bodies,
spread across the instance bucket's ~30-day retention window on every chain
that has a staging prefix, so the replay is exercised on many price levels
and on whatever order shapes the staging bots ran over the month.

  python3 tools/make_penalty_cap_corpus.py [--per-chain 25] [--out penalty_cap_corpus.csv]

Then:  python3 -m cow_certify.penalty_cap_batch penalty_cap_corpus.csv --out certs_penalty_cap/

Why staging: as of 2026-09-07 only the staging autopilots publish
`penaltyCapNative`; prod bodies carry no cap yet. The same command works on
prod the day the field ships (`--env prod` in the batch rows).

Sampling: the oldest key still in the bucket (prefix listing, first key) and
the newest auction id (barn orderbook `/api/v1/auction`) bound the window; ids
are spaced evenly and each is snapped to the next EXISTING object with a
`start-after` listing, so chains whose staging auctions have sparse bodies
(Arbitrum, BNB) still yield real rows.
"""
import argparse
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET

BUCKET = "https://solver-instances.s3.eu-central-1.amazonaws.com"
NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
UA = {"user-agent": "curl/8"}
# cow-certify network -> (bucket chain segment, barn API segment)
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


def _keys(prefix, start_after=None, n=1):
    url = f"{BUCKET}/?list-type=2&prefix={prefix}&max-keys={n}"
    if start_after:
        url += f"&start-after={start_after}"
    root = ET.fromstring(_get(url))
    return [k.find("s3:Key", NS).text for k in root.findall("s3:Contents", NS)]


def _aid(key):
    """Auction id of an object key, or None for non-auction objects (the
    Arbitrum staging prefix holds a `test.json`)."""
    stem = key.rsplit("/", 1)[1].split(".")[0]
    return int(stem) if stem.isdigit() else None


def _first_auction_key(prefix, start_after=None):
    for key in _keys(prefix, start_after=start_after, n=5):
        if _aid(key) is not None:
            return key
    return None


def sample_chain(network, per_chain, window_from=None):
    seg, api = CHAINS[network]
    prefix = f"staging/{seg}/auction/"
    first = _first_auction_key(prefix)
    if not first:
        return [], "no staging objects"
    oldest = _aid(first)
    if window_from is not None:
        oldest = max(oldest, int(window_from))
    try:
        newest = json.loads(_get(f"https://barn.api.cow.fi/{api}/api/v1/auction"))["id"]
    except Exception as e:  # barn unreachable: fall back to a listing walk
        return [], f"barn auction id unavailable ({str(e)[:60]})"
    if newest <= oldest:
        return [], f"window empty ({oldest}..{newest})"
    step = max(1, (newest - oldest) // per_chain)
    ids, seen = [], set()
    for k in range(per_chain):
        target = oldest + k * step
        nxt = _first_auction_key(prefix, start_after=f"{prefix}{target}.json")
        if not nxt:
            continue
        aid = _aid(nxt)
        if aid not in seen:
            seen.add(aid)
            ids.append(aid)
    return sorted(ids), f"window {oldest}..{newest}, step {step}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-chain", type=int, default=25)
    ap.add_argument("--out", default="penalty_cap_corpus.csv")
    ap.add_argument("--chains", default=",".join(CHAINS))
    ap.add_argument("--from", dest="window_from", default="",
                    help="start the window at an auction id per chain, "
                         "'base=153500000,mainnet=16300000' (e.g. the id from which a "
                         "staging autopilot began publishing penaltyCapNative)")
    ap.add_argument("--append", action="store_true", help="append rows to --out instead of rewriting")
    args = ap.parse_args()
    window_from = {}
    for pair in filter(None, args.window_from.split(",")):
        net, aid = pair.split("=", 1)
        window_from[net.strip()] = int(aid)
    rows = [] if args.append else [
        "# network,env,auction_id — staging auction bodies sampled across the bucket's",
        "# retention window (tools/make_penalty_cap_corpus.py); regenerate any time."]
    for network in args.chains.split(","):
        network = network.strip()
        if network not in CHAINS:
            print(f"  skip {network}: unknown", file=sys.stderr)
            continue
        try:
            ids, note = sample_chain(network, args.per_chain, window_from.get(network))
        except Exception as e:
            print(f"  {network}: failed ({str(e)[:80]})", file=sys.stderr)
            continue
        print(f"  {network}: {len(ids)} auctions ({note})", file=sys.stderr)
        rows += [f"{network},staging,{aid}" for aid in ids]
    with open(args.out, "a" if args.append else "w", encoding="utf-8") as f:
        f.write("\n".join(rows) + "\n")
    print(f"wrote {args.out}: {sum(1 for r in rows if not r.startswith('#'))} rows"
          f"{' (appended)' if args.append else ''}", file=sys.stderr)


if __name__ == "__main__":
    main()
