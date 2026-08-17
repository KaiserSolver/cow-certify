"""Public data sources for cow-certify. No keys, no private data, ever.

Every fetch is recorded (URL, sha256 of raw bytes, timestamp) so a certificate
can cite exactly what it saw and anyone can re-fetch and compare.
"""
import hashlib
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

UA = {"user-agent": "curl/8"}  # several public RPCs 403 unfamiliar agents


def _safe_url(url):
    """scheme://host only — the entire path and query are dropped, so no
    provider API key ever lands in the shareable certificate's evidence
    ledger. Keys ride in many shapes: query (?apikey=), a deep path
    (…/v2/<key>), or a SINGLE path segment (QuickNode …/quiknode.pro/<token>/,
    Chainstack …/p2pify.com/<key>) — so keeping any path segment can leak.
    Ledger provenance note: entries record the sha256 of the RESPONSE bytes
    plus this safe origin — the exact request is NOT pinned (a canonical
    request digest is future work; the old comment here claimed otherwise)."""
    try:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return "(url redacted)"

# CoW orderbook/competition API network path segments (verified live against
# api.cow.fi/<seg>/api/v1/version). The exact segment strings matter —
# Avalanche is "avalanche" (not "avalanche_c") and BNB is "bnb" (not "bsc").
NETWORKS = {
    "mainnet": "mainnet",
    "arbitrum": "arbitrum_one",
    "base": "base",
    "gnosis": "xdai",
    "polygon": "polygon",
    "avalanche": "avalanche",
    "bnb": "bnb",
    "ink": "ink",
    "linea": "linea",
    "plasma": "plasma",
    "sepolia": "sepolia",
}

# EVM chain id per network, for the certificate subject (a settlement is on a
# chain, not just a name). Verified via eth_chainId against each RPC below.
CHAIN_IDS = {
    "mainnet": 1,
    "arbitrum": 42161,
    "base": 8453,
    "gnosis": 100,
    "polygon": 137,
    "avalanche": 43114,
    "bnb": 56,
    "ink": 57073,
    "linea": 59144,
    "plasma": 9745,
    "sepolia": 11155111,
}

# Zero-config public RPCs with fallback rotation (override with --rpc-url
# for reliability/archive access). Public endpoints rate-limit unpredictably;
# rotating is a feature, not a bug. Primaries below are eth_chainId-verified and
# confirmed to serve the canonical GPv2 contract at 0x9008…ab41.
DEFAULT_RPC = {
    "mainnet": ["https://ethereum-rpc.publicnode.com",
                "https://eth.rpc.blxrbdn.com",
                "https://eth.llamarpc.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc",
                 "https://arbitrum-one-rpc.publicnode.com"],
    "base": ["https://base.rpc.blxrbdn.com",
             "https://base-rpc.publicnode.com",
             "https://mainnet.base.org"],
    "gnosis": ["https://rpc.gnosischain.com",
               "https://gnosis-rpc.publicnode.com"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com",
                "https://polygon.drpc.org",
                "https://polygon-rpc.com"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com",
                  "https://api.avax.network/ext/bc/C/rpc",
                  "https://avalanche.drpc.org"],
    "bnb": ["https://bsc-rpc.publicnode.com",
            "https://bsc.drpc.org",
            "https://binance.llamarpc.com"],
    "ink": ["https://rpc-gel.inkonchain.com",
            "https://ink.drpc.org"],
    "linea": ["https://rpc.linea.build",
              "https://linea-rpc.publicnode.com",
              "https://1rpc.io/linea"],
    "plasma": ["https://rpc.plasma.to",
               "https://plasma.drpc.org"],
    "sepolia": ["https://ethereum-sepolia-rpc.publicnode.com",
                "https://sepolia.drpc.org"],
}

GPV2 = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"  # same address on all chains
SETTLE_SELECTOR = "0x13d79a0b"
AUCTION_ID_SUFFIX_BYTES = 8  # autopilot appends the auction id to settle() calldata


class Evidence:
    """Ledger of every external fetch backing a certificate."""

    def __init__(self):
        self.items = []
        self.order_cache = {}   # (network, uid) -> order meta, per run

    def record(self, kind, ref, raw: bytes):
        self.items.append({
            "kind": kind,
            "ref": ref,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })


def _get(url, evidence: Evidence, kind, timeout=25, retries=3):
    """GET + JSON with a 404 shortcut and bounded retry/backoff on transient
    failures (429 rate-limit, 5xx, timeouts). api.cow.fi is a single host with
    no fallback, so a lone 429 must not abort an otherwise-complete
    certificate — it is exactly what rate-limits the self-audit corpus run."""
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=UA)
        try:
            raw = urllib.request.urlopen(req, timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                evidence.record(kind, url, b"404")
                return None
            last_err = e
            if e.code not in (429, 500, 502, 503, 504):
                raise
        except Exception as e:
            last_err = e
        else:
            evidence.record(kind, url, raw)
            return json.loads(raw)
        time.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s, 2s
    raise RuntimeError(f"{kind}: {url} failed after {retries} attempts: {last_err}")


def rpc(rpc_urls, method, params, evidence: Evidence, timeout=25):
    """JSON-RPC with fallback rotation across a list of endpoints."""
    if isinstance(rpc_urls, str):
        rpc_urls = [rpc_urls]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    last_err = None
    for url in rpc_urls:
        req = urllib.request.Request(url, data=body,
                                     headers={**UA, "content-type": "application/json"})
        try:
            raw = urllib.request.urlopen(req, timeout=timeout).read()
        except Exception as e:  # 403/429/timeouts: rotate to the next endpoint
            last_err = e
            time.sleep(0.3)
            continue
        out = json.loads(raw)
        if "error" in out:
            last_err = RuntimeError(f"{url}: {out['error']}")
            continue
        evidence.record("rpc:" + method,
                        f"{_safe_url(url)} {json.dumps(params)[:100]}", raw)
        return out["result"]
    raise RuntimeError(f"all RPC endpoints failed for {method}: {last_err}")


def competition_by_tx(network, tx_hash, evidence):
    net = NETWORKS[network]
    return _get(f"https://api.cow.fi/{net}/api/v2/solver_competition/by_tx_hash/{tx_hash}",
                evidence, "competition:by_tx_hash")


def competition_by_auction(network, auction_id, evidence):
    net = NETWORKS[network]
    return _get(f"https://api.cow.fi/{net}/api/v2/solver_competition/{auction_id}",
                evidence, "competition:by_auction")


def trades_by_order(network, order_uid, evidence):
    net = NETWORKS[network]
    return _get(f"https://api.cow.fi/{net}/api/v1/trades?orderUid={order_uid}",
                evidence, "orderbook:trades")


def order_meta(network, order_uid, evidence):
    # Memoized per run: C4 and C12 (and C5 on wrapper routes) each look up the
    # same order, so an un-cached fetch triples the orderbook load on a
    # multi-order batch.
    key = (network, order_uid)
    if key in evidence.order_cache:
        return evidence.order_cache[key]
    net = NETWORKS[network]
    meta = _get(f"https://api.cow.fi/{net}/api/v1/orders/{order_uid}",
                evidence, "orderbook:order")
    evidence.order_cache[key] = meta
    return meta
