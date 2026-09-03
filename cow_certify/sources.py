"""Public data sources for cow-certify. No keys, no private data, ever.

Every fetch is recorded (URL, sha256 of raw bytes, timestamp) so a certificate
can cite exactly what it saw and anyone can re-fetch and compare.
"""
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

UA = {"user-agent": "curl/8"}  # several public RPCs 403 unfamiliar agents


def _safe_url(url):
    """scheme://host[:port] only — path, query AND userinfo are dropped, so no
    provider credential ever lands in the shareable certificate. Keys ride in
    many shapes: query (?apikey=), a deep path (…/v2/<key>), a SINGLE path
    segment (QuickNode …/quiknode.pro/<token>/, Chainstack …/p2pify.com/<key>)
    or HTTP basic auth (https://user:pw@host) — so keeping any of them can leak.
    Ledger provenance note: entries record the sha256 of the RESPONSE bytes
    plus this safe origin — the exact request is NOT pinned."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
        return f"{p.scheme}://{host}{port}"
    except Exception:
        return "(url redacted)"


_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")


def redact(text):
    """Replace every URL inside free text with its safe origin. Every string
    that can land in a certificate (check details, error messages) goes through
    this, so a user's keyed --rpc-url cannot leak through an error path."""
    return _URL_RE.sub(lambda m: _safe_url(m.group(0)), str(text))


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
# rotating is a feature, not a bug. Every endpoint below answered eth_chainId
# with the expected id on 2026-09-03 (llamarpc.com and polygon-rpc.com had
# died since the previous check and were dropped).
DEFAULT_RPC = {
    "mainnet": ["https://ethereum-rpc.publicnode.com",
                "https://eth.rpc.blxrbdn.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc",
                 "https://arbitrum-one-rpc.publicnode.com"],
    "base": ["https://base.rpc.blxrbdn.com",
             "https://base-rpc.publicnode.com",
             "https://mainnet.base.org"],
    "gnosis": ["https://rpc.gnosischain.com",
               "https://gnosis-rpc.publicnode.com"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com",
                "https://polygon.drpc.org"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com",
                  "https://api.avax.network/ext/bc/C/rpc",
                  "https://avalanche.drpc.org"],
    "bnb": ["https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.bnbchain.org",
            "https://bsc.drpc.org"],
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
    failures (429 rate-limit, 5xx, timeouts, and a 200 whose body is not JSON —
    a rate-limit interstitial served with a 200). api.cow.fi is a single host
    with no fallback, so a lone 429 must not abort an otherwise-complete
    certificate — it is exactly what rate-limits the self-audit corpus run."""
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=UA)
        try:
            raw = urllib.request.urlopen(req, timeout=timeout).read()
            data = json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                evidence.record(kind, url, b"404")
                return None
            last_err = e
            if e.code not in (429, 500, 502, 503, 504):
                raise
        except Exception as e:  # timeouts, connection errors, non-JSON bodies
            last_err = e
        else:
            evidence.record(kind, url, raw)
            return data
        if attempt < retries - 1:
            time.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s
    raise RuntimeError(f"{kind}: {url} failed after {retries} attempts: {redact(last_err)}")


def rpc(rpc_urls, method, params, evidence: Evidence, timeout=25, rounds=None):
    """JSON-RPC with fallback rotation across a list of endpoints, plus bounded
    retry rounds so a single --rpc-url (no rotation possible) still survives one
    transient 429/timeout. A node-side JSON-RPC *error* object is deterministic
    (bad params, archive state refused) and rotates to the next endpoint but
    never triggers another round. URLs are redacted in every error message —
    an error string can end up in a shareable certificate."""
    if isinstance(rpc_urls, str):
        rpc_urls = [rpc_urls]
    if rounds is None:
        rounds = 3 if len(rpc_urls) == 1 else 2
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    last_err = None
    for rnd in range(rounds):
        transient = False
        for url in rpc_urls:
            req = urllib.request.Request(url, data=body,
                                         headers={**UA, "content-type": "application/json"})
            try:
                raw = urllib.request.urlopen(req, timeout=timeout).read()
                out = json.loads(raw)
            except Exception as e:  # 403/429/timeouts/non-JSON body: rotate
                last_err = e
                transient = True
                continue
            if not isinstance(out, dict):
                last_err = RuntimeError(f"{_safe_url(url)}: non-object JSON-RPC response")
                transient = True
                continue
            if "error" in out:
                last_err = RuntimeError(f"{_safe_url(url)}: {out['error']}")
                continue
            evidence.record("rpc:" + method,
                            f"{_safe_url(url)} {json.dumps(params)[:100]}", raw)
            return out.get("result")
        if not transient or rnd == rounds - 1:
            break
        time.sleep(0.3 * (rnd + 1))
    raise RuntimeError(f"all RPC endpoints failed for {method}: {redact(last_err)}")


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
