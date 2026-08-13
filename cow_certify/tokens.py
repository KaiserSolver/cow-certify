"""Best-effort ERC-20 metadata (symbol, decimals) via eth_call, for making the
detailed order ledger human-readable. Every field is optional: a token that
doesn't implement the call, or returns junk, degrades to raw atoms + address —
metadata is never allowed to fail a certificate.
"""
from . import sources

DECIMALS_SEL = "0x313ce567"  # decimals()
SYMBOL_SEL = "0x95d89b41"    # symbol()


def _call(rpc_url, to, data, ev):
    return sources.rpc(rpc_url, "eth_call",
                       [{"to": to, "data": data}, "latest"], ev)


def _decode_symbol(res):
    """Handle both ABI-encoded string returns and the legacy bytes32 form
    (e.g. MKR). Returns None if nothing sensible decodes."""
    if not res or res == "0x":
        return None
    h = res[2:]
    try:
        # ABI dynamic string: [offset][length][data...]
        if len(h) >= 192:
            length = int(h[64:128], 16)
            if 0 < length <= 64:
                s = bytes.fromhex(h[128:128 + length * 2]).decode(
                    "utf-8", "ignore").strip("\x00").strip()
                if s.isprintable() and s:
                    return s
        # legacy bytes32
        s = bytes.fromhex(h[:64]).rstrip(b"\x00").decode(
            "utf-8", "ignore").strip()
        return s if (s and s.isprintable()) else None
    except Exception:
        return None


def token_meta(rpc_url, token, ev, cache):
    """{address, symbol, decimals}; symbol/decimals may be None. Cached per run."""
    token = (token or "").lower()
    if token in cache:
        return cache[token]
    meta = {"address": token, "symbol": None, "decimals": None}
    try:
        d = _call(rpc_url, token, DECIMALS_SEL, ev)
        if d and d != "0x":
            dec = int(d, 16)
            if 0 <= dec <= 36:  # sanity: real tokens live in this range
                meta["decimals"] = dec
    except Exception:
        pass
    try:
        meta["symbol"] = _decode_symbol(_call(rpc_url, token, SYMBOL_SEL, ev))
    except Exception:
        pass
    cache[token] = meta
    return meta
