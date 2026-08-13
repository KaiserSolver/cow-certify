"""C14 price-vs-mid — the first rung of a best-execution signal.

Compares what the user actually got to the auction's own reference (oracle)
prices: for each settled order, native value received vs native value given up,
in basis points. Positive means the user did better than the fair mid; a small
negative is normal, because the reference mid is not itself tradable and the
figure includes fees + spread.

It is INFORMATION, never a verdict, and it is NOT full EBBO (best executable
on-chain price). Full EBBO needs baseline pool simulation and stays out of
scope; this rung uses only data already in the competition record.
"""
from .checks_decode import trade_events_with_fee

INFO = "INFO"
UNCERTAIN = "UNCERTAIN"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def price_vs_mid_bps(sell_amount, buy_amount, px_sell, px_buy):
    """Return (bps, native_in, native_out) or None if not computable.
    Value the user gave up vs received, in the auction's native reference terms."""
    native_in = sell_amount * px_sell // 10 ** 18
    native_out = buy_amount * px_buy // 10 ** 18
    if native_in <= 0:
        return None
    return (native_out - native_in) * 10000 / native_in, native_in, native_out


def run_price_vs_mid(comp, logs, checks):
    events = trade_events_with_fee(logs)
    if not events:
        return
    prices = (comp.get("auction") or {}).get("prices") or {}
    native = {k.lower(): int(v) for k, v in prices.items()}
    rows = []
    for e in events:
        st, bt = e["sell_token"], e["buy_token"]
        if st not in native or bt not in native:
            continue
        r = price_vs_mid_bps(e["sell_amount"], e["buy_amount"], native[st], native[bt])
        if r is not None:
            rows.append((e["uid"], r[0]))
    if not rows:
        checks.append(_v("C14.price-vs-mid", UNCERTAIN,
                         "the auction record has no reference price for the "
                         "traded tokens; execution-vs-mid not computable"))
        return
    parts = [f"{b:+.1f} bps" for _, b in rows[:4]]
    detail = ("execution vs the auction's reference mid: " + ", ".join(parts)
              + (f" (+{len(rows) - 4} more)" if len(rows) > 4 else "")
              + " — positive is better than the fair mid; a small negative is "
              "normal (fees + spread; the mid is not itself tradable). "
              "Informational: a reference-price comparison, NOT full EBBO.")
    checks.append(_v("C14.price-vs-mid", INFO, detail,
                     per_order=[{"uid": u, "bps": round(b, 2)} for u, b in rows]))
