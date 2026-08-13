"""C12 order-authenticity — confirm each settled order matches a real signed
order in the public orderbook.

The settlement calldata carries the signed order and its signature; the public
orderbook is CoW's independent record of that same signed order. C12 fetches the
order by uid and checks that the on-chain-settled parameters (tokens, signed
amounts, kind, validity, appData) match what was signed. It closes the gap where
C3 only checks the settled set against the *winning solution* — C12 checks it
against the *signed order* itself, from a different source.

Orders that aren't in the public book (JIT / on-chain orders) are reported as
INFO, not as a problem. A genuine field mismatch is reported as UNCERTAIN
(investigation, not accusation): a divergence between the chain and the public
record has more than one possible cause, and v0.3 does not accuse on it.
"""
from . import gpv2 as scorer
from . import sources
from .checks_decode import trade_events_with_fee

PASS = "PASS"
INFO = "INFO"
UNCERTAIN = "UNCERTAIN"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def run_authenticity_check(network, direct, calldata, logs, ev, checks, limits):
    events = trade_events_with_fee(logs)
    if not events:
        return
    trades = None
    if direct:
        try:
            trades = scorer.decode_settlement(calldata)["trades"]
        except Exception:
            trades = None

    matched = 0
    not_found = []
    mismatches = []
    for i, e in enumerate(events):
        uid = e["uid"]
        meta = sources.order_meta(network, uid, ev)
        if not meta:
            not_found.append(uid)
            continue
        problems = []
        if (meta.get("sellToken") or "").lower() != e["sell_token"]:
            problems.append("sellToken")
        if (meta.get("buyToken") or "").lower() != e["buy_token"]:
            problems.append("buyToken")
        if trades and i < len(trades):
            tr = trades[i]
            try:
                if int(meta["sellAmount"]) != int(tr[3]):
                    problems.append("sellAmount")
                if int(meta["buyAmount"]) != int(tr[4]):
                    problems.append("buyAmount")
            except (KeyError, TypeError, ValueError):
                pass
            kind_cd = "buy" if int(tr[8]) & scorer.FLAG_KIND_BUY else "sell"
            if meta.get("kind") and meta["kind"] != kind_cd:
                problems.append("kind")
            try:
                if meta.get("validTo") is not None and \
                        int(meta["validTo"]) != int(tr[5]):
                    problems.append("validTo")
            except (TypeError, ValueError):
                pass
            ad = tr[6]
            if isinstance(ad, (bytes, bytearray)):
                ad = "0x" + ad.hex()
            if meta.get("appData") and str(ad).lower() != meta["appData"].lower():
                problems.append("appData")
        if problems:
            mismatches.append((uid, problems))
        else:
            matched += 1

    total = len(events)
    if mismatches:
        parts = [f"{u[:14]}..: {'/'.join(p)}" for u, p in mismatches[:3]]
        checks.append(_v(
            "C12.order-authenticity", UNCERTAIN,
            f"{len(mismatches)} of {total} settled order(s) differ from the "
            f"public orderbook record: " + "; ".join(parts) +
            " — a chain-vs-record divergence with more than one possible cause; "
            "investigation, not a finding",
            mismatches=[{"uid": u, "fields": p} for u, p in mismatches]))
    elif matched and not not_found:
        basis = ("tokens, signed amounts, kind, validTo, appData" if trades
                 else "tokens (wrapper route; signed amounts not in calldata)")
        checks.append(_v(
            "C12.order-authenticity", PASS,
            f"all {matched} settled order(s) match a signed order in the public "
            f"orderbook ({basis})"))
    elif matched:
        checks.append(_v(
            "C12.order-authenticity", INFO,
            f"{matched} settled order(s) match the public orderbook; "
            f"{len(not_found)} not found (JIT / on-chain order, not placed via "
            f"the public book)"))
    else:
        checks.append(_v(
            "C12.order-authenticity", INFO,
            f"none of the {total} settled order(s) are in the public orderbook "
            f"(JIT / on-chain orders); authenticity not checkable against the "
            f"book"))
