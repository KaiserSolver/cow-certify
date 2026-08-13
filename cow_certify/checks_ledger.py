"""C10 order ledger — the detailed, per-order factual record of what a
settlement actually did on-chain: for every trade, the owner, kind, both tokens
(with symbol/decimals), executed and signed amounts, fee, executed vs limit
price, fill fraction, and before-fee surplus.

This is descriptive detail (INFO), not a verdict: it is the evidence the C3/C4/C5
verdicts are computed from, laid out in full so a reader can see exactly what was
verified. It never changes the overall verdict.
"""
import time

from . import gpv2 as scorer
from .checks_decode import trade_events_with_fee
from .tokens import token_meta

INFO = "INFO"


def _human(atoms, dec):
    if dec is None:
        return None
    try:
        return f"{int(atoms) / 10 ** dec:.8g}"
    except Exception:
        return None


def _price(num_atoms, num_dec, den_atoms, den_dec):
    """Human buy-per-sell price, decimals-adjusted. None if not computable."""
    if None in (num_dec, den_dec) or not den_atoms:
        return None
    try:
        return f"{(num_atoms / 10 ** num_dec) / (den_atoms / 10 ** den_dec):.8g}"
    except Exception:
        return None


def run_order_ledger(network, direct, calldata, logs, this_sol, comp, rpc_url,
                     ev, checks):
    events = trade_events_with_fee(logs)
    if not events:
        return
    decoded = None
    if direct:
        try:
            decoded = scorer.decode_settlement(calldata)
        except Exception:
            decoded = None
    cache = {}
    ledger = []
    for i, e in enumerate(events):
        st = token_meta(rpc_url, e["sell_token"], ev, cache)
        bt = token_meta(rpc_url, e["buy_token"], ev, cache)
        sdec, bdec = st["decimals"], bt["decimals"]
        entry = {
            "uid": e["uid"],
            "owner": e["owner"],
            "sell_token": st,
            "buy_token": bt,
            "executed_sell": str(e["sell_amount"]),
            "executed_buy": str(e["buy_amount"]),
            "executed_sell_human": _human(e["sell_amount"], sdec),
            "executed_buy_human": _human(e["buy_amount"], bdec),
            "fee_atoms": str(e.get("fee_amount", 0)),
            "executed_price": _price(e["buy_amount"], bdec,
                                     e["sell_amount"], sdec),
        }
        tr = (decoded["trades"][i]
              if decoded and i < len(decoded["trades"]) else None)
        if tr is not None:
            flags = int(tr[8])
            kind = "buy" if flags & scorer.FLAG_KIND_BUY else "sell"
            pf = bool(flags & scorer.FLAG_PARTIALLY_FILLABLE)
            signed_sell, signed_buy = int(tr[3]), int(tr[4])
            valid_to = int(tr[5])
            app_data = tr[6]
            if isinstance(app_data, (bytes, bytearray)):
                app_data = "0x" + app_data.hex()
            entry.update({
                "kind": kind,
                "partially_fillable": pf,
                "signed_sell": str(signed_sell),
                "signed_buy": str(signed_buy),
                "valid_to": valid_to,
                "valid_to_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime(valid_to)),
                "app_data": app_data,
                "limit_price": _price(signed_buy, bdec, signed_sell, sdec),
            })
            base = signed_sell if kind == "sell" else signed_buy
            got = e["sell_amount"] if kind == "sell" else e["buy_amount"]
            entry["fill_fraction"] = f"{got / base:.6g}" if base else None
            # Before-fee surplus from the EXECUTED amounts vs the signed limit
            # (un-forgeable; the earlier clearing-price form read a
            # solver-chosen slot — see gpv2.surplus_from_execution).
            exec_sell_net = e["sell_amount"] - e.get("fee_amount", 0)
            surplus = scorer.surplus_from_execution(
                kind, exec_sell_net, e["buy_amount"], signed_sell, signed_buy)
            entry["surplus_atoms"] = str(surplus)
            entry["surplus_token"] = (bt if kind == "sell" else st)["symbol"]
        ledger.append(entry)

    def _sym(t):
        return t["symbol"] or (t["address"][:10] + "..")

    def _fmt(en):
        k = en.get("kind") or "trade"
        ss = en.get("executed_sell_human") or en["executed_sell"]
        bb = en.get("executed_buy_human") or en["executed_buy"]
        return f"{k} {ss} {_sym(en['sell_token'])} → {bb} {_sym(en['buy_token'])}"

    detail = "; ".join(_fmt(en) for en in ledger[:4])
    if len(ledger) > 4:
        detail += f" (+{len(ledger) - 4} more)"
    checks.append({"check": "C10.order-ledger", "verdict": INFO,
                   "detail": f"{len(ledger)} settled order(s): {detail}",
                   "orders": ledger})
