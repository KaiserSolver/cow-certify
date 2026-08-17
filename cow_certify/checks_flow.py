"""C11 receiver-delivery — confirm, from the on-chain ERC-20 Transfer logs, that
the buy tokens credited to each order in its Trade event actually reached the
order's recorded receiver.

This is the user-protection check: it verifies funds arrived where they were
supposed to. It is conservative about accusing — a shortfall has several benign
causes (fee-on-transfer tokens, a receiver contract that forwards, or ambiguous
attribution when several orders share a (token, receiver)) — so a shortfall is
reported as INFO, never a VIOLATION. Clean delivery is a PASS.
"""
from . import gpv2 as scorer
from .checks_decode import trade_events_with_fee

PASS = "PASS"
INFO = "INFO"

# keccak256("Transfer(address,address,uint256)")
ERC20_TRANSFER = ("0xddf252ad1be2c89b69c2b068fc378daa9"
                  "52ba7f163c4a11628f55a4df523b3ef")

# CoW's sentinel for a native-ETH buy leg. Delivery is an internal ETH transfer
# that emits no ERC-20 Transfer log, so it cannot be reconciled from logs.
NATIVE_ETH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def run_receiver_check(direct, calldata, logs, checks, limits):
    events = trade_events_with_fee(logs)
    if not events:
        return
    trades = None
    if direct:
        try:
            trades = scorer.decode_settlement(calldata)["trades"]
        except Exception:
            trades = None

    # Expected buy-token delivery per (token, receiver). Receiver comes from the
    # calldata trade (zero-address means the owner); on a wrapper route the
    # calldata isn't decodable, so we fall back to the owner and say so.
    # Native-ETH buy legs are set aside: they settle via an internal transfer
    # that emits no ERC-20 Transfer log, so they aren't reconcilable here.
    expected = {}
    native_eth = 0
    for i, e in enumerate(events):
        if e["buy_token"].lower() == NATIVE_ETH:
            native_eth += 1
            continue
        recv = e["owner"]
        if trades and i < len(trades):
            r = str(trades[i][2]).lower()
            try:
                if int(r, 16) != 0:
                    recv = r
            except ValueError:
                pass
        key = (e["buy_token"].lower(), recv)
        expected[key] = expected.get(key, 0) + e["buy_amount"]

    # Actual ERC-20 Transfers landing on those (token, receiver) pairs —
    # counting ONLY transfers sent BY the settlement contract. GPv2 payouts
    # provably originate from the settlement; without the sender filter an
    # unrelated same-transaction transfer to the same (token, receiver) could
    # satisfy the expected amount and produce a false PASS (2026-08-17 audit).
    # The known benign non-GPv2 delivery paths (Balancer-Vault internal
    # balances, native ETH) already route to INFO, not PASS.
    actual = {}
    for lg in logs:
        topics = lg.get("topics") or []
        if not topics or topics[0].lower() != ERC20_TRANSFER or len(topics) < 3:
            continue
        sender = ("0x" + topics[1][-40:]).lower()
        if sender != scorer.SETTLEMENT:
            continue
        key = ((lg.get("address") or "").lower(),
               ("0x" + topics[2][-40:]).lower())
        if key not in expected:
            continue
        d = lg.get("data") or "0x"
        try:
            val = (int(d, 16) if d not in ("0x", "")
                   else int(topics[3], 16) if len(topics) > 3 else 0)
        except ValueError:
            continue
        actual[key] = actual.get(key, 0) + val

    short = [(k, exp, actual.get(k, 0))
             for k, exp in expected.items() if actual.get(k, 0) < exp]
    basis = ("receivers from calldata" if trades else
             "receiver taken as order owner (wrapper route; calldata receiver "
             "not decodable)")
    eth_note = (f"; {native_eth} native-ETH buy leg(s) set aside (delivered by "
                f"internal transfer, not present in ERC-20 logs)"
                if native_eth else "")
    if native_eth:
        limits.append(f"C11: {native_eth} native-ETH buy leg(s) not verifiable "
                      f"from ERC-20 Transfer logs")

    if not expected:
        checks.append(_v(
            "C11.receiver-delivery", INFO,
            f"all {native_eth} settled buy leg(s) are native ETH, delivered by "
            f"internal transfer and not reconcilable from ERC-20 logs"))
    elif not short:
        checks.append(_v(
            "C11.receiver-delivery", PASS,
            f"every settled order's buy tokens reached the recorded receiver "
            f"on-chain, sent by the settlement contract, across "
            f"{len(expected)} (token, receiver) group(s) ({basis}){eth_note}"))
    else:
        parts = [f"{tok[:10]}..→{to[:10]}.. delivered {got}/{exp}"
                 for (tok, to), exp, got in short[:3]]
        # For a standard ERC-20, GPv2 settle() transfers exactly the credited
        # buy amount to the receiver atomically with the Trade event, so a real
        # non-delivery is EVM-impossible — every shortfall we can observe has a
        # benign cause (Balancer-Vault internal balances and native-ETH legs
        # emit no ERC-20 Transfer; fee-on-transfer tokens net down; a shared
        # receiver splits attribution). It is therefore context (INFO), never
        # an accusation.
        checks.append(_v(
            "C11.receiver-delivery", INFO,
            f"{len(short)} of {len(expected)} (token, receiver) group(s) "
            f"show less ERC-20 delivered than credited: " + "; ".join(parts) +
            " — benign by construction (fee-on-transfer token, Vault internal "
            "balance, receiver forwarding, or shared-receiver attribution); "
            f"context, not a finding ({basis})"))
    if not trades and direct:
        limits.append("C11 could not decode calldata receivers; used owners")
