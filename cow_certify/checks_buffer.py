"""C15 settlement-buffer accounting — the net ERC-20 delta of the GPv2
settlement contract across this settlement.

GPv2 accumulates fees and leftover tokens as a "buffer"; the contract's own
NatSpec warns that solvers "will be slashed for abusing accumulated fees for
settlement." A clean settlement is close to a pass-through (sellers in, buyers
out), so the contract's net balance change per token is ~0 or slightly positive
(fee accrual). A materially NEGATIVE net delta means the settlement paid out
more of a token than it took in — it drew from the protocol buffer. That is
sometimes legitimate (solvers may use buffered tokens), so this is reported as
factual CONTEXT (INFO), never an accusation.

ERC-20 only: native-ETH moves and Balancer-Vault internal balances emit no
Transfer log, so the accounting is best-effort and stated as such.
"""
from . import gpv2 as scorer
from .checks_flow import ERC20_TRANSFER

INFO = "INFO"


def run_buffer_check(logs, checks):
    settlement = scorer.SETTLEMENT
    transfer_topic = ERC20_TRANSFER
    deltas = {}          # token -> net atoms (in - out) for the settlement
    seen = False
    for lg in logs or []:
        topics = lg.get("topics") or []
        if len(topics) < 3 or topics[0].lower() != transfer_topic:
            continue
        frm = ("0x" + topics[1][-40:]).lower()
        to = ("0x" + topics[2][-40:]).lower()
        if settlement not in (frm, to):
            continue
        try:
            amount = int((lg.get("data") or "0x0"), 16)
        except ValueError:
            continue
        token = (lg.get("address") or "").lower()
        if to == settlement:
            deltas[token] = deltas.get(token, 0) + amount
        if frm == settlement:
            deltas[token] = deltas.get(token, 0) - amount
        seen = True

    if not seen:
        return
    drawn = {t: d for t, d in deltas.items() if d < 0}
    if drawn:
        parts = [f"{t[:10]}.. {d}" for t, d in
                 sorted(drawn.items(), key=lambda kv: kv[1])[:3]]
        detail = (f"the settlement contract's ERC-20 buffer net-DECREASED for "
                  f"{len(drawn)} token(s) (drew from the protocol buffer): "
                  + "; ".join(parts) + ". This is sometimes legitimate (solvers "
                  "may use buffered tokens); reported as context, not a finding. "
                  "ERC-20 only — native-ETH / Vault-internal moves are not "
                  "captured here.")
    else:
        detail = (f"the settlement contract took in at least as much as it paid "
                  f"out for all {len(deltas)} ERC-20 token(s) touched (no buffer "
                  f"draw detected). ERC-20 only — native-ETH / Vault-internal "
                  f"moves are not captured here.")
    checks.append({"check": "C15.settlement-buffer", "verdict": INFO,
                   "detail": detail,
                   "net_deltas": {t: str(d) for t, d in deltas.items()}})
