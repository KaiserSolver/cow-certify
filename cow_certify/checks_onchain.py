"""On-chain checks that read contract state directly, independent of the
competition API.

C9 solver-authorization: confirm the address that called settle() is a
registered solver in the GPv2 authenticator (AllowListAuthentication). This
corroborates C2 (which trusts the API's recorded winner) against on-chain state
that the settlement contract itself enforces via its onlySolver modifier.
"""
from . import sources

# GPv2 AllowListAuthentication — same address on every CoW chain (verified
# deployed on mainnet/arbitrum/base/gnosis/polygon/avalanche/bnb/sepolia).
AUTHENTICATOR = "0x2c4c28ddbdac9c5e7055b4c863b72ea0149d8afe"
# isSolver(address) -> bool. Selector verified via `cast sig` and a live call
# (returns 1 for a known solver, 0 for a random address).
IS_SOLVER_SELECTOR = "0x02cc250d"

PASS = "PASS"
VIOLATION = "VIOLATION"
UNCERTAIN = "UNCERTAIN"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def _is_solver(rpc_url, addr, block_tag, ev):
    data = IS_SOLVER_SELECTOR + addr[2:].lower().rjust(64, "0")
    res = sources.rpc(rpc_url, "eth_call",
                      [{"to": AUTHENTICATOR, "data": data}, block_tag], ev)
    if not isinstance(res, str) or not res.startswith("0x") or len(res) < 3:
        # A node answering `null` (or garbage) is a failed query, not a reading.
        raise RuntimeError("no result from the authenticator query")
    return int(res, 16) == 1


def run_solver_auth_check(rpc_url, direct, to_addr, sender, landed_block,
                          ev, checks, limits, status_ok=True):
    """Append the C9 on-chain solver-authorization verdict. `direct` selects
    which address is the settle() caller: tx.from for a direct call, the wrapper
    (tx.to) for a solver-owned contract.

    Two guards keep this from accusing on a reconstruction artifact:
    * `status_ok` — a SUCCESSFUL settle() provably passed GPv2's onlySolver
      gate, so a negative reading on a succeeded tx can only be an artifact
      (de-registered since, or non-archive state) → UNCERTAIN. `status_ok=None`
      means the execution status itself is unknown (no receipt) → never accuse.
    * `pinned` — only a reading taken AT THE SETTLEMENT BLOCK describes the
      state the contract enforced. The `latest` fallback is an approximation
      whose own label says the solver set may have changed; it may corroborate
      (PASS) but may never accuse (VIOLATION)."""
    caller = sender if direct else to_addr
    if not caller:
        checks.append(_v("C9.solver-authorization", UNCERTAIN,
                         "no caller address on the transaction"))
        return

    # Query at the settlement block for a faithful answer; fall back to latest
    # if the RPC has pruned historical state (the registered-solver set changes
    # rarely, so latest is a labelled approximation, never a silent one).
    checked_at, ok, pinned = None, None, False
    if landed_block is not None:
        try:
            ok = _is_solver(rpc_url, caller, hex(landed_block), ev)
            checked_at = f"at block {landed_block}"
            pinned = True
        except Exception:
            ok = None
    if ok is None:
        try:
            ok = _is_solver(rpc_url, caller, "latest", ev)
            checked_at = ("at latest (historical state unavailable on this "
                          "RPC; the solver set may have changed since)")
        except Exception as e:
            checks.append(_v("C9.solver-authorization", UNCERTAIN,
                             f"authenticator query failed: {sources.redact(e)[:120]}"))
            return

    if direct:
        if ok:
            checks.append(_v("C9.solver-authorization", PASS,
                             f"settle() caller {caller} is a registered solver "
                             f"in the GPv2 authenticator ({checked_at})",
                             caller=caller, authorized=True))
        elif status_ok:
            # Succeeded tx ⇒ it passed onlySolver ⇒ this must be an artifact.
            checks.append(_v("C9.solver-authorization", UNCERTAIN,
                             f"settle() caller {caller} does not read as a "
                             f"registered solver ({checked_at}), yet the tx "
                             f"succeeded — which requires authorization on-chain. "
                             f"Treating as a reconstruction artifact (likely a "
                             f"non-archive RPC or a since-changed solver set), "
                             f"not a finding",
                             caller=caller, authorized=False))
        elif status_ok is False and pinned:
            checks.append(_v("C9.solver-authorization", VIOLATION,
                             f"settle() caller {caller} is NOT a registered "
                             f"solver on-chain ({checked_at})",
                             caller=caller, authorized=False))
        else:
            why = ("the execution status is unknown (no receipt)" if status_ok is None
                   else "the reading is from latest state, not the settlement block")
            checks.append(_v("C9.solver-authorization", UNCERTAIN,
                             f"settle() caller {caller} does not read as a "
                             f"registered solver ({checked_at}), but {why}; "
                             f"a registration that changed since cannot be told "
                             f"apart from an unauthorized call — flagged for "
                             f"review, not as a finding",
                             caller=caller, authorized=False))
    else:
        if ok:
            checks.append(_v("C9.solver-authorization", PASS,
                             f"the settlement's wrapper contract {caller} is "
                             f"itself a registered solver ({checked_at})",
                             caller=caller, authorized=True))
        else:
            # The authorized caller may be deeper in the call chain than tx.to;
            # confirming it would need an internal-call trace, so this is not an
            # accusation.
            checks.append(_v("C9.solver-authorization", UNCERTAIN,
                             f"wrapper target {caller} is not itself a "
                             f"registered solver ({checked_at}); the authorized "
                             f"caller of settle() may be deeper in the call "
                             f"chain, which is not determinable from the "
                             f"transaction alone",
                             caller=caller, authorized=False))
