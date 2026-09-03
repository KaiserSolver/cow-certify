"""C13 interactions — list the external calls a settlement made.

GPv2 settle() carries three ordered stages of interactions (pre / intra / post),
each an (target, value, callData) tuple. C13 decodes and lists them: the target
contract, any native-ETH value sent, and the function selector called. This is
descriptive detail (INFO).

services#2667 criterion 4 is that the settlement's pre/post interactions are a
subset of the matched orders' hooks (the pre/post interactions users attach to
their orders via appData). That relation is NOT a clean top-level subset in
practice: the driver wraps each order's hooks inside a call to the
HooksTrampoline contract, and it legitimately ADDS its own pre-interactions
(e.g. a DeadlineCheck) and may OMIT an order's hook when it's redundant. So a
naive (target, callData) subset check would match nothing and false-flag every
hook-bearing settlement. C13 therefore classifies the pre/post interactions it
can recognise — hook-execution calls via the trampoline, and known driver infra
— and lists the rest. Confirming each trampoline-wrapped hook against the
matched orders' declared appData hooks (positive hook verification), and the
full executed-⊆-proposed relation, are roadmap items; the latter needs the
/solve instance from the S3 bucket, not the public API.
"""
from . import gpv2 as scorer
from . import sources

INFO = "INFO"
UNCERTAIN = "UNCERTAIN"

STAGES = ("pre", "intra", "post")

# The driver wraps every order's pre/post hooks in a call to this contract
# (execute((address,bytes,uint256)[]), selector 0x760f2a0b) — same address on
# every chain. A pre/post interaction to this target is hook execution, not a
# solver-injected raw call.
HOOKS_TRAMPOLINE = "0x60bf78233f48ec42ee3f101b9a05ec7878728006"
# Driver-added infra pre-interaction (not an order hook): reverts if the
# auction deadline has passed. Recognised so it is not mistaken for an
# injected interaction.
DEADLINE_CHECK = "0x0e91b5b157e98c20b90332cc3b9cf4ae67b222ad"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def run_interactions_check(direct, calldata, checks, limits):
    if not direct:
        checks.append(_v("C13.interactions", INFO,
                         "wrapper route: settle() interactions are not at the "
                         "top level of the calldata and are not listed here"))
        return
    try:
        inter = scorer.decode_settlement(calldata)["interactions"]
    except Exception as e:
        # Context only: a listing that could not be produced is not a finding.
        checks.append(_v("C13.interactions", INFO,
                         f"could not decode interactions: "
                         f"{sources.redact(e)[:100]} (context check)"))
        return

    flat = []
    for si, stage_list in enumerate(inter):
        for it in stage_list:
            cd = it[2]
            if not isinstance(cd, (bytes, bytearray)):
                try:
                    cd = bytes.fromhex(str(cd).replace("0x", ""))
                except ValueError:
                    cd = b""
            flat.append({
                "stage": STAGES[si],
                "target": str(it[0]).lower(),
                "value": str(int(it[1])),
                "selector": ("0x" + cd[:4].hex()) if len(cd) >= 4 else "0x",
                "calldata_bytes": len(cd),
            })

    counts = {s: sum(1 for f in flat if f["stage"] == s) for s in STAGES}
    distinct = len({f["target"] for f in flat})
    with_value = sum(1 for f in flat if int(f["value"]) > 0)
    # Classify the pre/post interactions (intra is solver routing, not in
    # scope for criterion 4). Tag each so the ledger is honest about which are
    # order-hook execution vs driver infra vs unrecognised.
    prepost = [f for f in flat if f["stage"] in ("pre", "post")]
    hook_calls = 0
    infra_calls = 0
    for f in flat:
        if f["target"] == HOOKS_TRAMPOLINE:
            f["role"] = "order-hook execution (HooksTrampoline)"
            if f["stage"] in ("pre", "post"):
                hook_calls += 1
        elif f["target"] == DEADLINE_CHECK:
            f["role"] = "driver infra (deadline check)"
            if f["stage"] in ("pre", "post"):
                infra_calls += 1
        else:
            f["role"] = "routing" if f["stage"] == "intra" else "other"
    other_prepost = len(prepost) - hook_calls - infra_calls
    hook_note = ""
    if prepost:
        bits = []
        if hook_calls:
            bits.append(f"{hook_calls} order-hook execution (HooksTrampoline)")
        if infra_calls:
            bits.append(f"{infra_calls} driver infra (deadline check)")
        if other_prepost:
            bits.append(f"{other_prepost} other")
        hook_note = f"; pre/post: {', '.join(bits)}"
    checks.append(_v(
        "C13.interactions", INFO,
        f"{len(flat)} interaction(s): pre {counts['pre']} / intra "
        f"{counts['intra']} / post {counts['post']}; {distinct} distinct "
        f"target(s); {with_value} carrying native-ETH value{hook_note}",
        interactions=flat))
    limits.append(
        "C13 lists and role-tags the executed interactions. Confirming each "
        "trampoline-wrapped hook against the matched orders' declared appData "
        "hooks (positive hook verification), and the full services#2667 "
        "criterion-4 relation (executed pre/post ⊆ matched-order hooks), are "
        "not performed here — the latter needs the /solve instance from the S3 "
        "bucket, not the public API")
