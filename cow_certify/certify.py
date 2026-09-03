"""Certificate construction: run every check we can on one settlement,
report PASS / VIOLATION / UNCERTAIN per check, and never guess.

Check provenance: cowprotocol/services#2667 (2024-04-26) lists the core team's
own acceptance criteria for settlement verification — settlement references an
auction, submitter won it, exactly the winning orders settled at solution
prices, interactions are a subset — and states that "having multiple
independent implementations of this crucial logic is important."
This is one such independent implementation, from public data only.
"""
import os
import sys

from . import (
    __version__,  # tool version (display); schema_version = cert format
    sources,
)
from . import gpv2 as scorer
from .checks_authenticity import run_authenticity_check
from .checks_buffer import run_buffer_check
from .checks_decode import run_decode_checks
from .checks_ebbo import run_price_vs_mid
from .checks_flow import run_receiver_check
from .checks_interactions import run_interactions_check
from .checks_ledger import run_order_ledger
from .checks_onchain import run_solver_auth_check
from .sources import GPV2, SETTLE_SELECTOR, Evidence

SCHEMA_VERSION = "0.3.0"

PASS = "PASS"
VIOLATION = "VIOLATION"
UNCERTAIN = "UNCERTAIN"
INFO = "INFO"


def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def _receipt_status(receipt):
    """1 = succeeded, 0 = reverted, None = no receipt / no status field. Only an
    explicit on-chain status may ever feed an accusation."""
    if not isinstance(receipt, dict):
        return None
    st = receipt.get("status")
    if st is None:
        return None
    try:
        return 1 if int(st, 16) == 1 else 0
    except (TypeError, ValueError):
        try:
            return 1 if int(st) == 1 else 0
        except (TypeError, ValueError):
            return None


def certify_tx(network, tx_hash, rpc_url=None, ev=None):
    custom_rpc = rpc_url is not None
    rpc_url = rpc_url or sources.DEFAULT_RPC[network]
    # A caller may pass its own ledger so fetches it made to CHOOSE the subject
    # (the --order path's trades lookup) are part of the certificate's evidence.
    ev = ev if ev is not None else Evidence()
    checks = []
    limits = []

    # A user-supplied RPC must actually BE the selected network: certifying a
    # Base settlement against an Arbitrum node produces confident nonsense. A
    # trust tool verifies rather than assumes — eth_chainId is one cheap call
    # on the custom-RPC path only (built-in defaults are pre-verified).
    if custom_rpc:
        want = sources.CHAIN_IDS.get(network)
        try:
            got = int(sources.rpc(rpc_url, "eth_chainId", [], ev), 16)
        except Exception:
            got = None
        if want is not None and got is not None and got != want:
            raise SystemExit(
                f"--rpc-url is chain id {got}, but --network {network} is "
                f"chain id {want} — refusing to certify against the wrong chain")

    tx = sources.rpc(rpc_url, "eth_getTransactionByHash", [tx_hash], ev)
    if tx is None:
        raise SystemExit(f"transaction {tx_hash} not found on {network} — "
                         f"is --network correct? (a tx exists on one chain only)")
    receipt = sources.rpc(rpc_url, "eth_getTransactionReceipt", [tx_hash], ev)
    status = _receipt_status(receipt)  # 1 ok / 0 reverted / None unknown
    # Anything other than an explicit 0x1 is confirmed across EVERY endpoint we
    # know for this network — the user's --rpc-url AND the built-in defaults —
    # before it may shape a verdict. Two failure modes motivate this: public
    # RPCs intermittently return status 0x0 for a genuinely successful tx (a bad
    # read, not an error, so rotation never sees it), and a lagging or pruning
    # node returns a NULL receipt for a perfectly mined tx (or the tx is simply
    # still pending). A real revert is 0x0 on every node; a single 0x1 anywhere
    # proves the first read wrong. A single custom endpoint must never be the
    # only witness to an accusation. Only paid on the rare non-0x1 path.
    if status != 1:
        urls = rpc_url if isinstance(rpc_url, list) else [rpc_url]
        witnesses = list(dict.fromkeys(list(urls) + list(sources.DEFAULT_RPC.get(network, []))))
        for alt in witnesses:
            try:
                r2 = sources.rpc([alt], "eth_getTransactionReceipt", [tx_hash], ev, rounds=1)
            except Exception:
                continue
            s2 = _receipt_status(r2)
            if s2 == 1:
                receipt, status = r2, 1
                break
            if s2 == 0 and status is None:
                receipt, status = r2, 0   # an explicit receipt beats no receipt
    status_ok = status == 1
    receipt_missing = status is None
    try:
        landed_block = int(receipt["blockNumber"], 16) if receipt and receipt.get("blockNumber") else None
    except (TypeError, ValueError):
        landed_block = None
    sender = (tx.get("from") or "").lower()
    calldata = (tx.get("input") or "").lower()

    # C0 — settlement shape: direct settle() call, or a solver-owned wrapper.
    # Wrappers still execute GPv2 internally (Trade events fire from the
    # canonical contract) and the competition API indexes by tx hash either
    # way, so wrapper routing narrows the check set instead of ending it.
    to_addr = (tx.get("to") or "").lower()
    direct = to_addr == GPV2 and calldata.startswith(SETTLE_SELECTOR)
    gpv2_other_fn = to_addr == GPV2 and not direct  # e.g. swap(): GPv2, not settle()
    # Does the receipt carry GPv2 activity from the canonical contract? A real
    # settlement emits a Trade event per user order AND a Settlement(solver)
    # event once — an interactions-only settlement (CoW-AMM/JIT rebalance,
    # buffer op) has NO Trade events but STILL emits Settlement. Either proves
    # this is a genuine CoW settlement vs an unrelated pasted transaction.
    has_gpv2_activity = False
    for lg in ((receipt.get("logs") or []) if receipt else []):
        topics = lg.get("topics") or []
        if (topics and (lg.get("address") or "").lower() == scorer.SETTLEMENT
                and topics[0].lower() in (scorer.TRADE_TOPIC,
                                          scorer.SETTLEMENT_EVENT_TOPIC)):
            has_gpv2_activity = True
            break
    suffix_aid, suffix_len = None, None
    if direct:
        checks.append(_v("C0.settlement-shape", PASS,
                         "direct settle() call to the canonical GPv2 contract"))
        try:
            dec = scorer.decode_settlement(calldata)
            suffix_aid, suffix_len = dec["auction_id"], dec["suffix_len"]
        except Exception:
            suffix_aid = None
    elif receipt_missing:
        # Without a receipt there are no logs to classify a non-settle() call
        # by. Say exactly that — not "this is not a settlement".
        checks.append(_v(
            "C0.settlement-shape", UNCERTAIN,
            f"tx target {to_addr or '(contract creation)'} is not a direct "
            f"settle() call and no receipt is available yet to look for GPv2 "
            f"settlement events; cannot classify this transaction until it is "
            f"mined and indexed"))
        checks.append(_v("C8.execution-status", UNCERTAIN,
                         "no transaction receipt is available from any endpoint "
                         "queried: the transaction may still be pending, or the "
                         "nodes have not indexed it yet", receipt_missing=True))
        return _finish(network, tx_hash, checks, limits, ev, status_ok=None)
    elif not has_gpv2_activity:
        # Not a settle() call AND no GPv2 settlement activity (Trade or
        # Settlement event): this is not a CoW Protocol settlement at all
        # (most likely a mis-pasted hash). Say so plainly instead of inventing
        # a "wrapper route".
        checks.append(_v(
            "C0.settlement-shape", UNCERTAIN,
            f"this transaction is not a CoW Protocol settlement: its target "
            f"{to_addr or '(contract creation)'} is not the GPv2 settlement "
            f"contract and the receipt contains no GPv2 settlement events. "
            f"Nothing to certify — check the tx hash and --network."))
        if not status_ok:
            checks.append(_v("C8.execution-status", INFO,
                             "the transaction also reverted on-chain"))
        return _finish(network, tx_hash, checks, limits, ev,
                       status_ok=status_ok)
    elif gpv2_other_fn:
        checks.append(_v(
            "C0.settlement-shape", INFO,
            f"call to the canonical GPv2 contract through a non-settle() "
            f"function (selector {calldata[:10]}); the receipt carries GPv2 "
            f"settlement events. Certifying via the competition record and "
            f"canonical-contract events; the settle() calldata is not at the "
            f"top level so the auction-id cross-check is not accessible."))
        limits.append("non-settle() GPv2 entry point: calldata-suffix auction binding not independently checkable")
    else:
        checks.append(_v(
            "C0.settlement-shape", INFO,
            f"tx target {to_addr} is not the GPv2 settlement contract, but the "
            f"receipt carries GPv2 settlement events (solver-owned wrapper "
            f"route). Certifying via the competition record and canonical-"
            f"contract events; the calldata auction-id cross-check is not "
            f"accessible at "
            f"the top level."))
        limits.append("wrapper route: calldata-suffix auction binding not independently checkable")

    # C8 — execution status. Emitted HERE (before any competition-record early
    # return) so a reverted settlement can never certify without it: the
    # competition API 404s precisely because the settlement reverted, which is
    # the exact path that used to skip C8 entirely.
    if receipt_missing:
        # No receipt from ANY endpoint: pending, or not yet indexed. That is
        # not a revert and may not be reported as one.
        checks.append(_v("C8.execution-status", UNCERTAIN,
                         "no transaction receipt is available from any endpoint "
                         "queried: the transaction may still be pending, or the "
                         "nodes have not indexed it yet. Nothing about its "
                         "execution can be asserted — re-run once it is mined",
                         receipt_missing=True))
    elif not status_ok:
        checks.append(_v("C8.execution-status", VIOLATION,
                         "transaction REVERTED on-chain (or failed) — it did "
                         "not settle. This is not a completed settlement; "
                         "revert-reason forensics is a later check",
                         reverted=True))

    # C1 — auction binding: calldata suffix (autopilot-appended) vs stored
    # competition record. #2667 criterion 1.
    comp = sources.competition_by_tx(network, tx_hash, ev)
    if comp is None and suffix_aid is None:
        checks.append(_v("C1.auction-binding", UNCERTAIN,
                         "no public competition record for this tx and no "
                         "readable calldata auction id; nothing further is "
                         "verifiable from public data"))
        limits.append("no public competition record: C2-C7 not performable")
        return _finish(network, tx_hash, checks, limits, ev, status_ok=status_ok)
    if comp is None:
        # Legit reasons exist (barn/staging environment, out-of-competition
        # fee withdrawals, unstored records) — #2667 itself lists them. UNCERTAIN,
        # never an accusation.
        checks.append(_v(
            "C1.auction-binding", UNCERTAIN,
            f"calldata declares auction id {suffix_aid}, but the public "
            f"competition endpoint has no record for this tx (404). Possible "
            f"legitimate causes: staging/barn settlement, out-of-competition "
            f"maintenance, or unstored record. Cannot verify further from "
            f"public data.", auction_id=suffix_aid))
        limits.append("no public competition record: C2-C7 not performable")
        return _finish(network, tx_hash, checks, limits, ev,
                       auction_id=suffix_aid, status_ok=status_ok)
    # Coerce to int: the API has returned auctionId as both int and numeric
    # string across versions, and a bare `==` on mixed types would read a
    # perfectly-bound settlement as a MISMATCH (a false VIOLATION on every
    # settlement on the chain the moment the serialization changes).
    raw_aid = comp.get("auctionId")
    try:
        api_aid = int(raw_aid) if raw_aid is not None else None
    except (TypeError, ValueError):
        api_aid = None
    if raw_aid is not None and api_aid is None:
        checks.append(_v("C1.auction-binding", UNCERTAIN,
                         f"competition record's auctionId is not a parseable "
                         f"integer ({raw_aid!r}); cannot bind. Calldata suffix "
                         f"is {suffix_aid}", auction_id=suffix_aid))
    elif api_aid is None:
        # A record exists but carries no auctionId (indexing lag on a freshly
        # landed tx, or schema drift). Not comparable → UNCERTAIN, never an
        # accusation.
        checks.append(_v("C1.auction-binding", UNCERTAIN,
                         f"competition record carries no auctionId to bind "
                         f"against (partial or aged record); calldata suffix is "
                         f"{suffix_aid}", auction_id=suffix_aid))
    elif suffix_aid is None:
        if direct and suffix_len == 0:
            checks.append(_v("C1.auction-binding", INFO,
                             f"competition record binds this tx to auction "
                             f"{api_aid}; the settle() calldata carries no "
                             f"appended auction id (API-side binding only)",
                             api_auction_id=api_aid))
        elif direct and suffix_len is not None:
            # The autopilot appends exactly 8 bytes. A different tail is not an
            # autopilot suffix (a custom driver may append anything) — it is not
            # readable as an auction id and is NOT compared, so it cannot accuse.
            checks.append(_v("C1.auction-binding", UNCERTAIN,
                             f"competition record binds this tx to auction "
                             f"{api_aid}, but the settle() calldata ends in a "
                             f"non-standard {suffix_len}-byte tail (the autopilot "
                             f"appends exactly 8); the tail is not readable as an "
                             f"auction id and was not compared",
                             api_auction_id=api_aid, suffix_len=suffix_len))
        elif direct:
            checks.append(_v("C1.auction-binding", UNCERTAIN,
                             f"competition record binds this tx to auction "
                             f"{api_aid}, but the settle() calldata did not decode, "
                             f"so the calldata-side auction id is unavailable",
                             api_auction_id=api_aid))
        else:
            checks.append(_v("C1.auction-binding", INFO,
                             f"competition record binds this tx to auction "
                             f"{api_aid} (API-side binding only; wrapper route "
                             f"hides the calldata suffix)", api_auction_id=api_aid))
        suffix_aid = api_aid
    elif api_aid == int(suffix_aid):
        checks.append(_v("C1.auction-binding", PASS,
                         f"calldata auction id {suffix_aid} == stored "
                         f"competition record auctionId", auction_id=suffix_aid))
    else:
        checks.append(_v("C1.auction-binding", VIOLATION,
                         f"calldata auction id {suffix_aid} != competition "
                         f"record auctionId {api_aid}",
                         auction_id=suffix_aid, api_auction_id=api_aid))

    solutions = comp.get("solutions") or []
    winners = [s for s in solutions if s.get("isWinner")]

    # C2 — winner legitimacy: the submitting address won this auction, and this
    # tx is the winning solution's settlement. #2667 criterion 2.
    this_sol = [s for s in winners
                if (s.get("txHash") or "").lower() == tx_hash.lower()]
    if this_sol:
        s = this_sol[0]
        saddr = (s.get("solverAddress") or "").lower()
        # GPv2's authenticator authorizes the CALLER of settle(). For a direct
        # settlement that is tx.from; for a wrapper route it is the wrapper
        # contract itself (smart-contract solvers register the contract as
        # their solver address, and the tx sender is just an operator key).
        if saddr == sender:
            checks.append(_v("C2.winner-legitimacy", PASS,
                             f"tx sender {sender} is the recorded winning "
                             f"solver of solution ranked {s.get('ranking')}"))
        elif not direct and saddr == to_addr:
            checks.append(_v("C2.winner-legitimacy", PASS,
                             f"settle() was called by the recorded winning "
                             f"solver contract {saddr} (wrapper route; tx "
                             f"signed by operator key {sender})"))
        elif direct:
            checks.append(_v("C2.winner-legitimacy", VIOLATION,
                             f"tx sender {sender} != recorded winning solver "
                             f"{saddr} for this settlement"))
        else:
            checks.append(_v("C2.winner-legitimacy", UNCERTAIN,
                             f"neither tx sender {sender} nor wrapper target "
                             f"{to_addr} matches recorded winning solver "
                             f"{saddr}; warrants investigation, not "
                             f"accusation, from public data alone"))
    elif winners:
        checks.append(_v("C2.winner-legitimacy", UNCERTAIN,
                         f"{len(winners)} winning solution(s) recorded but none "
                         f"references this txHash; cannot bind sender to a "
                         f"specific winning solution from public data"))
    else:
        checks.append(_v("C2.winner-legitimacy", UNCERTAIN,
                         "competition record exists but flags no winning "
                         "solution (possibly a partial/aged record or schema "
                         "difference); the winner cannot be confirmed from "
                         "public data"))

    # C3/C4/C5 — decode-based: settled set vs scored solution, signed-limit
    # compliance, reconstructed-surplus sanity. (#2667 criterion 3.)
    if status_ok:
        run_decode_checks(network, direct, calldata,
                          (receipt.get("logs") or []) if receipt else [],
                          this_sol[0] if this_sol else None, comp, ev,
                          checks, limits)

    # C6 — timeliness: landed within the auction deadline. (The 'GPv2: order
    # filled' race and late settlements are exactly this check.)
    deadline = comp.get("auctionDeadlineBlock")
    start = comp.get("auctionStartBlock")
    if isinstance(deadline, int) and landed_block is not None:
        late_by = landed_block - deadline
        if late_by <= 0:
            checks.append(_v("C6.timeliness", PASS,
                             f"landed at block {landed_block}, deadline "
                             f"{deadline} ({-late_by} blocks to spare)",
                             landed_block=landed_block, deadline_block=deadline))
        else:
            checks.append(_v("C6.timeliness", UNCERTAIN,
                             f"landed {late_by} block(s) after the recorded "
                             f"auction deadline ({landed_block} > {deadline}). "
                             f"The deadline is not on-chain-enforced and benign "
                             f"causes exist (reorg, slow inclusion), so this is "
                             f"flagged for review, not as a violation",
                             landed_block=landed_block, deadline_block=deadline,
                             late_by_blocks=late_by))
    else:
        why = ("no transaction receipt available, so the landing block is "
               "unknown" if landed_block is None
               else "no auctionDeadlineBlock in the competition record")
        checks.append(_v("C6.timeliness", UNCERTAIN, why))

    # C7 — competition context (informational): how contested was this win.
    distinct = {(s.get("solverAddress") or "").lower()
                for s in solutions if not s.get("filteredOut")}
    filtered = sum(1 for s in solutions if s.get("filteredOut"))
    ctx = {
        "solutions": len(solutions),
        "distinct_solvers": len(distinct),
        "filtered_out": filtered,
        "winners": len(winners),
    }
    if this_sol:
        s = this_sol[0]
        try:
            score = int(s.get("score"))
            ref = int(s.get("referenceScore")) if s.get("referenceScore") is not None else None
            ctx["score"] = str(score)
            if ref is not None:
                ctx["reference_score"] = str(ref)
                ctx["margin"] = str(score - ref)
        except (TypeError, ValueError):
            pass
    checks.append(_v("C7.competition-context", INFO,
                     f"{len(solutions)} solution(s) from "
                     f"{len(distinct)} distinct solver(s), "
                     f"{filtered} filtered out, {len(winners)} winner(s)",
                     **ctx))

    # C9 — on-chain solver authorization: confirm the settle() caller is a
    # registered solver in the GPv2 authenticator, independent of the API.
    run_solver_auth_check(rpc_url, direct, to_addr, sender, landed_block,
                          ev, checks, limits,
                          status_ok=(None if receipt_missing else status_ok))

    # C10 — detailed per-order ledger (INFO): the full factual record C3/C4/C5
    # verify against, laid out per order.
    # C11 — receiver-delivery: confirm the buy tokens reached the receiver.
    if status_ok:
        settle_logs = (receipt.get("logs") or []) if receipt else []
        run_order_ledger(network, direct, calldata, settle_logs,
                         this_sol[0] if this_sol else None, comp, rpc_url,
                         ev, checks)
        run_receiver_check(direct, calldata, settle_logs, checks, limits)
        # C12 — order authenticity vs the public orderbook.
        run_authenticity_check(network, direct, calldata, settle_logs,
                               ev, checks, limits)
        # C13 — list the settlement's executed interactions.
        run_interactions_check(direct, calldata, checks, limits)
        # C14 — execution price vs the auction's reference mid (best-exec rung 1).
        run_price_vs_mid(comp, settle_logs, checks)
        # C15 — settlement-contract ERC-20 buffer accounting (context).
        run_buffer_check(settle_logs, checks)

    # (C8 execution-status is emitted near the top, before any early return.)

    limits.extend([
        "best-execution / EBBO (whether a better price was available elsewhere) is OUT OF SCOPE: this tool verifies a settlement's validity, not its optimality",
        "declines (won-but-never-submitted) are invisible in public data and cannot be certified by anyone outside the core team",
    ])
    return _finish(network, tx_hash, checks, limits, ev,
                   auction_id=suffix_aid, status_ok=status_ok,
                   start_block=start, deadline_block=deadline)


def _finish(network, tx_hash, checks, limits, ev, **subject_extra):
    worst = "PASS"
    order = {PASS: 0, INFO: 0, UNCERTAIN: 1, VIOLATION: 2}
    for c in checks:
        if order.get(c["verdict"], 0) > order.get(worst, 0):
            worst = c["verdict"]
    return {
        "schema_version": SCHEMA_VERSION,
        "subject": {"network": network,
                    "chain_id": sources.CHAIN_IDS.get(network),
                    "tx_hash": tx_hash, **subject_extra},
        "overall": worst,
        "checks": checks,
        "not_verifiable": limits,
        "evidence": ev.items,
        "disclaimer": "cow-certify is independent and not affiliated with CoW "
                      "Protocol; it verifies from public data only.",
        "reproduce": f"python3 -m cow_certify --network {network} {tx_hash}",
    }


# verdict -> (glyph, ANSI code, whether to color the whole line)
_VSTYLE = {
    PASS:      ("✓", "32", False),      # green
    VIOLATION: ("✗", "1;31", True),     # bold red, whole line
    UNCERTAIN: ("?", "33", False),      # yellow
    INFO:      ("·", "2", True),        # dim, whole line (context/detail)
}
_BANNER = {
    PASS: "PASS — settlement verified",
    VIOLATION: "VIOLATION — see the flagged check(s) below",
    UNCERTAIN: "UNCERTAIN — not fully verifiable from public data",
}


def render_text(cert, color=None):
    """Human-readable certificate. Colors when writing to a TTY; disable with
    color=False or the NO_COLOR env var."""
    if color is None:
        color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    def paint(s, code):
        return f"\033[{code}m{s}\033[0m" if (color and code) else s

    sub = cert["subject"]
    net = sub.get("network", "")
    cid = sub.get("chain_id")
    ov = cert["overall"]
    glyph, ovcode, _ = _VSTYLE.get(ov, ("", "", False))

    out = [
        paint(f"cow-certify {__version__} (schema {cert['schema_version']})", "2")
        + f"   {net}" + (f" (chain {cid})" if cid else ""),
        paint(sub.get("tx_hash", ""), "2"),
        "",
        "  " + paint(f"{glyph}  {_BANNER.get(ov, ov)}", ovcode),
    ]

    counts = {}
    for chk in cert["checks"]:
        counts[chk["verdict"]] = counts.get(chk["verdict"], 0) + 1
    tally = " · ".join(f"{counts[k]} {k.lower()}"
                       for k in (PASS, VIOLATION, UNCERTAIN, INFO)
                       if counts.get(k))
    out += ["  " + paint(tally, "2"), ""]

    for chk in cert["checks"]:
        g, code, whole = _VSTYLE.get(chk["verdict"], ("?", "", False))
        body = f"{chk['check']}: {chk['detail']}"
        if whole:
            out.append("  " + paint(f"{g} {body}", code))
        else:
            out.append(f"  {paint(g, code)} {body}")

    if cert.get("not_verifiable"):
        out.append("")
        out.append(paint("  not verifiable from public data:", "2"))
        for line in cert["not_verifiable"]:
            out.append(paint(f"    – {line}", "2"))

    out.append("")
    out.append(paint(f"  evidence: {len(cert['evidence'])} fetch(es)  ·  "
                     f"reproduce: {cert['reproduce']}", "2"))
    out.append(paint("  independent · not affiliated with CoW Protocol · "
                     "public data only", "2"))
    return "\n".join(out)
