"""Decode-based checks: C3 solution fidelity, C4 limit compliance,
C5 delivered-surplus (context).

C3/C4 implement criterion 3 of cowprotocol/services#2667 ("exactly the orders
that were referenced in the winning solution got settled and matched at the
prices indicated") plus the GPv2 signed-limit guarantee, from on-chain Trade
events cross-checked against calldata (direct route) or the public orderbook
(wrapper route).

Settlement decoding comes from the vendored `gpv2` module (imported here as
`scorer`); the only third-party dependency is eth-abi.
"""
from . import gpv2 as scorer
from . import sources

PASS = "PASS"
VIOLATION = "VIOLATION"
UNCERTAIN = "UNCERTAIN"
INFO = "INFO"

# Atom band for scored-vs-executed comparisons. Real settlements match the
# scored solution EXACTLY (0/94 corpus certificates ever showed a nonzero
# delta, and the protocol's own settlement validation requires equality) —
# so exact is the only PASS. A 1-2 atom user-deficit is theoretically
# producible by driver ceil/floor re-encoding, but "theoretically benign" is
# not "provably benign": it lands UNCERTAIN, never PASS (and never VIOLATION
# — never accuse from ambiguity). Beyond the band is a VIOLATION.
ROUNDING_ATOMS = 2

def _v(check, verdict, detail, **extra):
    out = {"check": check, "verdict": verdict, "detail": detail}
    out.update(extra)
    return out


def _aggregate_by_uid(events):
    """Sum executed sell/buy/fee per order uid. One order can be filled by
    several Trade events in a single settlement (GPv2 accumulates filledAmount),
    so a per-event comparison against a per-uid solution total would false-flag
    a legitimate multi-fill. Preserves first-seen order."""
    agg = {}
    for e in events:
        a = agg.get(e["uid"])
        if a is None:
            agg[e["uid"]] = {"uid": e["uid"], "owner": e["owner"],
                             "sell_token": e["sell_token"],
                             "buy_token": e["buy_token"],
                             "sell_amount": e["sell_amount"],
                             "buy_amount": e["buy_amount"],
                             "fee_amount": e.get("fee_amount", 0), "fills": 1}
        else:
            a["sell_amount"] += e["sell_amount"]
            a["buy_amount"] += e["buy_amount"]
            a["fee_amount"] += e.get("fee_amount", 0)
            a["fills"] += 1
    return list(agg.values())


def trade_events_with_fee(logs):
    """scorer.trade_events + the feeAmount word it skips (data word 4). The
    fee pass applies the SAME filter as trade_events (canonical contract, Trade
    topic, well-formed data) so the two lists can never misalign; if they still
    differ in length the fee is left at 0 rather than attached to the wrong
    event."""
    events = scorer.trade_events(logs)
    fees = []
    for lg in logs or []:
        topics = lg.get("topics") or []
        if not topics or topics[0].lower() != scorer.TRADE_TOPIC:
            continue
        if (lg.get("address") or "").lower() != scorer.SETTLEMENT:
            continue
        d = (lg.get("data") or "")[2:]
        if len(d) < 560:
            continue
        try:
            fees.append(int(d[256:320], 16))
        except ValueError:
            fees.append(0)
    if len(fees) != len(events):
        fees = [0] * len(events)
    for e, f in zip(events, fees):
        e["fee_amount"] = f
    return events


def run_decode_checks(network, direct, calldata, logs, this_sol, comp,
                      ev, checks, limits):
    """Append C3/C4/C5 verdicts to `checks`. Never raises on bad data —
    degrades to UNCERTAIN with the reason."""
    events = trade_events_with_fee(logs)
    if not events:
        checks.append(_v("C3.solution-fidelity", UNCERTAIN,
                         "no GPv2 Trade events in the receipt; nothing was "
                         "traded (or logs unavailable)"))
        return

    # --- C3: the settled order set + amounts vs the scored winning solution.
    # Aggregate settled amounts per uid first (a uid can be filled by several
    # Trade events in one settlement — comparing per-event to per-uid totals
    # would false-flag a legitimate multi-fill).
    settled = _aggregate_by_uid(events)
    ev_uids = [e["uid"] for e in settled]
    # JIT / liquidity classification: a settled uid NOT in the auction's user
    # order set (comp.auction.orders) is a solver-brought market-maker/CoW-AMM
    # liquidity order. These ARE listed in the winning solution (so C3 does not
    # false-flag them), but their surplus is the maker's, not a user's — C5
    # excludes them from the delivered-USER-surplus sum below, and C3 notes them.
    auction_uids = None
    au = (comp.get("auction") or {}).get("orders")
    if isinstance(au, list):
        auction_uids = {str(u).lower() for u in au}
    jit_uids = ({u for u in ev_uids if u not in auction_uids}
                if auction_uids is not None else set())
    # Only treat entries with a uid-shaped id as scored orders; a schema drift
    # that renames the id field must NOT collapse every order to key "" (which
    # would read as "nothing settled matches" = a false accusation).
    sol_orders = {}
    if this_sol:
        for o in (this_sol.get("orders") or []):
            oid = str(o.get("id") or "").lower()
            if oid.startswith("0x") and len(oid) == 114:
                sol_orders[oid] = o
    scored_ids = [o for o in (this_sol.get("orders") or [])] if this_sol else []
    if not this_sol or not scored_ids:
        checks.append(_v("C3.solution-fidelity", UNCERTAIN,
                         "winning solution carries no order list in the "
                         "public record; settled-set comparison not possible"))
    elif not sol_orders:
        checks.append(_v("C3.solution-fidelity", UNCERTAIN,
                         f"winning solution lists {len(scored_ids)} order(s) but "
                         f"none carries a uid-shaped id (schema drift?); "
                         f"settled-set comparison not performed rather than "
                         f"risk a false finding"))
    else:
        extra = [u for u in ev_uids if u not in sol_orders]
        # An unlisted settled uid that IS one of the auction's user orders is a
        # real discrepancy. One that is NOT (and the record carries the user-
        # order list) is far more likely a liquidity/JIT leg the record did not
        # list — investigate, never accuse. Without the list we cannot tell.
        extra_user = [u for u in extra
                      if auction_uids is not None and u in auction_uids]
        extra_unlisted = [u for u in extra if u not in extra_user]
        missing = [u for u in sol_orders if u not in ev_uids]
        amount_notes, worst = [], PASS
        compared = 0
        for e in settled:
            o = sol_orders.get(e["uid"])
            if not o:
                continue
            try:
                scored_sell = int(o["sellAmount"])
                scored_buy = int(o["buyAmount"])
            except (KeyError, TypeError, ValueError):
                continue
            compared += 1
            d_buy = e["buy_amount"] - scored_buy      # + = user got more
            d_sell = e["sell_amount"] - scored_sell   # + = user paid more
            if d_buy < -ROUNDING_ATOMS or d_sell > ROUNDING_ATOMS:
                worst = VIOLATION
                amount_notes.append(
                    f"{e['uid'][:18]}..: delivered {d_buy:+d} buy-atoms / "
                    f"{d_sell:+d} sell-atoms vs the scored solution")
            elif d_buy < 0 or d_sell > 0:
                # User-DEFICIT inside the band: within known driver-rounding
                # reach but NOT exact — flagged for review, never called
                # favorable (the old label said "user-favorable" for a
                # deficit), and never PASS.
                if worst == PASS:
                    worst = UNCERTAIN
                amount_notes.append(
                    f"{e['uid'][:18]}..: {d_buy:+d} buy / {d_sell:+d} sell "
                    f"atoms vs the scored solution — within the driver "
                    f"rounding band but not exact; flagged for review")
            elif d_buy or d_sell:
                amount_notes.append(
                    f"{e['uid'][:18]}..: user-favorable delta "
                    f"({d_buy:+d} buy, {d_sell:+d} sell atoms)")
        matched = [u for u in ev_uids if u in sol_orders]
        if extra_user or missing:
            checks.append(_v(
                "C3.solution-fidelity", VIOLATION,
                f"settled-order set differs from the winning solution: "
                f"{len(extra_user)} auction user order(s) settled but not in "
                f"the scored solution, {len(missing)} scored-but-not-settled",
                extra_uids=extra_user, missing_uids=missing,
                unlisted_uids=extra_unlisted))
        elif extra_unlisted:
            checks.append(_v(
                "C3.solution-fidelity", UNCERTAIN,
                f"{len(extra_unlisted)} settled order(s) are in neither the "
                f"winning solution's order list nor the auction's user order "
                f"set — most likely solver-brought liquidity (JIT / CoW-AMM) "
                f"that the public record did not list; flagged for review, "
                f"not as a finding. The {len(matched)} user order(s) matched.",
                unlisted_uids=extra_unlisted, orders=len(settled)))
        elif compared < len(matched):
            # The set matched but some amounts were not comparable — say so
            # rather than assert "amounts exact" over an empty comparison.
            checks.append(_v(
                "C3.solution-fidelity", UNCERTAIN,
                f"all {len(settled)} settled order(s) are in the winning "
                f"solution, but amounts were comparable for only "
                f"{compared}/{len(matched)} (missing sell/buy fields)",
                orders=len(settled)))
        else:
            jit_note = (f"; {len(jit_uids)} of these are JIT/liquidity order(s) "
                        f"not in the auction's user order set (expected for "
                        f"market-maker / CoW-AMM liquidity)" if jit_uids else "")
            checks.append(_v(
                "C3.solution-fidelity", worst,
                f"all {len(settled)} settled order(s) match the winning "
                f"solution's order set; amounts compared for {compared}/"
                f"{len(matched)}"
                + ("; amounts exact" if not amount_notes else
                   "; " + " | ".join(amount_notes[:4])) + jit_note,
                orders=len(settled)))

    # --- C4: signed-limit compliance per trade:
    # buy_received * limit_sell >= limit_buy * (sell_paid - fee).
    trades = None
    if direct:
        try:
            trades = scorer.decode_settlement(calldata)["trades"]
        except Exception as e:
            limits.append(f"calldata decode failed for C4: {e}")
    results, basis = [], None
    if trades is not None and len(trades) == len(events):
        basis = "signed limits from calldata"
        for t, e in zip(trades, events):
            results.append((e["uid"], int(t[3]), int(t[4]), e))
    else:
        # Wrapper route (or decode mismatch): signed limits from the public
        # orderbook, per uid.
        basis = "signed limits from the public orderbook"
        for e in events:
            meta = sources.order_meta(network, e["uid"], ev)
            try:
                lim_sell, lim_buy = int(meta["sellAmount"]), int(meta["buyAmount"])
            except (TypeError, KeyError, ValueError):
                continue
            if lim_sell > 0 and lim_buy > 0:   # a zero limit is not a limit
                results.append((e["uid"], lim_sell, lim_buy, e))
    if not results:
        checks.append(_v("C4.limit-compliance", UNCERTAIN,
                         "signed limits unavailable (calldata hidden and "
                         "orderbook lookup failed)"))
    else:
        bad = []
        for uid, lim_sell, lim_buy, e in results:
            paid_net = e["sell_amount"] - e.get("fee_amount", 0)
            if e["buy_amount"] * lim_sell < lim_buy * paid_net:
                bad.append(uid)
        if bad:
            checks.append(_v("C4.limit-compliance", VIOLATION,
                             f"{len(bad)} of {len(results)} trade(s) executed "
                             f"below the signed limit price ({basis})",
                             violating_uids=bad))
        else:
            checks.append(_v("C4.limit-compliance", PASS,
                             f"all {len(results)} trade(s) respect their "
                             f"signed limit price ({basis})"))
    if len(results) < len(events):
        limits.append(f"C4 covered {len(results)}/{len(events)} trades "
                      f"(missing signed limits for the rest)")

    # --- C5: the user surplus ACTUALLY delivered on-chain (context, INFO).
    # Surplus is computed from the executed Trade-event amounts against the
    # signed limits (see gpv2.surplus_from_execution) — never from a
    # solver-chosen clearing-price slot — and valued at the auction's native
    # reference prices. It is REPORTED, not adjudicated against the competition
    # score: the score folds in fee policy and the CIP-38 objective that public
    # data does not expose, so a legitimate fee-bearing settlement has
    # score > delivered surplus. The value here is that the delivered surplus
    # is un-forgeable — it is what the old price-based reconstruction tried to
    # confirm and a solver could game by editing an unread price slot.
    if not this_sol:
        return
    try:
        kinds = {}
        # Only pair calldata trades with events when the counts agree (the
        # same condition C4 uses) — a misaligned zip would value a buy as a sell.
        if trades is not None and len(trades) == len(events):
            for t, e in zip(trades, events):
                kinds[e["uid"]] = ("buy" if int(t[8]) & scorer.FLAG_KIND_BUY
                                   else "sell")
        prices = (comp.get("auction") or {}).get("prices") or {}
        native = {}
        for k, val in prices.items():
            try:
                native[str(k).lower()] = int(val)
            except (TypeError, ValueError):
                continue   # a malformed price is skipped, never fatal
        total_native = 0
        priced = 0
        jit_excluded = 0
        unclassified = 0
        for uid, lim_sell, lim_buy, e in results:
            # JIT/liquidity legs are the maker's, not a user's — exclude them
            # from the delivered-USER-surplus sum (F6).
            if uid in jit_uids:
                jit_excluded += 1
                continue
            kind = kinds.get(uid)
            if kind is None:
                meta = sources.order_meta(network, uid, ev)
                kind = (meta or {}).get("kind")
            if kind not in ("sell", "buy"):
                # Order kind unknowable from public data: a buy order valued
                # as a sell produces a WRONG surplus, so this tool never
                # guesses — the trade is left out and the coverage note says
                # so (previously this silently assumed "sell").
                unclassified += 1
                continue
            exec_sell_net = e["sell_amount"] - e.get("fee_amount", 0)
            surplus = scorer.surplus_from_execution(
                kind, exec_sell_net, e["buy_amount"], lim_sell, lim_buy)
            stoken = e["buy_token"] if kind == "sell" else e["sell_token"]
            if stoken in native:
                px = native[stoken]
                total_native += surplus * px // 10**18
                priced += 1
        if priced == 0:
            reason = ("every settled leg was a JIT/liquidity order (no user "
                      "order to value)" if jit_excluded and jit_excluded == len(results)
                      else "no settled trade could be classified sell/buy from "
                      "public data; surplus not computed rather than guessed"
                      if unclassified and unclassified + jit_excluded == len(results)
                      else "no native prices in the competition record for the "
                      "settled tokens; surplus not valuable in native terms")
            # Context only: C5 never moves the overall verdict.
            checks.append(_v("C5.surplus-delivered", INFO,
                             reason + " (context check; not a finding)"))
            return
        score = int(this_sol.get("score"))
        coverage = (f"{priced}/{len(results)} priced trade(s)"
                    if priced != len(results) else f"{priced} trade(s)")
        # The competition score is NOT the user surplus: it folds in protocol
        # fee policies and the CIP-38 objective, none of which are exposed in
        # public data, so `score` routinely exceeds the delivered user surplus
        # (a legitimate fee-bearing settlement shows exactly that). C5 therefore
        # REPORTS the un-forgeable delivered surplus rather than asserting it
        # equals the score — it is context (INFO), never a verdict. (The delivered
        # surplus is what the earlier price-based reconstruction tried to confirm
        # and a solver could game by editing an unread clearing-price slot; here
        # it is fixed by the on-chain Trade events and cannot be gamed.)
        jit_note = (f" {jit_excluded} JIT/liquidity leg(s) were excluded (maker "
                    f"surplus, not user)." if jit_excluded else "")
        if unclassified:
            jit_note += (f" {unclassified} trade(s) could not be classified "
                         f"sell/buy from public data and were left out rather "
                         f"than guessed.")
        detail = (f"delivered user surplus ≈ {total_native} native atoms over "
                  f"{coverage} (computed from the on-chain executed amounts "
                  f"against the signed limits — it cannot be inflated by the "
                  f"settlement's clearing prices).{jit_note} The reported "
                  f"competition score is {score}. C5 reports the delivered "
                  f"surplus; it does not independently confirm the score, which "
                  f"folds in fee policy and the CIP-38 objective that public "
                  f"data does not expose (so score >= delivered surplus is "
                  f"expected).")
        checks.append(_v("C5.surplus-delivered", INFO, detail,
                         delivered_surplus_native=str(total_native),
                         reported_score=str(score)))
    except Exception as e:
        checks.append(_v("C5.surplus-delivered", INFO,
                         f"surplus not computed: {sources.redact(e)[:120]} "
                         f"(context check; not a finding)"))
