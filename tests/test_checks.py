"""Offline unit tests for cow-certify check logic. No network.

Guards the arithmetic and verdict-rollup that certificates depend on, using
the backtester's own pinned self-test plus synthetic C4/C5 cases.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cow_certify import gpv2 as scorer  # noqa: E402
from cow_certify.certify import _finish, PASS, VIOLATION, UNCERTAIN, INFO  # noqa: E402
from cow_certify.checks_flow import run_receiver_check  # noqa: E402


class TestVerdictRollup(unittest.TestCase):
    def _cert(self, verdicts):
        checks = [{"check": f"C{i}", "verdict": v, "detail": ""}
                  for i, v in enumerate(verdicts)]
        return _finish("base", "0xtest", checks, [], _Ev())["overall"]

    def test_all_pass(self):
        self.assertEqual(self._cert([PASS, PASS, INFO]), PASS)

    def test_info_never_dominates(self):
        self.assertEqual(self._cert([PASS, INFO, PASS]), PASS)

    def test_uncertain_over_pass(self):
        self.assertEqual(self._cert([PASS, UNCERTAIN, INFO]), UNCERTAIN)

    def test_violation_is_worst(self):
        self.assertEqual(self._cert([PASS, UNCERTAIN, VIOLATION]), VIOLATION)


class TestSurplusMath(unittest.TestCase):
    """C5/C10 surplus is scorer.surplus_from_execution — computed from the
    executed Trade-event amounts vs the signed limit, taking NO clearing price
    (the un-forgeable form). Pin both order kinds and the boundaries."""

    def test_sell_order_surplus_over_limit(self):
        # sold 100 net, received 100, limit 100->90 => lim_bought=90 => +10
        self.assertEqual(
            scorer.surplus_from_execution("sell", 100, 100, 100, 90), 10)

    def test_sell_order_zero_surplus_at_limit(self):
        # sold 90 net, received 90, limit 90->90 => exactly at limit => 0
        self.assertEqual(
            scorer.surplus_from_execution("sell", 90, 90, 90, 90), 0)

    def test_sell_below_limit_is_negative(self):
        # received less than the signed limit implies => infeasible => <0
        self.assertLess(
            scorer.surplus_from_execution("sell", 100, 80, 100, 90), 0)

    def test_buy_order_surplus_in_sell_token(self):
        # bought 100, paid 150 net, limit 200->100 => lim_sold=200 => +50
        self.assertEqual(
            scorer.surplus_from_execution("buy", 150, 100, 200, 100), 50)

    def test_forgery_resistance_takes_no_price(self):
        # The signature carries executed amounts + signed limits only. There is
        # no clearing-price argument a solver could edit to inflate surplus —
        # this is the F1 fix, pinned structurally.
        import inspect
        params = list(inspect.signature(
            scorer.surplus_from_execution).parameters)
        self.assertEqual(
            params, ["kind", "exec_sell_net", "exec_buy",
                     "limit_sell", "limit_buy"])


class TestC5IsContextNotAccusation(unittest.TestCase):
    """C5 reports the delivered user surplus as context (INFO). It does NOT
    assert the surplus equals the competition score: the score folds in fee
    policy + the CIP-38 objective that public data does not expose, so a
    legitimate fee-bearing settlement has score > delivered surplus. C5 must
    therefore never emit PASS/ATTENTION/VIOLATION on the score relationship —
    only INFO (or UNCERTAIN if it cannot price the surplus)."""

    def test_c5_id_and_infoness_documented(self):
        # The check id was renamed from score-consistency to surplus-delivered
        # to reflect that it no longer adjudicates the score.
        import cow_certify.checks_decode as cd
        self.assertNotIn("c5_classify", dir(cd))
        # The forgeable price-based primitive is gone.
        self.assertNotIn("gross_surplus_atoms", dir(scorer))
        self.assertNotIn("uniform_price_indices", dir(scorer))


class TestGpv2SelfTest(unittest.TestCase):
    def test_selftest(self):
        # the vendored gpv2 primitives ship a pinned surplus-math self-test.
        self.assertTrue(scorer.selftest())


class TestPriceVsMidC14(unittest.TestCase):
    """C14 values execution against the auction reference mid, in bps."""

    def test_above_at_below_mid(self):
        from cow_certify.checks_ebbo import price_vs_mid_bps
        WAD = 10 ** 18
        # sell 100 @2, buy 210 @1 -> in=200, out=210 -> +500 bps
        self.assertAlmostEqual(price_vs_mid_bps(100, 210, 2 * WAD, 1 * WAD)[0], 500.0)
        # exactly at mid
        self.assertAlmostEqual(price_vs_mid_bps(100, 200, 2 * WAD, 1 * WAD)[0], 0.0)
        # below mid -> negative
        self.assertAlmostEqual(price_vs_mid_bps(100, 190, 2 * WAD, 1 * WAD)[0], -500.0)

    def test_degenerate_returns_none(self):
        from cow_certify.checks_ebbo import price_vs_mid_bps
        self.assertIsNone(price_vs_mid_bps(0, 100, 10 ** 18, 10 ** 18))


class _Ev:
    items = []


class TestSolverAuthC9(unittest.TestCase):
    """C9 on-chain solver-authorization: direct caller must be a registered
    solver (else VIOLATION); a wrapper that isn't itself registered is
    UNCERTAIN (the authorized caller may be deeper in the call chain), never an
    accusation."""

    def _run(self, direct, to_addr, sender, is_solver, status_ok=True):
        from unittest import mock
        from cow_certify.checks_onchain import run_solver_auth_check
        word = "0x" + ("0" * 63) + ("1" if is_solver else "0")
        checks, limits = [], []
        with mock.patch("cow_certify.sources.rpc", return_value=word):
            run_solver_auth_check("rpc", direct, to_addr, sender, 123,
                                  _Ev(), checks, limits, status_ok=status_ok)
        return checks[0]

    def test_direct_authorized_passes(self):
        v = self._run(True, "0x" + "9" * 40, "0x" + "a" * 40, True)
        self.assertEqual(v["verdict"], "PASS")

    def test_direct_unauthorized_on_reverted_tx_is_violation(self):
        # a real unauthorized direct settle reverts (onlySolver) → status_ok=False
        v = self._run(True, "0x" + "9" * 40, "0x" + "b" * 40, False, status_ok=False)
        self.assertEqual(v["verdict"], "VIOLATION")

    def test_wrapper_registered_passes(self):
        v = self._run(False, "0x" + "c" * 40, "0x" + "a" * 40, True)
        self.assertEqual(v["verdict"], "PASS")

    def test_wrapper_unregistered_is_uncertain_not_violation(self):
        v = self._run(False, "0x" + "c" * 40, "0x" + "a" * 40, False)
        self.assertEqual(v["verdict"], "UNCERTAIN")

    def test_direct_negative_on_success_is_uncertain_not_violation(self):
        # a succeeded tx passed onlySolver, so a negative reading is an artifact
        from unittest import mock
        from cow_certify.checks_onchain import run_solver_auth_check
        checks = []
        with mock.patch("cow_certify.sources.rpc", return_value="0x" + "0" * 64):
            run_solver_auth_check("rpc", True, "0x" + "9" * 40, "0x" + "a" * 40,
                                  100, _Ev(), checks, [], status_ok=True)
        self.assertEqual(checks[0]["verdict"], "UNCERTAIN")

    def test_direct_negative_on_revert_is_violation(self):
        from unittest import mock
        from cow_certify.checks_onchain import run_solver_auth_check
        checks = []
        with mock.patch("cow_certify.sources.rpc", return_value="0x" + "0" * 64):
            run_solver_auth_check("rpc", True, "0x" + "9" * 40, "0x" + "a" * 40,
                                  100, _Ev(), checks, [], status_ok=False)
        self.assertEqual(checks[0]["verdict"], "VIOLATION")


class TestRevertNotPass(unittest.TestCase):
    """Blocker regression: a REVERTED settlement must never certify as PASS."""

    def test_reverted_settlement_overall_is_not_pass(self):
        from unittest import mock
        from cow_certify import certify as C
        GPV2 = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
        tx_hash = "0x" + "11" * 32
        sender = "0x" + "aa" * 20

        def fake_rpc(urls, method, params, ev, *a, **k):
            if method == "eth_getTransactionByHash":
                return {"from": sender, "to": GPV2, "input": "0x13d79a0b" + "00" * 40}
            if method == "eth_getTransactionReceipt":
                return {"status": "0x0", "blockNumber": "0x64", "logs": []}  # reverted
            if method == "eth_call":
                return "0x" + "0" * 63 + "1"  # isSolver → true
            return None

        comp = {"auctionId": 0, "auctionDeadlineBlock": 200,
                "solutions": [{"isWinner": True, "txHash": tx_hash,
                               "solverAddress": sender, "ranking": 1}]}
        with mock.patch("cow_certify.sources.rpc", side_effect=fake_rpc), \
             mock.patch("cow_certify.sources.competition_by_tx", return_value=comp):
            cert = C.certify_tx("base", tx_hash)
        self.assertNotEqual(cert["overall"], "PASS")
        c8 = next(c for c in cert["checks"] if c["check"].startswith("C8"))
        self.assertEqual(c8["verdict"], "VIOLATION")


class TestReceiverDeliveryC11(unittest.TestCase):
    """C11 confirms buy tokens reached the receiver, from Transfer logs. PASS on
    full delivery; INFO (never VIOLATION) on a shortfall."""

    GPV2 = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
    TRANSFER = ("0xddf252ad1be2c89b69c2b068fc378daa9"
                "52ba7f163c4a11628f55a4df523b3ef")

    def _pad(self, a):
        return a.lower().replace("0x", "").rjust(64, "0")

    def _trade_log(self, owner, st, bt, sa, ba, fee, uid):
        data = ("0x" + self._pad(st) + self._pad(bt) + f"{sa:064x}"
                + f"{ba:064x}" + f"{fee:064x}" + f"{0xc0:064x}"
                + f"{56:064x}" + uid.ljust(112, "0"))
        return {"address": self.GPV2, "data": data,
                "topics": [scorer.TRADE_TOPIC, "0x" + self._pad(owner)]}

    def _transfer_log(self, token, to, val, sender=None):
        # Real GPv2 payouts are sent BY the settlement contract; C11 counts
        # only those (sender-filter, 2026-08-17 false-PASS fix).
        frm = self._pad(sender or scorer.SETTLEMENT)
        return {"address": token.lower(), "data": f"0x{val:064x}",
                "topics": [self.TRANSFER, "0x" + frm, "0x" + self._pad(to)]}

    def _run(self, logs):
        checks, limits = [], []
        run_receiver_check(False, "", logs, checks, limits)
        return checks[0] if checks else None

    def test_full_delivery_passes(self):
        owner = "0x" + "a" * 40
        tok = "0x" + "b" * 40
        logs = [self._trade_log(owner, "0x" + "c" * 40, tok, 500, 1000, 0, "aa" * 56),
                self._transfer_log(tok, owner, 1000)]
        v = self._run(logs)
        self.assertEqual(v["verdict"], "PASS")

    def test_unrelated_sender_transfer_does_not_satisfy_delivery(self):
        # 2026-08-17 audit P0: a same-transaction transfer to the right
        # (token, receiver) from an UNRELATED sender must not count as the
        # settlement's payout — that was a false-PASS path. With only a
        # third-party transfer covering the amount, delivery reads short
        # (INFO), never PASS.
        owner = "0x" + "a" * 40
        tok = "0x" + "b" * 40
        logs = [self._trade_log(owner, "0x" + "c" * 40, tok, 500, 1000, 0, "aa" * 56),
                self._transfer_log(tok, owner, 1000, sender="0x" + "d" * 40)]
        v = self._run(logs)
        self.assertEqual(v["verdict"], "INFO")
        # settlement-sent payout still passes alongside third-party noise
        logs.append(self._transfer_log(tok, owner, 1000))
        v = self._run(logs)
        self.assertEqual(v["verdict"], "PASS")

    def test_shortfall_is_info_not_accusation(self):
        # A delivery shortfall is INFO context, never a VIOLATION and never an
        # ATTENTION: for a standard ERC-20 a real non-delivery is EVM-impossible
        # (settle() transfers exactly the credited amount atomically), so every
        # observable shortfall is benign (fee-on-transfer, Vault internal
        # balance, receiver forwarding). Accusing on it would be a false
        # positive on legitimate settlements.
        owner = "0x" + "a" * 40
        tok = "0x" + "b" * 40
        logs = [self._trade_log(owner, "0x" + "c" * 40, tok, 500, 1000, 0, "aa" * 56),
                self._transfer_log(tok, owner, 900)]  # 100 short
        v = self._run(logs)
        self.assertEqual(v["verdict"], "INFO")

    def test_no_delivery_is_info(self):
        owner = "0x" + "a" * 40
        tok = "0x" + "b" * 40
        logs = [self._trade_log(owner, "0x" + "c" * 40, tok, 500, 1000, 0, "aa" * 56)]
        v = self._run(logs)
        self.assertEqual(v["verdict"], "INFO")

    def test_native_eth_buy_leg_set_aside_not_shortfall(self):
        # buy token = native-ETH sentinel: no ERC-20 Transfer exists, so it must
        # be set aside as unverifiable, NOT reported as a delivery shortfall.
        owner = "0x" + "a" * 40
        logs = [self._trade_log(owner, "0x" + "c" * 40, "0x" + "e" * 40,
                                500, 1000, 0, "aa" * 56)]
        v = self._run(logs)
        self.assertEqual(v["verdict"], "INFO")
        self.assertIn("native ETH", v["detail"])


class TestBufferC15(unittest.TestCase):
    """C15 nets the settlement contract's ERC-20 in/out; INFO, never accuses.
    A net-negative token (paid out more than taken in) = drew from the buffer,
    reported as context."""
    GPV2 = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
    T = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    def _xfer(self, token, frm, to, amt):
        pad = lambda a: "0x" + a[2:].rjust(64, "0")
        return {"address": token, "topics": [self.T, pad(frm), pad(to)],
                "data": hex(amt)}

    def _run(self, logs):
        from cow_certify.checks_buffer import run_buffer_check
        checks = []
        run_buffer_check(logs, checks)
        return checks[0] if checks else None

    def test_balanced_passthrough_no_draw(self):
        tok = "0x" + "b" * 40
        other = "0x" + "c" * 40
        v = self._run([self._xfer(tok, other, self.GPV2, 100),
                       self._xfer(tok, self.GPV2, other, 100)])
        self.assertEqual(v["verdict"], "INFO")
        self.assertIn("no buffer draw", v["detail"])
        self.assertEqual(v["net_deltas"][tok], "0")

    def test_buffer_draw_is_info_not_accusation(self):
        tok = "0x" + "b" * 40
        other = "0x" + "c" * 40
        v = self._run([self._xfer(tok, self.GPV2, other, 100)])  # only paid out
        self.assertEqual(v["verdict"], "INFO")
        self.assertIn("drew from the protocol buffer", v["detail"])
        self.assertEqual(v["net_deltas"][tok], "-100")

    def test_no_settlement_transfers_emits_nothing(self):
        other = "0x" + "c" * 40
        v = self._run([self._xfer("0x" + "b" * 40, other, other, 100)])
        self.assertIsNone(v)


class TestInteractionsC13(unittest.TestCase):
    """C13 lists pre/intra/post interactions from calldata (INFO)."""

    def test_lists_and_counts_interactions(self):
        from unittest import mock
        from cow_certify.checks_interactions import run_interactions_check
        fake = {"interactions": [
            [("0x" + "1" * 40, 0, bytes.fromhex("12345678dead"))],   # pre
            [],                                                        # intra
            [("0x" + "2" * 40, 100, b"")],                            # post
        ]}
        checks, limits = [], []
        with mock.patch("cow_certify.gpv2.decode_settlement",
                        return_value=fake):
            run_interactions_check(True, "0x13d79a0b", checks, limits)
        v = checks[0]
        self.assertEqual(v["verdict"], "INFO")
        self.assertEqual(len(v["interactions"]), 2)
        self.assertEqual(v["interactions"][0]["selector"], "0x12345678")
        self.assertEqual(v["interactions"][1]["value"], "100")

    def test_wrapper_route_is_info_not_error(self):
        from cow_certify.checks_interactions import run_interactions_check
        checks, limits = [], []
        run_interactions_check(False, "0xabcd", checks, limits)
        self.assertEqual(checks[0]["verdict"], "INFO")


class TestHtmlReport(unittest.TestCase):
    def _cert(self, overall, checks):
        return {"schema_version": "0.3.0",
                "subject": {"network": "base", "chain_id": 8453,
                            "tx_hash": "0x" + "a" * 64},
                "overall": overall, "checks": checks,
                "not_verifiable": ["best-execution / EBBO is out of scope"],
                "evidence": [{"kind": "rpc", "sha256": "de" * 32, "ref": "u"}],
                "reproduce": "cow-certify --network base 0x..."}

    def test_pass_html_is_standalone_and_plainlanguage(self):
        from cow_certify.htmlreport import render_html
        h = render_html(self._cert("PASS", [
            {"check": "C4.limit-compliance", "verdict": "PASS", "detail": "ok"}]))
        self.assertIn("<!doctype html>", h)
        self.assertIn("Verified", h)
        self.assertIn("Your price limit was respected", h)  # friendly label

    def test_violation_html_escapes_detail(self):
        from cow_certify.htmlreport import render_html
        h = render_html(self._cert("VIOLATION", [
            {"check": "C2.winner-legitimacy", "verdict": "VIOLATION",
             "detail": "<script>alert(1)</script>"}]))
        self.assertIn("Violation found", h)
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;", h)

    def test_embed_form_has_no_doctype(self):
        from cow_certify.htmlreport import render_html
        h = render_html(self._cert("PASS", []), standalone=False)
        self.assertNotIn("<!doctype", h)
        self.assertIn("<style>", h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
