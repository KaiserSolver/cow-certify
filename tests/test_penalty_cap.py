"""CIP-87 penalty-cap replay: arithmetic vectors pinned to the autopilot's own
semantics, plus hermetic (no-network) replays of recorded staging auction
bodies served through a stubbed transport, mutated one thing at a time.

Fixtures (tests/fixtures/penalty_cap_staging_*.json) are real public auction
bodies from the solver-instances bucket, trimmed (liquidity dropped, tokens
limited to what the kept orders reference). Each carries the autopilot's
published `penaltyCapNative` per order, so every fixture is a vector of
(inputs, expected output) produced by the reference implementation:
  base     2 bps, four partially fillable sell orders (cap on the FULL amount)
  bnb      1 bps sell order
  mainnet  USDT->USDC at the correlated 0.1 bps, and a 10,000 WETH buy order
           where the $20 bound binds (bound = 20e6 x price(USDC) / 1e18)
  gnosis   3 bps sell order
"""
import gzip
import io
import json
import os
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from cow_certify import penalty_cap as pc  # noqa: E402

FIX = {}
for _name in os.listdir(os.path.join(HERE, "fixtures")):
    if _name.startswith("penalty_cap_staging_"):
        with open(os.path.join(HERE, "fixtures", _name), encoding="utf-8") as _f:
            _body = json.load(_f)
        FIX[_name.split("_")[3]] = _body          # chain segment: base / bnb / mainnet / xdai

NETWORK_OF = {"base": "base", "bnb": "bnb", "mainnet": "mainnet", "xdai": "gnosis"}
USDC_MAINNET = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WETH_MAINNET = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"


class _Resp:
    def __init__(self, raw):
        self._raw = raw

    def read(self):
        return self._raw


def _http_error(url, code):
    return urllib.error.HTTPError(url, code, f"HTTP {code}", {}, io.BytesIO(b""))


class Transport:
    """Serves the fixture bodies the way the bucket does: gzip-compressed JSON
    at <bucket>/<env>/<chain>/auction/<id>.json, 404 elsewhere."""

    def __init__(self, bodies=None, plain=False):
        self.bodies = bodies if bodies is not None else dict(FIX)
        self.plain = plain
        self.calls = []

    def urlopen(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        for chain, body in self.bodies.items():
            if f"/staging/{chain}/auction/{body['id']}.json" in url:
                raw = json.dumps(body).encode()
                return _Resp(raw if self.plain else gzip.compress(raw))
        raise _http_error(url, 404)


def replay_with(tr, network, auction_id, **kw):
    with mock.patch("urllib.request.urlopen", tr.urlopen), \
         mock.patch("time.sleep", lambda s: None):
        return pc.replay(network, auction_id, env="staging", **kw)


def _cli(argv):
    from cow_certify.__main__ import main
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(sys, "argv", ["cow-certify"] + argv), \
         redirect_stdout(out), redirect_stderr(err):
        try:
            main()
            code = 0
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, out.getvalue(), err.getvalue()


# ===========================================================================
# arithmetic, pinned to services (crates/autopilot/src/domain/penalty_cap.rs,
# crates/configs/src/autopilot/penalty_cap.rs)
# ===========================================================================

class TestArithmetic(unittest.TestCase):
    def test_factor_scaling_is_parts_per_million(self):
        self.assertEqual(pc.bps_to_ppm(2), 200)
        self.assertEqual(pc.bps_to_ppm(0.1), 10)
        self.assertEqual(pc.bps_to_ppm(4), 400)
        with self.assertRaises(ValueError):
            pc.bps_to_ppm(0.005)          # 0.5 ppm: services rejects it too

    def test_apply_factor_matches_upstream_unit_test(self):
        # 0.1 bps of 1e18 is 1e13 (services' own test vector); U256::MAX overflows.
        self.assertEqual(pc.apply_factor(10 ** 18, 10), 10 ** 13)
        self.assertIsNone(pc.apply_factor(pc.U256_MAX, 10))
        self.assertEqual(pc.apply_factor(0, 200), 0)

    def test_apply_factor_floors(self):
        # 999_999 x 200 / 1e6 = 199.9998 -> 199 (integer division, no rounding up)
        self.assertEqual(pc.apply_factor(999_999, 200), 199)

    def test_volume_is_amount_times_price_over_wad(self):
        self.assertEqual(pc.volume_native(2 * 10 ** 18, 5 * 10 ** 17), 10 ** 18)
        self.assertIsNone(pc.volume_native(10, None))
        self.assertIsNone(pc.volume_native(pc.U256_MAX, 2))          # checked_mul -> None

    def test_absolute_cap_conversion_and_overflow(self):
        # $20 through a 6-decimal reference priced at 4.03296899690465115712258048e26
        # (mainnet staging 2026-09-07) -> 8065937993809302 wei, the published value.
        self.assertEqual(pc.absolute_cap_native(20, 6, 403296899690465115712258048),
                         8065937993809302)
        self.assertEqual(pc.absolute_cap_native(20, 6, pc.U256_MAX), pc.U256_MAX)

    def test_usd_cap_atoms_rounds_like_upstream_f64(self):
        # upstream: (usd * 10^dec).round() in f64 - fractional bounds are not truncated
        self.assertEqual(pc.usd_cap_atoms(20, 6), 20_000_000)
        self.assertEqual(pc.usd_cap_atoms(20, 18), 20 * 10 ** 18)          # bnb USDC has 18 decimals
        self.assertEqual(pc.usd_cap_atoms(20.5, 6), 20_500_000)
        self.assertEqual(pc.usd_cap_atoms(0.5, 6), 500_000)
        self.assertEqual(pc.usd_cap_atoms(0.0000005, 6), 1)                # .5 rounds away from zero
        with self.assertRaises(ValueError):
            pc.usd_cap_atoms(-1, 6)

    def test_factor_range_guard_matches_upstream(self):
        with self.assertRaises(ValueError):
            pc.bps_to_ppm(-3)                                              # factor < 0
        with self.assertRaises(ValueError):
            pc.bps_to_ppm(10_000)                                          # factor 1.0 is out of [0, 1)
        self.assertEqual(pc.bps_to_ppm(0), 0)
        self.assertEqual(pc.bps_to_ppm(9_999.99), 999_999)

    def test_int_or_none_never_coerces_loosely(self):
        self.assertEqual(pc._int_or_none("42"), 42)
        self.assertEqual(pc._int_or_none(42), 42)
        for bad in (True, False, 1.5, "0x2a", "1.5", "", "  ", None, [1], {"a": 1}):
            self.assertIsNone(pc._int_or_none(bad), bad)

    def test_override_precedence_is_first_match(self):
        a, b, c = "0xa", "0xb", "0xc"
        overrides = [{"name": "first", "tokens": {a, b}, "ppm": 10},
                     {"name": "second", "tokens": {a, b, c}, "ppm": 50}]
        self.assertEqual(pc.factor_for(a, b, overrides, 200), (10, "override:first"))
        self.assertEqual(pc.factor_for(a, c, overrides, 200), (50, "override:second"))
        self.assertEqual(pc.factor_for(b, c, overrides[:1], 200), (200, "default"))
        # both tokens must be in the SAME set
        self.assertEqual(pc.factor_for(a, "0xd", overrides, 200), (200, "default"))


class TestOrderReplay(unittest.TestCase):
    """Synthetic orders through replay_order, one branch at a time."""

    def setUp(self):
        self.cfg = pc.cip87_config("base")
        self.usdc = self.cfg["usd_reference"][0]
        self.weth = self.cfg["wrapped_native"]
        self.prices = {self.weth: 10 ** 18, self.usdc: 4 * 10 ** 26,
                       "0x00000000000000000000000000000000000000aa": 10 ** 15}
        self.decimals = {self.weth: 18, self.usdc: 6,
                         "0x00000000000000000000000000000000000000aa": 18}

    def order(self, **kw):
        o = {"uid": "0x" + "11" * 56, "kind": "sell", "sellToken": self.weth,
             "buyToken": self.usdc, "fullSellAmount": str(10 ** 18), "sellAmount": str(10 ** 17),
             "fullBuyAmount": "1", "buyAmount": "1", "partiallyFillable": True}
        o.update(kw)
        return o

    def run_order(self, o, **kw):
        return pc.replay_order(o, self.prices, self.decimals, self.cfg, **kw)

    def test_sell_order_uses_the_signed_full_amount(self):
        # 1 WETH at price 1e18 -> volume 1e18 -> 2 bps = 2e14 (NOT 2e13 from the remaining 0.1)
        r = self.run_order(self.order(penaltyCapNative=str(2 * 10 ** 14)))
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["regime"], "volume_factor")
        self.assertEqual(r["volume_amount"], 10 ** 18)
        self.assertFalse(r["inferred"])

    def test_buy_order_uses_buy_amount_and_buy_token_price(self):
        o = self.order(kind="buy", sellToken=self.usdc, buyToken=self.weth,
                       fullBuyAmount=str(3 * 10 ** 18), buyAmount=str(3 * 10 ** 18),
                       penaltyCapNative=str(6 * 10 ** 14))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["volume_token"], self.weth)
        self.assertEqual(r["volume_native"], 3 * 10 ** 18)

    def test_native_eth_placeholder_maps_to_wrapped(self):
        o = self.order(kind="buy", sellToken=self.usdc, buyToken=pc.BUY_ETH,
                       fullBuyAmount=str(10 ** 18), penaltyCapNative=str(2 * 10 ** 14))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["volume_token"], self.weth)

    def test_bound_binds_for_large_volume(self):
        # 10,000 WETH -> volume cap 2 ETH; bound = 20e6 x 4e26 / 1e18 = 8e15
        o = self.order(fullSellAmount=str(10_000 * 10 ** 18), penaltyCapNative=str(8 * 10 ** 15))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["regime"], "absolute_bound")
        self.assertEqual(r["volume_cap"], 2 * 10 ** 18)

    def test_transition_where_volume_cap_equals_bound(self):
        # volume cap == bound exactly: min() picks either; expected value is that number
        # bound 8e15; volume cap 8e15 needs volume 4e19 -> 40 WETH
        o = self.order(fullSellAmount=str(40 * 10 ** 18), penaltyCapNative=str(8 * 10 ** 15))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["volume_cap"], r["absolute_bound"])

    def test_missing_price_falls_back_to_the_bound_not_zero(self):
        o = self.order(sellToken="0x00000000000000000000000000000000000000bb",
                       penaltyCapNative=str(8 * 10 ** 15))
        r = self.run_order(o)
        self.assertIsNone(r["volume_native"])
        self.assertEqual(r["expected_regime"], "no_price_fallback")
        self.assertEqual(r["expected_cap"], 8 * 10 ** 15)
        self.assertEqual(r["verdict"], pc.MATCH)
        # and a published 0 for such an order is a DIFFERENCE, not accepted silently
        r0 = self.run_order(self.order(sellToken="0x00000000000000000000000000000000000000bb",
                                       penaltyCapNative="0"))
        self.assertEqual(r0["verdict"], pc.DIFFERENCE)

    def test_correlated_regime_is_inferred_and_marked(self):
        # published = 0.1 bps of volume: not the stated config (2 bps) -> inferred match
        o = self.order(penaltyCapNative=str(10 ** 13))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["regime"], "correlated_override")
        self.assertTrue(r["inferred"])
        self.assertEqual(r["expected_cap"], 2 * 10 ** 14)     # what the stated config says
        # the value and factor that actually matched are recorded, not just the verdict
        self.assertEqual(r["matched_by"], {"regime": "correlated_override", "factor_ppm": 10,
                                           "value": 10 ** 13})
        self.assertEqual(r["candidates"]["stated_config"], 2 * 10 ** 14)
        self.assertEqual(r["candidates"]["correlated_0.1bps"], 10 ** 13)
        self.assertIn("INFERRED", r["detail"])
        # strict mode refuses to infer
        rs = self.run_order(o, strict=True)
        self.assertEqual(rs["verdict"], pc.DIFFERENCE)
        self.assertEqual(rs["candidates"]["correlated_0.1bps"], 10 ** 13)

    def test_declared_override_makes_correlated_a_stated_match(self):
        cfg = pc.cip87_config("base", overrides=[{"name": "stables", "bps": 0.1,
                                                   "tokens": [self.weth, self.usdc]}])
        r = pc.replay_order(self.order(penaltyCapNative=str(10 ** 13)), self.prices,
                            self.decimals, cfg, strict=True)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["factor_source"], "override:stables")
        self.assertFalse(r["inferred"])

    def test_bound_through_another_token_is_inferred(self):
        # published equals $20 through token 0x..aa (18 decimals, price 1e15):
        # 20e18 x 1e15 / 1e18 = 2e16, and it is below the 2 ETH volume cap
        o = self.order(fullSellAmount=str(10_000 * 10 ** 18), penaltyCapNative=str(2 * 10 ** 16))
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(r["regime"], "absolute_bound")
        self.assertTrue(r["inferred"])
        self.assertEqual(r["bound_token_inferred"], "0x00000000000000000000000000000000000000aa")
        self.assertEqual(r["matched_by"]["value"], 2 * 10 ** 16)
        self.assertEqual(self.run_order(o, strict=True)["verdict"], pc.DIFFERENCE)

    def test_ambiguous_bound_tokens_are_all_listed(self):
        prices = dict(self.prices)
        prices["0x00000000000000000000000000000000000000cc"] = 10 ** 15
        decimals = dict(self.decimals)
        decimals["0x00000000000000000000000000000000000000cc"] = 18
        o = self.order(fullSellAmount=str(10_000 * 10 ** 18), penaltyCapNative=str(2 * 10 ** 16))
        r = pc.replay_order(o, prices, decimals, self.cfg)
        self.assertEqual(r["verdict"], pc.MATCH)
        self.assertEqual(sorted(r["bound_token_inferred"]),
                         ["0x00000000000000000000000000000000000000aa",
                          "0x00000000000000000000000000000000000000cc"])
        self.assertIn("ambiguous", r["detail"])

    def test_unreproducible_value_is_a_difference_with_candidates(self):
        r = self.run_order(self.order(penaltyCapNative=str(2 * 10 ** 14 + 1)))
        self.assertEqual(r["verdict"], pc.DIFFERENCE)
        self.assertIn("stated_config", r["candidates"])
        self.assertIn("correlated_0.1bps", r["candidates"])
        self.assertIn("not an accusation", r["detail"])

    def test_no_published_cap_still_reports_the_expectation(self):
        r = self.run_order(self.order())
        self.assertEqual(r["verdict"], pc.NO_PUBLISHED_CAP)
        self.assertEqual(r["expected_cap"], 2 * 10 ** 14)

    def test_malformed_inputs_are_not_computable(self):
        self.assertEqual(self.run_order(self.order(kind="swap"))["verdict"], pc.NOT_COMPUTABLE)
        self.assertEqual(self.run_order(self.order(fullSellAmount="x"))["verdict"], pc.NOT_COMPUTABLE)
        # a present-but-unparseable cap is NOT reported as "no cap published"
        r = self.run_order(self.order(penaltyCapNative=[1, 2]))
        self.assertEqual(r["verdict"], pc.NOT_COMPUTABLE)
        self.assertIn("not a decimal integer", r["detail"])

    def test_no_fallback_from_the_signed_amount_to_the_remaining_amount(self):
        # a body without fullSellAmount cannot be replayed; the remaining sellAmount
        # is never substituted (it would manufacture a DIFFERENCE and blame the cap)
        o = self.order(penaltyCapNative=str(2 * 10 ** 14))
        o.pop("fullSellAmount")
        r = self.run_order(o)
        self.assertEqual(r["verdict"], pc.NOT_COMPUTABLE)
        self.assertIn("fullSellAmount missing", r["detail"])
        # and only the side matching the kind is required
        o2 = self.order(penaltyCapNative=str(2 * 10 ** 14))
        o2.pop("fullBuyAmount")
        self.assertEqual(self.run_order(o2)["verdict"], pc.MATCH)
        self.assertEqual(self.run_order(o2)["amount_field"], "fullSellAmount")

    def test_overflowing_bound_is_uncapped(self):
        prices = dict(self.prices)
        prices[self.usdc] = pc.U256_MAX
        o = self.order(penaltyCapNative=str(2 * 10 ** 14))
        r = pc.replay_order(o, prices, self.decimals, self.cfg)
        self.assertEqual(r["absolute_bound"], pc.U256_MAX)
        self.assertEqual(r["verdict"], pc.MATCH)          # min(volume cap, MAX) = volume cap

    def test_config_rejects_unknown_network(self):
        with self.assertRaises(ValueError):
            pc.cip87_config("sepolia")


# ===========================================================================
# hermetic replays of recorded staging bodies
# ===========================================================================

class TestRecordedBodies(unittest.TestCase):
    def test_every_fixture_matches_the_published_caps(self):
        for chain, body in FIX.items():
            rep = replay_with(Transport(), NETWORK_OF[chain], body["id"])
            self.assertEqual(rep["overall"], pc.MATCH, (chain, rep["summary"]))
            self.assertEqual(rep["summary"]["verdicts"], {pc.MATCH: len(body["orders"])})
            self.assertEqual(rep["subject"]["env"], "staging")
            self.assertEqual(rep["subject"]["auction_id"], body["id"])
            self.assertTrue(rep["evidence"] and rep["evidence"][0]["kind"] == "instances:staging")

    def test_regimes_per_chain(self):
        base = replay_with(Transport(), "base", FIX["base"]["id"])
        self.assertEqual(base["summary"]["regimes"], {"volume_factor": 4})
        self.assertEqual(base["summary"]["inferred_matches"], 0)
        self.assertTrue(all(o["partially_fillable"] for o in base["orders"]))
        bnb = replay_with(Transport(), "bnb", FIX["bnb"]["id"])
        self.assertEqual(bnb["orders"][0]["factor_ppm"], 100)                  # 1 bps
        gno = replay_with(Transport(), "gnosis", FIX["xdai"]["id"])
        self.assertEqual(gno["orders"][0]["factor_ppm"], 300)                  # 3 bps
        main = replay_with(Transport(), "mainnet", FIX["mainnet"]["id"])
        regimes = {o["buy_token"]: (o["regime"], o["inferred"]) for o in main["orders"]}
        self.assertEqual(regimes[USDC_MAINNET], ("correlated_override", True))   # USDT->USDC
        self.assertEqual(regimes[WETH_MAINNET], ("absolute_bound", False))       # $20 via USDC
        self.assertFalse(main["config"]["usd_reference_assumed"])

    def test_verification_status_is_stated_per_chain(self):
        # base's 2 bps default is confirmed by published caps; mainnet's 4 bps is
        # CIP text only (its published caps were all correlated or bound-bound).
        base = replay_with(Transport(), "base", FIX["base"]["id"])
        self.assertTrue(base["config"]["default_factor_verified"])
        self.assertFalse(any("not yet been confirmed" in lim for lim in base["not_verifiable"]))
        main = replay_with(Transport(), "mainnet", FIX["mainnet"]["id"])
        self.assertFalse(main["config"]["default_factor_verified"])
        self.assertTrue(any("4 bps default factor for mainnet" in lim
                            for lim in main["not_verifiable"]))
        self.assertTrue(main["config"]["reference_commit"].startswith("cowprotocol/services@d4bc7947"))
        # the CIP-text-vs-implementation basis note is always present
        self.assertTrue(any("follows the implementation" in lim for lim in main["not_verifiable"]))

    def test_mainnet_correlated_is_a_difference_in_strict_mode(self):
        main = replay_with(Transport(), "mainnet", FIX["mainnet"]["id"], strict=True)
        self.assertEqual(main["overall"], pc.DIFFERENCE)
        v = {o["buy_token"]: o["verdict"] for o in main["orders"]}
        self.assertEqual(v[USDC_MAINNET], pc.DIFFERENCE)
        self.assertEqual(v[WETH_MAINNET], pc.MATCH)                              # bound needs no inference

    def test_mainnet_declared_override_removes_the_inference(self):
        usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7"
        main = replay_with(Transport(), "mainnet", FIX["mainnet"]["id"], strict=True,
                           overrides=[{"name": "stables", "bps": 0.1, "tokens": [usdt, USDC_MAINNET]}])
        self.assertEqual(main["overall"], pc.MATCH)
        self.assertEqual(main["summary"]["inferred_matches"], 0)

    def test_one_wei_off_is_a_difference_never_a_violation(self):
        body = json.loads(json.dumps(FIX["base"]))
        body["orders"][0]["penaltyCapNative"] = str(int(body["orders"][0]["penaltyCapNative"]) + 1)
        rep = replay_with(Transport({"base": body}), "base", body["id"])
        self.assertEqual(rep["overall"], pc.DIFFERENCE)
        self.assertEqual(rep["orders"][0]["verdict"], pc.DIFFERENCE)
        self.assertNotIn("VIOLATION", json.dumps(rep))

    def test_body_without_caps_reports_expectations(self):
        body = json.loads(json.dumps(FIX["base"]))
        for o in body["orders"]:
            o.pop("penaltyCapNative")
        rep = replay_with(Transport({"base": body}), "base", body["id"])
        self.assertEqual(rep["overall"], pc.NO_PUBLISHED_CAP)
        self.assertTrue(all(o["expected_cap"] is not None for o in rep["orders"]))

    def test_one_match_never_vouches_for_unverified_siblings(self):
        # overall is the WORST order verdict: exit 0 must mean every order matched
        body = json.loads(json.dumps(FIX["base"]))
        body["orders"][1].pop("penaltyCapNative")
        rep = replay_with(Transport({"base": body}), "base", body["id"])
        self.assertEqual(rep["overall"], pc.NO_PUBLISHED_CAP)
        self.assertEqual(rep["summary"]["verdicts"], {pc.MATCH: 3, pc.NO_PUBLISHED_CAP: 1})
        body["orders"][2]["kind"] = "swap"
        rep = replay_with(Transport({"base": body}), "base", body["id"])
        self.assertEqual(rep["overall"], pc.NOT_COMPUTABLE)
        tr = Transport({"base": body})
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None):
            code, out, err = _cli(["--network", "base", "--penalty-cap", str(body["id"]),
                                   "--env", "staging", "--no-color"])
        self.assertEqual(code, 2, err)
        self.assertIn("2 matched", out)

    def test_gnosis_match_with_unknown_bound_is_explained_in_text(self):
        # the assumed reference token has no price in the Gnosis body: the match is
        # sound (published == volume cap) but the caveat must be visible in the render
        rep = replay_with(Transport(), "gnosis", FIX["xdai"]["id"])
        self.assertEqual(rep["overall"], pc.MATCH)
        self.assertIsNone(rep["orders"][0]["absolute_bound"])
        self.assertEqual(rep["summary"]["matches_with_unknown_bound"], 1)
        text = pc.render_text(rep)
        self.assertIn("bound not computable", text)
        main = replay_with(Transport(), "mainnet", FIX["mainnet"]["id"])
        self.assertIn("INFERRED", pc.render_text(main))

    def test_missing_reference_price_uses_the_fallback_path(self):
        body = json.loads(json.dumps(FIX["base"]))
        sell = body["orders"][0]["sellToken"]
        body["tokens"][sell]["referencePrice"] = None
        rep = replay_with(Transport({"base": body}), "base", body["id"])
        o = rep["orders"][0]
        self.assertIsNone(o["volume_native"])
        self.assertEqual(o["expected_regime"], "no_price_fallback")
        self.assertEqual(o["expected_cap"], o["absolute_bound"])
        self.assertEqual(o["verdict"], pc.DIFFERENCE)     # the published value was a volume cap

    def test_plain_json_body_is_accepted_too(self):
        rep = replay_with(Transport(plain=True), "base", FIX["base"]["id"])
        self.assertEqual(rep["overall"], pc.MATCH)

    def test_missing_body_is_an_input_problem(self):
        with self.assertRaises(SystemExit):
            replay_with(Transport(), "base", 1)

    def test_no_sepolia_bucket(self):
        with self.assertRaises(ValueError):
            replay_with(Transport(), "sepolia", 1)


class TestCli(unittest.TestCase):
    def test_json_output_and_exit_code(self):
        tr = Transport()
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None):
            code, out, err = _cli(["--network", "base", "--penalty-cap",
                                   str(FIX["base"]["id"]), "--env", "staging", "--json"])
        self.assertEqual(code, 0, err)
        rep = json.loads(out)                     # stdout is JSON only
        self.assertEqual(rep["kind"], pc.KIND)
        self.assertEqual(rep["overall"], pc.MATCH)

    def test_difference_exits_2_and_text_render(self):
        body = json.loads(json.dumps(FIX["base"]))
        body["orders"][1]["penaltyCapNative"] = "7"
        tr = Transport({"base": body})
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None):
            code, out, err = _cli(["--network", "base", "--penalty-cap",
                                   str(body["id"]), "--env", "staging", "--no-color"])
        self.assertEqual(code, 2, err)
        self.assertIn("DIFFERENCE", out)
        self.assertIn("candidate stated_config", out)

    def test_bad_inputs_are_operational_errors(self):
        code, _, err = _cli(["--network", "base", "--penalty-cap", "0xabc"])
        self.assertEqual(code, 3, err)
        code, _, err = _cli(["--network", "sepolia", "--penalty-cap", "5"])
        self.assertEqual(code, 3, err)
        code, _, err = _cli(["--network", "base", "--penalty-cap", "5", "0x" + "ab" * 32])
        self.assertEqual(code, 3, err)
        code, _, err = _cli(["--network", "base", "--penalty-cap", "5", "--rpc-url", "https://x"])
        self.assertEqual(code, 3, err)
        self.assertIn("not used by --penalty-cap", err)

    def test_env_and_strict_only_with_penalty_cap(self):
        code, _, err = _cli(["--network", "base", "--env", "staging", "0x" + "ab" * 32])
        self.assertEqual(code, 3, err)
        self.assertIn("only apply to --penalty-cap", err)
        code, _, err = _cli(["--network", "base", "--strict", "0x" + "ab" * 32])
        self.assertEqual(code, 3, err)

    def test_text_render_lists_at_most_max_listed_orders(self):
        body = json.loads(json.dumps(FIX["base"]))
        template = body["orders"][0]
        body["orders"] = []
        for i in range(pc.MAX_LISTED + 5):
            o = dict(template)
            o["uid"] = "0x" + format(i, "0112x")
            body["orders"].append(o)
        tr = Transport({"base": body})
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None):
            code, out, err = _cli(["--network", "base", "--penalty-cap",
                                   str(body["id"]), "--env", "staging", "--no-color"])
        self.assertEqual(code, 0, err)
        self.assertIn("5 more orders not listed", out)
        # per-order lines are indented "       published <n>"; the banner's
        # "the published penaltyCapNative" must not be counted
        self.assertEqual(out.count("\n       published "), pc.MAX_LISTED)

    def test_missing_body_exits_3(self):
        tr = Transport()
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None):
            code, _, err = _cli(["--network", "base", "--penalty-cap", "1", "--env", "staging"])
        self.assertEqual(code, 3, err)
        self.assertIn("no staging auction body", err)


if __name__ == "__main__":
    unittest.main()
