"""Hermetic (no-network) certificate tests against a recorded real settlement.

The shipped fixture corpora are all-PASS, so they can never exercise the
paths where a verifier goes wrong: a node that answers `null`, a receipt
that arrives from a different endpoint than the transaction, a reverted tx
against a non-archive RPC, a custom endpoint carrying a key, malformed API
values. These tests stub the transport (urllib.request.urlopen) with a
recorded Base settlement and mutate ONE thing at a time, asserting the
cardinal rule every time: a legitimate settlement is never accused, and an
accusation is only ever made from an explicit on-chain fact.

Fixture: tests/fixtures/base_0x859d015d.json (real public data, trimmed).
"""
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

from cow_certify import certify as C
from cow_certify import gpv2, sources

with open(os.path.join(HERE, "fixtures", "base_0x859d015d.json"), encoding="utf-8") as _f:
    FIX = json.load(_f)
TX = FIX["tx"]["hash"]
UID = FIX["_provenance"]["settled_uid"]
AID = FIX["comp"]["auctionId"]
BASE_URLS = list(sources.DEFAULT_RPC["base"])
IS_SOLVER = "0x02cc250d"
ONE = "0x" + "0" * 63 + "1"
ZERO = "0x" + "0" * 64


class RAW:
    """Marker: return these exact bytes as the HTTP body (non-JSON etc.)."""
    def __init__(self, body):
        self.body = body


class _Resp:
    def __init__(self, raw):
        self._raw = raw

    def read(self):
        return self._raw


def _http_error(url, code):
    return urllib.error.HTTPError(url, code, f"HTTP {code}", {}, io.BytesIO(b""))


class Transport:
    """A fake network. Default behaviour = the recorded settlement; per-URL
    behaviour can be overridden with `per_url[url] = handler(method, params)`
    which may return a JSON-RPC result, return RAW(bytes), or raise."""

    def __init__(self):
        self.tx = dict(FIX["tx"])
        self.rc = dict(FIX["rc"])
        self.comp = json.loads(json.dumps(FIX["comp"]))
        self.orders = {UID: FIX["order"]}
        self.trades = [{"txHash": TX, "orderUid": UID}]
        self.chain_id = 8453
        self.is_solver = lambda addr, tag: True   # (address, block tag) -> bool | raise
        self.symbol_hex = None                     # override the ERC-20 symbol() result
        self.per_url = {}
        self.calls = []                            # (url, method-or-GET)

    # --- default JSON-RPC behaviour -------------------------------------
    def default_rpc(self, method, params):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getTransactionByHash":
            return self.tx
        if method == "eth_getTransactionReceipt":
            return self.rc
        if method == "eth_call":
            data = (params[0].get("data") or "").lower()
            if data.startswith(IS_SOLVER):
                return ONE if self.is_solver("0x" + data[-40:], params[1]) else ZERO
            if data.startswith("0x313ce567"):            # decimals()
                return "0x" + format(18, "064x")
            if data.startswith("0x95d89b41"):            # symbol()
                if self.symbol_hex is not None:
                    return self.symbol_hex
                return ("0x" + format(32, "064x") + format(4, "064x")
                        + b"TEST".hex().ljust(64, "0"))
            return "0x"
        return None

    # --- urlopen replacement --------------------------------------------
    def urlopen(self, req, timeout=None):
        url = req.full_url
        if req.data:                                    # JSON-RPC POST
            body = json.loads(req.data)
            method, params = body["method"], body["params"]
            self.calls.append((url, method))
            handler = self.per_url.get(url)
            if handler is not None:
                out = handler(method, params)
                if out is RAW or isinstance(out, RAW):
                    return _Resp(out.body)
                if out == "__default__":
                    out = self.default_rpc(method, params)
            else:
                out = self.default_rpc(method, params)
            if isinstance(out, dict) and "__error__" in out:
                return _Resp(json.dumps({"jsonrpc": "2.0", "id": 1,
                                         "error": out["__error__"]}).encode())
            return _Resp(json.dumps({"jsonrpc": "2.0", "id": 1, "result": out}).encode())
        # api.cow.fi GET
        self.calls.append((url, "GET"))
        if "/solver_competition/by_tx_hash/" in url:
            if self.comp is None:
                raise _http_error(url, 404)
            return _Resp(json.dumps(self.comp).encode())
        if "/orders/" in url:
            uid = url.rsplit("/", 1)[1].lower()
            if uid in self.orders:
                return _Resp(json.dumps(self.orders[uid]).encode())
            raise _http_error(url, 404)
        if "/trades?orderUid=" in url:
            return _Resp(json.dumps(self.trades).encode())
        raise _http_error(url, 404)


def certify(tr, network="base", rpc_url=None, ev=None):
    with mock.patch("urllib.request.urlopen", tr.urlopen), \
         mock.patch("time.sleep", lambda s: None):
        kwargs = {"rpc_url": rpc_url}
        if ev is not None:
            kwargs["ev"] = ev
        return C.certify_tx(network, TX, **kwargs)


def check(cert, prefix):
    return next((c for c in cert["checks"] if c["check"].startswith(prefix + ".")), None)


def verdicts(cert):
    return {c["check"].split(".")[0]: c["verdict"] for c in cert["checks"]}


# ---- calldata / log helpers ----------------------------------------------

def canonical_calldata():
    """The fixture's settle() calldata with the autopilot's 8-byte suffix removed."""
    cd = FIX["tx"]["input"]
    assert gpv2.decode_settlement(cd)["suffix_len"] == 8
    return cd[:-16]


def _word(n):
    return format(int(n), "064x")


def trade_log(owner, sell_token, buy_token, sell, buy, fee, uid):
    """A GPv2 Trade event with the same data layout as the real one."""
    uid_hex = uid[2:].lower()
    data = ("0x" + sell_token[2:].lower().rjust(64, "0") + buy_token[2:].lower().rjust(64, "0")
            + _word(sell) + _word(buy) + _word(fee) + _word(0xc0) + _word(0x38)
            + uid_hex.ljust(128, "0"))
    return {"address": gpv2.SETTLEMENT,
            "topics": [gpv2.TRADE_TOPIC, "0x" + owner[2:].lower().rjust(64, "0")],
            "data": data}


def fixture_trade():
    ev = gpv2.trade_events(FIX["rc"]["logs"])
    assert len(ev) == 1
    return ev[0]


# ===========================================================================

class TestBaseline(unittest.TestCase):
    def test_recorded_settlement_certifies_pass(self):
        cert = certify(Transport())
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))
        self.assertIsNone(check(cert, "C8"))
        self.assertEqual(check(cert, "C1")["verdict"], "PASS")
        self.assertEqual(check(cert, "C1")["auction_id"], AID)
        self.assertEqual(check(cert, "C4")["verdict"], "PASS")

    def test_context_checks_never_raise_the_overall_verdict(self):
        # C5/C13/C14 are context. A missing reference price is routine on a
        # long-tail pair and must not turn a valid settlement UNCERTAIN.
        tr = Transport()
        tr.comp["auction"]["prices"] = {}
        cert = certify(tr)
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))
        for cid in ("C5", "C14"):
            c = check(cert, cid)
            self.assertIsNotNone(c, cid)
            self.assertEqual(c["verdict"], "INFO", c)

    def test_malformed_reference_price_does_not_abort_the_certificate(self):
        tr = Transport()
        tr.comp["auction"]["prices"] = {k: "1.5" for k in tr.comp["auction"]["prices"]}
        cert = certify(tr)   # must not raise
        self.assertNotEqual(cert["overall"], "VIOLATION")
        self.assertEqual(check(cert, "C14")["verdict"], "INFO")

    def test_uppercase_hex_calldata_is_still_a_direct_settlement(self):
        tr = Transport()
        tr.tx["input"] = "0x" + tr.tx["input"][2:].upper()
        cert = certify(tr)
        self.assertEqual(check(cert, "C0")["verdict"], "PASS")
        self.assertEqual(check(cert, "C1")["verdict"], "PASS")


class TestReceiptNeverAccusesWithoutAFact(unittest.TestCase):
    """CF-1: a missing receipt is not a revert."""

    def test_null_receipt_everywhere_is_uncertain_not_violation(self):
        tr = Transport()
        tr.rc = None
        cert = certify(tr)
        self.assertNotEqual(cert["overall"], "VIOLATION", verdicts(cert))
        c8 = check(cert, "C8")
        self.assertIsNotNone(c8)
        self.assertEqual(c8["verdict"], "UNCERTAIN", c8)
        self.assertNotIn("VIOLATION", verdicts(cert).values())

    def test_null_receipt_from_one_lagging_node_is_confirmed_elsewhere(self):
        tr = Transport()
        lagging = BASE_URLS[0]
        tr.per_url[lagging] = lambda m, p: None if m == "eth_getTransactionReceipt" else "__default__"
        cert = certify(tr)
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))

    def test_bad_status_read_on_one_node_is_confirmed_elsewhere(self):
        tr = Transport()
        bad = dict(FIX["rc"], status="0x0")
        tr.per_url[BASE_URLS[0]] = lambda m, p: bad if m == "eth_getTransactionReceipt" else "__default__"
        cert = certify(tr)
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))

    def test_receipt_without_a_status_field_is_uncertain(self):
        tr = Transport()
        tr.rc = {k: v for k, v in FIX["rc"].items() if k != "status"}
        cert = certify(tr)
        self.assertEqual(check(cert, "C8")["verdict"], "UNCERTAIN")
        self.assertNotIn("VIOLATION", verdicts(cert).values())

    def test_true_revert_on_every_node_is_still_a_violation(self):
        tr = Transport()
        tr.rc = dict(FIX["rc"], status="0x0", logs=[])
        cert = certify(tr)
        self.assertEqual(check(cert, "C8")["verdict"], "VIOLATION")
        self.assertEqual(cert["overall"], "VIOLATION")

    def test_single_custom_rpc_is_not_the_only_witness(self):
        """CF-5: with --rpc-url, an apparent revert is confirmed against the
        built-in endpoints too, so one flaky paid node cannot accuse alone."""
        tr = Transport()
        custom = "https://my-node.example/rpc"
        bad = dict(FIX["rc"], status="0x0")
        tr.per_url[custom] = lambda m, p: bad if m == "eth_getTransactionReceipt" else "__default__"
        cert = certify(tr, rpc_url=custom)
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))

    def test_c6_names_the_missing_receipt_not_the_record(self):
        tr = Transport()
        tr.rc = None
        cert = certify(tr)
        c6 = check(cert, "C6")
        self.assertIsNotNone(c6)
        self.assertIn("receipt", c6["detail"].lower())


class TestSolverAuthorizationC9(unittest.TestCase):
    """CF-4: a `latest` reading may not accuse."""

    def _reverted(self):
        tr = Transport()
        tr.rc = dict(FIX["rc"], status="0x0", logs=[])
        return tr

    def test_latest_fallback_on_reverted_tx_is_uncertain(self):
        tr = self._reverted()

        def is_solver(addr, tag):
            if tag != "latest":
                raise RuntimeError("missing trie node")   # non-archive node
            return False                                   # de-registered since
        tr.is_solver = is_solver
        cert = certify(tr)
        c9 = check(cert, "C9")
        self.assertEqual(c9["verdict"], "UNCERTAIN", c9)

    def test_pinned_negative_on_reverted_tx_may_accuse(self):
        tr = self._reverted()
        tr.is_solver = lambda addr, tag: False
        cert = certify(tr)
        self.assertEqual(check(cert, "C9")["verdict"], "VIOLATION")

    def test_rpc_null_result_is_not_an_interpreter_error_in_the_cert(self):
        tr = Transport()
        tr.per_url[BASE_URLS[0]] = lambda m, p: None if m == "eth_call" else "__default__"
        tr.per_url[BASE_URLS[1]] = tr.per_url[BASE_URLS[0]]
        tr.per_url[BASE_URLS[2]] = tr.per_url[BASE_URLS[0]]
        cert = certify(tr)
        c9 = check(cert, "C9")
        self.assertNotIn("int()", c9["detail"])
        self.assertNotIn("NoneType", c9["detail"])


class TestTransport(unittest.TestCase):
    def test_non_json_200_rotates_to_the_next_endpoint(self):
        """CF-14: a Cloudflare interstitial served as 200 is a failed endpoint,
        not the end of the certificate."""
        tr = Transport()
        tr.per_url[BASE_URLS[0]] = lambda m, p: RAW(b"<html>error 1015</html>")
        cert = certify(tr)
        self.assertEqual(cert["overall"], "PASS", verdicts(cert))

    def test_custom_rpc_key_never_reaches_the_certificate(self):
        """CF-22: an RPC error message must not carry the endpoint URL."""
        tr = Transport()
        custom = "https://node.example/v2/SECRETKEY123"

        def handler(m, p):
            if m == "eth_call":
                return {"__error__": {"code": -32602, "message": "archive requests require a token"}}
            return "__default__"
        tr.per_url[custom] = handler
        cert = certify(tr, rpc_url=custom)
        blob = json.dumps(cert)
        self.assertNotIn("SECRETKEY123", blob)
        self.assertNotIn("node.example/v2", blob)

    def test_safe_url_strips_userinfo(self):
        self.assertEqual(sources._safe_url("https://user:pw@host.example/path?key=abc"),
                         "https://host.example")
        self.assertEqual(sources._safe_url("https://host.example:8545/v2/KEY"),
                         "https://host.example:8545")

    def test_no_dead_default_endpoints(self):
        flat = [u for urls in sources.DEFAULT_RPC.values() for u in urls]
        for dead in ("llamarpc.com", "polygon-rpc.com"):
            self.assertFalse(any(dead in u for u in flat), dead)

    def test_evidence_can_be_threaded_from_the_caller(self):
        """CF-31: the --order path's trades lookup must land in the ledger."""
        tr = Transport()
        ev = sources.Evidence()
        with mock.patch("urllib.request.urlopen", tr.urlopen), mock.patch("time.sleep", lambda s: None):
            sources.trades_by_order("base", UID, ev)
        cert = certify(tr, ev=ev)
        self.assertIn("orderbook:trades", [e["kind"] for e in cert["evidence"]])


class TestAuctionBindingC1(unittest.TestCase):
    """CF-2 (Python side): the autopilot appends exactly 8 bytes. Anything
    else is not an autopilot suffix and may not be read as one."""

    def test_wrong_8_byte_suffix_on_canonical_calldata_is_a_violation(self):
        tr = Transport()
        tr.tx["input"] = canonical_calldata() + format(AID + 1, "016x")
        cert = certify(tr)
        self.assertEqual(check(cert, "C1")["verdict"], "VIOLATION")

    def test_16_byte_tail_is_not_read_as_an_auction_id(self):
        tr = Transport()
        tr.tx["input"] = canonical_calldata() + "00" * 8 + format(AID + 1, "016x")
        cert = certify(tr)
        c1 = check(cert, "C1")
        self.assertNotEqual(c1["verdict"], "VIOLATION", c1)
        self.assertNotEqual(cert["overall"], "VIOLATION")

    def test_no_suffix_is_api_side_binding_only(self):
        tr = Transport()
        tr.tx["input"] = canonical_calldata()
        cert = certify(tr)
        c1 = check(cert, "C1")
        self.assertIn(c1["verdict"], ("INFO", "UNCERTAIN"))
        self.assertNotIn("wrapper", c1["detail"].lower())


class TestSolutionFidelityC3(unittest.TestCase):
    """CF-6: an unlisted settled uid that is ALSO not an auction user order
    is most likely a liquidity leg the record did not carry — investigate,
    do not accuse. An unlisted uid that IS a user order of the auction is a
    real discrepancy."""

    def _with_extra_trade(self, uid):
        tr = Transport()
        e = fixture_trade()
        tr.rc["logs"] = list(FIX["rc"]["logs"]) + [
            trade_log("0x" + "ab" * 20, e["sell_token"], e["buy_token"], 10 ** 18, 1, 0, uid)]
        return tr

    def test_unlisted_non_auction_uid_is_uncertain(self):
        cert = certify(self._with_extra_trade("0x" + "cd" * 56))
        c3 = check(cert, "C3")
        self.assertEqual(c3["verdict"], "UNCERTAIN", c3)
        self.assertNotEqual(cert["overall"], "VIOLATION")

    def test_unlisted_auction_user_order_is_a_violation(self):
        other = next(u for u in FIX["comp"]["auction"]["orders"] if u.lower() != UID)
        cert = certify(self._with_extra_trade(other))
        self.assertEqual(check(cert, "C3")["verdict"], "VIOLATION")


class TestCliContract(unittest.TestCase):
    def _main(self, argv, tr=None):
        from cow_certify import __main__ as M
        tr = tr or Transport()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", tr.urlopen), \
             mock.patch("time.sleep", lambda s: None), \
             mock.patch.object(sys, "argv", ["cow-certify"] + argv), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                M.main()
                code = 0
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_typoed_hash_is_operational_exit_3(self):
        code, _, err = self._main(["--network", "base", "0xdeadbeef"])
        self.assertEqual(code, 3, err)

    def test_bad_order_uid_is_operational_exit_3(self):
        code, _, _ = self._main(["--network", "base", "--order", "0xzz"])
        self.assertEqual(code, 3)

    def test_unknown_network_is_operational_exit_3(self):
        code, _, _ = self._main(["--network", "notachain", TX])
        self.assertEqual(code, 3)

    def test_json_is_json_only_with_out_and_html(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = self._main(["--network", "base", TX, "--json",
                                       "--out", os.path.join(d, "c.json"),
                                       "--html", os.path.join(d, "c.html")])
            self.assertEqual(code, 0)
            json.loads(out)   # must parse: nothing but the certificate on stdout
            self.assertTrue(os.path.exists(os.path.join(d, "c.html")))

    def test_json_is_json_only_on_the_order_path(self):
        code, out, _ = self._main(["--network", "base", "--order", UID, "--json"])
        self.assertEqual(code, 0)
        cert = json.loads(out)
        self.assertIn("orderbook:trades", [e["kind"] for e in cert["evidence"]])

    def test_pass_exits_0_and_violation_exits_1(self):
        code, _, _ = self._main(["--network", "base", TX, "--no-color"])
        self.assertEqual(code, 0)
        tr = Transport()
        tr.rc = dict(FIX["rc"], status="0x0", logs=[])
        code, _, _ = self._main(["--network", "base", TX, "--no-color"], tr)
        self.assertEqual(code, 1)


class TestBatchContract(unittest.TestCase):
    def _batch(self, lines, tr):
        import tempfile

        from cow_certify import batch as B
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            corpus = os.path.join(d, "c.csv")
            with open(corpus, "w") as f:
                f.write("\n".join(lines) + "\n")
            with mock.patch("urllib.request.urlopen", tr.urlopen), \
                 mock.patch("time.sleep", lambda s: None), \
                 mock.patch.object(sys, "argv", ["cow-certify-batch", corpus, "--out",
                                                 os.path.join(d, "certs"), "--sleep", "0"]), \
                 redirect_stdout(out):
                return B.main(), out.getvalue()

    def test_clean_batch_exits_0(self):
        code, _ = self._batch([f"base,{TX}"], Transport())
        self.assertEqual(code, 0)

    def test_fetch_error_or_unknown_network_exits_3(self):
        code, out = self._batch([f"base,{TX}", f"notachain,{TX}"], Transport())
        self.assertEqual(code, 3, out)
        self.assertNotIn("KeyError", out)

    def test_violation_exits_1(self):
        tr = Transport()
        tr.rc = dict(FIX["rc"], status="0x0", logs=[])
        code, _ = self._batch([f"base,{TX}"], tr)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
