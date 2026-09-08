"""cow-certify CLI: verify any CoW Protocol settlement from public data.

  cow-certify --network base 0x<settlement_tx_hash>
  cow-certify --network mainnet --order 0x<order_uid>
  cow-certify --network base --penalty-cap <auction_id> --env staging   # CIP-87 replay
"""
import argparse
import json
import re
import sys

from . import penalty_cap, sources
from .certify import certify_tx, render_text

_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_UID_RE = re.compile(r"^0x[0-9a-fA-F]{112}$")  # 56-byte order uid

# Exit-code contract (documented in --help): the VERDICT codes 0/1/2 must be
# distinguishable from an OPERATIONAL failure, so a CI job can tell "the solver
# cheated" (1) from "you typo'd the hash / the RPC was down" (3).
_EXIT_OPERATIONAL = 3
_VERDICT_EXIT = {"PASS": 0, "VIOLATION": 1, "UNCERTAIN": 2}


def _fail(msg):
    print(f"cow-certify: {sources.redact(msg)}", file=sys.stderr)
    sys.exit(_EXIT_OPERATIONAL)


def _status(msg):
    """Progress/status lines go to stderr so `--json` stdout stays pipeable."""
    print(msg, file=sys.stderr)


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on bad input — the code this tool reserves for the
    UNCERTAIN verdict. Bad input is an OPERATIONAL failure (3)."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(_EXIT_OPERATIONAL)


def _utf8_safe_streams():
    # The human render uses ✓ ✗ → glyphs. Under a C/POSIX locale (Docker,
    # cron, minimal CI) stdout is ASCII and printing them raises; degrade the
    # glyphs instead of crashing after the certificate was already computed.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def main():
    _utf8_safe_streams()
    ap = _Parser(
        prog="cow-certify",
        description="Independent, public-data verification for a CoW Protocol "
                    "settlement. Paste a settlement tx (or your order id) and "
                    "get a reproducible verdict with the evidence to re-check "
                    "it yourself.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  cow-certify --network base 0x<settlement_tx_hash>\n"
               "  cow-certify --network mainnet --order 0x<order_uid>\n"
               "  cow-certify --network arbitrum 0x<tx> --json --out cert.json\n"
               "  cow-certify --network base --penalty-cap 153714586 --env staging\n"
               "\nexit codes: 0 PASS · 1 VIOLATION · 2 UNCERTAIN · "
               "3 operational error (bad input, RPC/API unreachable)\n"
               "--penalty-cap: 0 every order MATCHes · 2 any order that is a "
               "DIFFERENCE, has no published cap, or could not be replayed (a "
               "finding, never a violation) · 3 operational\n"
               "--json prints ONLY the certificate JSON on stdout; status lines "
               "go to stderr.\n")
    ap.add_argument("tx_hash", nargs="?", help="settlement transaction hash")
    ap.add_argument("--order", help="order UID (resolves to its settlement tx)")
    ap.add_argument("--network", required=True, choices=list(sources.NETWORKS),
                    help="which CoW chain the settlement is on")
    ap.add_argument("--penalty-cap", metavar="AUCTION_ID",
                    help="CIP-87 mode: recompute every order's penalty cap from the "
                         "public auction body and compare with the published "
                         "penaltyCapNative")
    ap.add_argument("--env", choices=list(sources.BUCKET_ENVS), default=None,
                    help="--penalty-cap only: which instance-bucket environment the "
                         "auction id belongs to (default prod)")
    ap.add_argument("--retained-lookback", type=int, default=0, metavar="N",
                    help="--penalty-cap only: when the body carries no price for the usd "
                         "reference token, look back up to N prior auction bodies for the "
                         "price the autopilot retained (default 0 = off)")
    ap.add_argument("--strict", action="store_true",
                    help="--penalty-cap only: compare against the stated config only, "
                         "no inference of correlated/bound regimes")
    ap.add_argument("--rpc-url", help="override the default public RPC")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also print the full per-order ledger")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="print the full certificate JSON (and nothing else) on stdout")
    ap.add_argument("--out", help="write certificate JSON to this path")
    ap.add_argument("--html", metavar="FILE",
                    help="write a shareable HTML certificate to this path")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    args = ap.parse_args()

    # One evidence ledger for the whole run, so a fetch made to CHOOSE the
    # subject (the --order path's trades lookup) is cited in the certificate.
    ev = sources.Evidence()
    if args.penalty_cap is not None:
        _penalty_cap_mode(ap, args, ev)
        return
    if args.env is not None or args.strict or args.retained_lookback:
        ap.error("--env, --strict and --retained-lookback only apply to --penalty-cap")
    tx = args.tx_hash
    if args.order and not tx:
        if not _UID_RE.match(args.order.strip()):
            ap.error("--order must be a 0x-prefixed 112-hex-character order uid "
                     "(the id shown on CoW Explorer)")
        try:
            trades = sources.trades_by_order(args.network, args.order.strip(), ev)
        except Exception as e:
            _fail(f"could not reach the CoW orderbook API: {e}")
        if not trades:
            _fail(f"order not found on {args.network}, or it hasn't traded "
                  f"yet — is --network correct?")
        # An order can be filled across several settlements; certify the most
        # recent by default and tell the user the rest exist.
        tx_hashes = [t.get("txHash") for t in trades if t.get("txHash")]
        uniq = list(dict.fromkeys(tx_hashes))
        if not uniq:
            _fail("order has trades but no settlement txHash recorded yet")
        tx = uniq[-1]
        extra = (f" (of {len(uniq)} settlements for this order; pass a specific "
                 f"tx hash to certify another)" if len(uniq) > 1 else "")
        _status(f"order {args.order[:20]}… settled in {tx}{extra}\n")

    if not tx:
        ap.error("provide a settlement tx hash, or --order <uid>")
    tx = tx.strip()
    if not _HASH_RE.match(tx):
        ap.error(f"'{tx}' is not a valid transaction hash "
                 f"(expected 0x followed by 64 hex characters)")

    try:
        cert = certify_tx(args.network, tx, rpc_url=args.rpc_url, ev=ev)
    except SystemExit as e:
        # certify_tx signals unrecoverable input problems (e.g. tx not found)
        # via SystemExit(str); surface as an operational failure (exit 3), not
        # exit 1 (which would read as a VIOLATION verdict).
        _fail(str(e.code) if e.code is not None else "could not certify")
    except Exception as e:
        msg = sources.redact(e)
        if "all RPC endpoints failed" in msg:
            _fail(f"couldn't reach a working RPC for {args.network}. "
                  f"Retry, or pass --rpc-url <your endpoint>.")
        _fail(f"could not certify {tx[:12]}… on {args.network}: {msg[:160]}")

    if args.as_json:
        # JSON only — so the output is pipeable (a CI job / `jq` must not get
        # the human render or any status line prepended or appended).
        print(json.dumps(cert, indent=2))
    else:
        print(render_text(cert, color=(False if args.no_color else None)))
        if args.verbose:
            _print_ledger(cert)
    try:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(cert, f, indent=2)
            _status(f"\ncertificate written: {args.out}")
        if args.html:
            from .htmlreport import render_html
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(render_html(cert))
            _status(f"\nHTML certificate written: {args.html}")
    except (OSError, UnicodeError) as e:
        _fail(f"could not write output file: {e}")

    sys.exit(_VERDICT_EXIT.get(cert["overall"], 0))


_PENALTY_EXIT = {penalty_cap.MATCH: 0, penalty_cap.DIFFERENCE: 2,
                 penalty_cap.NO_PUBLISHED_CAP: 2, penalty_cap.NOT_COMPUTABLE: 2}


def _penalty_cap_mode(ap, args, ev):
    """`--penalty-cap AUCTION_ID`: replay CIP-87 caps for one public auction body."""
    if args.tx_hash or args.order:
        ap.error("--penalty-cap takes an auction id and cannot be combined with a "
                 "settlement tx hash or --order")
    aid = args.penalty_cap.strip()
    if not aid.isdigit():
        ap.error(f"'{aid}' is not an auction id (expected a decimal integer, e.g. 153714586)")
    if args.network not in sources.BUCKET_CHAINS:
        ap.error(f"no public instance bucket for {args.network}; --penalty-cap supports "
                 f"{', '.join(sources.BUCKET_CHAINS)}")
    if args.rpc_url:
        ap.error("--rpc-url is not used by --penalty-cap (the replay reads only the public "
                 "instance bucket)")
    env = args.env or "prod"
    if args.retained_lookback < 0:
        ap.error("--retained-lookback must be >= 0")
    try:
        rep = penalty_cap.replay(args.network, int(aid), env=env,
                                 strict=args.strict, ev=ev,
                                 retained_lookback=args.retained_lookback)
    except SystemExit as e:
        _fail(str(e.code) if e.code is not None else "could not replay")
    except Exception as e:
        _fail(f"could not replay auction {aid} on {args.network} ({env}): "
              f"{sources.redact(e)[:160]}")
    if args.as_json:
        print(penalty_cap.to_json(rep))
    else:
        print(penalty_cap.render_text(rep))
    try:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2)
            _status(f"\nreport written: {args.out}")
        if args.html:
            _status("--html is not available for --penalty-cap reports (use --json / --out)")
    except (OSError, UnicodeError) as e:
        _fail(f"could not write output file: {e}")
    sys.exit(_PENALTY_EXIT.get(rep["overall"], 2))


def _print_ledger(cert):
    led = next((c for c in cert["checks"] if c["check"].startswith("C10")), None)
    orders = (led or {}).get("orders") or []
    if not orders:
        return
    print("\n  per-order ledger:")
    for i, o in enumerate(orders, 1):
        st, bt = o["sell_token"], o["buy_token"]
        ssym = st.get("symbol") or st["address"][:10] + "…"
        bsym = bt.get("symbol") or bt["address"][:10] + "…"
        sh = o.get("executed_sell_human") or o["executed_sell"]
        bh = o.get("executed_buy_human") or o["executed_buy"]
        kind = o.get("kind", "trade")
        print(f"    {i}. {kind}  {sh} {ssym} → {bh} {bsym}")
        bits = []
        if o.get("executed_price"):
            bits.append(f"exec price {o['executed_price']}")
        if o.get("limit_price"):
            bits.append(f"limit {o['limit_price']}")
        if o.get("fill_fraction"):
            bits.append(f"fill {o['fill_fraction']}")
        if o.get("surplus_atoms"):
            bits.append(f"surplus {o['surplus_atoms']} {o.get('surplus_token') or ''}".strip())
        if bits:
            print("       " + "  ·  ".join(bits))
        print(f"       owner {o['owner']}  ·  uid {o['uid'][:22]}…")


if __name__ == "__main__":
    main()
