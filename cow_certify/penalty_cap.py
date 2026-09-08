"""CIP-87 penalty-cap replay: an independent implementation of the per-order
penalty cap the autopilot publishes as `penaltyCapNative`, computed from the
same public auction body and compared with the published value.

Why this exists. CIP-87 (forum.cow.fi/t/3520, Snapshot passed 2026-08-25)
replaces the flat penalty cap with `min(factor x volume, $20)` per order. The
autopilot computes it (cowprotocol/services, crates/autopilot/src/domain/
penalty_cap.rs) and writes it into every order of the auction it hands to
solvers. That auction body is public: solver-instances.s3.eu-central-1.
amazonaws.com/<env>/<chain>/auction/<id>.json. Everything the calculation
consumes is inside the body too (order amounts, the per-token native prices),
so the cap can be recomputed from scratch and diffed against the published
number - two independent implementations of one formula, compared on the
same inputs. (services#2667, cited for checks C1-C3, is about the settlement
circuit breaker; it is not a statement about penalty caps.)

What is mirrored, line by line against services `main` at commit
d4bc7947eb49992ed1d71bb93514211f546c7ca9 (2026-09-07; crates/autopilot/src/
domain/penalty_cap.rs, crates/configs/src/autopilot/penalty_cap.rs, the
call site in crates/autopilot/src/solvable_orders.rs and the driver's body
mapping in crates/driver/src/infra/solver/dto/auction.rs):
  volume  = amount x price / 1e18            (SIGNED sell amount for sell
                                              orders, signed buy amount for buy
                                              orders - `fullSellAmount` /
                                              `fullBuyAmount` in the body; the
                                              native-ETH placeholder mapped to
                                              the wrapped token)
  factor  = first override whose token set holds BOTH the sell token and the
            wrapped buy token, else the chain default
  vcap    = volume x round(factor x 1e6) / 1e6   (PenaltyFactor::apply_to)
  bound   = $20 x 10^dec(ref) x price(ref) / 1e18  (usd reference token)
  cap     = min(vcap, bound)
Fallbacks that are easy to get wrong and are mirrored deliberately: no price
for the volume token (or a multiplication overflow) makes the cap the BOUND,
not zero; an overflow converting the bound makes it U256::MAX (uncapped).

Two things the CIP text says differently from the code, noted so nobody
"fixes" the replay toward the text: CIP-87 defines the basis as the order's
QUOTE (buy amount net of volume fees for sell orders, sell amount plus fees
for buy orders); the implementation values the order's own sell side (sell
orders) or buy side (buy orders) at the auction's reference prices. And the
CIP's scaling of the cap to the executed fraction of a partially fillable
order happens at penalty time, not in the published per-order cap: the body
carries the cap for the full signed amount, and that is what is replayed.
The published number is the implementation's, so the replay follows the code.

What is not public. The override token sets ("correlated" pairs) and the usd
reference token are autopilot deployment config. This module ships CIP-87's
numbers and a per-chain USDC default, and when the published value is only
reproducible under the 0.1 bps correlated factor or under a bound derived
from a different token, it says so explicitly (`inferred: true`) instead of
guessing silently; `strict=True` disables inference. A stale reference price
(the autopilot keeps its last value when the reference token has no price in
a cycle) is not observable from outside; the replay uses this auction's price.

Never-accuse rule, applied to accounting: a value the replay cannot reproduce
is reported as DIFFERENCE with every candidate it tried - a finding to take to
the core team, never a "violation". This is rewards accounting, not settlement
safety, and the tool has no standing to call it anything else.
"""
import json
import math
import time

from . import __version__, sources

SCHEMA_VERSION = "0.3.0"          # penalty-cap report format (independent of certificates)
VECTOR_SCHEMA = "cow-certify/penalty-cap-vectors/2"
KIND = "penalty_cap_replay"

MATCH = "MATCH"
DIFFERENCE = "DIFFERENCE"
NO_PUBLISHED_CAP = "NO_PUBLISHED_CAP"
NOT_COMPUTABLE = "NOT_COMPUTABLE"

U256_MAX = (1 << 256) - 1
WAD = 10 ** 18
FACTOR_SCALE = 1_000_000          # PenaltyFactor::HIGH_PRECISION_SCALE
BUY_ETH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

# CIP-87 initial defaults per chain, basis points of the order's native volume
# (forum.cow.fi/t/3520 text as of 2026-08-19; Snapshot passed 2026-08-25). The
# core team holds a mandate to retune within [0, 10] bps with notice, so these
# are the CIP's numbers, not a live read of the deployed config. Sepolia is
# not in the CIP and has no instance bucket.
DEFAULT_FACTOR_BPS = {
    "mainnet": 4, "gnosis": 3, "arbitrum": 1, "base": 2, "avalanche": 2,
    "polygon": 3, "bnb": 1, "linea": 2, "ink": 1, "plasma": 1,
}
# Chains whose default factor has been CONFIRMED by exactly reproducing
# published staging caps in the volume-factor regime (2026-09-07 corpus).
# Mainnet's published caps were all correlated or bound-bound, so its 4 bps
# is the CIP text only; polygon/linea/ink/plasma publish no cap yet.
DEFAULT_FACTOR_VERIFIED = {"base", "gnosis", "arbitrum", "bnb", "avalanche"}
# 0.1 bps: the VALUE is confirmed by exact reproduction of 41 published caps;
# which token pairs are in the correlated sets stays inferred (no public config).
CORRELATED_FACTOR_BPS = 0.1
ABSOLUTE_CAP_USD = 20             # "bounded by the equivalent of $20" - confirmed on mainnet

# Wrapped native token per chain: the target of the autopilot's BUY_ETH
# mapping. Every address below was read back from a live prod auction body
# (symbol + address + decimals) on 2026-09-07.
WRAPPED_NATIVE = {
    "mainnet": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "arbitrum": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
    "base": "0x4200000000000000000000000000000000000006",
    "gnosis": "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d",
    "polygon": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
    "avalanche": "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",
    "bnb": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "linea": "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f",
    "ink": "0x4200000000000000000000000000000000000006",
    "plasma": "0x6100e367285b01f48d07953803a2d8dca5d19873",
}

# Usd reference token (address, decimals) the $20 bound is converted through.
# services' own config example uses mainnet USDC, and mainnet staging data
# reproduces the published bound exactly through USDC's price (2026-09-07).
# On every other chain this is an ASSUMPTION (native-issue USDC where two
# exist; Plasma has no USDC in its auctions, USDT0 is the only dollar token
# there), reported as such until a bound-binding order confirms it.
USD_REFERENCE = {
    "mainnet": ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
    "arbitrum": ("0xaf88d065e77c8cc2239327c5edb3a432268e5831", 6),
    "base": ("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
    "gnosis": ("0xddafbb505ad214d7b80b1f830fccc89b60fb7a83", 6),
    "polygon": ("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", 6),
    "avalanche": ("0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", 6),
    "bnb": ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
    "linea": ("0x176211869ca2b568f2a7d4ee941e073a821ee1ff", 6),
    "ink": ("0x2d270e6886d130d724215a266106e6832161eaed", 6),
    "plasma": ("0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb", 6),
}
USD_REFERENCE_CONFIRMED = {"mainnet"}   # confirmed from published bound-binding caps


# ---------------------------------------------------------------------------
# arithmetic, mirrored from the autopilot
# ---------------------------------------------------------------------------

def bps_to_ppm(bps):
    """A PenaltyFactor is stored as parts-per-million (round(factor x 1e6));
    1 bps = 100 ppm. services rejects factors outside [0, 1) and factors that
    do not scale to an integer (tolerance 1e-6), so the replay does too."""
    factor = bps / 10_000
    if not 0.0 <= factor < 1.0:
        raise ValueError(f"factor {bps} bps is outside [0, 10000) bps")
    ppm = factor * FACTOR_SCALE
    if abs(ppm - round(ppm)) >= 1e-6:
        raise ValueError(f"factor {bps} bps is not a multiple of 0.01 bps")
    return int(round(ppm))


def apply_factor(amount, ppm):
    """PenaltyFactor::apply_to: amount x ppm / 1e6, None on U256 overflow."""
    prod = amount * ppm
    if prod > U256_MAX:
        return None
    return prod // FACTOR_SCALE


def volume_native(amount, price):
    """Order volume in native wei: amount x price / 1e18, None on overflow (the
    autopilot's checked_mul, which then falls back to the absolute bound)."""
    if price is None:
        return None
    prod = amount * price
    if prod > U256_MAX:
        return None
    return prod // WAD


def usd_cap_atoms(usd_cap, ref_decimals):
    """Upstream converts the USD bound to reference-token atoms in f64:
    `(absolute_cap_usd * 10f64.powi(dec)).round()` (round half away from
    zero) - mirrored with the same float arithmetic, so a fractional bound
    (the CIP allows retuning) lands on the same integer."""
    x = float(usd_cap) * (10.0 ** int(ref_decimals))
    if x < 0:
        raise ValueError("usd cap must be non-negative")
    return int(math.floor(x + 0.5))


def absolute_cap_native(usd_cap, ref_decimals, ref_price):
    """The $ bound in native wei: atoms(usd) x price(ref) / 1e18. An overflow
    yields U256::MAX - an uncapped order - exactly as upstream."""
    prod = usd_cap_atoms(usd_cap, ref_decimals) * ref_price
    if prod > U256_MAX:
        return U256_MAX
    return prod // WAD


def min_reference_price(expected_cap, usd_cap, ref_decimals):
    """The smallest usd reference price (native wei per 10^18 atoms) at which the
    absolute bound is still >= `expected_cap`, i.e. at which the published value
    keeps coming from the volume factor: bound(price) = atoms * price // 1e18 >=
    expected  <=>  price >= ceil(expected * 1e18 / atoms). A literal
    implementation constructed with ANY price at or above it returns
    `expected_cap`; one wei below it the bound binds and it returns the bound."""
    atoms = usd_cap_atoms(usd_cap, ref_decimals)
    if expected_cap is None or atoms <= 0:
        return None
    return -(-int(expected_cap) * 10 ** 18 // atoms)


def retained_reference_price(network, env, auction_id, token, ev, lookback):
    """The autopilot keeps the last price it fetched for the usd reference token
    when a cycle brings none (Gnosis staging lists the token in every body with a
    null price). The body publishes the same price map the calculator reads, so
    the retained value is the price in the most recent PRIOR body that carried
    one - unless the autopilot restarted in between (its startup fetch is never
    published). Walks back up to `lookback` auction ids; every fetch is recorded
    as evidence. Returns (price, from_auction_id, bodies_scanned)."""
    scanned = 0
    for back in range(1, int(lookback) + 1):
        aid = int(auction_id) - back
        if aid < 0:
            break
        body = sources.auction_body(network, aid, ev, env=env)
        if not isinstance(body, dict):
            continue
        scanned += 1
        prices, _ = body_prices(body)
        p = prices.get(token)
        if p is not None:
            return p, aid, scanned
    return None, None, scanned


def factor_for(sell, buy_wrapped, overrides, default_ppm):
    """First override whose token set contains BOTH tokens wins (Vec order),
    else the default. `overrides` = [{"name", "tokens": set, "ppm"}]."""
    for ov in overrides:
        if sell in ov["tokens"] and buy_wrapped in ov["tokens"]:
            return ov["ppm"], "override:" + ov.get("name", "?")
    return default_ppm, "default"


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def cip87_config(network, overrides=None, usd_reference=None, default_bps=None,
                 absolute_cap_usd=ABSOLUTE_CAP_USD):
    """The replay's parameters for one network. Anything not fixed by the CIP
    text is marked assumed so the report can say so."""
    if network not in DEFAULT_FACTOR_BPS or network not in WRAPPED_NATIVE:
        raise ValueError(f"no CIP-87 parameters for network '{network}'")
    bps = DEFAULT_FACTOR_BPS[network] if default_bps is None else default_bps
    ref = usd_reference if usd_reference is not None else USD_REFERENCE.get(network)
    ovs = []
    for ov in overrides or []:
        ovs.append({"name": ov.get("name", "override"),
                    "tokens": {t.lower() for t in ov["tokens"]},
                    "ppm": bps_to_ppm(ov["bps"])})
    return {
        "network": network,
        "cip": "CIP-87",
        "default_bps": bps,
        "default_ppm": bps_to_ppm(bps),
        "default_factor_verified": (default_bps is None
                                    and network in DEFAULT_FACTOR_VERIFIED),
        "reference_commit": "cowprotocol/services@d4bc7947eb49992ed1d71bb93514211f546c7ca9",
        "correlated_bps": CORRELATED_FACTOR_BPS,
        "correlated_ppm": bps_to_ppm(CORRELATED_FACTOR_BPS),
        "overrides": ovs,
        "absolute_cap_usd": absolute_cap_usd,
        "usd_reference": (ref[0].lower(), int(ref[1])) if ref else None,
        "usd_reference_assumed": (usd_reference is None
                                  and network not in USD_REFERENCE_CONFIRMED),
        "wrapped_native": WRAPPED_NATIVE[network],
    }


def _config_public(cfg, prices=None, ref_info=None):
    out = dict(cfg)
    out["overrides"] = [{"name": o["name"], "bps": o["ppm"] / 100,
                         "tokens": sorted(o["tokens"])} for o in cfg["overrides"]]
    if cfg["usd_reference"]:
        out["usd_reference"] = {"token": cfg["usd_reference"][0],
                                "decimals": cfg["usd_reference"][1],
                                # the price this body carried for the reference token
                                # (None when absent: the bound was not computable)
                                "price": (prices or {}).get(cfg["usd_reference"][0])}
        if ref_info:
            out["usd_reference"].update({
                # the token being listed in the body without any order using it is
                # public evidence that it IS the deployed reference token
                "token_in_body": ref_info.get("in_body"),
                "price_in_body": ref_info.get("price_in_body"),
                "retained_price": ref_info.get("retained_price"),
                "retained_from_auction": ref_info.get("retained_from_auction"),
                "retained_scanned": ref_info.get("retained_scanned"),
            })
    return out


# ---------------------------------------------------------------------------
# vectors: self-contained (inputs, expected) records a second implementation
# can consume - the shared fixture that connects this replay to any other
# implementation (services' own Rust tests included)
# ---------------------------------------------------------------------------

def order_vector(network, env, auction_id, order, res, prices, decimals, cfg):
    """A vector for one MATCHed order: every input the formula consumes, verbatim
    from the body, plus the configuration that reproduces the published value.
    Inferred regimes are made explicit (a declared override for a correlated
    match; the matched token as the usd reference for an inferred bound), so a
    literal implementation of the formula reproduces `expected_cap` without
    knowing anything about inference."""
    if res.get("verdict") != MATCH:
        return None
    sell = res["sell_token"]
    buy = res["buy_token"]
    buy_w = cfg["wrapped_native"] if buy == BUY_ETH else buy
    overrides = [{"tokens": sorted(o["tokens"]), "factor_ppm": o["ppm"]} for o in cfg["overrides"]]
    if res.get("regime") == "correlated_override" and res.get("inferred"):
        overrides = [{"tokens": sorted({sell, buy_w}), "factor_ppm": cfg["correlated_ppm"]}] + overrides
    bi = res.get("absolute_bound_inputs") or {}
    ref_token, ref_dec = bi.get("token"), bi.get("decimals")
    # The usd reference price the calculator must be constructed with: the body's
    # own when it carried one; else the retained value recovered from a prior body
    # (only when it does not contradict the published cap); else unknown - then
    # `min_usd_reference_price` is the provable threshold.
    ref_price_out, ref_src = None, None
    if ref_token:
        if bi.get("price") is not None:
            ref_price_out, ref_src = bi["price"], "auction"
        elif bi.get("retained_price") is not None and bi.get("retained_consistent"):
            ref_price_out, ref_src = bi["retained_price"], f"retained:{bi['retained_from_auction']}"
        elif bi.get("token_in_body"):
            ref_src = "unpublished"     # listed in the body with a null price
        else:
            ref_src = "absent"
    vec_prices = {}
    if res.get("volume_price") is not None:
        vec_prices[res["volume_token"]] = str(res["volume_price"])
    if ref_token and bi.get("price") is not None:
        vec_prices[ref_token] = str(bi["price"])
    return {
        "id": f"{network}/{env}/{auction_id}/{order.get('uid')}",
        "network": network, "env": env, "auction_id": auction_id, "order_uid": order.get("uid"),
        "order": {"kind": order.get("kind"), "sell_token": sell, "buy_token": buy,
                  "sell_amount": str(_int_or_none(order.get("fullSellAmount"))),
                  "buy_amount": str(_int_or_none(order.get("fullBuyAmount")))},
        "prices": vec_prices,
        "config": {"default_factor_ppm": cfg["default_ppm"], "overrides": overrides,
                   "absolute_cap_usd": cfg["absolute_cap_usd"],
                   "usd_reference_token": ref_token, "usd_reference_decimals": ref_dec,
                   "wrapped_native": cfg["wrapped_native"]},
        "expected_cap": str(res["published_cap"]),
        "regime": res.get("regime"), "inferred": bool(res.get("inferred")),
        "usd_reference_price": str(ref_price_out) if ref_price_out is not None else None,
        "usd_reference_price_source": ref_src,
        "usd_reference_token_in_body": bi.get("token_in_body") if ref_token else None,
        "min_usd_reference_price": (str(res["min_usd_reference_price"])
                                    if res.get("min_usd_reference_price") is not None else None),
        "reference_commit": cfg.get("reference_commit"),
    }


def cap_from_vector(v):
    """Recompute a vector's cap from ITS OWN fields only (no body, no network,
    no inference) - the arithmetic a foreign implementation must reproduce."""
    o, c = v["order"], v["config"]
    prices = {k.lower(): int(p) for k, p in v["prices"].items()}
    kind = o["kind"]
    sell, buy = o["sell_token"].lower(), o["buy_token"].lower()
    wrapped = c["wrapped_native"].lower()
    tok, amount = (sell, int(o["sell_amount"])) if kind == "sell" else (buy, int(o["buy_amount"]))
    tok_w = wrapped if tok == BUY_ETH else tok
    buy_w = wrapped if buy == BUY_ETH else buy
    overrides = [{"tokens": {t.lower() for t in ov["tokens"]}, "ppm": ov["factor_ppm"],
                  "name": "vector"} for ov in c.get("overrides", [])]
    ppm, _ = factor_for(sell, buy_w, overrides, c["default_factor_ppm"])
    volume = volume_native(amount, prices.get(tok_w))
    volume_cap = apply_factor(volume, ppm) if volume is not None else None
    ref_price = prices.get((c.get("usd_reference_token") or "").lower())
    if ref_price is None and v.get("usd_reference_price") is not None:
        ref_price = int(v["usd_reference_price"])
    bound = (absolute_cap_native(c["absolute_cap_usd"], c["usd_reference_decimals"], ref_price)
             if ref_price is not None and c.get("usd_reference_decimals") is not None else None)
    if volume_cap is None:
        return bound
    if bound is None:
        return volume_cap
    return min(volume_cap, bound)


# ---------------------------------------------------------------------------
# per-order replay
# ---------------------------------------------------------------------------

def _int_or_none(v):
    """An integer from a JSON number or decimal string; anything else (null,
    bool, float, hex, list) is None - the replay never coerces loosely."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def body_prices(body):
    """{address: native price} and {address: decimals} from the body's tokens
    map. A null/malformed referencePrice counts as no price (the fallback path)."""
    prices, decimals = {}, {}
    for addr, meta in (body.get("tokens") or {}).items():
        a = str(addr).lower()
        if not isinstance(meta, dict):
            continue
        p = _int_or_none(meta.get("referencePrice"))
        if p is not None and p >= 0:
            prices[a] = p
        d = _int_or_none(meta.get("decimals"))
        if d is not None:
            decimals[a] = d
    return prices, decimals


def replay_order(order, prices, decimals, cfg, strict=False, ref_info=None):
    """Recompute one order's cap and compare with the published value."""
    res = {"uid": order.get("uid"), "kind": order.get("kind"),
           "sell_token": str(order.get("sellToken", "")).lower(),
           "buy_token": str(order.get("buyToken", "")).lower(),
           "partially_fillable": bool(order.get("partiallyFillable"))}
    raw_cap = order.get("penaltyCapNative")
    published = _int_or_none(raw_cap)
    res["published_cap"] = published
    if raw_cap is not None and published is None:
        res.update(verdict=NOT_COMPUTABLE,
                   detail=f"penaltyCapNative is present but not a decimal integer "
                          f"({str(raw_cap)[:40]!r}); nothing to compare against")
        return res
    kind = order.get("kind")
    if kind not in ("sell", "buy"):
        res.update(verdict=NOT_COMPUTABLE, detail=f"unknown order kind {kind!r}")
        return res
    # The autopilot uses the SIGNED amount of the side matching the kind
    # (order.data.sell_amount / buy_amount). In the solver-engine body those
    # are fullSellAmount / fullBuyAmount; sellAmount / buyAmount are the
    # remaining, fee-adjusted part of a partially fillable order and are NEVER
    # used as a fallback - a body without the signed field cannot be replayed.
    amount_field = "fullSellAmount" if kind == "sell" else "fullBuyAmount"
    amount = _int_or_none(order.get(amount_field))
    if amount is None:
        res.update(verdict=NOT_COMPUTABLE,
                   detail=f"{amount_field} missing or malformed; the replay needs the signed "
                          f"amount and does not fall back to the remaining amount")
        return res
    res["amount_field"] = amount_field
    sell, buy = res["sell_token"], res["buy_token"]
    wrapped = cfg["wrapped_native"]
    tok = sell if kind == "sell" else buy
    tok_w = wrapped if tok == BUY_ETH else tok
    buy_w = wrapped if buy == BUY_ETH else buy
    price = prices.get(tok_w)
    volume = volume_native(amount, price)
    ppm, factor_source = factor_for(sell, buy_w, cfg["overrides"], cfg["default_ppm"])
    volume_cap = apply_factor(volume, ppm) if volume is not None else None
    ref = cfg["usd_reference"]
    ref_price = prices.get(ref[0]) if ref else None
    bound = (absolute_cap_native(cfg["absolute_cap_usd"], ref[1], ref_price)
             if ref_price is not None else None)
    res.update({
        "volume_token": tok_w, "volume_amount": amount, "volume_price": price,
        "volume_native": volume, "factor_ppm": ppm, "factor_source": factor_source,
        "volume_cap": volume_cap, "absolute_bound": bound,
        # Every input behind the bound, kept verbatim so the branch can be
        # recomputed from the report alone after the body leaves the bucket.
        "absolute_bound_inputs": ({"token": ref[0], "decimals": ref[1], "price": ref_price,
                                   "usd": cfg["absolute_cap_usd"]} if ref else None),
    })
    ri = ref_info or {}
    abi = res["absolute_bound_inputs"]
    if abi is not None:
        abi["token_in_body"] = ri.get("in_body")
        abi["price_in_body"] = ref_price is not None
        if ref_price is None:
            abi["retained_scanned"] = ri.get("retained_scanned")
            if ri.get("retained_price") is not None:
                abi["retained_price"] = ri["retained_price"]
                abi["retained_from_auction"] = ri.get("retained_from_auction")
                abi["bound_from_retained"] = absolute_cap_native(
                    cfg["absolute_cap_usd"], ref[1], ri["retained_price"])
    # The threshold below which the bound would have overtaken the published value
    # (meaningful when the published cap came from the volume side).
    res["min_usd_reference_price"] = (min_reference_price(published, cfg["absolute_cap_usd"], ref[1])
                                      if ref and published is not None else None)
    if abi is not None and abi.get("bound_from_retained") is not None and published is not None:
        abi["retained_consistent"] = abi["bound_from_retained"] >= published

    # Expected value under the STATED configuration.
    if volume_cap is None:
        expected, regime = bound, "no_price_fallback"        # bound, not zero
    elif bound is None:
        expected, regime = volume_cap, "volume_factor"       # bound unknown; see note
    else:
        expected = min(volume_cap, bound)
        regime = "volume_factor" if expected == volume_cap else "absolute_bound"
    res["expected_cap"] = expected
    res["expected_regime"] = regime
    res["inferred"] = False
    # Every value the replay can derive from this body, always reported, so a
    # consumer never has to trust the verdict without the numbers behind it.
    candidates = {"stated_config": expected}
    corr_alt = None
    if volume is not None:
        corr_cap = apply_factor(volume, cfg["correlated_ppm"])
        corr_alt = corr_cap if bound is None or corr_cap is None else min(corr_cap, bound)
        candidates["correlated_0.1bps"] = corr_alt
    res["candidates"] = candidates

    if published is None:
        res.update(verdict=NO_PUBLISHED_CAP,
                   detail="body carries no penaltyCapNative for this order; expected value "
                          "shown (as of 2026-09-07 only the staging autopilots publish it)")
        return res
    if expected is not None and published == expected:
        if regime == "volume_factor" and bound is None:
            note = (" (absolute bound not computable: the reference token has no price in "
                    "this body; consistent only if bound >= volume cap)")
        else:
            note = ""
        if regime != "volume_factor":
            res["min_usd_reference_price"] = None
        res.update(verdict=MATCH, regime=regime,
                   matched_by={"regime": regime, "factor_ppm": ppm, "value": expected},
                   detail=f"published == replay ({regime}, factor {factor_source})" + note)
        return res

    # Not reproduced under the stated config. Try the regimes that public data
    # cannot pin down - explicitly, never silently.
    if not strict and corr_alt is not None and published == corr_alt:
        res.update(verdict=MATCH, regime="correlated_override", inferred=True,
                   matched_by={"regime": "correlated_override",
                               "factor_ppm": cfg["correlated_ppm"], "value": corr_alt},
                   detail=f"published == replay under the {CORRELATED_FACTOR_BPS} bps "
                          f"correlated factor ({cfg['correlated_ppm']} ppm), not the stated "
                          f"{factor_source} factor; the override token sets are deployment "
                          f"config, so this regime is INFERRED from the published value")
        return res
    if not strict:
        via = []
        for addr, p in prices.items():
            dec = decimals.get(addr)
            if dec is None:
                continue
            b = absolute_cap_native(cfg["absolute_cap_usd"], dec, p)
            if b == published and (volume_cap is None or b <= volume_cap):
                via.append(addr)
                candidates["absolute_bound_via:" + addr] = b
        if via:
            res["min_usd_reference_price"] = None
            res.update(verdict=MATCH, regime="absolute_bound", inferred=True,
                       bound_token_inferred=via if len(via) > 1 else via[0],
                       absolute_bound_inputs={"token": via[0], "decimals": decimals[via[0]],
                                              "price": prices[via[0]],
                                              "usd": cfg["absolute_cap_usd"],
                                              "inferred": True},
                       matched_by={"regime": "absolute_bound", "factor_ppm": None,
                                   "value": published},
                       detail=f"published == the ${cfg['absolute_cap_usd']} bound converted "
                              f"through {', '.join(via)} (not the assumed reference token) - "
                              f"INFERRED from the published value"
                              + (f"; {len(via)} tokens reproduce it, so the token is ambiguous"
                                 if len(via) > 1 else ""))
            return res
    res.update(verdict=DIFFERENCE,
               detail=f"published {published} is not reproduced by any regime the "
                      f"replay can compute from this body (stated config -> "
                      f"{expected}); a finding to investigate, not an accusation")
    return res


# ---------------------------------------------------------------------------
# whole auction
# ---------------------------------------------------------------------------

def replay_body(network, body, env="prod", strict=False, cfg=None, ev=None, retained_lookback=0):
    cfg = cfg or cip87_config(network)
    ev = ev if ev is not None else sources.Evidence()
    auction_id = body.get("id")
    prices, decimals = body_prices(body)
    ref = cfg["usd_reference"]
    ref_info = None
    if ref:
        listed = {str(a).lower() for a in (body.get("tokens") or {})}
        ref_info = {"in_body": ref[0] in listed, "price_in_body": ref[0] in prices,
                    "retained_price": None, "retained_from_auction": None, "retained_scanned": 0}
        if ref[0] not in prices and retained_lookback and auction_id is not None:
            p, frm, scanned = retained_reference_price(network, env, auction_id, ref[0], ev,
                                                       retained_lookback)
            ref_info.update(retained_price=p, retained_from_auction=frm, retained_scanned=scanned)
    orders = []
    for o in (body.get("orders") or []):
        res = replay_order(o, prices, decimals, cfg, strict=strict, ref_info=ref_info)
        vec = order_vector(network, env, auction_id, o, res, prices, decimals, cfg)
        if vec is not None:
            res["vector"] = vec
        orders.append(res)
    counts, regimes, inferred, bound_unknown = {}, {}, 0, 0
    for o in orders:
        counts[o["verdict"]] = counts.get(o["verdict"], 0) + 1
        if o["verdict"] == MATCH:
            regimes[o["regime"]] = regimes.get(o["regime"], 0) + 1
            inferred += 1 if o.get("inferred") else 0
            bound_unknown += 1 if o.get("absolute_bound") is None else 0
    # The overall verdict is the WORST order verdict, so exit 0 means every
    # order matched: one matched order never vouches for unverified siblings.
    if counts.get(DIFFERENCE):
        overall = DIFFERENCE
    elif counts.get(NOT_COMPUTABLE):
        overall = NOT_COMPUTABLE
    elif counts.get(NO_PUBLISHED_CAP):
        overall = NO_PUBLISHED_CAP
    elif counts.get(MATCH):
        overall = MATCH
    else:
        overall = NOT_COMPUTABLE      # an auction with no orders at all
    limits = [
        "the correlated-token override sets and the usd reference token are autopilot "
        "deployment config, not published; the replay uses CIP-87's numbers plus a "
        "per-chain USDC default and marks any regime it had to infer (`inferred: true`)",
        "a stale usd reference price (the autopilot keeps its last value when the "
        "reference token has no price in a cycle) is only observable when a prior body "
        "carried one: the replay uses this auction's price, else the most recent prior "
        "body's within --retained-lookback (reported as retained), else it reports the "
        "minimum reference price that reproduces the published cap",
    ]
    if cfg.get("usd_reference_assumed"):
        limits.append(f"usd reference token on {network} is ASSUMED "
                      f"({cfg['usd_reference'][0] if cfg['usd_reference'] else 'none'}); "
                      f"it only matters where the bound binds")
    if not cfg.get("default_factor_verified"):
        limits.append(f"the {cfg['default_bps']} bps default factor for {network} is the "
                      f"CIP-87 text value; it has not yet been confirmed by a published cap "
                      f"in the volume-factor regime (the core team may retune within 0-10 bps "
                      f"with notice)")
    limits.append("the CIP text defines the basis as the order's quote (net of volume fees); "
                  "the implementation values the signed sell side (sell orders) or buy side "
                  "(buy orders) at reference prices - the replay follows the implementation; "
                  "the CIP's scaling to the executed fraction of a partial fill happens at "
                  "penalty time and is not part of the published per-order cap")
    if strict:
        limits.append("strict mode: no regime inference; only the stated config counts")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "tool_version": __version__,
        "subject": {"network": network, "chain_id": sources.CHAIN_IDS.get(network),
                    "env": env, "auction_id": auction_id,
                    "source": sources.auction_body_url(network, auction_id, env)},
        "config": _config_public(cfg, prices, ref_info),
        "overall": overall,
        "summary": {"orders": len(orders),
                    "distinct_orders": len({str(o.get("uid")) for o in orders}),
                    "verdicts": counts, "regimes": regimes, "inferred_matches": inferred,
                    "matches_with_unknown_bound": bound_unknown,
                    "reference_price_in_body": bool(ref_info and ref_info.get("price_in_body")),
                    "reference_price_retained": bool(ref_info and ref_info.get("retained_price") is not None),
                    "prices": len(prices)},
        "orders": orders,
        "not_verifiable": limits,
        "evidence": ev.items,
        "disclaimer": "cow-certify is independent and not affiliated with CoW Protocol; "
                      "this replay recomputes a rewards-accounting parameter from public "
                      "data and reports differences, it does not adjudicate them.",
        "reproduce": f"python3 -m cow_certify --network {network} --penalty-cap "
                     f"{auction_id} --env {env}" + (" --strict" if strict else "")
                     + (f" --retained-lookback {int(retained_lookback)}" if retained_lookback else ""),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def replay(network, auction_id, env="prod", strict=False, ev=None, overrides=None,
           retained_lookback=0):
    """Fetch the public auction body and replay it. Raises SystemExit(str) when
    the body does not exist (an input problem, not a verdict)."""
    ev = ev if ev is not None else sources.Evidence()
    cfg = cip87_config(network, overrides=overrides)
    body = sources.auction_body(network, auction_id, ev, env=env)
    if body is None:
        raise SystemExit(f"no {env} auction body for id {auction_id} on {network} in the "
                         f"public instance bucket (bodies are kept ~30 days; is --env right?)")
    if not isinstance(body, dict) or "orders" not in body:
        raise SystemExit(f"auction body {auction_id} on {network} has no orders field")
    return replay_body(network, body, env=env, strict=strict, cfg=cfg, ev=ev,
                       retained_lookback=retained_lookback)


# ---------------------------------------------------------------------------
# human rendering
# ---------------------------------------------------------------------------

MAX_LISTED = 40   # a prod body has thousands of orders; the text render lists this many


def _eth(wei):
    if wei is None:
        return "n/a"
    if wei == U256_MAX:
        return "U256::MAX (uncapped)"
    return f"{wei / 1e18:.9f}".rstrip("0").rstrip(".") + " native"


def render_text(rep):
    sub, cfg, summ = rep["subject"], rep["config"], rep["summary"]
    lines = [f"cow-certify {rep['tool_version']} · CIP-87 penalty-cap replay · "
             f"{sub['network']} {sub['env']} auction {sub['auction_id']}",
             f"  config: default {cfg['default_bps']} bps · correlated "
             f"{cfg['correlated_bps']} bps · bound ${cfg['absolute_cap_usd']}"
             + (f" via {cfg['usd_reference']['token'][:10]}…"
                f"{' (assumed)' if cfg.get('usd_reference_assumed') else ''}"
                if cfg.get("usd_reference") else " (no reference token)")
             + f" · {len(cfg['overrides'])} override set(s) declared"]
    ov = rep["overall"]
    n = summ["orders"]
    v = summ["verdicts"]
    m = v.get(MATCH, 0)
    banner = {MATCH: f"MATCH — {m}/{n} orders reproduce the published penaltyCapNative",
              DIFFERENCE: f"DIFFERENCE — {v.get(DIFFERENCE, 0)}/{n} orders not reproduced (see below)",
              NO_PUBLISHED_CAP: f"NO PUBLISHED CAP — {v.get(NO_PUBLISHED_CAP, 0)}/{n} orders carry no "
                                f"penaltyCapNative in this body (expected values shown"
                                + (f"; {m} matched" if m else "") + ")",
              NOT_COMPUTABLE: f"NOT COMPUTABLE — {v.get(NOT_COMPUTABLE, 0)}/{n} orders could not be "
                              f"replayed" + (f"; {m} matched" if m else "")}[ov]
    lines.append("  " + banner)
    if summ["regimes"]:
        lines.append("  regimes: " + ", ".join(f"{k} x{c}" for k, c in sorted(summ["regimes"].items()))
                     + (f" ({summ['inferred_matches']} inferred)" if summ["inferred_matches"] else "")
                     + (f" ({summ['matches_with_unknown_bound']} with the bound not computable)"
                        if summ.get("matches_with_unknown_bound") else ""))
    shown = rep["orders"][:MAX_LISTED]
    for i, o in enumerate(shown, 1):
        mark = {MATCH: "✓", DIFFERENCE: "≠", NO_PUBLISHED_CAP: "·", NOT_COMPUTABLE: "?"}[o["verdict"]]
        head = (f"  {mark} {i}. {o.get('kind', '?')} {o['sell_token'][:10]}… → {o['buy_token'][:10]}…"
                f"  volume {_eth(o.get('volume_native'))}")
        lines.append(head)
        lines.append(f"       published {o.get('published_cap')}  expected {o.get('expected_cap')}"
                     f"  [{o.get('regime') or o.get('expected_regime')}"
                     f"{', inferred' if o.get('inferred') else ''}]")
        if o["verdict"] in (DIFFERENCE, NOT_COMPUTABLE):
            lines.append(f"       {o['detail']}")
            for k, val in (o.get("candidates") or {}).items():
                lines.append(f"         candidate {k}: {val}")
        elif o["verdict"] == MATCH and (o.get("inferred") or o.get("absolute_bound") is None):
            # a green mark next to two different numbers needs its reason printed
            lines.append(f"       {o['detail']}")
        if o["verdict"] == MATCH and o.get("absolute_bound") is None and o.get("absolute_bound_inputs"):
            bi = o["absolute_bound_inputs"]
            where = ("listed in the body with no price" if bi.get("token_in_body")
                     else "not listed in the body")
            if bi.get("retained_price") is not None:
                ret = (f"retained {bi['retained_price']} from auction {bi['retained_from_auction']} "
                       f"({'consistent' if bi.get('retained_consistent') else 'CONTRADICTS the published cap'})")
            elif bi.get("retained_scanned"):
                ret = f"none in the {bi['retained_scanned']} prior bodies scanned"
            else:
                ret = "no lookback (--retained-lookback N)"
            lines.append(f"       usd reference price: {where} · {ret}"
                         + (f" · published cap holds for any reference price >= "
                            f"{o['min_usd_reference_price']}"
                            if o.get("min_usd_reference_price") is not None else ""))
    if len(rep["orders"]) > len(shown):
        lines.append(f"  … {len(rep['orders']) - len(shown)} more orders not listed "
                     f"(use --json for every order)")
    lines.append("  not verifiable from public data:")
    for lim in rep["not_verifiable"]:
        lines.append(f"    - {lim}")
    lines.append(f"  reproduce: {rep['reproduce']}")
    return "\n".join(lines)


def to_json(rep):
    return json.dumps(rep, indent=2)
