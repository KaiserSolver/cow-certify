"""GPv2 settlement decoding + surplus primitives.

Vendored from cow-backtester (github.com/KaiserSolver/cow-backtester, MIT, same
author) so cow-certify is self-contained and installable anywhere — no external
checkout on the path. The only third-party dependency is `eth_abi` for ABI
decoding of the settle() calldata.

Kept identical to the source so certificates reconstruct settlements the same
way the backtester does; `selftest()` pins the surplus math.
"""
from eth_abi import decode, encode

# GPv2Settlement — same address on every CoW chain.
SETTLEMENT = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
SETTLE_SELECTOR = "0x13d79a0b"
# Trade(address indexed owner, address sellToken, address buyToken,
#       uint256 sellAmount, uint256 buyAmount, uint256 feeAmount, bytes orderUid)
TRADE_TOPIC = "0xa07a543ab8a018198e99ca0184c93fe9050a79400a0a723441f84de1d972cc17"
# Settlement(address indexed solver) — emitted once per settle() by the
# canonical contract, even when the settlement carries no user Trade events
# (a CoW-AMM/JIT rebalance or buffer/interactions-only op). Presence of this
# event from the canonical contract is proof the tx is a real CoW settlement.
# keccak256("Settlement(address)").
SETTLEMENT_EVENT_TOPIC = "0x40338ce1a7c49204f0099533b1e9a7ee0a3d261f84974ab7af36105b8c4e9db4"
# Autopilot reads the auction id from exactly the last 8 bytes of the calldata.
AUCTION_ID_SUFFIX_LEN = 8

# settle(address[] tokens, uint256[] clearingPrices, Trade[] trades,
#        Interaction[][3] interactions)
_TRADE = "(uint256,uint256,address,uint256,uint256,uint32,bytes32,uint256,uint256,uint256,bytes)"
_INTER = "(address,uint256,bytes)"
_SETTLE_TYPES = ["address[]", "uint256[]", f"{_TRADE}[]", f"{_INTER}[][3]"]

# GPv2 order flags: bit 0 = kind (0 sell / 1 buy), bit 1 = partiallyFillable.
FLAG_KIND_BUY = 1
FLAG_PARTIALLY_FILLABLE = 2


def _ceildiv(a: int, b: int) -> int:
    return (a + b - 1) // b


def decode_settlement(calldata_hex: str):
    """Decode a settle() calldata string into tokens[], clearing_prices[],
    trades[] (raw tuples), interactions, and the appended auction_id (last 8
    bytes of the suffix, per autopilot's rule, or None if the prefix does not
    re-encode canonically). Raises ValueError if not a settle() call."""
    if not calldata_hex.startswith("0x"):
        calldata_hex = "0x" + calldata_hex
    if calldata_hex[:10].lower() != SETTLE_SELECTOR:
        raise ValueError(f"not a GPv2 settle() call (selector {calldata_hex[:10]})")
    raw = bytes.fromhex(calldata_hex[10:])
    tokens, prices, trades, interactions = decode(_SETTLE_TYPES, raw)
    canon = encode(_SETTLE_TYPES, (tokens, prices, trades, interactions))
    suffix = raw[len(canon):]
    auction_id = None
    if raw[:len(canon)] == canon and len(suffix) >= AUCTION_ID_SUFFIX_LEN:
        auction_id = int.from_bytes(suffix[-AUCTION_ID_SUFFIX_LEN:], "big")
    return {
        "tokens": [t.lower() for t in tokens],
        "clearing_prices": list(prices),
        "trades": list(trades),
        "interactions": interactions,
        "auction_id": auction_id,
        "suffix_len": len(suffix),
    }


def surplus_from_execution(kind, exec_sell_net, exec_buy, limit_sell, limit_buy):
    """Before-fee surplus of one trade, in SURPLUS-TOKEN atoms, computed from
    the ACTUALLY EXECUTED amounts (the on-chain Trade event) versus the signed
    limit — no clearing prices involved.

    kind='sell': surplus token = BUY token:
        received - ceil(net_sold * limit_buy / limit_sell)
    kind='buy':  surplus token = SELL token:
        floor(received * limit_sell / limit_buy) - net_sold

    This is the un-forgeable form. The earlier price-based reconstruction read a
    clearing-price SLOT the settlement author chooses freely (a settle() may
    carry duplicate token entries; the EVM reads the slot each trade's
    sellTokenIndex/buyTokenIndex points at, which nothing validates for content),
    so a solver could inflate the reconstructed surplus by editing an
    otherwise-unread slot. The executed amounts in the Trade event are what the
    EVM actually moved and cannot be edited after the fact; the signed limits are
    the user's. `exec_sell_net` is the executed sell amount NET of fee (the
    Trade event's sellAmount is fee-inclusive).

    Returns 0 on degenerate inputs; a negative result (limit violation) is
    returned as-is so callers can distinguish infeasible from zero-surplus."""
    if not (limit_sell and limit_buy and exec_sell_net and exec_buy):
        return 0
    if kind == "sell":
        lim_bought = _ceildiv(exec_sell_net * limit_buy, limit_sell)
        return exec_buy - lim_bought
    else:
        lim_sold = exec_buy * limit_sell // limit_buy
        return lim_sold - exec_sell_net


def surplus_token(kind, sell_token, buy_token):
    """Official surplus token: buy token for sell orders, sell token for buy."""
    return buy_token if kind == "sell" else sell_token


def to_native(atoms, ref_price):
    """Convert surplus-token atoms to native wei at the auction referencePrice."""
    if ref_price is None:
        return None
    return atoms * ref_price // 10 ** 18


def trade_events(logs):
    """Extract executed amounts + orderUid from GPv2 Trade events — ground truth.

    Filters by BOTH topic0 and the emitting address (the canonical settlement
    contract), so a foreign contract emitting a same-signature event can't shift
    the positional events[i] <-> trades[i] alignment."""
    out = []
    for lg in logs:
        topics = lg.get("topics") or []
        if not topics or topics[0].lower() != TRADE_TOPIC:
            continue
        if lg.get("address", "").lower() != SETTLEMENT:
            continue
        d = (lg.get("data") or "")[2:]
        if len(d) < 560:  # 5 words + offset + length + 56-byte uid
            continue
        out.append({
            "owner": ("0x" + lg["topics"][1][-40:]).lower(),
            "sell_token": ("0x" + d[24:64]).lower(),
            "buy_token": ("0x" + d[64 + 24:128]).lower(),
            "sell_amount": int(d[128:192], 16),
            "buy_amount": int(d[192:256], 16),
            "uid": ("0x" + d[448:560]).lower(),
        })
    return out


def selftest():
    """Deterministic surplus-math vectors — both order kinds and boundaries."""
    # sell: sold 100 net, received 200, limit 100->150 => lim_bought=150 => +50
    assert surplus_from_execution("sell", 100, 200, 100, 150) == 50
    # sell exactly at limit => 0
    assert surplus_from_execution("sell", 100, 150, 100, 150) == 0
    # sell below limit (infeasible) => negative
    assert surplus_from_execution("sell", 100, 100, 100, 150) < 0
    # buy: received 100, paid 150 net, limit 200->100 => lim_sold=200 => +50
    assert surplus_from_execution("buy", 150, 100, 200, 100) == 50
    # buy exactly at limit => 0
    assert surplus_from_execution("buy", 200, 100, 200, 100) == 0
    assert surplus_from_execution("sell", 0, 200, 100, 150) == 0
    assert surplus_token("sell", "a", "b") == "b"
    assert surplus_token("buy", "a", "b") == "a"
    return True
