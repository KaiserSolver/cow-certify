// GPv2 settlement decoding + surplus primitives, in the browser.
// Hand-rolled minimal ABI decoder for the fixed settle() signature — no
// dependencies, so the page stays tiny and auditable. Validated to decode
// byte-identically to the Python cow_certify.gpv2 across the full corpus.
//
//   settle(address[] tokens, uint256[] clearingPrices,
//          Trade[] trades, Interaction[][3] interactions)

export const SETTLEMENT = "0x9008d19f58aabd9ed0d60971565aa8510560ab41";
export const SETTLE_SELECTOR = "0x13d79a0b";
export const TRADE_TOPIC =
  "0xa07a543ab8a018198e99ca0184c93fe9050a79400a0a723441f84de1d972cc17";
// Settlement(address indexed solver) — emitted once per settle() even with no
// user Trade events; proof the tx is a real CoW settlement. keccak Settlement(address).
export const SETTLEMENT_EVENT_TOPIC =
  "0x40338ce1a7c49204f0099533b1e9a7ee0a3d261f84974ab7af36105b8c4e9db4";
export const ERC20_TRANSFER =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
export const AUCTION_ID_SUFFIX_BYTES = 8;
export const FLAG_KIND_BUY = 1n;
export const FLAG_PARTIALLY_FILLABLE = 2n;

export function ceilDiv(a, b) {
  return (a + b - 1n) / b;
}

// --- minimal ABI reader over the calldata after the 4-byte selector ---
function reader(calldataHex) {
  const hex = calldataHex.startsWith("0x") ? calldataHex.slice(2) : calldataHex;
  const data = hex.slice(8); // drop selector
  const word = (byteOff) => data.slice(byteOff * 2, byteOff * 2 + 64);
  return {
    hex,
    uint: (byteOff) => BigInt("0x" + (word(byteOff) || "0")),
    int: (byteOff) => Number(BigInt("0x" + (word(byteOff) || "0"))),
    addr: (byteOff) => ("0x" + word(byteOff).slice(24)).toLowerCase(),
    word32: (byteOff) => "0x" + word(byteOff),
    bytesAt: (byteOff) => {
      const len = Number(BigInt("0x" + word(byteOff)));
      return data.slice((byteOff + 32) * 2, (byteOff + 32) * 2 + len * 2);
    },
  };
}

export function decodeSettlement(calldataHex) {
  if (!/^0x/i.test(calldataHex)) calldataHex = "0x" + calldataHex;
  if (calldataHex.slice(0, 10).toLowerCase() !== SETTLE_SELECTOR) {
    throw new Error("not a GPv2 settle() call");
  }
  const r = reader(calldataHex);
  const offTokens = r.int(0), offPrices = r.int(32),
        offTrades = r.int(64), offInter = r.int(96);

  // A malicious/garbage RPC response can declare an array length of 2^256-1;
  // looping to it would freeze the tab (no worker to kill). Bound every length
  // by the words the calldata actually contains. (Python's eth_abi raises on
  // the same input in ~1ms.)
  const maxWords = r.hex.length / 64;
  const len = (off) => {
    const n = r.int(off);
    if (n < 0 || n > maxWords) throw new Error("array length exceeds calldata");
    return n;
  };
  const nTokens = len(offTokens);
  const tokens = [];
  for (let i = 0; i < nTokens; i++)
    tokens.push(r.addr(offTokens + 32 + i * 32));
  const nPrices = len(offPrices);
  const clearingPrices = [];
  for (let i = 0; i < nPrices; i++)
    clearingPrices.push(r.uint(offPrices + 32 + i * 32));

  // Trade[]: dynamic array of dynamic tuples. Element offsets are relative to
  // the position after the length word. We only need the 10 static words.
  const trades = [];
  const tbase = offTrades + 32;
  const nTrades = len(offTrades);
  for (let i = 0; i < nTrades; i++) {
    const s = tbase + r.int(tbase + i * 32);
    trades.push({
      sellTokenIndex: r.int(s),
      buyTokenIndex: r.int(s + 32),
      receiver: r.addr(s + 64),
      sellAmount: r.uint(s + 96),
      buyAmount: r.uint(s + 128),
      validTo: r.int(s + 160),
      appData: r.word32(s + 192),
      feeAmount: r.uint(s + 224),
      flags: r.uint(s + 256),
      executedAmount: r.uint(s + 288),
    });
  }

  // Interaction[][3]: fixed-3 array of dynamic arrays of dynamic tuples.
  const interactions = [];
  for (let stage = 0; stage < 3; stage++) {
    const sp = offInter + r.int(offInter + stage * 32); // stage array pos
    const sbase = sp + 32;
    const list = [];
    const nInter = len(sp);
    for (let j = 0; j < nInter; j++) {
      const it = sbase + r.int(sbase + j * 32); // interaction tuple pos
      const cd = r.bytesAt(it + r.int(it + 64)); // callData: offset rel. to tuple
      list.push({
        target: r.addr(it),
        value: r.uint(it + 32),
        selector: cd.length >= 8 ? "0x" + cd.slice(0, 8) : "0x",
      });
    }
    interactions.push(list);
  }

  // Auction id: the autopilot appends exactly 8 bytes to an otherwise ABI-
  // canonical (32-byte-aligned) blob. So the suffix is present iff the data
  // after the selector is NOT a whole number of 32-byte words — matching the
  // Python decoder's canonical-re-encode check, without needing an encoder.
  // A settle() with no appended suffix yields null (not a garbage id).
  const dataBytes = (r.hex.length - 8) / 2; // after the 4-byte selector
  const auctionId = dataBytes % 32 === AUCTION_ID_SUFFIX_BYTES
    ? BigInt("0x" + r.hex.slice(-2 * AUCTION_ID_SUFFIX_BYTES)) : null;

  return { tokens, clearingPrices, trades, interactions, auctionId };
}

export function tradeEvents(logs) {
  const out = [];
  for (const lg of logs || []) {
    const topics = lg.topics || [];
    if (!topics.length || topics[0].toLowerCase() !== TRADE_TOPIC) continue;
    if ((lg.address || "").toLowerCase() !== SETTLEMENT) continue;
    const d = (lg.data || "").slice(2);
    if (d.length < 560) continue; // 5 words + offset + length + 56-byte uid
    out.push({
      owner: ("0x" + topics[1].slice(-40)).toLowerCase(),
      sell_token: ("0x" + d.slice(24, 64)).toLowerCase(),
      buy_token: ("0x" + d.slice(64 + 24, 128)).toLowerCase(),
      sell_amount: BigInt("0x" + d.slice(128, 192)),
      buy_amount: BigInt("0x" + d.slice(192, 256)),
      fee_amount: BigInt("0x" + d.slice(256, 320)),
      uid: ("0x" + d.slice(448, 560)).toLowerCase(),
    });
  }
  return out;
}

// Before-fee surplus of one trade, in SURPLUS-TOKEN atoms, from the EXECUTED
// Trade-event amounts against the signed limit — no clearing price (the
// un-forgeable form; mirrors Python gpv2.surplus_from_execution). execSellNet
// is the executed sell amount net of fee.
export function surplusFromExecution(kind, execSellNet, execBuy, limitSell, limitBuy) {
  if (!(limitSell && limitBuy && execSellNet && execBuy)) return 0n;
  if (kind === "sell") {
    return execBuy - ceilDiv(execSellNet * limitBuy, limitSell);
  }
  return (execBuy * limitSell) / limitBuy - execSellNet;
}
