// GPv2 settlement decoding + surplus primitives, in the browser.
// Hand-rolled minimal ABI decoder for the fixed settle() signature — no
// dependencies, so the page stays tiny and auditable. Validated to decode
// byte-identically to the Python cow_certify.gpv2 across the full corpus.
//
//   settle(address[] tokens, uint256[] clearingPrices,
//          Trade[] trades, Interaction[][3] interactions)
//
// The reader is STRICT: every word is bounds-checked (a short read throws
// instead of decoding as zero — a zero-filled read once fabricated a signed
// limit of 0 and certified a limit-breaking trade as PASS), and padding bytes
// are validated the way eth_abi's strict decoder validates them. Whether the
// blob is laid out canonically is tracked while decoding, so the appended
// auction id is read only from a canonical blob with EXACTLY an 8-byte tail —
// mirroring the Python decoder's re-encode-and-compare rule.

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

const pad32 = (n) => Math.ceil(n / 32) * 32;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

// --- minimal, strict ABI reader over the calldata after the 4-byte selector ---
function reader(calldataHex) {
  const hex = calldataHex.startsWith("0x") ? calldataHex.slice(2) : calldataHex;
  const data = hex.slice(8); // drop selector
  const word = (byteOff) => {
    const a = byteOff * 2;
    if (byteOff < 0 || a + 64 > data.length)
      throw new Error(`calldata truncated: word at byte ${byteOff} lies beyond the ${data.length / 2} bytes present`);
    return data.slice(a, a + 64);
  };
  const int = (byteOff) => {
    const v = BigInt("0x" + word(byteOff));
    if (v > MAX_SAFE) throw new Error("offset or length exceeds calldata");
    return Number(v);
  };
  return {
    hex,
    dataBytes: data.length / 2,
    uint: (byteOff) => BigInt("0x" + word(byteOff)),
    int,
    u32: (byteOff) => {
      const w = word(byteOff);
      if (!/^0{56}/.test(w)) throw new Error("malformed uint32 word (non-zero padding)");
      return Number(BigInt("0x" + w));
    },
    addr: (byteOff) => {
      const w = word(byteOff);
      if (!/^0{24}/.test(w)) throw new Error("malformed address word (non-zero padding)");
      return ("0x" + w.slice(24)).toLowerCase();
    },
    word32: (byteOff) => "0x" + word(byteOff),
    // dynamic `bytes` at byteOff: [length][data padded to 32]; returns the hex
    // of the data and validates that the padding is present and zero.
    bytesAt: (byteOff) => {
      const len = int(byteOff);
      const a = (byteOff + 32) * 2;
      const paddedLen = pad32(len) * 2;
      if (a + paddedLen > data.length) throw new Error("calldata truncated: bytes lie beyond the data present");
      const padding = data.slice(a + len * 2, a + paddedLen);
      if (!/^0*$/.test(padding)) throw new Error("malformed bytes (non-zero padding)");
      return data.slice(a, a + len * 2);
    },
  };
}

export function decodeSettlement(calldataHex) {
  if (!/^0x/i.test(calldataHex)) calldataHex = "0x" + calldataHex;
  if (calldataHex.slice(0, 10).toLowerCase() !== SETTLE_SELECTOR) {
    throw new Error("not a GPv2 settle() call");
  }
  const r = reader(calldataHex);
  // `canonical` records whether every dynamic offset equals the one a canonical
  // encoder would have written. A non-canonical blob still decodes (the EVM
  // reads it the same way) but carries no readable autopilot suffix.
  let canonical = true;
  const expect = (actual, want) => { if (actual !== want) canonical = false; };

  const offTokens = r.int(0), offPrices = r.int(32),
        offTrades = r.int(64), offInter = r.int(96);

  // A malicious/garbage RPC response can declare an array length of 2^256-1;
  // looping to it would freeze the tab (no worker to kill). Bound every length
  // by the words the calldata actually contains. (Python's eth_abi raises on
  // the same input in ~1ms.)
  const maxWords = r.dataBytes / 32;
  const len = (off) => {
    const n = r.int(off);
    if (n < 0 || n > maxWords) throw new Error("array length exceeds calldata");
    return n;
  };

  let cursor = 128; // canonical position right after the 4 head words
  expect(offTokens, cursor);
  const nTokens = len(offTokens);
  const tokens = [];
  for (let i = 0; i < nTokens; i++)
    tokens.push(r.addr(offTokens + 32 + i * 32));
  cursor += 32 + 32 * nTokens;

  expect(offPrices, cursor);
  const nPrices = len(offPrices);
  const clearingPrices = [];
  for (let i = 0; i < nPrices; i++)
    clearingPrices.push(r.uint(offPrices + 32 + i * 32));
  cursor += 32 + 32 * nPrices;

  // Trade[]: dynamic array of dynamic tuples (the 11th field, `bytes
  // signature`, makes the tuple dynamic). Element offsets are relative to the
  // position after the length word.
  expect(offTrades, cursor);
  const trades = [];
  const tbase = offTrades + 32;
  const nTrades = len(offTrades);
  let rel = 32 * nTrades; // canonical relative offset of the first tuple
  for (let i = 0; i < nTrades; i++) {
    const relOff = r.int(tbase + i * 32);
    expect(relOff, rel);
    const s = tbase + relOff;
    trades.push({
      sellTokenIndex: r.int(s),
      buyTokenIndex: r.int(s + 32),
      receiver: r.addr(s + 64),
      sellAmount: r.uint(s + 96),
      buyAmount: r.uint(s + 128),
      validTo: r.u32(s + 160),
      appData: r.word32(s + 192),
      feeAmount: r.uint(s + 224),
      flags: r.uint(s + 256),
      executedAmount: r.uint(s + 288),
    });
    const sigOff = r.int(s + 320); // offset of `signature` relative to the tuple
    expect(sigOff, 352);
    const sig = r.bytesAt(s + sigOff);
    rel += 352 + 32 + pad32(sig.length / 2);
  }
  cursor = tbase + rel;

  // Interaction[][3]: fixed-3 array of dynamic arrays of dynamic tuples.
  expect(offInter, cursor);
  const interactions = [];
  let irel = 96; // three stage offsets first
  for (let stage = 0; stage < 3; stage++) {
    const so = r.int(offInter + stage * 32);
    expect(so, irel);
    const sp = offInter + so;
    const nInter = len(sp);
    const sbase = sp + 32;
    let jrel = 32 * nInter;
    const list = [];
    for (let j = 0; j < nInter; j++) {
      const jo = r.int(sbase + j * 32);
      expect(jo, jrel);
      const it = sbase + jo;
      const cdOff = r.int(it + 64);
      expect(cdOff, 96);
      const cd = r.bytesAt(it + cdOff);
      list.push({
        target: r.addr(it),
        value: r.uint(it + 32),
        selector: cd.length >= 8 ? "0x" + cd.slice(0, 8) : "0x",
      });
      jrel += 96 + 32 + pad32(cd.length / 2);
    }
    interactions.push(list);
    irel += 32 + jrel;
  }
  cursor = offInter + irel;

  // Auction id: the autopilot appends EXACTLY 8 bytes to a canonical blob. Any
  // other tail — none, or a non-standard length a custom driver could have
  // appended — is not an autopilot suffix and yields null, never a guessed id.
  let suffixLen = r.dataBytes - cursor;
  if (suffixLen < 0) { canonical = false; suffixLen = 0; }
  const auctionId = (canonical && suffixLen === AUCTION_ID_SUFFIX_BYTES)
    ? BigInt("0x" + r.hex.slice(-2 * AUCTION_ID_SUFFIX_BYTES)) : null;

  return { tokens, clearingPrices, trades, interactions, auctionId, suffixLen, canonical };
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
