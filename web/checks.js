// The full C0–C14 verification pipeline in the browser. Ported from the audited
// Python cow_certify; a corpus drift-guard forces verdict parity. Detail prose
// may differ from Python — only verdicts are contractual.
import {
  decodeSettlement, tradeEvents, surplusFromExecution,
  SETTLEMENT, TRADE_TOPIC, SETTLEMENT_EVENT_TOPIC, ERC20_TRANSFER, FLAG_KIND_BUY, FLAG_PARTIALLY_FILLABLE,
} from "./gpv2.js";
import * as src from "./sources.js";

const GPV2 = SETTLEMENT;
const SETTLE_SELECTOR = "0x13d79a0b";
const AUTHENTICATOR = "0x2c4c28ddbdac9c5e7055b4c863b72ea0149d8afe";
const NATIVE_ETH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const SCHEMA_VERSION = "0.3.0";
const PASS = "PASS", VIOLATION = "VIOLATION", UNCERTAIN = "UNCERTAIN", INFO = "INFO";
const ROUNDING_ATOMS = 2n;
const WAD = 10n ** 18n;
// Driver wraps order hooks in this contract (execute(...), 0x760f2a0b); a
// pre/post interaction here is hook execution, not an injected call.
const HOOKS_TRAMPOLINE = "0x60bf78233f48ec42ee3f101b9a05ec7878728006";
const DEADLINE_CHECK = "0x0e91b5b157e98c20b90332cc3b9cf4ae67b222ad"; // driver infra
// A uid is 0x + 56 bytes (112 hex) = 114 chars.
const isUid = (s) => typeof s === "string" && /^0x[0-9a-f]{112}$/i.test(s);

const v = (check, verdict, detail, extra = {}) => ({ check, verdict, detail, ...extra });
const floorDiv = (a, b) => { let q = a / b; if (a % b !== 0n && (a < 0n) !== (b < 0n)) q -= 1n; return q; };

function finish(network, txHash, checks, limits, ev, extra = {}) {
  const order = { PASS: 0, INFO: 0, UNCERTAIN: 1, VIOLATION: 2 };
  let worst = "PASS";
  for (const c of checks) if ((order[c.verdict] ?? 0) > (order[worst] ?? 0)) worst = c.verdict;
  return {
    schema_version: SCHEMA_VERSION,
    subject: { network, chain_id: src.CHAIN_IDS[network], tx_hash: txHash, ...extra },
    overall: worst, checks, not_verifiable: limits, evidence: ev.items,
    disclaimer: "cow-certify is independent and not affiliated with CoW Protocol; it verifies from public data only.",
    reproduce: `python3 -m cow_certify --network ${network} ${txHash}`,
  };
}

export async function certify(network, txHash, opts = {}) {
  const rpc = opts.rpcUrl || src.DEFAULT_RPC[network];
  const ev = new src.Evidence();
  const checks = [], limits = [];

  const tx = await src.rpc(rpc, "eth_getTransactionByHash", [txHash], ev);
  if (!tx) throw new Error(`transaction ${txHash} not found on ${network} — is the network correct?`);
  let receipt = await src.rpc(rpc, "eth_getTransactionReceipt", [txHash], ev);
  let statusOk = receipt && parseInt(receipt.status, 16) === 1;
  // Confirm an apparent revert before accusing (C8): public RPCs intermittently
  // return status 0x0 for a genuinely successful tx. A real revert is 0x0 on
  // every node, so any single 0x1 from another endpoint means the first read
  // was bad. Only pay the extra round-trip on the rare apparent-revert path.
  if (receipt && !statusOk) {
    const urls = Array.isArray(rpc) ? rpc : [rpc];
    for (const alt of urls) {
      let r2; try { r2 = await src.rpc([alt], "eth_getTransactionReceipt", [txHash], ev); } catch { continue; }
      if (r2 && parseInt(r2.status, 16) === 1) { receipt = r2; statusOk = true; break; }
    }
  }
  const landedBlock = receipt ? parseInt(receipt.blockNumber, 16) : null;
  const sender = (tx.from || "").toLowerCase();
  const toAddr = (tx.to || "").toLowerCase();
  const calldata = (tx.input || "").toLowerCase();
  const logs = (receipt && receipt.logs) || [];
  const direct = toAddr === GPV2 && calldata.startsWith(SETTLE_SELECTOR);

  // Does the receipt carry GPv2 activity (a Trade event, or the once-per-
  // settle Settlement(solver) event that fires even on an interactions-only
  // settlement)? Separates a real (possibly wrapper-routed) settlement from an
  // unrelated pasted tx.
  const hasGpv2Activity = logs.some((lg) =>
    (lg.address || "").toLowerCase() === SETTLEMENT &&
    [TRADE_TOPIC, SETTLEMENT_EVENT_TOPIC].includes((lg.topics || [])[0]?.toLowerCase()));

  // C0
  let suffixAid = null;
  if (direct) {
    checks.push(v("C0.settlement-shape", PASS, "direct settle() call to the canonical GPv2 contract"));
    try { const a = decodeSettlement(calldata).auctionId; suffixAid = a === null ? null : a; } catch { suffixAid = null; }
  } else if (!hasGpv2Activity) {
    // Not a settle() call and no GPv2 settlement activity: not a CoW settlement.
    checks.push(v("C0.settlement-shape", UNCERTAIN, `this transaction is not a CoW Protocol settlement: its target ${toAddr || "(contract creation)"} is not the GPv2 settlement contract and the receipt contains no GPv2 settlement events. Nothing to certify — check the tx hash and network.`));
    if (!statusOk) checks.push(v("C8.execution-status", INFO, "the transaction also reverted on-chain"));
    return finish(network, txHash, checks, limits, ev);
  } else {
    checks.push(v("C0.settlement-shape", INFO, `wrapper route (target ${toAddr}); the receipt carries GPv2 settlement events. Certifying via the competition record and canonical-contract events`));
    limits.push("wrapper route: calldata-suffix auction binding not independently checkable");
  }

  // C8 — emitted here (before any early return) so a reverted settlement can
  // never skip it: the competition API 404s precisely because it reverted.
  if (!statusOk) checks.push(v("C8.execution-status", VIOLATION, "transaction REVERTED on-chain (or failed) — it did not settle. This is not a completed settlement", { reverted: true }));

  // C1
  const comp = await src.competitionByTx(network, txHash, ev);
  if (!comp && suffixAid === null) {
    checks.push(v("C1.auction-binding", UNCERTAIN, "no public competition record and no readable calldata auction id"));
    limits.push("no public competition record: C2-C7 not performable");
    return finish(network, txHash, checks, limits, ev);
  }
  if (!comp) {
    checks.push(v("C1.auction-binding", UNCERTAIN, `calldata declares auction id ${suffixAid}, but no public competition record for this tx (404)`, { auction_id: Number(suffixAid) }));
    limits.push("no public competition record: C2-C7 not performable");
    return finish(network, txHash, checks, limits, ev, { auction_id: Number(suffixAid) });
  }
  // Coerce to BigInt: the API has returned auctionId as both int and numeric
  // string; a type-sensitive compare would false-VIOLATION every settlement
  // the moment the serialization changes.
  const rawAid = comp.auctionId;
  let apiAid = null;
  if (rawAid !== null && rawAid !== undefined) {
    try { apiAid = BigInt(rawAid); } catch { apiAid = null; }
  }
  if (rawAid !== null && rawAid !== undefined && apiAid === null) {
    checks.push(v("C1.auction-binding", UNCERTAIN, `competition record's auctionId is not a parseable integer (${JSON.stringify(rawAid)}); cannot bind. Calldata suffix is ${suffixAid}`, { auction_id: suffixAid === null ? null : Number(suffixAid) }));
  } else if (apiAid === null) {
    checks.push(v("C1.auction-binding", UNCERTAIN, `competition record carries no auctionId to bind against (partial or aged record); calldata suffix is ${suffixAid}`, { auction_id: suffixAid === null ? null : Number(suffixAid) }));
  } else if (suffixAid === null) {
    checks.push(v("C1.auction-binding", INFO, `competition record binds this tx to auction ${apiAid} (API-side only; wrapper route)`, { api_auction_id: Number(apiAid) }));
    suffixAid = apiAid;
  } else if (apiAid === BigInt(suffixAid)) {
    checks.push(v("C1.auction-binding", PASS, `calldata auction id ${suffixAid} == stored competition record auctionId`, { auction_id: Number(suffixAid) }));
  } else {
    checks.push(v("C1.auction-binding", VIOLATION, `calldata auction id ${suffixAid} != competition record auctionId ${apiAid}`));
  }

  const solutions = comp.solutions || [];
  const winners = solutions.filter((s) => s.isWinner);
  const thisSolArr = winners.filter((s) => (s.txHash || "").toLowerCase() === txHash.toLowerCase());
  const thisSol = thisSolArr[0];

  // C2
  if (thisSol) {
    const saddr = (thisSol.solverAddress || "").toLowerCase();
    if (saddr === sender)
      checks.push(v("C2.winner-legitimacy", PASS, `tx sender ${sender} is the recorded winning solver (ranking ${thisSol.ranking})`));
    else if (!direct && saddr === toAddr)
      checks.push(v("C2.winner-legitimacy", PASS, `settle() called by the recorded winning solver contract ${saddr} (wrapper route)`));
    else if (direct)
      checks.push(v("C2.winner-legitimacy", VIOLATION, `tx sender ${sender} != recorded winning solver ${saddr}`));
    else
      checks.push(v("C2.winner-legitimacy", UNCERTAIN, `neither tx sender nor wrapper target matches recorded winning solver ${saddr}`));
  } else if (winners.length) {
    checks.push(v("C2.winner-legitimacy", UNCERTAIN, `${winners.length} winner(s) recorded but none references this txHash`));
  } else {
    checks.push(v("C2.winner-legitimacy", UNCERTAIN, "competition record exists but flags no winning solution (possibly a partial/aged record or schema difference); the winner cannot be confirmed from public data"));
  }

  // C3/C4/C5
  if (statusOk) await runDecodeChecks(network, direct, calldata, logs, thisSol, comp, ev, checks, limits);

  // C6
  const deadline = comp.auctionDeadlineBlock;
  if (Number.isInteger(deadline) && landedBlock !== null) {
    const lateBy = landedBlock - deadline;
    if (lateBy <= 0) checks.push(v("C6.timeliness", PASS, `landed at block ${landedBlock}, deadline ${deadline} (${-lateBy} to spare)`));
    else checks.push(v("C6.timeliness", UNCERTAIN, `landed ${lateBy} block(s) after the recorded deadline (${landedBlock} > ${deadline}); the deadline is not on-chain-enforced and benign causes exist (reorg, slow inclusion), so this is flagged for review, not a violation`));
  } else {
    checks.push(v("C6.timeliness", UNCERTAIN, "no auctionDeadlineBlock in the competition record"));
  }

  // C7
  const distinct = new Set(solutions.filter((s) => !s.filteredOut).map((s) => (s.solverAddress || "").toLowerCase()));
  const filtered = solutions.filter((s) => s.filteredOut).length;
  checks.push(v("C7.competition-context", INFO,
    `${solutions.length} solution(s) from ${distinct.size} distinct solver(s), ${filtered} filtered out, ${winners.length} winner(s)`,
    { solutions: solutions.length, distinct_solvers: distinct.size, filtered_out: filtered, winners: winners.length }));

  // C9
  await runSolverAuth(rpc, direct, toAddr, sender, landedBlock, ev, checks, statusOk);

  // C10 / C11 / C12 / C13
  if (statusOk) {
    await runOrderLedger(rpc, direct, calldata, logs, ev, checks);
    runReceiverCheck(direct, calldata, logs, checks, limits);
    await runAuthenticity(network, direct, calldata, logs, ev, checks, limits);
    runInteractions(direct, calldata, checks, limits);
    runPriceVsMid(comp, logs, checks);
    runBufferCheck(logs, checks);
  }

  // (C8 execution-status is emitted near the top, before any early return.)

  limits.push("best-execution / EBBO (whether a better price was available elsewhere) is OUT OF SCOPE: this tool verifies validity, not optimality");
  limits.push("declines (won-but-never-submitted) are invisible in public data");
  return finish(network, txHash, checks, limits, ev, { auction_id: suffixAid === null ? null : Number(suffixAid) });
}

async function runDecodeChecks(network, direct, calldata, logs, thisSol, comp, ev, checks, limits) {
  const events = tradeEvents(logs);
  if (!events.length) { checks.push(v("C3.solution-fidelity", UNCERTAIN, "no GPv2 Trade events in the receipt")); return; }

  // C3 — aggregate settled amounts per uid first (a uid can be filled by
  // several Trade events in one settlement; a per-event compare to per-uid
  // totals would false-flag a legitimate multi-fill).
  const settled = aggregateByUid(events);
  const evUids = settled.map((e) => e.uid);
  // JIT/liquidity classification: a settled uid NOT in the auction's user order
  // set is solver-brought maker liquidity — noted in C3, excluded from C5's
  // user-surplus sum (F6).
  const au = (comp.auction && comp.auction.orders);
  const auctionUids = Array.isArray(au) ? new Set(au.map((u) => String(u).toLowerCase())) : null;
  const jitUids = auctionUids ? new Set(evUids.filter((u) => !auctionUids.has(u))) : new Set();
  const solOrders = new Map();
  const scoredIds = (thisSol && thisSol.orders) || [];
  for (const o of scoredIds) {
    const oid = String(o.id || "").toLowerCase();
    if (isUid(oid)) solOrders.set(oid, o);
  }
  if (!thisSol || !scoredIds.length) {
    checks.push(v("C3.solution-fidelity", UNCERTAIN, "winning solution carries no order list in the public record; settled-set comparison not possible"));
  } else if (!solOrders.size) {
    checks.push(v("C3.solution-fidelity", UNCERTAIN, `winning solution lists ${scoredIds.length} order(s) but none carries a uid-shaped id (schema drift?); settled-set comparison not performed rather than risk a false finding`));
  } else {
    const extra = evUids.filter((u) => !solOrders.has(u));
    const missing = [...solOrders.keys()].filter((u) => !evUids.includes(u));
    const matched = evUids.filter((u) => solOrders.has(u));
    let worst = PASS, compared = 0;
    for (const e of settled) {
      const o = solOrders.get(e.uid); if (!o) continue;
      let sSell, sBuy; try { sSell = BigInt(o.sellAmount); sBuy = BigInt(o.buyAmount); } catch { continue; }
      compared++;
      const dBuy = e.buy_amount - sBuy, dSell = e.sell_amount - sSell;
      if (dBuy < -ROUNDING_ATOMS || dSell > ROUNDING_ATOMS) worst = VIOLATION;
    }
    if (extra.length || missing.length)
      checks.push(v("C3.solution-fidelity", VIOLATION, `settled-order set differs from the winning solution: ${extra.length} settled-but-not-scored, ${missing.length} scored-but-not-settled`));
    else if (compared < matched.length)
      checks.push(v("C3.solution-fidelity", UNCERTAIN, `all ${settled.length} settled order(s) are in the winning solution, but amounts were comparable for only ${compared}/${matched.length}`));
    else {
      const jitNote = jitUids.size ? `; ${jitUids.size} of these are JIT/liquidity order(s) not in the auction's user order set (expected for market-maker / CoW-AMM liquidity)` : "";
      checks.push(v("C3.solution-fidelity", worst, `all ${settled.length} settled order(s) match the winning solution's order set; amounts compared for ${compared}/${matched.length}${jitNote}`));
    }
  }

  // C4
  let trades = null;
  if (direct) { try { trades = decodeSettlement(calldata).trades; } catch (e) { limits.push(`calldata decode failed for C4: ${e}`); } }
  const results = [];
  if (trades && trades.length === events.length) {
    for (let i = 0; i < trades.length; i++) results.push([events[i].uid, trades[i].sellAmount, trades[i].buyAmount, events[i]]);
  } else {
    for (const e of events) {
      const meta = await src.orderMeta(network, e.uid, ev);
      if (meta && meta.sellAmount && meta.buyAmount) results.push([e.uid, BigInt(meta.sellAmount), BigInt(meta.buyAmount), e]);
    }
  }
  if (!results.length) checks.push(v("C4.limit-compliance", UNCERTAIN, "signed limits unavailable"));
  else {
    const bad = [];
    for (const [uid, limSell, limBuy, e] of results) {
      const paidNet = e.sell_amount - (e.fee_amount || 0n);
      if (e.buy_amount * limSell < limBuy * paidNet) bad.push(uid);
    }
    if (bad.length) checks.push(v("C4.limit-compliance", VIOLATION, `${bad.length} of ${results.length} trade(s) below the signed limit`));
    else checks.push(v("C4.limit-compliance", PASS, `all ${results.length} trade(s) respect their signed limit price`));
  }

  // C5 — the user surplus actually delivered on-chain (context, INFO), from the
  // executed Trade-event amounts vs the signed limits (no clearing price → not
  // forgeable). It is REPORTED, not adjudicated against the competition score,
  // which folds in fee policy + the CIP-38 objective that public data does not
  // expose (so score >= delivered surplus is expected).
  if (!thisSol) return;
  try {
    const kinds = new Map();
    if (trades) for (let i = 0; i < Math.min(trades.length, events.length); i++)
      kinds.set(events[i].uid, (trades[i].flags & FLAG_KIND_BUY) ? "buy" : "sell");
    const prices = (comp.auction && comp.auction.prices) || {};
    const native = {}; for (const [k, val] of Object.entries(prices)) native[k.toLowerCase()] = BigInt(val);
    let totalNative = 0n, priced = 0, jitExcluded = 0;
    for (const [uid, limSell, limBuy, e] of results) {
      if (jitUids.has(uid)) { jitExcluded++; continue; }  // maker leg, not user (F6)
      let kind = kinds.get(uid);
      if (!kind) { const meta = await src.orderMeta(network, uid, ev); kind = (meta && meta.kind) || "sell"; }
      const execSellNet = e.sell_amount - (e.fee_amount || 0n);
      const surplus = surplusFromExecution(kind, execSellNet, e.buy_amount, limSell, limBuy);
      const stok = kind === "sell" ? e.buy_token : e.sell_token;
      if (stok in native) { totalNative += floorDiv(surplus * native[stok], WAD); priced++; }
    }
    if (priced === 0) {
      const reason = (jitExcluded && jitExcluded === results.length)
        ? "every settled leg was a JIT/liquidity order (no user order to value)"
        : "no native prices in the competition record for the settled tokens; surplus not valuable in native terms";
      checks.push(v("C5.surplus-delivered", UNCERTAIN, reason)); return;
    }
    const score = BigInt(thisSol.score);
    const coverage = priced !== results.length ? `${priced}/${results.length} priced trade(s)` : `${priced} trade(s)`;
    const jitNote = jitExcluded ? ` ${jitExcluded} JIT/liquidity leg(s) were excluded (maker surplus, not user).` : "";
    checks.push(v("C5.surplus-delivered", INFO,
      `delivered user surplus ≈ ${totalNative} native atoms over ${coverage} (computed from the on-chain executed amounts against the signed limits — it cannot be inflated by the settlement's clearing prices).${jitNote} The reported competition score is ${score}. C5 reports the delivered surplus; it does not independently confirm the score, which folds in fee policy and the CIP-38 objective that public data does not expose (so score >= delivered surplus is expected).`,
      { delivered_surplus_native: totalNative.toString(), reported_score: score.toString() }));
  } catch (e) {
    checks.push(v("C5.surplus-delivered", UNCERTAIN, `surplus computation failed: ${e}`));
  }
}

// Sum executed sell/buy/fee per order uid (multi-fill safety); mirrors
// Python checks_decode._aggregate_by_uid.
function aggregateByUid(events) {
  const agg = new Map();
  for (const e of events) {
    const a = agg.get(e.uid);
    if (!a) agg.set(e.uid, { uid: e.uid, owner: e.owner, sell_token: e.sell_token, buy_token: e.buy_token, sell_amount: e.sell_amount, buy_amount: e.buy_amount, fee_amount: e.fee_amount || 0n, fills: 1 });
    else { a.sell_amount += e.sell_amount; a.buy_amount += e.buy_amount; a.fee_amount += e.fee_amount || 0n; a.fills++; }
  }
  return [...agg.values()];
}

async function isSolver(rpc, addr, blockTag, ev) {
  const data = "0x02cc250d" + addr.slice(2).toLowerCase().padStart(64, "0");
  const res = await src.rpc(rpc, "eth_call", [{ to: AUTHENTICATOR, data }, blockTag], ev);
  return BigInt(res) === 1n;
}
async function runSolverAuth(rpc, direct, toAddr, sender, landedBlock, ev, checks, statusOk = true) {
  const caller = direct ? sender : toAddr;
  if (!caller) { checks.push(v("C9.solver-authorization", UNCERTAIN, "no caller address")); return; }
  let ok = null;
  if (landedBlock !== null) { try { ok = await isSolver(rpc, caller, "0x" + landedBlock.toString(16), ev); } catch { ok = null; } }
  if (ok === null) { try { ok = await isSolver(rpc, caller, "latest", ev); } catch (e) { checks.push(v("C9.solver-authorization", UNCERTAIN, `authenticator query failed: ${e}`)); return; } }
  if (direct) {
    if (ok) checks.push(v("C9.solver-authorization", PASS, `settle() caller ${caller} is a registered solver`));
    else if (statusOk) checks.push(v("C9.solver-authorization", UNCERTAIN, `settle() caller ${caller} does not read as a registered solver, yet the tx succeeded (which requires authorization on-chain) — treating as a reconstruction artifact (non-archive RPC or since-changed solver set), not a finding`));
    else checks.push(v("C9.solver-authorization", VIOLATION, `settle() caller ${caller} is NOT a registered solver`));
  } else {
    checks.push(v("C9.solver-authorization", ok ? PASS : UNCERTAIN, ok ? `wrapper ${caller} is a registered solver` : `wrapper ${caller} not itself registered; authorized caller may be deeper`));
  }
}

const _sig = (x) => (isFinite(x) ? parseFloat(x.toPrecision(8)).toString() : null); // ~Python :.8g
const _human = (atoms, dec) => (dec === null || dec === undefined) ? null : _sig(Number(atoms) / 10 ** dec);
const _price = (numA, numDec, denA, denDec) =>
  (numDec == null || denDec == null || denA === 0n) ? undefined
    : _sig((Number(numA) / 10 ** numDec) / (Number(denA) / 10 ** denDec)) ?? undefined;

async function runOrderLedger(rpc, direct, calldata, logs, ev, checks) {
  const events = tradeEvents(logs);
  if (!events.length) return;
  let decoded = null; if (direct) { try { decoded = decodeSettlement(calldata); } catch {} }
  const cache = new Map();
  const orders = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const st = await src.tokenMeta(rpc, e.sell_token, ev, cache);
    const bt = await src.tokenMeta(rpc, e.buy_token, ev, cache);
    const o = {
      uid: e.uid, owner: e.owner, sell_token: st, buy_token: bt,
      executed_sell: e.sell_amount.toString(), executed_buy: e.buy_amount.toString(),
      executed_sell_human: _human(e.sell_amount, st.decimals), executed_buy_human: _human(e.buy_amount, bt.decimals),
      executed_price: _price(e.buy_amount, bt.decimals, e.sell_amount, st.decimals),
    };
    const t = decoded && decoded.trades[i];
    if (t) {
      const kind = (t.flags & FLAG_KIND_BUY) ? "buy" : "sell";
      o.kind = kind;
      o.partially_fillable = (t.flags & FLAG_PARTIALLY_FILLABLE) !== 0n;
      o.signed_sell = t.sellAmount.toString(); o.signed_buy = t.buyAmount.toString();
      o.valid_to = t.validTo; o.app_data = t.appData;
      o.limit_price = _price(t.buyAmount, bt.decimals, t.sellAmount, st.decimals);
      const base = kind === "sell" ? t.sellAmount : t.buyAmount;
      const got = kind === "sell" ? e.sell_amount : e.buy_amount;
      o.fill_fraction = base ? _sig(Number(got) / Number(base)) : null;
      // Before-fee surplus from executed amounts vs signed limit (un-forgeable).
      const execSellNet = e.sell_amount - (e.fee_amount || 0n);
      const surplus = surplusFromExecution(kind, execSellNet, e.buy_amount, t.sellAmount, t.buyAmount);
      o.surplus_atoms = surplus.toString();
      o.surplus_token = (kind === "sell" ? bt : st).symbol;
    }
    orders.push(o);
  }
  checks.push(v("C10.order-ledger", INFO, `${orders.length} settled order(s)`, { orders }));
}

function runReceiverCheck(direct, calldata, logs, checks, limits) {
  const events = tradeEvents(logs);
  if (!events.length) return;
  let trades = null; if (direct) { try { trades = decodeSettlement(calldata).trades; } catch {} }
  const expected = new Map(); let nativeEth = 0;
  events.forEach((e, i) => {
    if (e.buy_token === NATIVE_ETH) { nativeEth++; return; }
    let recv = e.owner;
    if (trades && trades[i]) { const r = trades[i].receiver.toLowerCase(); if (BigInt(r) !== 0n) recv = r; }
    const key = e.buy_token + "|" + recv;
    expected.set(key, (expected.get(key) || 0n) + e.buy_amount);
  });
  const actual = new Map();
  for (const lg of logs) {
    const topics = lg.topics || [];
    if (!topics.length || topics[0].toLowerCase() !== ERC20_TRANSFER || topics.length < 3) continue;
    const key = (lg.address || "").toLowerCase() + "|" + ("0x" + topics[2].slice(-40)).toLowerCase();
    if (!expected.has(key)) continue;
    let val; try { val = BigInt(lg.data && lg.data !== "0x" ? lg.data : (topics[3] || "0x0")); } catch { continue; }
    actual.set(key, (actual.get(key) || 0n) + val);
  }
  const short = [...expected].filter(([k, exp]) => (actual.get(k) || 0n) < exp);
  if (nativeEth) limits.push(`C11: ${nativeEth} native-ETH buy leg(s) not verifiable from ERC-20 logs`);
  if (!expected.size) checks.push(v("C11.receiver-delivery", INFO, `all ${nativeEth} buy leg(s) are native ETH, not reconcilable from ERC-20 logs`));
  else if (!short.length) checks.push(v("C11.receiver-delivery", PASS, `buy tokens reached the receiver across ${expected.size} group(s)`));
  else checks.push(v("C11.receiver-delivery", INFO, `${short.length} of ${expected.size} group(s) show less ERC-20 delivered than credited — benign by construction (fee-on-transfer, Vault internal balance, receiver forwarding, shared-receiver attribution); context, not a finding`));
}

async function runAuthenticity(network, direct, calldata, logs, ev, checks, limits) {
  const events = tradeEvents(logs);
  if (!events.length) return;
  let trades = null; if (direct) { try { trades = decodeSettlement(calldata).trades; } catch {} }
  let matched = 0; const notFound = [], mism = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const meta = await src.orderMeta(network, e.uid, ev);
    if (!meta) { notFound.push(e.uid); continue; }
    const problems = [];
    if ((meta.sellToken || "").toLowerCase() !== e.sell_token) problems.push("sellToken");
    if ((meta.buyToken || "").toLowerCase() !== e.buy_token) problems.push("buyToken");
    const t = trades && trades[i];
    if (t) {
      try { if (BigInt(meta.sellAmount) !== t.sellAmount) problems.push("sellAmount"); } catch {}
      try { if (BigInt(meta.buyAmount) !== t.buyAmount) problems.push("buyAmount"); } catch {}
      const kindCd = (t.flags & FLAG_KIND_BUY) ? "buy" : "sell";
      if (meta.kind && meta.kind !== kindCd) problems.push("kind");
      try { if (meta.validTo != null && Number(meta.validTo) !== t.validTo) problems.push("validTo"); } catch {}
      if (meta.appData && String(t.appData).toLowerCase() !== meta.appData.toLowerCase()) problems.push("appData");
    }
    if (problems.length) mism.push([e.uid, problems]); else matched++;
  }
  const total = events.length;
  if (mism.length) checks.push(v("C12.order-authenticity", UNCERTAIN, `${mism.length} of ${total} settled order(s) differ from the public orderbook record`));
  else if (matched && !notFound.length) checks.push(v("C12.order-authenticity", PASS, `all ${matched} settled order(s) match a signed order in the public orderbook`));
  else if (matched) checks.push(v("C12.order-authenticity", INFO, `${matched} matched; ${notFound.length} not in the public orderbook (JIT/on-chain)`));
  else checks.push(v("C12.order-authenticity", INFO, `none of the ${total} order(s) are in the public orderbook`));
}

function runPriceVsMid(comp, logs, checks) {
  const events = tradeEvents(logs);
  if (!events.length) return;
  const prices = (comp.auction && comp.auction.prices) || {};
  const native = {};
  for (const [k, val] of Object.entries(prices)) native[k.toLowerCase()] = BigInt(val);
  const rows = [];
  for (const e of events) {
    const st = e.sell_token, bt = e.buy_token;
    if (!(st in native) || !(bt in native)) continue;
    const nin = e.sell_amount * native[st] / WAD;
    const nout = e.buy_amount * native[bt] / WAD;
    if (nin <= 0n) continue;
    rows.push([e.uid, Number(nout - nin) * 10000 / Number(nin)]);
  }
  if (!rows.length) {
    checks.push(v("C14.price-vs-mid", UNCERTAIN, "no reference price for the traded tokens"));
    return;
  }
  const parts = rows.slice(0, 4).map(([, b]) => `${b >= 0 ? "+" : ""}${b.toFixed(1)} bps`);
  checks.push(v("C14.price-vs-mid", INFO,
    `execution vs the auction's reference mid: ${parts.join(", ")}${rows.length > 4 ? ` (+${rows.length - 4} more)` : ""} — positive is better than fair mid; small negatives are normal (fees + spread). Informational, NOT full EBBO.`,
    { per_order: rows.map(([u, b]) => ({ uid: u, bps: Math.round(b * 100) / 100 })) }));
}

// C15 — settlement-contract ERC-20 buffer accounting (context, INFO). Mirrors
// Python checks_buffer.run_buffer_check.
function runBufferCheck(logs, checks) {
  const deltas = new Map();
  let seen = false;
  for (const lg of logs || []) {
    const topics = lg.topics || [];
    if (topics.length < 3 || (topics[0] || "").toLowerCase() !== ERC20_TRANSFER) continue;
    const frm = ("0x" + topics[1].slice(-40)).toLowerCase();
    const to = ("0x" + topics[2].slice(-40)).toLowerCase();
    if (frm !== GPV2 && to !== GPV2) continue;
    let amount; try { amount = BigInt(lg.data || "0x0"); } catch { continue; }
    const token = (lg.address || "").toLowerCase();
    if (to === GPV2) deltas.set(token, (deltas.get(token) || 0n) + amount);
    if (frm === GPV2) deltas.set(token, (deltas.get(token) || 0n) - amount);
    seen = true;
  }
  if (!seen) return;
  const drawn = [...deltas].filter(([, d]) => d < 0n).sort((a, b) => (a[1] < b[1] ? -1 : 1));
  let detail;
  if (drawn.length) {
    const parts = drawn.slice(0, 3).map(([t, d]) => `${t.slice(0, 10)}.. ${d}`);
    detail = `the settlement contract's ERC-20 buffer net-DECREASED for ${drawn.length} token(s) (drew from the protocol buffer): ${parts.join("; ")}. This is sometimes legitimate (solvers may use buffered tokens); reported as context, not a finding. ERC-20 only — native-ETH / Vault-internal moves are not captured here.`;
  } else {
    detail = `the settlement contract took in at least as much as it paid out for all ${deltas.size} ERC-20 token(s) touched (no buffer draw detected). ERC-20 only — native-ETH / Vault-internal moves are not captured here.`;
  }
  const net = {}; for (const [t, d] of deltas) net[t] = d.toString();
  checks.push(v("C15.settlement-buffer", INFO, detail, { net_deltas: net }));
}

function runInteractions(direct, calldata, checks, limits) {
  if (!direct) { checks.push(v("C13.interactions", INFO, "wrapper route: interactions not listed")); return; }
  let inter; try { inter = decodeSettlement(calldata).interactions; } catch (e) { checks.push(v("C13.interactions", UNCERTAIN, `could not decode interactions: ${e}`)); return; }
  const stages = ["pre", "intra", "post"]; const flat = [];
  inter.forEach((stage, si) => stage.forEach((it) => flat.push({ stage: stages[si], target: it.target, value: it.value.toString(), selector: it.selector })));
  const counts = { pre: 0, intra: 0, post: 0 }; for (const f of flat) counts[f.stage]++;
  // Role-tag pre/post interactions (intra = routing, out of criterion-4 scope).
  const prepost = flat.filter((f) => f.stage !== "intra");
  let hookCalls = 0, infraCalls = 0;
  for (const f of flat) {
    if (f.target === HOOKS_TRAMPOLINE) { f.role = "order-hook execution (HooksTrampoline)"; if (f.stage !== "intra") hookCalls++; }
    else if (f.target === DEADLINE_CHECK) { f.role = "driver infra (deadline check)"; if (f.stage !== "intra") infraCalls++; }
    else f.role = f.stage === "intra" ? "routing" : "other";
  }
  const otherPrepost = prepost.length - hookCalls - infraCalls;
  let hookNote = "";
  if (prepost.length) {
    const bits = [];
    if (hookCalls) bits.push(`${hookCalls} order-hook execution (HooksTrampoline)`);
    if (infraCalls) bits.push(`${infraCalls} driver infra (deadline check)`);
    if (otherPrepost) bits.push(`${otherPrepost} other`);
    hookNote = `; pre/post: ${bits.join(", ")}`;
  }
  const distinct = new Set(flat.map((f) => f.target)).size;
  const withValue = flat.filter((f) => BigInt(f.value) > 0n).length;
  checks.push(v("C13.interactions", INFO, `${flat.length} interaction(s): pre ${counts.pre} / intra ${counts.intra} / post ${counts.post}; ${distinct} distinct target(s); ${withValue} carrying native-ETH value${hookNote}`, { interactions: flat }));
  limits.push("C13 lists and role-tags the executed interactions; positive hook verification and the full services#2667 criterion-4 relation need the /solve instance from the S3 bucket, not the public API");
}
