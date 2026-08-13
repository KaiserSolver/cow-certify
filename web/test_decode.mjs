// Drift guard (stage 1): the browser decoder must produce byte-identical
// results to the Python cow_certify.gpv2 on every settlement in the corpus.
import { readFileSync } from "node:fs";
import { decodeSettlement } from "./gpv2.js";

const truthPath = process.env.TRUTH || "./testdata/decode_truth.json";
const truth = JSON.parse(readFileSync(new URL(truthPath, import.meta.url)));

let ok = 0;
const fails = [];

function eqTrades(a, b) {
  if (a.length !== b.length) return `trade count ${a.length}!=${b.length}`;
  for (let i = 0; i < a.length; i++) {
    const p = b[i];
    const j = {
      sellTokenIndex: a[i].sellTokenIndex, buyTokenIndex: a[i].buyTokenIndex,
      receiver: a[i].receiver, sellAmount: a[i].sellAmount.toString(),
      buyAmount: a[i].buyAmount.toString(), validTo: a[i].validTo,
      appData: a[i].appData, feeAmount: a[i].feeAmount.toString(),
      flags: Number(a[i].flags), executedAmount: a[i].executedAmount.toString(),
    };
    for (const k of Object.keys(j)) {
      if (String(j[k]).toLowerCase() !== String(p[k]).toLowerCase())
        return `trade[${i}].${k}: ${j[k]} != ${p[k]}`;
    }
  }
  return null;
}

function eqInter(a, b) {
  if (a.length !== b.length) return `stages ${a.length}!=${b.length}`;
  for (let s = 0; s < a.length; s++) {
    if (a[s].length !== b[s].length) return `stage ${s} len ${a[s].length}!=${b[s].length}`;
    for (let j = 0; j < a[s].length; j++) {
      const x = a[s][j], y = b[s][j];
      if (x.target !== y.target || x.value.toString() !== y.value ||
          x.selector.toLowerCase() !== y.selector.toLowerCase())
        return `interaction[${s}][${j}] mismatch`;
    }
  }
  return null;
}

for (const row of truth) {
  const d = decodeSettlement(row.calldata);
  const T = row.decoded;
  const problems = [];
  if (JSON.stringify(d.tokens) !== JSON.stringify(T.tokens)) problems.push("tokens");
  if (JSON.stringify(d.clearingPrices.map(String)) !== JSON.stringify(T.clearingPrices))
    problems.push("clearingPrices");
  const te = eqTrades(d.trades, T.trades); if (te) problems.push(te);
  const ie = eqInter(d.interactions, T.interactions); if (ie) problems.push(ie);
  const aid = d.auctionId === null ? null : d.auctionId.toString();
  if (aid !== T.auctionId) problems.push(`auctionId ${aid}!=${T.auctionId}`);
  if (problems.length) fails.push(`${row.network} ${row.tx.slice(0, 14)}: ${problems.join("; ")}`);
  else ok++;
}

console.log(`decoder parity: ${ok}/${truth.length} identical to Python`);
for (const f of fails.slice(0, 10)) console.log("  MISMATCH", f);
process.exit(fails.length ? 1 : 0);
