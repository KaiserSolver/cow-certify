// Hermetic (no-network) browser-engine tests against a recorded real settlement.
//   node web/test_hermetic.mjs
//
// The shipped corpora are all-PASS, so they never exercise the paths where a
// verifier goes wrong. Here `fetch` is stubbed with a recorded Base settlement
// (tests/fixtures/base_0x859d015d.json, shared with the Python suite) and ONE
// thing is mutated per case. The cardinal rule is asserted every time: a
// legitimate settlement is never accused; an accusation needs an on-chain fact.
import { readFileSync } from "node:fs";

const FIX = JSON.parse(readFileSync(new URL("../tests/fixtures/base_0x859d015d.json", import.meta.url)));
const TX = FIX.tx.hash;
const UID = FIX._provenance.settled_uid;
const AID = FIX.comp.auctionId;
const IS_SOLVER = "0x02cc250d";
const ONE = "0x" + "0".repeat(63) + "1", ZERO = "0x" + "0".repeat(64);
const TRADE_TOPIC = "0xa07a543ab8a018198e99ca0184c93fe9050a79400a0a723441f84de1d972cc17";

// ---- fake network ----------------------------------------------------------
class Transport {
  constructor() {
    this.tx = { ...FIX.tx };
    this.rc = JSON.parse(JSON.stringify(FIX.rc));
    this.comp = JSON.parse(JSON.stringify(FIX.comp));
    this.orders = { [UID]: FIX.order };
    this.chainId = 8453;
    this.isSolver = (addr, tag) => true;
    this.symbolHex = null;
    this.perUrl = {};         // url -> (method, params) => result | {__error__} | {__raw__} | throw
    this.apiStatus = null;    // force an HTTP status on api.cow.fi
    this.calls = [];
  }
  defaultRpc(method, params) {
    if (method === "eth_chainId") return "0x" + this.chainId.toString(16);
    if (method === "eth_getTransactionByHash") return this.tx;
    if (method === "eth_getTransactionReceipt") return this.rc;
    if (method === "eth_call") {
      const d = (params[0].data || "").toLowerCase();
      if (d.startsWith(IS_SOLVER)) return this.isSolver("0x" + d.slice(-40), params[1]) ? ONE : ZERO;
      if (d.startsWith("0x313ce567")) return "0x" + (18).toString(16).padStart(64, "0");
      if (d.startsWith("0x95d89b41")) return this.symbolHex ?? ("0x" + (32).toString(16).padStart(64, "0") + (4).toString(16).padStart(64, "0") + Buffer.from("TEST").toString("hex").padEnd(64, "0"));
      return "0x";
    }
    return null;
  }
  install() {
    globalThis.fetch = async (url, opts = {}) => {
      url = String(url);
      const resp = (status, text) => ({ status, ok: status >= 200 && status < 300, text: async () => text });
      if (opts.body) {
        const { method, params } = JSON.parse(opts.body);
        this.calls.push([url, method]);
        const h = this.perUrl[url];
        let out = h ? h(method, params) : "__default__";
        if (out && out.__raw__ !== undefined) return resp(200, out.__raw__);
        if (out && out.__http__ !== undefined) return resp(out.__http__, "");
        if (out === "__default__") out = this.defaultRpc(method, params);
        if (out && out.__error__) return resp(200, JSON.stringify({ jsonrpc: "2.0", id: 1, error: out.__error__ }));
        return resp(200, JSON.stringify({ jsonrpc: "2.0", id: 1, result: out }));
      }
      this.calls.push([url, "GET"]);
      if (this.apiStatus) return resp(this.apiStatus, "");
      if (url.includes("/solver_competition/by_tx_hash/")) return this.comp ? resp(200, JSON.stringify(this.comp)) : resp(404, "");
      if (url.includes("/orders/")) { const uid = url.split("/").pop().toLowerCase(); return this.orders[uid] ? resp(200, JSON.stringify(this.orders[uid])) : resp(404, ""); }
      if (url.includes("/trades?orderUid=")) return resp(200, JSON.stringify([{ txHash: TX, orderUid: UID }]));
      return resp(404, "");
    };
  }
}

let checksMod = null;
async function certify(tr, opts = {}) {
  tr.install();
  if (!checksMod) checksMod = await import("./checks.js");   // after the stub is installed
  return checksMod.certify("base", TX, opts);
}
const check = (cert, p) => cert.checks.find((c) => c.check.startsWith(p + "."));
const verdicts = (cert) => Object.fromEntries(cert.checks.map((c) => [c.check.split(".")[0], c.verdict]));

// ---- calldata / log helpers -------------------------------------------------
const canonical = () => FIX.tx.input.slice(0, -16);   // strip the 8-byte autopilot suffix
const word = (n) => BigInt(n).toString(16).padStart(64, "0");
function tradeLog(owner, sellToken, buyToken, sell, buy, fee, uid) {
  const data = "0x" + sellToken.slice(2).padStart(64, "0") + buyToken.slice(2).padStart(64, "0")
    + word(sell) + word(buy) + word(fee) + word(0xc0) + word(0x38) + uid.slice(2).padEnd(128, "0");
  return { address: "0x9008d19f58aabd9ed0d60971565aa8510560ab41", topics: [TRADE_TOPIC, "0x" + owner.slice(2).padStart(64, "0")], data };
}
function halveTradeBuy(rc) {
  const lg = rc.logs.find((l) => (l.topics || [])[0]?.toLowerCase() === TRADE_TOPIC);
  const d = lg.data.slice(2);
  const buy = BigInt("0x" + d.slice(192, 256)) / 2n;
  lg.data = "0x" + d.slice(0, 192) + word(buy) + d.slice(256);
}
// Non-canonical but decodable: 32 bytes of unread junk after the 4-word head,
// every head offset bumped by 32.
function nonCanonical(cd) {
  const body = cd.slice(10);
  const head = [];
  for (let i = 0; i < 4; i++) head.push(word(BigInt("0x" + body.slice(i * 64, (i + 1) * 64)) + 32n));
  return "0x13d79a0b" + head.join("") + "0".repeat(64) + body.slice(256);
}

// ---- test runner -----------------------------------------------------------
let pass = 0, fail = 0;
const failures = [];
async function t(name, fn) {
  try { await fn(); pass++; }
  catch (e) { fail++; failures.push(`${name}: ${e.message || e}`); }
}
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m || ""} expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
const neq = (a, b, m) => { if (a === b) throw new Error(`${m || ""} must not be ${JSON.stringify(b)}`); };
const noViolation = (cert) => { for (const [k, vv] of Object.entries(verdicts(cert))) if (vv === "VIOLATION") throw new Error(`${k} is VIOLATION`); };

await t("baseline: recorded settlement certifies PASS", async () => {
  const cert = await certify(new Transport());
  eq(cert.overall, "PASS", JSON.stringify(verdicts(cert)));
  eq(check(cert, "C8"), undefined, "C8 absent on a successful tx");
  eq(check(cert, "C1").verdict, "PASS");
  eq(check(cert, "C4").verdict, "PASS");
});

await t("CF-1: null receipt everywhere is UNCERTAIN, not a revert accusation", async () => {
  const tr = new Transport(); tr.rc = null;
  const cert = await certify(tr);
  neq(cert.overall, "VIOLATION", JSON.stringify(verdicts(cert)));
  eq(check(cert, "C8")?.verdict, "UNCERTAIN", "C8");
  noViolation(cert);
});

await t("CF-1: null receipt from one lagging node is confirmed elsewhere", async () => {
  const tr = new Transport();
  const { DEFAULT_RPC } = await import("./sources.js");
  tr.perUrl[DEFAULT_RPC.base[0]] = (m) => (m === "eth_getTransactionReceipt" ? null : "__default__");
  const cert = await certify(tr);
  eq(cert.overall, "PASS", JSON.stringify(verdicts(cert)));
});

await t("CF-1: true revert on every node is still a VIOLATION", async () => {
  const tr = new Transport(); tr.rc = { ...FIX.rc, status: "0x0", logs: [] };
  const cert = await certify(tr);
  eq(check(cert, "C8").verdict, "VIOLATION"); eq(cert.overall, "VIOLATION");
});

await t("CF-5: a single custom rpcUrl is not the only witness to an apparent revert", async () => {
  const tr = new Transport();
  const custom = "https://my-node.example/rpc";
  tr.perUrl[custom] = (m) => (m === "eth_getTransactionReceipt" ? { ...FIX.rc, status: "0x0" } : "__default__");
  const cert = await certify(tr, { rpcUrl: custom });
  eq(cert.overall, "PASS", JSON.stringify(verdicts(cert)));
});

await t("CF-14 (JS): custom rpcUrl on the wrong chain is refused", async () => {
  const tr = new Transport(); tr.chainId = 42161;
  let threw = null;
  try { await certify(tr, { rpcUrl: "https://arb.example/rpc" }); } catch (e) { threw = String(e); }
  if (!threw || !/chain/i.test(threw)) throw new Error(`expected a chain-id refusal, got ${threw}`);
});

await t("CF-3: truncated calldata must not fabricate a passing limit", async () => {
  const tr = new Transport();
  tr.tx.input = tr.tx.input.slice(0, 10 + 20 * 64);   // 20 words of a ~200-word blob
  halveTradeBuy(tr.rc);                                  // the trade now genuinely breaks its limit
  const cert = await certify(tr);
  neq(check(cert, "C4")?.verdict, "PASS", "C4 on a broken limit");
  eq(check(cert, "C4")?.verdict, "VIOLATION", "C4 via orderbook fallback");
});

await t("CF-9: out-of-range trade offset does not lose the certificate", async () => {
  const tr = new Transport();
  // point the trades array offset far past the end of the data
  const body = tr.tx.input.slice(10);
  tr.tx.input = "0x13d79a0b" + body.slice(0, 128) + word(0xffff00) + body.slice(192);
  const cert = await certify(tr);   // must resolve
  if (!cert || !cert.checks) throw new Error("no certificate");
  noViolation(cert);
});

await t("CF-2: wrong 8-byte suffix on canonical calldata IS a violation", async () => {
  const tr = new Transport(); tr.tx.input = canonical() + (AID + 1).toString(16).padStart(16, "0");
  const cert = await certify(tr);
  eq(check(cert, "C1").verdict, "VIOLATION");
});

await t("CF-2: 16-byte tail is not read as an auction id", async () => {
  const tr = new Transport(); tr.tx.input = canonical() + "00".repeat(8) + (AID + 1).toString(16).padStart(16, "0");
  const cert = await certify(tr);
  neq(check(cert, "C1").verdict, "VIOLATION", "C1"); neq(cert.overall, "VIOLATION");
});

await t("CF-2: non-canonical layout with a wrong suffix is not accused", async () => {
  const tr = new Transport(); tr.tx.input = nonCanonical(canonical()) + (AID + 1).toString(16).padStart(16, "0");
  const cert = await certify(tr);
  neq(check(cert, "C1").verdict, "VIOLATION", "C1"); neq(cert.overall, "VIOLATION");
});

await t("CF-4: C9 latest-fallback on a reverted tx is UNCERTAIN", async () => {
  const tr = new Transport(); tr.rc = { ...FIX.rc, status: "0x0", logs: [] };
  tr.isSolver = (a, tag) => { if (tag !== "latest") throw new Error("missing trie node"); return false; };
  const cert = await certify(tr);
  eq(check(cert, "C9").verdict, "UNCERTAIN", check(cert, "C9").detail);
});

await t("CF-22: a custom RPC key never reaches the certificate", async () => {
  const tr = new Transport();
  const custom = "https://node.example/v2/SECRETKEY123";
  tr.perUrl[custom] = (m) => (m === "eth_call" ? { __error__: { code: -32602, message: "archive requests require a token" } } : "__default__");
  const cert = await certify(tr, { rpcUrl: custom });
  const blob = JSON.stringify(cert);
  if (blob.includes("SECRETKEY123") || blob.includes("node.example/v2")) throw new Error("key leaked into the certificate");
});

await t("CF-19: a 400 from api.cow.fi is not retried", async () => {
  const tr = new Transport(); tr.apiStatus = 400;
  let threw = false;
  try { await certify(tr); } catch { threw = true; }
  const n = tr.calls.filter(([u, m]) => m === "GET" && u.includes("solver_competition")).length;
  eq(n, 1, "competition requests");
  if (!threw) throw new Error("expected the certificate to fail operationally");
});

await t("CF-19: a deterministic JSON-RPC error is not re-rounded", async () => {
  const tr = new Transport();
  const { DEFAULT_RPC } = await import("./sources.js");
  for (const u of DEFAULT_RPC.base) tr.perUrl[u] = (m, p) => (m === "eth_call" && (p[0].data || "").startsWith("0x313ce567") ? { __error__: { code: -32000, message: "execution reverted" } } : "__default__");
  await certify(tr);
  const n = tr.calls.filter(([, m]) => m === "eth_call").length;
  const perDecimalsCall = DEFAULT_RPC.base.length;   // one attempt per endpoint, no extra rounds
  // 2 tokens × decimals() over N endpoints + symbol()/isSolver calls (1 each, first endpoint)
  if (n > 2 * perDecimalsCall + 6) throw new Error(`too many eth_call attempts: ${n}`);
});

await t("CF-25: the ledger cites the full api.cow.fi URL", async () => {
  const cert = await certify(new Transport());
  const e = cert.evidence.find((x) => x.kind === "competition:by_tx_hash");
  if (!e || !e.ref.includes("/api/v2/solver_competition/by_tx_hash/")) throw new Error(`ref = ${e && e.ref}`);
});

await t("CF-24: an RTL-override token symbol is rejected like Python", async () => {
  const tr = new Transport();
  const spoof = Buffer.from("‮CDSU‬", "utf8").toString("hex");
  tr.symbolHex = "0x" + (32).toString(16).padStart(64, "0") + (spoof.length / 2).toString(16).padStart(64, "0") + spoof.padEnd(64, "0");
  const cert = await certify(tr);
  const o = check(cert, "C10").orders[0];
  eq(o.sell_token.symbol, null, "spoofed symbol"); eq(o.buy_token.symbol, null, "spoofed symbol");
});

await t("CF-32: context checks never raise the overall verdict", async () => {
  const tr = new Transport(); tr.comp.auction.prices = {};
  const cert = await certify(tr);
  eq(cert.overall, "PASS", JSON.stringify(verdicts(cert)));
  eq(check(cert, "C14").verdict, "INFO"); eq(check(cert, "C5").verdict, "INFO");
});

await t("CF-16: a malformed reference price does not abort the certificate", async () => {
  const tr = new Transport();
  for (const k of Object.keys(tr.comp.auction.prices)) tr.comp.auction.prices[k] = "1.5";
  const cert = await certify(tr);
  neq(cert.overall, "VIOLATION"); eq(check(cert, "C14").verdict, "INFO");
});

await t("CF-6: an unlisted settled uid outside the auction's user orders is UNCERTAIN", async () => {
  const tr = new Transport();
  const st = FIX._provenance.sell_token, bt = FIX._provenance.buy_token;
  tr.rc.logs = [...FIX.rc.logs, tradeLog("0x" + "ab".repeat(20), st, bt, 10n ** 18n, 1n, 0n, "0x" + "cd".repeat(56))];
  const cert = await certify(tr);
  eq(check(cert, "C3").verdict, "UNCERTAIN", check(cert, "C3").detail); neq(cert.overall, "VIOLATION");
});

await t("CF-6: an unlisted settled uid that IS an auction user order is a VIOLATION", async () => {
  const tr = new Transport();
  const st = FIX._provenance.sell_token, bt = FIX._provenance.buy_token;
  const other = FIX.comp.auction.orders.find((u) => u.toLowerCase() !== UID);
  tr.rc.logs = [...FIX.rc.logs, tradeLog("0x" + "ab".repeat(20), st, bt, 10n ** 18n, 1n, 0n, other)];
  const cert = await certify(tr);
  eq(check(cert, "C3").verdict, "VIOLATION");
});

console.log(`\nhermetic (JS): ${pass} passed, ${fail} failed`);
for (const f of failures) console.log("  FAIL", f);
process.exit(fail ? 1 : 0);
