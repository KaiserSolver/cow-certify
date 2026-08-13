// Render a certificate object into the trader-facing HTML view (browser DOM).
// Faithful port of the Python htmlreport design; CSS lives in index.html.
import { EXPLORER, CHAIN_IDS } from "./sources.js";

const FRIENDLY = {
  C0: ["Settlement type", "How the trade reached the chain — CoW's contract directly, or via a solver's own contract."],
  C1: ["Bound to its auction", "The on-chain settlement matches the auction it claims to have won."],
  C2: ["Settled by the auction winner", "The solver that won the auction is the one that settled it."],
  C3: ["Settled as solved", "Exactly the winning solution's orders settled, at the amounts that were scored."],
  C4: ["Your price limit was respected", "Every trade executed at or better than the limit price you signed."],
  C5: ["Surplus you received", "The user surplus actually delivered on-chain, computed from the executed amounts against your signed limit — it cannot be inflated by the settlement's prices. (The competition score is a separate, fee-inclusive number this tool does not adjudicate.)"],
  C6: ["Settled on time", "The settlement landed within the auction's deadline."],
  C7: ["Auction competition", "How many solvers and solutions competed for this batch."],
  C8: ["Transaction status", "Whether the settlement transaction succeeded on-chain."],
  C9: ["Solver authorized on-chain", "The account that settled is a registered CoW solver in the on-chain allowlist."],
  C10: ["Trade details", "The full per-order record."],
  C11: ["You received your tokens", "The tokens bought actually reached the recorded receiver on-chain."],
  C12: ["Matches your signed order", "The settled order matches a real signed order in CoW's public orderbook."],
  C13: ["External calls", "The contracts the settlement interacted with."],
  C14: ["Execution vs fair mid", "How your price compared to the auction's reference mid — a best-execution signal, not full EBBO."],
  C15: ["Protocol buffer", "Whether the settlement drew from CoW's accumulated-fee buffer (ERC-20 net delta of the settlement contract). Context, not a judgment."],
};
const HERO = {
  PASS: ["✓", "ok", "Verified", "This settlement is a valid execution of the auction it claims."],
  VIOLATION: ["✗", "bad", "Violation found", "One or more checks failed — see the flagged items below."],
  UNCERTAIN: ["?", "warn", "Inconclusive", "Some parts can't be confirmed from public data alone."],
};
const TONE = { PASS: "ok", VIOLATION: "bad", UNCERTAIN: "warn", INFO: "info" };
const GLYPH = { PASS: "✓", VIOLATION: "✗", UNCERTAIN: "?", INFO: "·" };
// checks presented as signal/context (collapsed), not primary judgments.
const CONTEXT = new Set(["C7", "C13", "C14", "C15"]);

const esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" }[c]));
const short = (h, a = 10, b = 8) => { h = String(h || ""); return h.length <= a + b + 1 ? h : `${h.slice(0, a)}…${h.slice(-b)}`; };
const tsym = (t) => esc(t.symbol || (t.address.slice(0, 8) + "…"));
const copyable = (full, shown) => `<span class="mono copyable" data-copy="${esc(full)}" title="click to copy">${esc(shown ?? full)}</span>`;

function tradeCards(orders, vsMid) {
  return orders.map((o) => {
    const ss = o.executed_sell_human || o.executed_sell;
    const bb = o.executed_buy_human || o.executed_buy;
    const kind = o.kind || "trade";
    const meta = [];
    if (o.executed_price) meta.push(`<span>price <b class="mono">${esc(o.executed_price)}</b></span>`);
    const bps = vsMid[(o.uid || "").toLowerCase()];
    if (bps !== undefined) meta.push(`<span>vs fair mid <b class="mono ${bps >= 0 ? "good" : ""}">${bps >= 0 ? "+" : ""}${esc(bps)} bps</b></span>`);
    meta.push(`<span>trader ${copyable(o.owner, short(o.owner))}</span>`);
    return `<div class="tcard"><div class="flow">
      <span class="side"><span class="amt mono">${esc(ss)}</span> ${tsym(o.sell_token)}<small>${kind === "sell" ? "you sold" : "sold"}</small></span>
      <span class="arrow">→</span>
      <span class="side"><span class="amt mono">${esc(bb)}</span> ${tsym(o.buy_token)}<small>${kind === "sell" ? "you received" : "received"}</small></span>
    </div><div class="tmeta">${meta.join("")}</div></div>`;
  }).join("");
}

function checkRow(chk) {
  const cid = chk.check.split(".")[0];
  const [label, gloss] = FRIENDLY[cid] || [chk.check, ""];
  const tone = TONE[chk.verdict] || "info";
  const cls = chk.verdict === "INFO" ? "row info" : "row";
  return `<div class="${cls}" style="--tone:var(--${tone})">
    <div class="g">${GLYPH[chk.verdict] || "·"}</div>
    <div><div class="label">${esc(label)}</div>
      <div class="detail">${esc(chk.detail)}</div>
      ${gloss ? `<div class="gloss">${esc(gloss)}</div>` : ""}</div></div>`;
}

export function renderCertificate(cert) {
  const sub = cert.subject, net = sub.network || "", cid = sub.chain_id || CHAIN_IDS[net], tx = sub.tx_hash || "";
  const [glyph, tone, title, sentence] = HERO[cert.overall] || ["·", "info", cert.overall, ""];
  const counts = {};
  for (const c of cert.checks) counts[c.verdict] = (counts[c.verdict] || 0) + 1;
  const pills = [["PASS", "ok"], ["VIOLATION", "bad"], ["UNCERTAIN", "warn"], ["INFO", "info"]]
    .filter(([k]) => counts[k]).map(([k, cl]) => `<span class="pill ${cl}">${counts[k]} ${k.toLowerCase()}</span>`).join("");

  const ledger = cert.checks.find((c) => c.check.startsWith("C10"));
  const orders = (ledger && ledger.orders) || [];
  const c14 = cert.checks.find((c) => c.check.startsWith("C14"));
  const vsMid = {};
  for (const o of (c14 && c14.per_order) || []) vsMid[(o.uid || "").toLowerCase()] = o.bps;

  const judgments = cert.checks.filter((c) => !CONTEXT.has(c.check.split(".")[0]) && c.check.split(".")[0] !== "C10");
  const context = cert.checks.filter((c) => CONTEXT.has(c.check.split(".")[0]));
  const exp = EXPLORER[net];
  const txLink = exp ? `<a href="${exp}${esc(tx)}" target="_blank" rel="noopener">view on explorer ↗</a>` : "";

  const tradeHtml = orders.length ? `<div class="section"><h2>The trade</h2><div class="trade">${tradeCards(orders, vsMid)}</div></div>` : "";
  const ctxHtml = context.length ? `<details class="ctx"><summary>Signals &amp; context — competition, execution vs mid, interactions</summary><div class="checks">${context.map(checkRow).join("")}</div></details>` : "";
  const limits = cert.not_verifiable || [];
  const limitsHtml = limits.length ? `<div class="note">What this certificate does not check:</div><ul class="limits">${limits.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : "";
  const ev = cert.evidence || [];
  const evrows = ev.map((e) => `<div class="evrow"><span>${esc(e.kind || "")}</span><span class="mono">${esc((e.sha256 || "").slice(0, 16))}…</span><span class="mono">${esc(short(e.ref || "", 40, 6))}</span></div>`).join("");

  return `<div class="wrap" style="--tone:var(--${tone})">
    <div class="masthead"><div><div class="brand">cow<span>·</span>certify</div><div class="tagline">independent settlement verification</div></div>
      <div style="text-align:right"><div class="chip">${esc(net)}${cid ? ` · chain ${cid}` : ""}</div></div></div>
    <div class="txline">${copyable(tx)} ${txLink}</div>
    <div class="verdict" style="--tone:var(--${tone})"><div class="seal">${glyph}</div>
      <div style="flex:1"><h1>${esc(title)}</h1><p>${esc(sentence)}</p><div class="tally">${pills}</div></div></div>
    ${tradeHtml}
    <div class="section"><h2>Verification checks</h2><div class="checks">${judgments.map(checkRow).join("")}</div></div>
    ${ctxHtml}
    <div class="section"><h2>Verify this yourself</h2>
      <div class="note">Every result is reconstructed from public data only. Re-run this exact certificate:</div>
      <div class="repro mono">${esc(cert.reproduce || "")}</div>
      <details><summary>Evidence — ${ev.length} fetch(es), each fingerprinted (sha256)</summary>${evrows}</details>
      ${limitsHtml}</div>
    <footer><span>cow-certify ${esc(cert.schema_version || "")} · not affiliated with CoW Protocol · public data only</span>
      <span><a href="https://github.com/KaiserSolver/cow-certify" target="_blank" rel="noopener">source · MIT</a></span></footer>
  </div>`;
}
