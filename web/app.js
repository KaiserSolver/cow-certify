// Wires the input form to the in-browser verification pipeline, with shareable
// deep-links: ?net=<chain>&tx=<hash> (or ?order=<uid>) auto-runs on load, and a
// successful run rewrites the address bar to a canonical, copyable permalink.
import { certify } from "./checks.js";
import { renderCertificate } from "./render.js";
import { NETWORKS, DEFAULT_RPC, rpc, tradesByOrder, Evidence } from "./sources.js";

const $ = (id) => document.getElementById(id);
const q = $("q"), net = $("net"), go = $("go"), statusEl = $("status"), result = $("result"), share = $("share");

const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const UID_RE = /^0x[0-9a-fA-F]{112}$/;
const NET_ORDER = ["mainnet", "arbitrum", "base", "gnosis", "polygon", "avalanche", "bnb", "ink", "linea", "plasma", "sepolia"];

$("ex").onclick = () => {
  q.value = "0x859d015d472ab27905ef704ec48b7c3e11b0e0cc5c86e09bfd885acb04ca1aee";
  net.value = "base";
};

// DOM-built, never innerHTML: error text can carry a (malicious) RPC's response,
// so it must never be interpreted as HTML.
const clearStatus = () => statusEl.replaceChildren();
function loading(m) {
  statusEl.replaceChildren();
  const s = document.createElement("span"); s.className = "spinner";
  statusEl.append(s, document.createTextNode(" " + m));
}
function error(m) {
  statusEl.replaceChildren();
  const d = document.createElement("div"); d.className = "err"; d.textContent = m;
  statusEl.append(d);
}

function toast(msg) {
  let t = document.getElementById("toast");
  if (!t) { t = document.createElement("div"); t.id = "toast"; t.className = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 1200);
}
function wireCopy() {
  result.querySelectorAll("[data-copy]").forEach((el) => {
    el.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(el.getAttribute("data-copy")); toast("Copied"); }
      catch { toast("Copy failed — select manually"); }
    });
  });
}

async function detectForTx(tx) {
  for (const n of NET_ORDER) {
    try { if (await rpc(DEFAULT_RPC[n], "eth_getTransactionByHash", [tx], new Evidence(), 1)) return n; } catch {}
  }
  return null;
}
async function resolveOrder(uid, chosen) {
  for (const n of (chosen === "auto" ? NET_ORDER : [chosen])) {
    try {
      const trades = await tradesByOrder(n, uid, new Evidence());
      if (trades && trades.length && trades[trades.length - 1].txHash)
        return { network: n, tx: trades[trades.length - 1].txHash };
    } catch {}
  }
  return null;
}

async function resolveTarget(rawInput, chosen) {
  const value = rawInput.trim();
  if (UID_RE.test(value)) {
    loading("finding your trade's settlement…");
    const r = await resolveOrder(value, chosen);
    if (!r) throw new Error("Order not found, or it hasn't settled yet. Double-check the id (and chain).");
    return r;
  }
  if (!HASH_RE.test(value)) throw new Error("That doesn't look like a transaction hash (0x + 64 hex) or an order id (0x + 112 hex).");
  let network = chosen;
  if (network === "auto") {
    loading("detecting the chain…");
    network = await detectForTx(value);
    if (!network) throw new Error("Couldn't find that transaction on any CoW chain. Is the hash correct?");
  }
  return { network, tx: value };
}

function showShare(network, tx) {
  const link = `${location.origin}${location.pathname}?net=${network}&tx=${tx}`;
  history.replaceState(null, "", `?net=${network}&tx=${tx}`);
  share.hidden = false;
  share.replaceChildren();
  const label = document.createElement("span"); label.className = "share-label"; label.textContent = "Shareable link";
  const input = document.createElement("input"); input.className = "mono"; input.readOnly = true; input.value = link;
  input.onfocus = () => input.select();
  const btn = document.createElement("button"); btn.type = "button"; btn.textContent = "Copy";
  btn.onclick = async () => {
    try { await navigator.clipboard.writeText(link); }
    catch { input.select(); try { document.execCommand("copy"); } catch {} }
    btn.textContent = "Copied ✓"; setTimeout(() => { btn.textContent = "Copy"; }, 1500);
  };
  share.append(label, input, btn);
}

async function doVerify(rawInput, chosen) {
  result.innerHTML = ""; share.hidden = true; go.disabled = true;
  try {
    const { network, tx } = await resolveTarget(rawInput, chosen);
    loading(`verifying on ${network}…`);
    const cert = await certify(network, tx);
    clearStatus();
    result.innerHTML = renderCertificate(cert);
    wireCopy();
    showShare(network, tx);
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    error(String(err && err.message ? err.message : err));
  } finally {
    go.disabled = false;
  }
}

$("f").addEventListener("submit", (e) => { e.preventDefault(); doVerify(q.value, net.value); });

// Deep-link: ?net=<chain>&tx=<hash> or ?order=<uid> auto-runs on load.
(function initFromUrl() {
  const p = new URLSearchParams(location.search);
  const value = p.get("tx") || p.get("order");
  if (!value) return;
  q.value = value.trim();
  const n = p.get("net");
  if (n && (n === "auto" || NETWORKS[n])) net.value = n;
  doVerify(q.value, net.value);
})();
