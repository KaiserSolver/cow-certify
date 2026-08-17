// Public data sources for the browser build. Works in Node 20 and browsers
// (both have global fetch + crypto.subtle). No keys, public data only.

export const NETWORKS = {
  mainnet: "mainnet", arbitrum: "arbitrum_one", base: "base", gnosis: "xdai",
  polygon: "polygon", avalanche: "avalanche", bnb: "bnb",
  ink: "ink", linea: "linea", plasma: "plasma", sepolia: "sepolia",
};
export const CHAIN_IDS = {
  mainnet: 1, arbitrum: 42161, base: 8453, gnosis: 100,
  polygon: 137, avalanche: 43114, bnb: 56, ink: 57073, linea: 59144, plasma: 9745, sepolia: 11155111,
};
export const DEFAULT_RPC = {
  mainnet: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"], // both CORS-enabled (eth.llamarpc is not)
  arbitrum: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
  base: ["https://base-rpc.publicnode.com", "https://base.rpc.blxrbdn.com", "https://mainnet.base.org"],
  gnosis: ["https://rpc.gnosischain.com", "https://gnosis-rpc.publicnode.com"],
  polygon: ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"],
  avalanche: ["https://avalanche-c-chain-rpc.publicnode.com", "https://api.avax.network/ext/bc/C/rpc"],
  bnb: ["https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"], // both CORS-enabled (llamarpc is not)
  ink: ["https://rpc-gel.inkonchain.com", "https://ink.drpc.org"], // both CORS-enabled
  linea: ["https://rpc.linea.build", "https://linea-rpc.publicnode.com", "https://1rpc.io/linea"],
  plasma: ["https://rpc.plasma.to", "https://plasma.drpc.org"],
  sepolia: ["https://ethereum-sepolia-rpc.publicnode.com"],
};
export const EXPLORER = {
  mainnet: "https://etherscan.io/tx/", arbitrum: "https://arbiscan.io/tx/",
  base: "https://basescan.org/tx/", gnosis: "https://gnosisscan.io/tx/",
  polygon: "https://polygonscan.com/tx/", avalanche: "https://snowtrace.io/tx/",
  bnb: "https://bscscan.com/tx/", ink: "https://explorer.inkonchain.com/tx/",
  linea: "https://lineascan.build/tx/",
  plasma: "https://plasmascan.to/tx/", sepolia: "https://sepolia.etherscan.io/tx/",
};

const UA = { "user-agent": "cow-certify" }; // browsers ignore; helps some RPCs in Node

// scheme://host only in the evidence ledger — never a path or query, where a
// provider API key can ride (mirrors Python sources._safe_url). The default
// endpoints are keyless, but a fork adding a keyed RPC must not leak it.
function safeUrl(u) {
  try { const p = new URL(u); return `${p.protocol}//${p.host}`; } catch { return "(url redacted)"; }
}

async function sha256hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class Evidence {
  constructor() { this.items = []; this.orderCache = new Map(); }
  async record(kind, ref, raw) {
    this.items.push({
      kind, ref, sha256: await sha256hex(raw), bytes: raw.length,
      fetched_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    });
  }
}

// fetch with a hard timeout so one hung endpoint can't leave the UI spinning
// forever (the Verify button stays disabled until the promise settles).
async function fetchT(url, opts = {}, timeoutMs = 25000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctl.signal }); }
  finally { clearTimeout(t); }
}

export async function rpc(urls, method, params, ev, rounds = 3) {
  if (typeof urls === "string") urls = [urls];
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  let last;
  for (let round = 0; round < rounds; round++) {
    for (const url of urls) {
      try {
        const res = await fetchT(url, { method: "POST", headers: { ...UA, "content-type": "application/json" }, body });
        const text = await res.text();
        if (!res.ok) { last = new Error(`${url}: HTTP ${res.status}`); continue; }
        const out = JSON.parse(text);
        if (out.error) { last = new Error(`${url}: ${JSON.stringify(out.error)}`); continue; }
        if (ev) await ev.record("rpc:" + method, `${safeUrl(url)} ${JSON.stringify(params).slice(0, 100)}`, text);
        return out.result;
      } catch (e) { last = e; }
    }
    if (round < rounds - 1) await new Promise((r) => setTimeout(r, 400 * (round + 1)));
  }
  throw new Error(`all RPC endpoints failed for ${method}: ${last}`);
}

// GET + JSON with a 404 shortcut and bounded retry/backoff on transient
// failures (429/5xx/timeout). api.cow.fi is a single host with no fallback, so
// a lone 429 must not abort an otherwise-complete certificate.
async function getJson(url, ev, kind, retries = 3) {
  let last;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetchT(url, { headers: UA });
      if (res.status === 404) { if (ev) await ev.record(kind, safeUrl(url), "404"); return null; }
      const text = await res.text();
      if (res.ok) { if (ev) await ev.record(kind, safeUrl(url), text); return JSON.parse(text); }
      last = new Error(`${kind}: HTTP ${res.status}`);
      if (![429, 500, 502, 503, 504].includes(res.status)) throw last;
    } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, 500 * (2 ** attempt)));
  }
  throw last || new Error(`${kind}: failed`);
}

const api = (net) => `https://api.cow.fi/${NETWORKS[net]}/api`;
export const competitionByTx = (net, tx, ev) =>
  getJson(`${api(net)}/v2/solver_competition/by_tx_hash/${tx}`, ev, "competition:by_tx_hash");
export const tradesByOrder = (net, uid, ev) =>
  getJson(`${api(net)}/v1/trades?orderUid=${uid}`, ev, "orderbook:trades");
export async function orderMeta(net, uid, ev) {
  // Memoized per run (C4, C12, and wrapper-route C5 look up the same order).
  const key = `${net}/${uid}`;
  if (ev && ev.orderCache.has(key)) return ev.orderCache.get(key);
  const meta = await getJson(`${api(net)}/v1/orders/${uid}`, ev, "orderbook:order");
  if (ev) ev.orderCache.set(key, meta);
  return meta;
}

// --- ERC-20 metadata (symbol/decimals), best-effort ---
function hexToUtf8(h) {
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  return new TextDecoder().decode(bytes).replace(/\0/g, "").trim();
}
function decodeSymbol(res) {
  if (!res || res === "0x") return null;
  const h = res.slice(2);
  try {
    if (h.length >= 192) {
      const len = Number(BigInt("0x" + h.slice(64, 128)));
      if (len > 0 && len <= 64) {
        const s = hexToUtf8(h.slice(128, 128 + len * 2));
        if (s) return s;
      }
    }
    const s = hexToUtf8(h.slice(0, 64));
    return s || null;
  } catch { return null; }
}
export async function tokenMeta(rpcUrls, token, ev, cache) {
  token = (token || "").toLowerCase();
  if (cache.has(token)) return cache.get(token);
  const meta = { address: token, symbol: null, decimals: null };
  try {
    const d = await rpc(rpcUrls, "eth_call", [{ to: token, data: "0x313ce567" }, "latest"], ev);
    if (d && d !== "0x") { const n = Number(BigInt(d)); if (n >= 0 && n <= 36) meta.decimals = n; }
  } catch {}
  try { meta.symbol = decodeSymbol(await rpc(rpcUrls, "eth_call", [{ to: token, data: "0x95d89b41" }, "latest"], ev)); } catch {}
  cache.set(token, meta);
  return meta;
}
