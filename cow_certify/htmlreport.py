"""render_html — a self-contained, shareable HTML certificate from a cert dict.

Built for a non-technical audience (a trader who pasted an order id) as much as
for solvers: it leads with a plain-language verdict, shows the trade in human
terms, then the checks, then how to reproduce it. No external assets, no JS —
one file you can open or send to anyone.
"""
import html
import time

from .sources import CHAIN_IDS

EXPLORER = {
    "mainnet": "https://etherscan.io/tx/",
    "arbitrum": "https://arbiscan.io/tx/",
    "base": "https://basescan.org/tx/",
    "gnosis": "https://gnosisscan.io/tx/",
    "polygon": "https://polygonscan.com/tx/",
    "avalanche": "https://snowtrace.io/tx/",
    "bnb": "https://bscscan.com/tx/",
    "sepolia": "https://sepolia.etherscan.io/tx/",
}

# check id -> (trader-facing label, one-line gloss)
FRIENDLY = {
    "C0": ("Settlement type", "How the trade reached the chain — CoW's contract directly, or via a solver's own contract."),
    "C1": ("Bound to its auction", "The on-chain settlement matches the auction it claims to have won."),
    "C2": ("Settled by the auction winner", "The solver that won the auction is the one that settled it."),
    "C3": ("Settled as solved", "Exactly the winning solution's orders settled, at the amounts that were scored."),
    "C4": ("Your price limit was respected", "Every trade executed at or better than the limit price you signed."),
    "C5": ("Surplus you received", "The user surplus actually delivered on-chain, computed from the executed amounts against your signed limit — it cannot be inflated by the settlement's prices. (The competition score is a separate, fee-inclusive number this tool does not adjudicate.)"),
    "C6": ("Settled on time", "The settlement landed within the auction's deadline."),
    "C7": ("Auction competition", "How many solvers and solutions competed for this batch."),
    "C8": ("Transaction status", "Whether the settlement transaction succeeded on-chain."),
    "C9": ("Solver authorized on-chain", "The account that settled is a registered CoW solver in the on-chain allowlist."),
    "C10": ("Trade details", "The full per-order record."),
    "C11": ("You received your tokens", "The tokens bought actually reached the recorded receiver on-chain."),
    "C12": ("Matches your signed order", "The settled order matches a real signed order in CoW's public orderbook."),
    "C13": ("External calls", "The contracts the settlement interacted with."),
    "C14": ("Execution vs fair mid", "How your price compared to the auction's reference mid — a best-execution signal, not full EBBO."),
    "C15": ("Protocol buffer", "Whether the settlement drew from CoW's accumulated-fee buffer (ERC-20 net delta of the settlement contract). Context, not a judgment."),
}

_HERO = {
    "PASS": ("✓", "ok", "Verified", "This settlement is a valid execution of the auction it claims."),
    "VIOLATION": ("✗", "bad", "Violation found", "One or more checks failed — see the flagged items below."),
    "UNCERTAIN": ("?", "warn", "Inconclusive", "Some parts can't be confirmed from public data alone."),
}
_TONE = {"PASS": "ok", "VIOLATION": "bad", "UNCERTAIN": "warn", "INFO": "info"}
_GLYPH = {"PASS": "✓", "VIOLATION": "✗", "UNCERTAIN": "?", "INFO": "·"}

CSS = """
*{box-sizing:border-box}
:root{
  --bg:#f6f7f9; --surface:#ffffff; --surface2:#f0f2f5;
  --ink:#10151c; --muted:#5a6572; --line:#e4e8ee;
  --accent:#127a8a;
  --ok:#1a7f4b; --ok-bg:#e7f4ec; --bad:#c02626; --bad-bg:#fbe9e9;
  --warn:#9a6a00; --warn-bg:#f7efdd; --info:#5a6572; --info-bg:#f0f2f5;
  --shadow:0 1px 2px rgba(16,21,28,.06),0 6px 20px rgba(16,21,28,.05);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0c0f14; --surface:#141922; --surface2:#1b212b;
  --ink:#e7ecf2; --muted:#93a0b0; --line:#232b36;
  --accent:#3fb4c4;
  --ok:#4cc487; --ok-bg:#122a20; --bad:#f2685f; --bad-bg:#2c1618;
  --warn:#e0b24d; --warn-bg:#2a2413; --info:#93a0b0; --info-bg:#1b212b;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.28);
}}
:root[data-theme="dark"]{
  --bg:#0c0f14; --surface:#141922; --surface2:#1b212b;
  --ink:#e7ecf2; --muted:#93a0b0; --line:#232b36;
  --accent:#3fb4c4;
  --ok:#4cc487; --ok-bg:#122a20; --bad:#f2685f; --bad-bg:#2c1618;
  --warn:#e0b24d; --warn-bg:#2a2413; --info:#93a0b0; --info-bg:#1b212b;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.28);
}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  line-height:1.5;-webkit-font-smoothing:antialiased}
.mono{font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px 64px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

.masthead{display:flex;justify-content:space-between;align-items:baseline;
  gap:16px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--line)}
.brand{font-weight:700;letter-spacing:-.02em;font-size:1.05rem}
.brand span{color:var(--accent)}
.tagline{color:var(--muted);font-size:.82rem}
.chip{display:inline-block;padding:2px 9px;border:1px solid var(--line);
  border-radius:999px;font-size:.72rem;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em}
.txline{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  margin-top:14px;font-size:.86rem}
.txline .mono{color:var(--muted);word-break:break-all}

.verdict{margin-top:22px;display:flex;gap:18px;align-items:flex-start;
  padding:22px;border-radius:14px;border:1px solid var(--line);
  background:var(--surface);box-shadow:var(--shadow);border-left:5px solid var(--tone)}
.seal{flex:none;width:52px;height:52px;border-radius:50%;display:grid;
  place-items:center;font-size:1.6rem;font-weight:700;color:#fff;background:var(--tone)}
.verdict h1{margin:0;font-size:1.5rem;letter-spacing:-.01em;text-wrap:balance}
.verdict p{margin:4px 0 0;color:var(--muted)}
.tally{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.tally .pill{font-size:.74rem;padding:2px 10px;border-radius:999px;
  background:var(--info-bg);color:var(--muted);font-weight:600}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}

.section{margin-top:34px}
.section > h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;
  color:var(--muted);margin:0 0 12px;font-weight:700}

.trade{display:grid;gap:12px}
.tcard{border:1px solid var(--line);border-radius:12px;background:var(--surface);
  padding:16px 18px}
.flow{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:1.05rem}
.flow .amt{font-weight:700}
.flow .arrow{color:var(--accent);font-weight:700}
.flow .side small{display:block;color:var(--muted);font-size:.72rem;font-weight:400}
.tmeta{margin-top:10px;display:flex;gap:16px;flex-wrap:wrap;font-size:.78rem;color:var(--muted)}
.tmeta b{color:var(--ink);font-weight:600}
.tmeta .mono{font-size:.76rem}

.checks{display:grid;gap:1px;background:var(--line);border:1px solid var(--line);
  border-radius:12px;overflow:hidden}
.row{display:grid;grid-template-columns:26px 1fr;gap:12px;padding:13px 16px;
  background:var(--surface)}
.row .g{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;
  font-size:.8rem;font-weight:700;color:#fff;background:var(--tone)}
.row.info .g{background:transparent;color:var(--muted);font-size:1.1rem}
.row .label{font-weight:600}
.row .detail{color:var(--muted);font-size:.85rem;margin-top:2px}
.row .gloss{color:var(--muted);font-size:.8rem;margin-top:3px;opacity:.9}

.repro{background:var(--surface2);border:1px solid var(--line);border-radius:10px;
  padding:12px 14px;font-size:.84rem;overflow-x:auto;white-space:pre;
  color:var(--ink)}
details{margin-top:12px;border:1px solid var(--line);border-radius:10px;
  background:var(--surface);padding:0 14px}
summary{cursor:pointer;padding:12px 0;font-size:.85rem;font-weight:600;color:var(--muted)}
.evrow{font-size:.76rem;color:var(--muted);padding:6px 0;border-top:1px solid var(--line);
  display:flex;gap:10px;flex-wrap:wrap}
.limits{margin:10px 0 0;padding-left:18px;color:var(--muted);font-size:.83rem}
.limits li{margin:4px 0}

footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.78rem;display:flex;gap:14px;flex-wrap:wrap;
  justify-content:space-between}
.note{margin-top:6px;color:var(--muted);font-size:.82rem}
details.ctx{margin-top:34px}
details.ctx>summary{font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;
  color:var(--muted);font-weight:700}
.good{color:var(--ok)}
"""


def _esc(x):
    return html.escape(str(x if x is not None else ""))


def _short(h, head=10, tail=8):
    h = str(h or "")
    return h if len(h) <= head + tail + 1 else f"{h[:head]}…{h[-tail:]}"


def _tokspan(t):
    sym = t.get("symbol") or (t["address"][:8] + "…")
    return _esc(sym)


def _trade_section(orders, vsmid=None):
    cards = []
    for o in orders:
        ss = o.get("executed_sell_human") or o["executed_sell"]
        bb = o.get("executed_buy_human") or o["executed_buy"]
        kind = o.get("kind", "trade")
        meta = []
        if o.get("executed_price"):
            meta.append(f"<span>price <b class='mono'>{_esc(o['executed_price'])}</b></span>")
        bps = (vsmid or {}).get((o.get("uid") or "").lower())
        if bps is not None:
            gcls = " good" if bps >= 0 else ""
            meta.append(f"<span>vs fair mid <b class='mono{gcls}'>"
                        f"{'+' if bps >= 0 else ''}{_esc(bps)} bps</b></span>")
        if o.get("fill_fraction") and o["fill_fraction"] not in ("1", "1.0"):
            meta.append(f"<span>filled <b>{_esc(o['fill_fraction'])}</b></span>")
        if o.get("surplus_atoms"):
            meta.append(f"<span>surplus <b class='mono'>{_esc(o['surplus_atoms'])}</b> {_esc(o.get('surplus_token') or '')}</span>")
        meta.append(f"<span>trader <span class='mono'>{_esc(_short(o['owner']))}</span></span>")
        cards.append(f"""
      <div class="tcard">
        <div class="flow">
          <span class="side"><span class="amt mono">{_esc(ss)}</span> {_tokspan(o['sell_token'])}<small>{'you sold' if kind=='sell' else 'sold'}</small></span>
          <span class="arrow">→</span>
          <span class="side"><span class="amt mono">{_esc(bb)}</span> {_tokspan(o['buy_token'])}<small>{'you received' if kind=='sell' else 'received'}</small></span>
        </div>
        <div class="tmeta">{''.join(meta)}</div>
      </div>""")
    return "".join(cards)


def _check_row(chk):
    cid = chk["check"].split(".")[0]
    label, gloss = FRIENDLY.get(cid, (chk["check"], ""))
    tone = _TONE.get(chk["verdict"], "info")
    glyph = _GLYPH.get(chk["verdict"], "·")
    cls = "row info" if chk["verdict"] == "INFO" else "row"
    return f"""
      <div class="{cls}" style="--tone:var(--{tone})">
        <div class="g">{glyph}</div>
        <div>
          <div class="label">{_esc(label)}</div>
          <div class="detail">{_esc(chk['detail'])}</div>
          {f'<div class="gloss">{_esc(gloss)}</div>' if gloss else ''}
        </div>
      </div>"""


def render_html(cert, standalone=True):
    sub = cert["subject"]
    net = sub.get("network", "")
    cid = sub.get("chain_id") or CHAIN_IDS.get(net)
    tx = sub.get("tx_hash", "")
    ov = cert["overall"]
    glyph, tone, title, sentence = _HERO.get(
        ov, ("·", "info", ov, ""))

    counts = {}
    for c in cert["checks"]:
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
    pills = ""
    for k, cls in (("PASS", "ok"), ("VIOLATION", "bad"),
                   ("UNCERTAIN", "warn"), ("INFO", "info")):
        if counts.get(k):
            pills += f'<span class="pill {cls}">{counts[k]} {k.lower()}</span>'

    ledger = next((c for c in cert["checks"] if c["check"].startswith("C10")), None)
    orders = (ledger or {}).get("orders") or []
    c14 = next((c for c in cert["checks"] if c["check"].startswith("C14")), None)
    vsmid = {(o.get("uid") or "").lower(): o.get("bps")
             for o in (c14.get("per_order") if c14 else []) or []}

    context_ids = {"C7", "C10", "C13", "C14", "C15"}
    verdict_checks = [c for c in cert["checks"]
                      if c["check"].split(".")[0] not in context_ids]
    context_checks = [c for c in cert["checks"]
                      if c["check"].split(".")[0] in {"C7", "C13", "C14", "C15"}]

    explorer = EXPLORER.get(net)
    tx_link = (f'<a href="{explorer}{_esc(tx)}" target="_blank" rel="noopener">view on explorer ↗</a>'
               if explorer else "")
    gen = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

    trade_html = ""
    if orders:
        trade_html = f"""
    <div class="section">
      <h2>The trade</h2>
      <div class="trade">{_trade_section(orders, vsmid)}</div>
    </div>"""

    context_html = ""
    if context_checks:
        context_html = f"""
    <details class="ctx">
      <summary>Signals &amp; context — competition, execution vs mid, interactions</summary>
      <div class="checks">{''.join(_check_row(c) for c in context_checks)}</div>
    </details>"""

    limits = cert.get("not_verifiable") or []
    limits_html = ""
    if limits:
        limits_html = ("<div class='note'>What this certificate does not check:</div>"
                       "<ul class='limits'>"
                       + "".join(f"<li>{_esc(l)}</li>" for l in limits)
                       + "</ul>")

    ev = cert.get("evidence") or []
    evrows = "".join(
        f'<div class="evrow"><span>{_esc(e.get("kind",""))}</span>'
        f'<span class="mono">{_esc(e.get("sha256","")[:16])}…</span>'
        f'<span class="mono">{_esc(_short(e.get("ref",""),40,6))}</span></div>'
        for e in ev)

    body = f"""
  <div class="wrap" style="--tone:var(--{tone})">
    <div class="masthead">
      <div>
        <div class="brand">cow<span>·</span>certify</div>
        <div class="tagline">independent settlement verification</div>
      </div>
      <div style="text-align:right">
        <div class="chip">{_esc(net)}{f' · chain {cid}' if cid else ''}</div>
        <div class="tagline" style="margin-top:6px">generated {gen}</div>
      </div>
    </div>
    <div class="txline">
      <span class="mono">{_esc(tx)}</span> {tx_link}
    </div>

    <div class="verdict" style="--tone:var(--{tone})">
      <div class="seal">{glyph}</div>
      <div style="flex:1">
        <h1>{_esc(title)}</h1>
        <p>{_esc(sentence)}</p>
        <div class="tally">{pills}</div>
      </div>
    </div>
{trade_html}
    <div class="section">
      <h2>Verification checks</h2>
      <div class="checks">{''.join(_check_row(c) for c in verdict_checks)}</div>
    </div>
{context_html}
    <div class="section">
      <h2>Verify this yourself</h2>
      <div class="note">Every result above is reconstructed from public data only.
        Re-run this exact certificate with:</div>
      <div class="repro mono" style="margin-top:8px">{_esc(cert.get('reproduce',''))}</div>
      <details>
        <summary>Evidence — {len(ev)} fetch(es), each fingerprinted (sha256)</summary>
        {evrows}
      </details>
      {limits_html}
    </div>

    <footer>
      <span>cow-certify {_esc(cert.get('schema_version',''))} · not affiliated with CoW Protocol · public data only</span>
      <span><a href="https://github.com/KaiserSolver/cow-certify" target="_blank" rel="noopener">source · MIT</a></span>
    </footer>
  </div>"""

    if not standalone:
        return f"<style>{CSS}</style>\n{body}"
    return (f"<!doctype html>\n<html lang=\"en\">\n<head>\n"
            f"<meta charset=\"utf-8\">\n"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>cow-certify — {_esc(net)} {_esc(_short(tx))}</title>\n"
            f"<style>{CSS}</style>\n</head>\n<body>{body}\n</body>\n</html>\n")
