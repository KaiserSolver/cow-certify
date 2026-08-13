// Drift guard (stage 2): the browser pipeline must produce the SAME verdicts as
// the audited Python certificates, per check and overall, across the corpus.
//   node test_certify.mjs [count]   (default: all)
import { readFileSync, readdirSync } from "node:fs";
import { certify } from "./checks.js";

const dir = new URL(process.env.CERTS || "../certs_self_audit/", import.meta.url);
let certs = readdirSync(dir).filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(new URL(f, dir))));
const limit = parseInt(process.argv[2] || "0", 10);
if (limit) certs = certs.slice(0, limit);

const prefixes = (checks) => {
  const m = {};
  for (const c of checks) m[c.check.split(".")[0]] = c.verdict;
  return m;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ok = 0, fetchErr = 0;
const mism = [];
for (const py of certs) {
  const { network, tx_hash } = py.subject;
  let js = null;
  for (let a = 0; a < 3; a++) {
    try { js = await certify(network, tx_hash); break; }
    catch (e) { if (a === 2) { fetchErr++; console.log(`  fetcherr ${network} ${tx_hash.slice(0, 12)}: ${String(e).slice(0, 70)}`); } await sleep(1200); }
  }
  if (!js) continue;
  const P = prefixes(py.checks), J = prefixes(js.checks);
  const problems = [];
  if (js.overall !== py.overall) problems.push(`overall ${js.overall}!=${py.overall}`);
  const keys = new Set([...Object.keys(P), ...Object.keys(J)]);
  for (const k of keys) if (P[k] !== J[k]) problems.push(`${k}: js ${J[k] || "-"} != py ${P[k] || "-"}`);
  if (problems.length) mism.push(`${network} ${tx_hash.slice(0, 12)}: ${problems.join("; ")}`);
  else ok++;
  await sleep(250);
}

console.log(`\nverdict parity: ${ok}/${certs.length - fetchErr} matched (${fetchErr} fetch errors skipped)`);
for (const m of mism.slice(0, 15)) console.log("  MISMATCH", m);
process.exit(mism.length ? 1 : 0);
