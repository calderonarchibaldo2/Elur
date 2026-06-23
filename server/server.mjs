// Elur sponsor backend — the ONLY place the private Enoki key lives.
// It does exactly two things: ask Enoki to sponsor a transaction, and submit
// the user's signature for execution. It never sees file keys or content
// (zero-custody: auth/gas only). Run from server/:  node server.mjs
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";

// --- load secrets from .env (no dependencies) ---
let PRIVATE_KEY = process.env.ENOKI_PRIVATE_KEY || "";
let RELAYER_MNEMONIC = process.env.RELAYER_MNEMONIC || "";
try {
  for (const line of readFileSync(new URL(".env", import.meta.url), "utf8").split("\n")) {
    let m = line.match(/^\s*ENOKI_PRIVATE_KEY\s*=\s*(.+?)\s*$/);
    if (m) PRIVATE_KEY = m[1];
    m = line.match(/^\s*RELAYER_MNEMONIC\s*=\s*"?(.+?)"?\s*$/);
    if (m) RELAYER_MNEMONIC = m[1];
  }
} catch {}
if (!PRIVATE_KEY || PRIVATE_KEY.includes("PASTE")) {
  console.error("✗ Put your Enoki PRIVATE key in server/.env first (ENOKI_PRIVATE_KEY=...)");
  process.exit(1);
}

const ENOKI = "https://api.enoki.mystenlabs.com";
const NETWORK = "testnet";
// Hosts (Railway/Render/Fly) assign the port via $PORT and require binding 0.0.0.0.
const PORT = process.env.PORT || 3777;
// Only Elur's own contract can be sponsored — nobody can drain the gas budget
// through this server for anything else.
// PACKAGE_ID = original-id (v1) — the app still mints/revokes here and Seal's
// identity namespace lives here; left untouched so the working demo is unaffected.
const PACKAGE_ID = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
// RECORD_PKG = published-at (v2, 2026-06-10) — carries the record_open guard.
// Only the relayer's record_open is routed here so the guard is live, with no
// change to the app's mint/revoke/Seal paths.
const RECORD_PKG = "0xe69d8597d9cdec396acd3c8f76f7a4e5eb1de52d07ec2344289b279ee995bb3b";
// Both package versions allowlisted during the v1→v2 rewire (2026-06-10): the app
// now targets v2 (RECORD_PKG) for all calls; v1 stays allowed as rollback + for
// older builds. Same module, same contract authority — no new sponsor surface.
const ALLOWED_TARGETS = [PACKAGE_ID, RECORD_PKG].flatMap((p) => [
  `${p}::access::mint`,
  `${p}::access::revoke`,
  `${p}::access::reinstate`,
  `${p}::access::record_open`,
  `${p}::access::add_recipient`,
  `${p}::access::remove_recipient`,
  `${p}::access::update_scope`,
]);
const MODULE = "access";

// Relayer: records opens on-chain for ANONYMOUS recipients (who have no wallet
// to sign with). Pays its own gas from a funded testnet keypair. record_open is
// unguarded in the contract, so the relayer can call it on anyone's behalf —
// this is best-effort open-counting (a documented limitation).
const suiClient = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(NETWORK), network: NETWORK });
let relayer = null;
try {
  if (RELAYER_MNEMONIC) {
    relayer = Ed25519Keypair.deriveKeypair(RELAYER_MNEMONIC.trim());
    console.log("relayer address:", relayer.toSuiAddress());
  }
} catch (e) {
  console.warn("relayer mnemonic invalid:", e.message);
}

const json = (res, code, obj) => {
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  });
  res.end(JSON.stringify(obj));
};

async function enoki(path, { jwt, body }) {
  const r = await fetch(ENOKI + path, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + PRIVATE_KEY,
      "Content-Type": "application/json",
      ...(jwt ? { "zklogin-jwt": jwt } : {}),
    },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Enoki ${path} (${r.status}): ${JSON.stringify(data).slice(0, 300)}`);
  return data.data;
}

createServer(async (req, res) => {
  if (req.method === "OPTIONS") return json(res, 204, {});
  if (req.method === "GET") return json(res, 200, { ok: true, service: "elur-sponsor", network: NETWORK }); // health check
  if (req.method !== "POST") return json(res, 405, { error: "POST only" });
  let body = "";
  for await (const chunk of req) body += chunk;
  let p;
  try { p = JSON.parse(body || "{}"); } catch { return json(res, 400, { error: "bad json" }); }

  try {
    if (req.url === "/sponsor") {
      if (!p.jwt || !p.transactionKindBytes) return json(res, 400, { error: "jwt and transactionKindBytes required" });
      const out = await enoki("/v1/transaction-blocks/sponsor", {
        jwt: p.jwt,
        body: {
          network: NETWORK,
          transactionBlockKindBytes: p.transactionKindBytes,
          allowedMoveCallTargets: ALLOWED_TARGETS,
        },
      });
      console.log(new Date().toISOString(), "sponsored", out.digest);
      return json(res, 200, out); // { bytes, digest }
    }
    if (req.url === "/execute") {
      if (!p.digest || !p.signature) return json(res, 400, { error: "digest and signature required" });
      const out = await enoki(`/v1/transaction-blocks/sponsor/${p.digest}`, { body: { signature: p.signature } });
      console.log(new Date().toISOString(), "executed ", out.digest);
      return json(res, 200, out); // { digest }
    }
    if (req.url === "/record-open") {
      if (!relayer) return json(res, 503, { error: "relayer not configured (add RELAYER_MNEMONIC to server/.env)" });
      if (!p.policyId) return json(res, 400, { error: "policyId required" });
      const tx = new Transaction();
      tx.moveCall({ target: `${RECORD_PKG}::${MODULE}::record_open`, arguments: [tx.object(p.policyId)] });
      const out = await suiClient.signAndExecuteTransaction({ signer: relayer, transaction: tx, options: { showEffects: true } });
      await suiClient.waitForTransaction({ digest: out.digest });
      console.log(new Date().toISOString(), "recorded open", out.digest);
      return json(res, 200, { digest: out.digest });
    }
    return json(res, 404, { error: "unknown route" });
  } catch (e) {
    console.error(e.message);
    return json(res, 502, { error: e.message });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`Elur sponsor backend → :${PORT} (${NETWORK})`));
