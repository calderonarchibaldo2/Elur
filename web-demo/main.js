// Elur web demo — recipient deal room. Real, in-browser decryption through the
// on-chain gate: fetch the encrypted blob from Walrus → Seal dry-runs seal_approve
// on Sui → releases the key only if the policy allows → decrypt locally. The revoked
// document denies live. Nothing is mocked; nothing is installed.

import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";
import { CONFIG } from "./config.js";

// Package config — must match the app that sealed the docs:
//  seal_approve target = the latest CALL package; Seal identity/session = the ORIGINAL package.
const CALL_PKG = "0xe69d8597d9cdec396acd3c8f76f7a4e5eb1de52d07ec2344289b279ee995bb3b";
const SEAL_PKG = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
const MODULE = "access", CLOCK = "0x6";
const SERVER_CONFIGS = [
  { objectId: "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98", weight: 1, aggregatorUrl: "https://seal-aggregator-testnet.mystenlabs.com" },
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
];

const suiClient = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl("testnet"), network: "testnet" });
const subtle = window.crypto.subtle;
const newSeal = () => new SealClient({ suiClient, serverConfigs: SERVER_CONFIGS, verifyKeyServers: false });
const $ = (s) => document.querySelector(s);
const esc = (s) => (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const ub64 = (str) => { const s = atob(str); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };

function approvalTxBytes(policyId) {
  const tx = new Transaction();
  tx.moveCall({ target: `${CALL_PKG}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
  return tx.build({ client: suiClient, onlyTransactionKind: true });
}
async function memDecrypt(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  return new TextDecoder().decode(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}
function opener() {
  return CONFIG.recipientSecret ? Ed25519Keypair.fromSecretKey(CONFIG.recipientSecret) : new Ed25519Keypair();
}
async function fetchPkg(blobId) {
  const r = await fetch(CONFIG.walrusAggregator + blobId);
  if (!r.ok) throw new Error("Couldn't read the blob from Walrus (" + r.status + ")");
  return JSON.parse(await r.text());
}

// open one document end-to-end; returns { policyId, text } or throws (with .policyId set if known)
async function openDoc(doc, statusEl) {
  statusEl.textContent = "Fetching the sealed document from Walrus…";
  const pkg = await fetchPkg(doc.blobId);
  try {
    statusEl.textContent = "Authorizing through the on-chain gate…";
    const kp = opener();
    const sessionKey = await SessionKey.create({ address: kp.toSuiAddress(), packageId: SEAL_PKG, ttlMin: 10, signer: kp, suiClient });
    statusEl.textContent = "Fetching the key from the Seal key servers…";
    const ck = await newSeal().decrypt({ data: ub64(pkg.ek), sessionKey, txBytes: await approvalTxBytes(pkg.policyId) });
    statusEl.textContent = "Decrypting on your device…";
    const { name, bytes } = await aesDecryptFile(ub64(pkg.iv), ub64(pkg.ct), new Uint8Array(ck));
    statusEl.textContent = "";
    return { policyId: pkg.policyId, name, bytes };
  } catch (e) { e.policyId = pkg.policyId; throw e; }
}

// ---- render the deal room ----
const grid = $("#grid");
const groups = new Map();
for (const d of CONFIG.docs) { const k = d.folder || "Documents"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(d); }
let html = "";
for (const [folder, docs] of groups) {
  html += `<div class="folder">${esc(folder)}</div>`;
  docs.forEach((d) => {
    const id = d.blobId.slice(0, 8);
    html += `<div class="doc"><div class="dinfo"><div class="dname">${esc(d.label)}</div>${d.note ? `<div class="dnote">${esc(d.note)}</div>` : ""}</div>
      <button class="open" data-id="${id}">Open</button></div>
      <div class="out" id="out-${id}"></div>`;
  });
}
grid.innerHTML = html;

CONFIG.docs.forEach((d) => {
  const id = d.blobId.slice(0, 8);
  const btn = document.querySelector(`[data-id="${id}"]`);
  const out = $("#out-" + id);
  btn.onclick = async () => {
    btn.disabled = true; out.innerHTML = `<div class="status" id="st-${id}"></div>`;
    const st = $("#st-" + id);
    try {
      const { name, bytes } = await openDoc(d, st);
      out.innerHTML = `<div class="opened"><div class="okbadge">✓ decrypted on your device · through the gate</div><div class="sr"></div></div>`;
      renderBytes(out.querySelector(".sr"), name, bytes);
    } catch (e) {
      const m = (e && (e.message || String(e))) || "";
      const denied = /access|approve|denied|NoAccess|revoked|expired|maxopens|abort/i.test(m);
      const scan = e.policyId ? `<a href="https://suiscan.xyz/testnet/object/${e.policyId}" target="_blank" rel="noreferrer">verify the policy on Sui ↗</a>` : "";
      out.innerHTML = `<div class="denied"><div class="nobadge">🔒 ACCESS DENIED</div>
        <div class="dmsg">${denied ? "The on-chain gate refused this — the document is revoked, expired, or not shared with you. The key was never released." : esc(m.slice(0, 160))}</div>
        <div class="dscan">${scan}</div></div>`;
    } finally { btn.disabled = false; }
  };
});

// ============================================================================
// SENDER — "Try it on your own document" (zkLogin + sponsored gas). Real lifecycle:
// sign in with Google → encrypt your file locally → mint a policy + Seal-wrap the key
// (gas sponsored) → open it through the gate → revoke it and watch it deny. The sealed
// package is held in memory (no Walrus write needed for the self-test).
// ============================================================================
import { beginSignIn, completeRedirect, restoreSession, signOut } from "./zklogin.web.js";

let zk = null;      // the zkLogin signer
let myDoc = null;   // { name, policyId, capId, pkg:{policyId,ek,iv,ct}, revoked }
const b64e = (u8) => { let s = ""; for (const x of u8) s += String.fromCharCode(x); return btoa(s); };
function sizeClass(n) { const b = [16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864]; for (const x of b) if (n <= x) return x; return Math.ceil(n / 67108864) * 67108864; }
async function aesEncryptFile(fileBytes, name, ck) {
  const header = new TextEncoder().encode(JSON.stringify({ name, len: fileBytes.length }));
  const hlen = new Uint8Array(4); new DataView(hlen.buffer).setUint32(0, header.length);
  const total = sizeClass(4 + header.length + fileBytes.length);
  const frame = new Uint8Array(total); frame.set(hlen, 0); frame.set(header, 4); frame.set(fileBytes, 4 + header.length);
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, frame));
  return { iv, ct };
}
async function aesDecryptFile(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  const frame = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  const hlen = new DataView(frame.buffer).getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(frame.subarray(4, 4 + hlen)));
  return { name: header.name, bytes: frame.subarray(4 + hlen, 4 + hlen + header.len) };
}
function renderBytes(el, name, bytes) {
  const ext = (name.split(".").pop() || "").toLowerCase(); const blob = new Blob([bytes]);
  if (["png","jpg","jpeg","gif","webp"].includes(ext)) { const i = document.createElement("img"); i.src = URL.createObjectURL(blob); el.appendChild(i); }
  else if (ext === "pdf") { const f = document.createElement("iframe"); f.src = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" })); el.appendChild(f); }
  else if (["txt","md","csv","json","log","xml","html"].includes(ext)) { const p = document.createElement("pre"); p.textContent = new TextDecoder().decode(bytes); el.appendChild(p); }
  else { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.textContent = "⬇ Download " + name; a.style.color = "var(--brass)"; el.appendChild(a); }
}
const createdObj = (ch, ends) => ch?.find((c) => c.type === "created" && c.objectType?.endsWith(ends));

async function senderMint(file) {
  const st = $("#sst");
  try {
    st.textContent = "Encrypting on your device (AES-256-GCM)…";
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const ck = crypto.getRandomValues(new Uint8Array(32));
    const { iv, ct } = await aesEncryptFile(fileBytes, file.name, ck);
    st.textContent = "Minting your access policy on Sui (gas sponsored)…";
    const mint = new Transaction();
    mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(0), mint.pure.u64(0), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
    const res = await zk.signAndExecute(suiClient, mint, { showObjectChanges: true });
    const policyId = createdObj(res.objectChanges, "::access::AccessPolicy").objectId;
    const capId = createdObj(res.objectChanges, "::access::OwnerCap").objectId;
    st.textContent = "Sealing the key to your policy…";
    const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });
    myDoc = { name: file.name, policyId, capId, pkg: { policyId, ek: b64e(encryptedObject), iv: b64e(iv), ct: b64e(ct) }, revoked: false };
    st.textContent = "✓ Sealed and governed on-chain. Open it, then revoke it.";
    renderMyDoc();
  } catch (e) { st.textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}
// Open the held document AS a given keypair (the gate judges its address). Used for
// "open as anyone" (a fresh ephemeral key) and "open as your agent" (the agent's badge key).
async function decryptAs(kp, out, who) {
  out.innerHTML = `<div class="status">Authorizing ${who} through the gate…</div>`;
  try {
    const o = myDoc.pkg;
    const sessionKey = await SessionKey.create({ address: kp.toSuiAddress(), packageId: SEAL_PKG, ttlMin: 10, signer: kp, suiClient });
    const ck = await newSeal().decrypt({ data: ub64(o.ek), sessionKey, txBytes: await approvalTxBytes(o.policyId) });
    const { name, bytes } = await aesDecryptFile(ub64(o.iv), ub64(o.ct), ck);
    out.innerHTML = `<div class="opened"><div class="okbadge">✓ ${who} — decrypted through the gate</div><div class="sr"></div></div>`;
    renderBytes(out.querySelector(".sr"), name, bytes);
  } catch (e) {
    const denied = /access|approve|denied|NoAccess|revoked|expired|abort/i.test(e.message || "");
    out.innerHTML = `<div class="denied"><div class="nobadge">🔒 ACCESS DENIED</div><div class="dmsg">${denied ? "The gate refused " + who + " — not on the allowlist, or revoked. The key was never released." : esc((e.message || "").slice(0, 160))}</div><div class="dscan"><a href="https://suiscan.xyz/testnet/object/${myDoc.policyId}" target="_blank" rel="noreferrer">verify the policy on Sui ↗</a></div></div>`;
  }
}
async function senderRevoke() {
  const st = $("#sst");
  try {
    st.textContent = "Revoking on Sui (gas sponsored)…";
    const tx = new Transaction();
    tx.moveCall({ target: `${CALL_PKG}::${MODULE}::revoke`, arguments: [tx.object(myDoc.capId), tx.object(myDoc.policyId)] });
    await zk.signAndExecute(suiClient, tx, { showEffects: true });
    myDoc.revoked = true; st.textContent = "Revoked — now open it again and watch the gate deny."; renderMyDoc();
  } catch (e) { st.textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}
function renderMyDoc() {
  const el = $("#sdoc"); if (!el) return;
  el.innerHTML = `<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--line)">
    <div style="font-weight:600">🔒 ${esc(myDoc.name)} <span style="font:11.5px 'JetBrains Mono',monospace;color:${myDoc.revoked ? "var(--bad)" : "var(--ok)"};margin-left:8px">${myDoc.revoked ? "revoked — sealed" : "governed on-chain"}</span></div>
    <div class="row"><button class="gbtn" id="sOpen">Open it</button><button class="gbtn danger" id="sRev" ${myDoc.revoked ? "disabled" : ""}>Revoke it</button>
      <a href="https://suiscan.xyz/testnet/object/${myDoc.policyId}" target="_blank" rel="noreferrer" style="color:var(--brass);font-size:13px">view policy on Sui ↗</a></div>
    <div id="sout"></div>
    <div class="card" style="margin-top:18px;background:var(--cream)">
      <div style="font-weight:700">🤖 Govern an AI agent — the headline feature</div>
      <p style="color:var(--muted);font-size:14px;margin:8px 0 0">Point <b>your own</b> agent (Claude Desktop, Cursor — anything that speaks MCP) at Elur's MCP server and watch it read governed documents through the same gate, and lose access the instant you revoke. ~5 minutes, no app — see <b>agent/CONNECT.md</b> in the repo.</p>
    </div>
  </div>`;
  $("#sOpen").onclick = () => decryptAs(new Ed25519Keypair(), $("#sout"), "an anonymous bearer");
  const rev = $("#sRev"); if (rev && !myDoc.revoked) rev.onclick = senderRevoke;
}
function renderSender() {
  const b = $("#senderBody"); if (!b) return;
  if (!zk) {
    b.innerHTML = `<div class="card"><div style="font-weight:700;font-size:18px">Seal your own document</div>
      <p style="color:var(--muted);font-size:14.5px;margin:8px 0 16px">Sign in with Google to mint a real, revocable policy on Sui testnet. No wallet, no SUI — gas is sponsored.</p>
      <button class="gbtn" id="sSignIn">Sign in with Google →</button><div class="status" id="sst"></div></div>`;
    $("#sSignIn").onclick = async () => { const st = $("#sst"); try { st.textContent = "Redirecting to Google…"; await beginSignIn((m) => st.textContent = m); } catch (e) { st.textContent = "❌ " + (e.message || e); } };
    return;
  }
  b.innerHTML = `<div class="card">
    <div class="who">Signed in as <b>${esc(zk.email || zk.address.slice(0, 10) + "…")}</b><span class="so" id="sOut">sign out</span></div>
    <div class="drop" id="sdrop">Choose a document to seal — encrypted on your device, then governed on-chain</div>
    <input type="file" id="sfile" style="display:none">
    <div class="status" id="sst"></div>
    <div id="sdoc"></div></div>`;
  $("#sOut").onclick = () => { signOut(); zk = null; myDoc = null; renderSender(); };
  const inp = $("#sfile"), drop = $("#sdrop");
  drop.onclick = () => inp.click();
  inp.onchange = (e) => { if (e.target.files[0]) senderMint(e.target.files[0]); };
  if (myDoc) renderMyDoc();
}

// tabs
function showTab(which) {
  const r = which === "R";
  $("#tabR").classList.toggle("on", r); $("#tabS").classList.toggle("on", !r);
  $("#paneRecipient").style.display = r ? "" : "none"; $("#paneSender").style.display = r ? "none" : "";
}
$("#tabR").onclick = () => showTab("R");
$("#tabS").onclick = () => showTab("S");

// init: enable the sender tab; finish an OAuth redirect or restore a session
(async function initSender() {
  if (!CONFIG.enableSender) return;
  $("#tabS").style.display = "";
  try { const back = await completeRedirect(); if (back) { zk = back; showTab("S"); } } catch (e) { console.warn("zklogin redirect:", e); }
  if (!zk) { try { zk = restoreSession(); } catch {} }
  renderSender();
})();
