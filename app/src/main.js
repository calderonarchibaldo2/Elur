// Yale macOS — encryption engine.
// Ported from the proven web viewer: Open (recipient) + Share (sender) + Revoke.
// Differences from the browser: native file dialogs (Rust read_path/write_path)
// instead of download/drag, and the recovery phrase lives in the macOS Keychain.

import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { signInWithGoogle, restoreZkSession, zkSignOut } from "./zklogin.js";
import { SPONSOR_URL } from "./enoki.js";

// Two package IDs since the v2 upgrade (record_open guard) — see contracts/DEPLOYMENT.md wiring note:
// CALL_PKG  = published-at of the LATEST upgrade → all Move call targets (mint/revoke/record_open/seal_approve).
// SEAL_PKG  = ORIGINAL package id → Seal identity namespace, SessionKey, encrypt(). NEVER changes on upgrade,
//             or existing files stop decrypting. If key servers ever reject the seal_approve target on
//             CALL_PKG, flip ONLY the seal_approve target in approvalTxBytes back to SEAL_PKG.
const CALL_PKG = "0xe69d8597d9cdec396acd3c8f76f7a4e5eb1de52d07ec2344289b279ee995bb3b";
const SEAL_PKG = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
const MODULE = "access";
const CLOCK = "0x6";
const SERVER_CONFIGS = [
  { objectId: "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98", weight: 1, aggregatorUrl: "https://seal-aggregator-testnet.mystenlabs.com" },
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
];

const suiClient = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl("testnet"), network: "testnet" });
const subtle = window.crypto.subtle;
const newSeal = () => new SealClient({ suiClient, serverConfigs: SERVER_CONFIGS, verifyKeyServers: false });

const $ = (s) => document.querySelector(s);
const b64 = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
const ub64 = (str) => { const s = atob(str); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
const baseName = (p) => p.split(/[\\/]/).pop();
// opaque on-disk filename: reveals nothing about the real file (zero-metadata principle)
const opaqueYaleName = () => { const r = crypto.getRandomValues(new Uint8Array(6)); let s = ""; for (const b of r) s += b.toString(16).padStart(2, "0"); return s + ".elur"; };
// human-readable scope summary for the "Your shares" list
const fmtScope = (expAbs, maxOpens) => {
  const e = expAbs === 0 ? "never expires" : "exp " + new Date(expAbs).toLocaleDateString([], { month: "short", day: "numeric" }) + " " + new Date(expAbs).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const o = maxOpens === 0 ? "∞ opens" : maxOpens + (maxOpens === 1 ? " open" : " opens");
  return e + " · " + o;
};

// ---- platform layer ----
// Every native (Tauri) capability is funnelled through this one object. The web build
// supplies a browser implementation of the SAME surface — File API for the file ops,
// Walrus publisher/aggregator HTTP for store/read (read is already HTTP), and no-ops or
// substitutes for the macOS-only conveniences — so porting to the browser is swapping
// this object, not rewriting the app. Nothing else in main.js touches invoke()/dialogs.
const platform = {
  readPath: (path) => invoke("read_path", { path }),                            // -> b64
  writePath: (path, b64v) => invoke("write_path", { path, b64: b64v }),
  zipPath: (folder) => invoke("zip_path", { folder }),                          // -> b64
  listDir: (path) => invoke("list_dir", { path }),                             // -> [path]
  deletePath: (path) => invoke("delete_path", { path }),
  walrusStore: (b64v, epochs) => invoke("walrus_store", { b64: b64v, epochs }), // -> blobId
  walrusRead: (id) => invoke("walrus_read", { id }),                           // -> b64
  keychainGet: () => invoke("keychain_get"),
  keychainSet: (value) => invoke("keychain_set", { value }),
  keychainClear: () => invoke("keychain_clear"),
  openUrl: (url) => invoke("open_url", { url }),
  openInApp: (name, b64v) => invoke("open_in_default_app", { name, b64: b64v }),
  revealInFinder: (path) => invoke("reveal_in_finder", { path }),
  chooseFile: (filters) => openDialog({ multiple: false, ...(filters ? { filters } : {}) }),
  chooseFiles: (filters) => openDialog({ multiple: true, ...(filters ? { filters } : {}) }),
  chooseFolder: () => openDialog({ directory: true, multiple: false }),
  chooseSavePath: (defaultPath) => saveDialog({ defaultPath }),
};

// ---- file helpers (built on the platform layer) ----
async function pickFile(filters) {
  const path = await platform.chooseFile(filters);
  if (!path) return null;
  const bytes = ub64(await platform.readPath(path));
  return { name: baseName(path), bytes, path };
}
// Pick a whole folder → zip it (native) → treat it as one "FolderName.zip" file.
// Everything downstream (encrypt/share/open) is unchanged: a folder is just a .zip.
async function pickFolder() {
  const path = await platform.chooseFolder();
  if (!path) return null;
  const bytes = ub64(await platform.zipPath(path));
  return { name: baseName(path) + ".zip", bytes, path };
}
async function saveBytes(defaultName, bytes) {
  let path = await platform.chooseSavePath(defaultName);
  if (!path) return null;
  // keep the original extension even if the save dialog strips it, so the file opens naturally
  const dot = defaultName.lastIndexOf(".");
  const ext = dot > 0 ? defaultName.slice(dot) : "";
  if (ext && !path.toLowerCase().endsWith(ext.toLowerCase())) path += ext;
  await platform.writePath(path, b64(bytes));
  return path;
}

// ---- crypto (identical to the web viewer) ----
function approvalTxBytes(policyId) {
  const tx = new Transaction();
  tx.moveCall({ target: `${CALL_PKG}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
  return tx.build({ client: suiClient, onlyTransactionKind: true });
}
// Coarse size-classes: everything up to ~1 MB encrypts to the SAME size, so all
// everyday documents look identical; only large media falls into bigger buckets.
function sizeClass(n) { const b = [1048576, 8388608, 67108864]; for (const x of b) if (n <= x) return x; return Math.ceil(n / 67108864) * 67108864; }
async function aesEncrypt(fileBytes, name, ck) {
  const header = new TextEncoder().encode(JSON.stringify({ name, len: fileBytes.length }));
  const hlen = new Uint8Array(4); new DataView(hlen.buffer).setUint32(0, header.length);
  const total = sizeClass(4 + header.length + fileBytes.length);
  const frame = new Uint8Array(total);
  frame.set(hlen, 0); frame.set(header, 4); frame.set(fileBytes, 4 + header.length);
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, frame));
  return { iv, ct };
}
async function aesDecrypt(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  const frame = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  const hlen = new DataView(frame.buffer).getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(frame.subarray(4, 4 + hlen)));
  return { name: header.name, bytes: frame.subarray(4 + hlen, 4 + hlen + header.len) };
}

// ---- tabs ----
function switchTab(which) {
  const tabs = { Open: "tabOpen", Overview: "tabOverview", Room: "tabRoom", Share: "tabShare", Agent: "tabAgent", Requests: "tabRequests", QA: "tabQA", Activity: "tabActivity" };
  const panes = { Open: "paneOpen", Overview: "paneOverview", Room: "paneRoom", Share: "paneShare", Agent: "paneAgent", Requests: "paneRequests", QA: "paneQA", Activity: "paneActivity" };
  for (const k of Object.keys(tabs)) {
    $("#" + tabs[k]).classList.toggle("on", k === which);
    $("#" + panes[k]).style.display = k === which ? "" : "none";
  }
  if (which === "Agent" && typeof agentRefreshAuth === "function") agentRefreshAuth();
  if (which === "Activity") loadActivity();
  if (which === "Room") { stageDefaultRoom(); roomRefreshViewers(); roomFolder = null; roomOpenBlob = null; renderRoom(); }
  if (which === "Requests") renderRequests();
  if (which === "QA") renderQA();
  if (which === "Overview") renderOverview();
}
$("#tabOpen").onclick = () => switchTab("Open");
$("#tabRoom").onclick = () => switchTab("Room");
$("#tabShare").onclick = () => switchTab("Share");
$("#tabActivity").onclick = () => switchTab("Activity");
$("#tabRequests").onclick = () => switchTab("Requests");

// ---- REQUESTS (two-way document negotiation) ----
// The demand side to Access control's supply side. Two directions:
//   • OUTGOING — documents you request FROM a counterparty (they owe you)
//   • INCOMING — documents a counterparty requests FROM you (you owe them)
// Each request carries a deadline (needed-by) and a review window. Fulfilling an
// incoming request grants the chosen document to the requester with its expiry set to
// the review window — so a fulfilled request is a pre-agreed, time-boxed grant. The
// request board + fulfilment are real (persisted locally; fulfilment is a live on-chain
// grant). Cross-party DELIVERY of a request rides the same messaging layer as Q&A
// (pending), so in this demo the counterparty side is staged.
let dealRequests = [];
try { dealRequests = JSON.parse(localStorage.getItem("elurRequests") || "[]"); } catch {}
const requestsPersist = () => { try { localStorage.setItem("elurRequests", JSON.stringify(dealRequests)); } catch {} };
let _reqStaged = false;
function stageDemoRequests() {
  if (dealRequests.length || _reqStaged) return;
  if (!(typeof DEMO_CAMILA !== "undefined" && DEMO_CAMILA in peopleBook)) return;
  const D = 864e5, now = Date.now();
  dealRequests = [
    { id: "rq1", dir: "in",  doc: "Cap table (fully diluted)",      party: DEMO_CAMILA, neededBy: now + 1 * D, reviewDays: 7,  status: "pending",   at: now - 2 * D },
    { id: "rq2", dir: "in",  doc: "Audited 2024 financials",        party: DEMO_NIKOS,  neededBy: now + 3 * D, reviewDays: 14, status: "pending",   at: now - 1 * D },
    { id: "rq3", dir: "out", doc: "Signed NDA (counter-executed)",  party: DEMO_CAMILA, neededBy: now + 2 * D, reviewDays: 0,  status: "pending",   at: now - 1 * D },
    { id: "rq4", dir: "out", doc: "Proof of funds letter",          party: DEMO_CROSBY, neededBy: now - 1 * D, reviewDays: 30, status: "fulfilled", at: now - 6 * D, fulfilledDoc: "Proof of funds", expiry: now + 29 * D },
  ];
  _reqStaged = true; requestsPersist();
}
const rqStatus = (r) => (r.status === "pending" && r.neededBy && Date.now() > r.neededBy) ? "overdue" : r.status;
const rqBadge = (s) => ({ pending: `<span class="rqs pend">pending</span>`, overdue: `<span class="rqs over">overdue</span>`, fulfilled: `<span class="rqs done">fulfilled</span>`, declined: `<span class="rqs decl">declined</span>` }[s] || "");

function renderRequests() {
  stageDemoRequests();
  const sel = $("#rqParty");
  if (sel) sel.innerHTML = Object.entries(peopleBook).map(([a, n]) => `<option value="${a}">${(n || a).split(" · ")[0]}</option>`).join("") || `<option value="">add a counterparty first</option>`;
  const fmtBy = (r) => r.neededBy ? `needed ${ovWhen(r.neededBy)} (${new Date(r.neededBy).toLocaleDateString([], { month: "short", day: "numeric" })})` : "no deadline";
  const fmtWin = (r) => r.reviewDays ? ` · review window ${r.reviewDays}d` : "";
  const nm = (addr) => (peopleBook[addr] || (addr || "").slice(0, 10) + "…").split(" · ")[0];

  // OUTGOING — they owe you
  const out = dealRequests.filter((r) => r.dir === "out");
  const outBox = $("#rqOut");
  if (outBox) outBox.innerHTML = out.length ? out.map((r) => {
    const s = rqStatus(r);
    const cancel = r.status === "pending" ? `<button class="mini" data-rqcancel="${r.id}">Cancel</button>` : "";
    return `<div class="ovrow"><span class="ovwarn ${s === "overdue" ? "urg" : ""}">●</span>
      <div class="ovrowmain"><div class="nm">${r.doc}</div><div class="ovmeta">from ${nm(r.party)} · ${fmtBy(r)}${fmtWin(r)}</div></div>
      ${rqBadge(s)}${cancel}</div>`;
  }).join("") : `<p class="muted small">You haven't requested anything yet — use “Request a document” above.</p>`;

  // INCOMING — you owe them
  const inc = dealRequests.filter((r) => r.dir === "in");
  const inBox = $("#rqIn");
  if (inBox) inBox.innerHTML = inc.length ? inc.map((r) => {
    const s = rqStatus(r);
    let act = "";
    if (r.status === "pending") {
      act = `<button class="mini" data-rqfulfill="${r.id}">Fulfill</button><button class="mini danger" data-rqdecline="${r.id}">Decline</button>
        <div class="rqfill" id="fill-${r.id}" style="display:none">
          <span class="muted small rqflead">Grant for ${r.reviewDays || "∞"} day${r.reviewDays === 1 ? "" : "s"} — from a document already in Elur, or upload one (it's sealed on upload):</span>
          <div class="rqfopt">
            <select class="inp" id="fillsel-${r.id}" style="max-width:260px">${memOptions()}</select>
            <button class="mini" data-rqgrant="${r.id}">Grant from Elur</button>
            <span class="muted small">or</span>
            <button class="mini" data-rqupload="${r.id}">Upload &amp; seal a file…</button>
          </div>
        </div>`;
    } else if (r.status === "fulfilled") {
      act = `<span class="muted small">${r.fulfilledDoc ? `granted “${r.fulfilledDoc}”` : "granted"}${r.expiry ? ` · expires ${ovWhen(r.expiry)}` : ""}</span>`;
    }
    return `<div class="ovrow"><span class="ovwarn ${s === "overdue" ? "urg" : ""}">●</span>
      <div class="ovrowmain"><div class="nm">${r.doc}</div><div class="ovmeta">${nm(r.party)} asked · ${fmtBy(r)}${fmtWin(r)}</div></div>
      ${rqBadge(s)}</div>${act ? `<div class="rqact">${act}</div>` : ""}`;
  }).join("") : `<p class="muted small">No one has requested a document from you.</p>`;

  outBox && outBox.querySelectorAll("[data-rqcancel]").forEach((b) => b.onclick = () => { dealRequests = dealRequests.filter((x) => x.id !== b.dataset.rqcancel); requestsPersist(); renderRequests(); });
  document.querySelectorAll("[data-rqdecline]").forEach((b) => b.onclick = () => { const r = dealRequests.find((x) => x.id === b.dataset.rqdecline); if (r) { r.status = "declined"; requestsPersist(); renderRequests(); } });
  document.querySelectorAll("[data-rqfulfill]").forEach((b) => b.onclick = () => { const f = $("#fill-" + b.dataset.rqfulfill); if (f) f.style.display = f.style.display === "none" ? "block" : "none"; });
  document.querySelectorAll("[data-rqgrant]").forEach((b) => b.onclick = () => fulfillRequest(b.dataset.rqgrant, ($("#fillsel-" + b.dataset.rqgrant) || {}).value));
  document.querySelectorAll("[data-rqupload]").forEach((b) => b.onclick = () => fulfillByUpload(b.dataset.rqupload));
}

// Build the "grant from Elur" picker: every held document, grouped by folder, plus a
// "whole folder" option per folder so a request can be fulfilled with a folder at once.
const REQ_DOC_EXT = ["pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "rtf", "html", "htm", "md", "txt", "csv", "tsv", "json", "log", "markdown", "yaml", "yml", "xml", "toml", "ini", "tex", "vtt", "srt", "eml"];
function memOptions() {
  const mems = agentMems || [];
  if (!mems.length) return `<option value="">no documents in Elur yet — upload one →</option>`;
  const groups = new Map();
  for (const m of mems) { const k = m.folder || "Unfiled"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(m); }
  return [...groups.entries()].map(([f, ms]) => {
    const whole = f !== "Unfiled" ? `<option value="folder:${f}">▸ Whole ${f} folder (${ms.length})</option>` : "";
    return `<optgroup label="${f}">${whole}${ms.map((m) => `<option value="${m.label}">${m.label}</option>`).join("")}</optgroup>`;
  }).join("");
}

// Fulfil an incoming request by granting the chosen target — a single held document or
// a whole folder already in Elur — to the requester, expiring at the end of the review
// window. Real on-chain grant (one transaction).
async function fulfillRequest(reqId, sel) {
  const r = dealRequests.find((x) => x.id === reqId); if (!r) return;
  const mems = agentMems || [];
  let grant = [], label = "";
  if (sel && sel.startsWith("folder:")) { const f = sel.slice(7); grant = mems.filter((m) => (m.folder || "") === f); label = `${f} folder (${grant.length} docs)`; }
  else { const m = mems.find((x) => x.label === sel); if (m) { grant = [m]; label = `“${m.label}”`; } }
  if (!grant.length) { $("#rqMsg").textContent = "Choose a document or folder to grant — or upload a new file."; return; }
  const expiryMs = r.reviewDays ? Date.now() + r.reviewDays * 864e5 : 0;
  const who = (peopleBook[r.party] || "the requester").split(" · ")[0];
  $("#rqMsg").textContent = `Granting ${label} to ${who}…`;
  try {
    const tx = new Transaction();
    for (const m of grant) {
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::update_scope`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.u8(1), tx.pure.u64(expiryMs), tx.pure.u64(0)] });
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::add_recipient`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.address(r.party)] });
    }
    await exec(tx, "fulfill request");
    r.status = "fulfilled"; r.fulfilledDoc = label.replace(/[“”]/g, ""); r.expiry = expiryMs; requestsPersist();
    $("#rqMsg").textContent = `✓ Fulfilled — ${label} granted to ${who}${expiryMs ? `, access expires ${ovWhen(expiryMs)}` : ""}.`;
    renderRequests();
  } catch (e) { $("#rqMsg").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
}

// Fulfil by uploading a file from disk: it's sealed on upload — encrypt → mint policy →
// Seal-wrap the key → store on Walrus, the same protocol as every other document — then
// granted to the requester for the review window. Nothing leaves the device in the clear.
async function fulfillByUpload(reqId) {
  const r = dealRequests.find((x) => x.id === reqId); if (!r) return;
  let picked;
  try { picked = await platform.chooseFile([{ name: "Documents", extensions: REQ_DOC_EXT }]); } catch { return; }
  if (!picked) return;
  const path = Array.isArray(picked) ? picked[0] : picked;
  const label = baseName(path).replace(/\.[^.]+$/, "").replace(/^\d+[_\-\s]*/, "").replace(/[_\-]+/g, " ").trim() || baseName(path);
  $("#rqMsg").textContent = `Sealing “${label}” on upload (encrypt → mint policy → Seal → Walrus)…`;
  try {
    let text;
    try { text = await extractText(path); } catch (e) { $("#rqMsg").textContent = `Couldn't read that file: ${(e.message || e).toString().slice(0, 80)}`; return; }
    if (!text) { $("#rqMsg").textContent = "No readable text found in that file."; return; }
    await agentRemember(label, text, "Shared on request");
    if (typeof agentRenderMems === "function") await agentRenderMems();
    await fulfillRequest(reqId, label);
  } catch (e) { $("#rqMsg").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
}

$("#rqSend") && ($("#rqSend").onclick = () => {
  const doc = ($("#rqDoc").value || "").trim();
  const party = $("#rqParty").value;
  const by = $("#rqBy").value ? new Date($("#rqBy").value + "T17:00:00").getTime() : 0;
  const days = Math.max(0, Number($("#rqDays").value) || 0);
  if (!doc) { $("#rqMsg").textContent = "Name the document you need."; return; }
  if (!party) { $("#rqMsg").textContent = "Choose a counterparty to request from (add one in Access control)."; return; }
  dealRequests.unshift({ id: "rq" + Date.now(), dir: "out", doc, party, neededBy: by, reviewDays: days, status: "pending", at: Date.now() });
  requestsPersist();
  $("#rqDoc").value = "";
  $("#rqMsg").innerHTML = `<span class="muted">Request tracked: <b>${doc.replace(/[<>&]/g, "")}</b> from ${(peopleBook[party] || "").split(" · ")[0]}${by ? ` · needed ${ovWhen(by)}` : ""}. <span class="small">(Cross-party delivery rides the messaging layer — pending; tracked here now.)</span></span>`;
  renderRequests();
});
$("#tabQA").onclick = () => switchTab("QA");

// ---- Q&A (designed preview — governed deal conversation) ----
// Not wired to Sui Stack Messaging: that SDK targets an older stack generation than
// ours (see the why-panel). We render the finished thread design with the demo cast
// so the gate-scoped conversation reads as real, and answer the composer honestly.
function renderQA() {
  const box = $("#qaThread"); if (!box) return;
  const msgs = [
    { who: "Camila Duarte", role: "buyer's counsel", side: "in",  t: "09:14",
      body: "Can you confirm the Q3 revenue recognition in <b>Financial / 2024-Q3.xlsx</b> — is the $4.2M deferred or booked?" },
    { who: "Margaux Lefèvre", role: "sell-side advisor", side: "out", t: "09:21",
      body: "Booked. See note 4 — only the $0.8M tail is deferred. The recognition memo is in <b>Legal / rev-rec-policy.pdf</b>, just granted to your team." },
    { who: "Nikos Andreou", role: "Aegis Audit", side: "in", t: "09:33",
      body: "Confirming scope: the ledger shows this thread is gated to the clean team — buyer-side corp dev can't see it. That's intended for the financials, correct?" },
    { who: "Margaux Lefèvre", role: "sell-side advisor", side: "out", t: "09:35",
      body: "Correct. Financials stay clean-team only until exclusivity. The thread seals to anyone removed." },
  ];
  const sys = `<div class="qasys">🔒 Gated to Legal + Financial clean team · every message signed on-chain · sealed on revoke</div>`;
  box.innerHTML = sys + msgs.map((m, i) => {
    const color = m.side === "out" ? "var(--brass)" : "var(--ink)";
    return `<div class="qamsg ${m.side}">
      <div class="pavatar qaav" style="background:${color}">${m.who[0]}</div>
      <div class="qabubble">
        <div class="qameta"><b>${m.who}</b> <span class="qarole">${m.role}</span> <span class="qatime">${m.t}</span></div>
        <div class="qabody">${m.body}</div>
      </div>
    </div>`;
  }).join("");
}
$("#qaSend") && ($("#qaSend").onclick = () => {
  const v = ($("#qaInput").value || "").trim();
  $("#qaMsg").innerHTML = `<span class="prevnote">Preview — in the shipped version this posts to the deal's gated thread over Sui Stack Messaging: signed by your on-chain identity, visible only to the clean team, and sealed if you're ever removed. It's switched off until that SDK reaches our stack generation — the honest reason is below.</span>`;
  if (v) $("#qaInput").value = "";
});
$("#tabOverview").onclick = () => switchTab("Overview");

// ---- OVERVIEW (real, working dashboard) ----
// Reads only what the other rooms already fetch: held documents (agentMems), each
// policy's on-chain object (live vs sealed, expiry), the people allowlists, and the
// ledger event cache (opens this week). No server, no new state, no contract change —
// just a summed view of your own records and the public chain.
async function ovPolicyState(policyId) {
  try {
    const o = await suiClient.getObject({ id: policyId, options: { showContent: true } });
    const f = o?.data?.content?.fields; if (!f) return null;
    const expiry = Number(f.expiry_ms) || 0, maxOpens = Number(f.max_opens) || 0, opens = Number(f.opens) || 0;
    const expired = expiry !== 0 && Date.now() >= expiry;
    const exhausted = maxOpens !== 0 && opens >= maxOpens;
    const sealed = !!(f.revoked || f.destroyed || expired || exhausted);
    return { sealed, expiry, opens, allow: (f.allowlist || []).length };
  } catch { return null; }
}
const ovWhen = (ms) => {
  if (!ms) return null;
  const diff = ms - Date.now();
  if (diff < 0) return "expired";
  const hrs = diff / 36e5;
  if (hrs < 1) return `in ${Math.max(1, Math.round(diff / 6e4))} min`;
  if (hrs < 48) return `in ${Math.round(hrs)}h`;
  const d = Math.round(hrs / 24);
  if (d < 14) return `in ${d} days`;
  return new Date(ms).toLocaleDateString([], { month: "short", day: "numeric" });
};
const ovTime = (ts) => !ts ? "" : (Date.now() - ts < 864e5
  ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  : new Date(ts).toLocaleDateString([], { month: "short", day: "numeric" }));
async function renderOverview() {
  const box = $("#ovBody"); if (!box) return;
  box.innerHTML = `<p class="muted small">Reading your deals from the ledger…</p>`;
  if (typeof stageDefaultRoom === "function") stageDefaultRoom(); // furnish the demo deal if empty
  const mems = agentMems || [];
  if (!mems.length) {
    box.innerHTML = `<div class="card pad"><div class="lab">No deal yet</div>
      <p class="muted" style="margin:6px 0 14px">You haven't sealed any documents on this device. Encrypt a file or hand the agent a folder, and this room fills in from the ledger.</p>
      <button class="btn primary" id="ovToShare">Encrypt a document →</button></div>`;
    $("#ovToShare") && ($("#ovToShare").onclick = () => switchTab("Share"));
    return;
  }
  if (!evCache.length) { try { await loadActivity(); } catch {} }

  // 1 · per-document on-chain state → live/sealed counts + the 48h expiry radar
  const states = await Promise.all(mems.map((m) => m.policyId ? ovPolicyState(m.policyId).then((s) => ({ m, s })) : Promise.resolve({ m, s: null })));
  const H48 = Date.now() + 48 * 36e5;
  let live = 0, sealed = 0; const expiring = [];
  for (const { m, s } of states) {
    if (!s) { live++; continue; }
    if (s.sealed) { sealed++; continue; }
    live++;
    if (s.expiry && s.expiry <= H48) expiring.push({ m, expiry: s.expiry, allow: s.allow });
  }
  expiring.sort((a, b) => a.expiry - b.expiry);

  // 2 · counterparty engagement, read from the ledger (opens this week + last seen).
  // Facts only — counts and timestamps, sorted most-active-first. No scores, no charts.
  const WEEK = Date.now() - 7 * 864e5;
  const opensWk = new Map(), lastSeen = new Map();
  for (const e of evCache) {
    if (!(e.type || "").endsWith("AccessGranted")) continue;
    const j = e.parsedJson || {}; if (!evLabel(j.policy) || !j.who) continue;
    const ts = Number(e.timestampMs || 0);
    if (ts >= WEEK) opensWk.set(j.who, (opensWk.get(j.who) || 0) + 1);
    if (ts > (lastSeen.get(j.who) || 0)) lastSeen.set(j.who, ts);
  }
  let cps = [];
  try { cps = (await collectPeople()).filter((p) => p.docs > 0); } catch {}
  cps.forEach((p) => { p.wk = opensWk.get(p.addr) || 0; p.last = lastSeen.get(p.addr) || 0; });
  cps.sort((a, b) => b.wk - a.wk || b.last - a.last);
  const totalWk = [...opensWk.values()].reduce((a, b) => a + b, 0);

  // 3 · recent opens (who looked at what, when) + honest flags (openers not in your book)
  const recent = evCache.filter((e) => (e.type || "").endsWith("AccessGranted") && evLabel((e.parsedJson || {}).policy))
    .slice(0, 6).map((e) => { const j = e.parsedJson || {}; return { who: j.who, doc: evLabel(j.policy)?.name, ts: Number(e.timestampMs || 0) }; });
  const flags = recent.filter((r) => r.who && !nameOf(r.who));

  const isDemo = (typeof DEMO_CAMILA !== "undefined" && DEMO_CAMILA in peopleBook);
  const dealName = isDemo ? "Project Páramo" : "Your deal room";
  const cpName = (p) => (p.name || (p.addr.slice(0, 8) + "…")).split(" · ")[0];
  const roleOf = (p) => ((p.name || "").split(" · ")[1] || "");
  const short1 = (n) => (n || "").split(" · ")[0];

  let html = `<div class="ovstatus">
    <div class="ovdeal">${dealName}</div>
    <div class="ovstats">
      <span class="ovstat"><b>${live}</b> live</span>
      <span class="ovstat"><b>${cps.length}</b> ${cps.length === 1 ? "counterparty" : "counterparties"}</span>
      <span class="ovstat"><b>${totalWk}</b> open${totalWk === 1 ? "" : "s"} this week</span>
      ${sealed ? `<span class="ovstat muted"><b>${sealed}</b> sealed</span>` : ""}
    </div>
    <button class="mini" id="ovOpenRoom">Open room →</button>
  </div>`;

  // ---- On the clock: every time-bound obligation, both directions ----
  // Time is the shared spine: request deadlines (owed to you / owed by you) and access
  // expiries (the programmed token lifetime) all surface here, soonest first.
  const reqs = (typeof dealRequests !== "undefined" && Array.isArray(dealRequests)) ? dealRequests : [];
  const owed = reqs.filter((r) => r.dir === "out" && r.status === "pending" && r.neededBy).sort((a, b) => a.neededBy - b.neededBy);
  const owe  = reqs.filter((r) => r.dir === "in"  && r.status === "pending" && r.neededBy).sort((a, b) => a.neededBy - b.neededBy);
  const nmp = (addr) => (peopleBook[addr] || (addr || "").slice(0, 10) + "…").split(" · ")[0];
  html += `<div class="ovsec"><div class="ovsech">On the clock <span class="ovhint">deadlines &amp; expiries, both directions</span></div>`;
  if (!expiring.length && !owed.length && !owe.length) {
    html += `<p class="muted small ovcalm">Nothing on the clock — no pending request deadlines, no access expiring soon.</p>`;
  }
  if (owed.length) {
    html += `<div class="ovgroup">Due from counterparties</div>` + owed.map((r) => {
      const over = Date.now() > r.neededBy;
      return `<div class="ovrow"><span class="ovwarn ${over ? "urg" : ""}">●</span><div class="ovrowmain"><div class="nm">${escapeHtml(r.doc)}</div><div class="ovmeta">from ${escapeHtml(nmp(r.party))} · ${over ? "overdue" : "due " + ovWhen(r.neededBy)}${r.reviewDays ? ` · ${r.reviewDays}d review` : ""}</div></div><button class="mini" data-tab="Requests">View</button></div>`;
    }).join("");
  }
  if (owe.length) {
    html += `<div class="ovgroup">Due to counterparties</div>` + owe.map((r) => {
      const over = Date.now() > r.neededBy;
      return `<div class="ovrow"><span class="ovwarn ${over ? "urg" : ""}">●</span><div class="ovrowmain"><div class="nm">${escapeHtml(r.doc)}</div><div class="ovmeta">${escapeHtml(nmp(r.party))} waiting · ${over ? "overdue" : "due " + ovWhen(r.neededBy)}</div></div><button class="mini" data-tab="Requests">Fulfill</button></div>`;
    }).join("");
  }
  if (expiring.length) {
    html += `<div class="ovgroup">Access expiring</div>` + expiring.map(({ m, expiry, allow }) => {
      const urgent = (expiry - Date.now()) < 24 * 36e5;
      return `<div class="ovrow"><span class="ovwarn ${urgent ? "urg" : ""}">●</span><div class="ovrowmain"><div class="nm">${escapeHtml(m.label)}</div><div class="ovmeta">${allow} ${allow === 1 ? "party" : "parties"} can open · loses access ${ovWhen(expiry)}</div></div><button class="mini danger" data-revdoc="${escapeHtml(m.label)}">Revoke now</button></div>`;
    }).join("");
  }
  html += `</div>`;

  // counterparty activity, ranked
  html += `<div class="ovsec"><div class="ovsech">Counterparty activity <span class="ovhint">most active first</span></div>`;
  if (!cps.length) html += `<p class="muted small">No counterparties have access yet — grant one in Access control.</p>`;
  else html += cps.map((p, i) => {
    const color = i % 2 ? "var(--brass)" : "var(--ink)";
    const eng = p.wk ? `${p.wk} open${p.wk > 1 ? "s" : ""} this week · last ${ovTime(p.last)}`
      : p.last ? `last opened ${ovTime(p.last)}` : `<span class="ovcold">not opened yet</span>`;
    const role = roleOf(p);
    return `<div class="person"><div class="pavatar" style="background:${color}">${(cpName(p)[0] || "?").toUpperCase()}</div>
      <div class="pinfo"><div class="ovcpname">${cpName(p)}${role ? ` <span class="ovrole">${role}</span>` : ""}</div>
      <div class="paddr">${eng} · can open ${p.docs} of ${mems.length}</div></div>
      <button class="mini danger" data-revcp="${p.addr}">Revoke access</button></div>`;
  }).join("");
  html += `</div>`;

  // recent opens + flags
  if (recent.length) {
    html += `<div class="ovsec"><div class="ovsech">Recent opens</div>`;
    if (flags.length) html += flags.map((r) => `<div class="ovrow flag"><span class="ovflag">⚑</span><div class="ovrowmain"><div class="nm">Unrecognized identity opened “${r.doc}”</div><div class="ovmeta">${evShort(r.who)} · ${ovTime(r.ts)} · not in your address book — name or verify it</div></div></div>`).join("");
    html += recent.map((r) => `<div class="ovrow"><span class="ovdotopen">●</span><div class="ovrowmain"><div class="nm">${nameOf(r.who) ? short1(nameOf(r.who)) : evShort(r.who)} opened “${r.doc}”</div><div class="ovmeta">${ovTime(r.ts)}</div></div></div>`).join("");
    html += `</div>`;
  }

  html += `<p class="muted small" style="margin-top:14px">Read live from ${mems.length} document${mems.length === 1 ? "" : "s"} and your ledger activity — no charts, no stored analytics. One deal for now; multi-deal projects are on the roadmap. (Silent screen captures can't be detected by any software — view-only files are watermarked so a leaked copy traces back to whoever opened it.)</p>`;

  box.innerHTML = html;
  $("#ovOpenRoom") && ($("#ovOpenRoom").onclick = () => switchTab("Room"));
  box.querySelectorAll("[data-tab]").forEach((b) => b.onclick = () => switchTab(b.dataset.tab));
  box.querySelectorAll("[data-revcp]").forEach((b) => b.onclick = async () => {
    b.disabled = true; b.textContent = "Revoking…";
    try { await badgeAll(b.dataset.revcp, "remove_recipient"); } catch {}
    renderOverview();
  });
  box.querySelectorAll("[data-revdoc]").forEach((b) => b.onclick = async () => {
    b.disabled = true; b.textContent = "Sealing…";
    try { await agentRevoke(b.dataset.revdoc); } catch {}
    setTimeout(renderOverview, 600);
  });
}

// ---- PEOPLE (identities you govern) ----
// The address book: names live ONLY in this device's localStorage. The chain
// stays pseudonymous — that's the design (no GUD, ever). Names feed the
// Activity feed so the ledger reads "opened by Maria", not hex.
// Two real, funded demo identities — a human counsel and a second party — so the
// roster is never empty. On-chain grants persist, so once "Load demo notes" grants
// them they stay key-holders across sessions.
const DEMO_CAMILA  = "0x5010562848c713490e73e1b7be1435cb3bd2d6566a5b80beee67c68c1369d11c"; // real, openable counterparty
const DEMO_CROSBY  = "0x4506bc687360ba89fb1146f0e078432a691cdc374d5a77b1840fd810c3506e11"; // real relayer badge
const DEMO_MARGAUX = "0x9f2c7a1e4b8d6035c9e1f7a3b5d20486e0c2a4f6189b3d5e7c0a2f4681b3d5e7"; // roster identity
const DEMO_NIKOS   = "0x3e5d7f912a4c6b8e0d1f3a5c7b9e2d4f6a8c0e13f5a7c9e1b3d5f7091c3e5a7d"; // roster identity
let peopleBook = {};
try { peopleBook = JSON.parse(localStorage.getItem("elurPeople") || "{}"); } catch {}
const DEMO_PEOPLE = {
  [DEMO_MARGAUX]: "Margaux Lefèvre · Meridian Partners (sell-side advisor)",
  [DEMO_CAMILA]:  "Camila Duarte · Lex Andina (buyer's counsel)",
  [DEMO_NIKOS]:   "Nikos Andreou · Aegis Audit (financial due diligence)",
  [DEMO_CROSBY]:  "Crosby Whitfield · buyer's corp development",
};
for (const [a, n] of Object.entries(DEMO_PEOPLE)) if (!(a in peopleBook)) peopleBook[a] = n;
const peoplePersist = () => { try { localStorage.setItem("elurPeople", JSON.stringify(peopleBook)); } catch {} };
const nameOf = (addr) => peopleBook[addr] || null;

$("#ppAdd").onclick = () => {
  const a = $("#ppAddr").value.trim(), n = $("#ppName").value.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(a)) { $("#ppAddMsg").textContent = "That isn't a Sui address — paste the full 0x… (64 characters) the other side copied from their Elur. No address yet? Use “generate a test identity” below."; return; }
  $("#ppAddMsg").textContent = "";
  peopleBook[a] = n || "unnamed identity";
  peoplePersist(); $("#ppAddr").value = ""; $("#ppName").value = "";
  renderPeople();
};
// No real counterparty handy? Generate a throwaway identity to try the flow.
$("#ppGen").onclick = (e) => {
  e.preventDefault();
  const a = new Ed25519Keypair().toSuiAddress();
  const n = "Test identity " + (Object.values(peopleBook).filter((x) => /^Test identity/.test(x)).length + 1);
  peopleBook[a] = n; peoplePersist();
  $("#ppAddMsg").textContent = "";
  renderPeople();
};


// Identities = address book ∪ everyone on a known policy's on-chain allowlist.
// Each person carries `pol` — the Set of document policyIds they can open — so the
// roster can show "access to N" and the Manage-access picker can pre-tick per doc.
async function collectPeople() {
  const found = new Map(Object.entries(peopleBook).map(([a, n]) => [a, { addr: a, name: n, pol: new Set() }]));
  const policies = [...agentMems.map((m) => m.policyId), ...shares.map((s) => s.policyId)];
  for (const pid of policies) {
    try {
      const o = await suiClient.getObject({ id: pid, options: { showContent: true } });
      for (const a of (o?.data?.content?.fields?.allowlist || [])) {
        if (!found.has(a)) found.set(a, { addr: a, name: null, pol: new Set() });
        found.get(a).pol.add(pid);
      }
    } catch {}
  }
  return [...found.values()].map((p) => ({ ...p, docs: p.pol.size }));
}
const ppExpanded = new Set();

async function renderPeople() {
  const box = $("#ppList");
  box.innerHTML = `<p class="muted small">Reading allowlists from the ledger…</p>`;
  const ppl = await collectPeople();
  if (!ppl.length) { box.innerHTML = `<p class="muted small">No identities yet — grant an agent below, or add a person above.</p>`; return; }
  box.innerHTML = ppl.map((p, i) => {
    const color = i % 2 ? "var(--brass)" : "var(--ink)";
    const open = ppExpanded.has(p.addr);
    const pickBody = () => {
      if (!agentMems.length) return `<p class="muted small" style="margin:0">No documents yet — add some below.</p>`;
      const groups = new Map();
      for (const m of agentMems) { const k = m.folder || ""; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(m); }
      const ordered = [...groups.entries()].sort((a, b) => (a[0] ? 0 : 1) - (b[0] ? 0 : 1));
      return ordered.map(([folder, mems]) => {
        const have = mems.filter((m) => p.pol.has(m.policyId)).length;
        const fhead = folder ? `<label class="docpick docfolder"><input type="checkbox" style="accent-color:${color}" data-folder="${folder}" ${have === mems.length ? "checked" : ""}/> <span><b>${folder}</b> <span class="muted">(${have}/${mems.length})</span></span></label>` : "";
        const items = mems.map((m) => `<label class="docpick${folder ? " docchild" : ""}"><input type="checkbox" style="accent-color:${color}" data-pid="${m.policyId}" data-infolder="${folder}" ${p.pol.has(m.policyId) ? "checked" : ""}/> <span>${m.label}</span></label>`).join("");
        return fhead + items;
      }).join("");
    };
    const picker = !open ? "" : `<div class="docpicker" data-for="${p.addr}" style="border-left:3px solid ${color}">
      ${pickBody()}
      <div class="docpickfoot"><button class="mini" data-apply-p="${p.addr}">Apply changes</button><span class="muted small" style="margin-left:8px">Tick the documents ${(p.name || "this identity").split(" ·")[0]} may open.</span></div>
    </div>`;
    return `<div class="person">
      <div class="pavatar" style="background:${color}">${(p.name || "?").slice(0, 1).toUpperCase()}</div>
      <div class="pinfo">
        <input class="pname" data-addr="${p.addr}" value="${p.name || ""}" placeholder="name this identity…" />
        <div class="paddr">${p.addr.slice(0, 12)}…${p.addr.slice(-6)} · access to ${p.docs} document${p.docs === 1 ? "" : "s"}</div>
      </div>
      <button class="mini" data-act-p="${p.addr}">Activity</button>
      <button class="mini" data-manage-p="${p.addr}">${open ? "Close" : "Manage access"}</button>
      <button class="mini danger" data-rev-p="${p.addr}">Revoke all</button>
    </div>${picker}`;
  }).join("");
  box.querySelectorAll(".pname").forEach((inp) => inp.addEventListener("change", () => {
    peopleBook[inp.dataset.addr] = inp.value.trim() || "unnamed identity"; peoplePersist(); renderPeople();
  }));
  box.querySelectorAll("[data-act-p]").forEach((b) => b.onclick = () => { switchTab("Activity"); $("#evSearch").value = b.dataset.actP; setTimeout(() => renderActivity(), 400); });
  box.querySelectorAll("[data-manage-p]").forEach((b) => b.onclick = () => { const a = b.dataset.manageP; ppExpanded.has(a) ? ppExpanded.delete(a) : ppExpanded.add(a); renderPeople(); });
  box.querySelectorAll("[data-rev-p]").forEach((b) => b.onclick = async () => { await badgeAll(b.dataset.revP, "remove_recipient"); renderPeople(); });
  box.querySelectorAll("[data-apply-p]").forEach((b) => b.onclick = () => applyAccess(b.dataset.applyP, ppl.find((x) => x.addr === b.dataset.applyP)));
  // Folder checkbox toggles every document under it; folder header reflects children.
  box.querySelectorAll('.docpicker input[data-folder]').forEach((fb) => fb.onchange = () => {
    const panel = fb.closest(".docpicker");
    panel.querySelectorAll(`input[data-infolder="${fb.dataset.folder}"]`).forEach((cb) => { cb.checked = fb.checked; });
  });
  box.querySelectorAll('.docpicker input[data-infolder]').forEach((cb) => cb.onchange = () => {
    const panel = cb.closest(".docpicker"), folder = cb.dataset.infolder;
    if (!folder) return;
    const kids = [...panel.querySelectorAll(`input[data-infolder="${folder}"]`)];
    const head = panel.querySelector(`input[data-folder="${folder}"]`);
    if (head) head.checked = kids.every((k) => k.checked);
  });
}

// Apply the per-document selection: diff the checkboxes against current access and
// submit the adds and removes in one ledger transaction.
async function applyAccess(addr, person) {
  if (!person) return;
  const panel = $("#ppList").querySelector(`.docpicker[data-for="${addr}"]`);
  if (!panel) return;
  const tx = new Transaction();
  let adds = 0, removes = 0;
  panel.querySelectorAll('input[data-pid]').forEach((cb) => {
    const pid = cb.dataset.pid, want = cb.checked, has = person.pol.has(pid);
    const m = agentMems.find((x) => x.policyId === pid);
    if (!m) return;
    if (want && !has) {
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::update_scope`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.u8(1), tx.pure.u64(0), tx.pure.u64(0)] });
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::add_recipient`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.address(addr)] });
      adds++;
    } else if (!want && has) {
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::remove_recipient`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.address(addr)] });
      removes++;
    }
  });
  if (!adds && !removes) { $("#aStatus").textContent = "No changes to apply."; return; }
  $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = true);
  try {
    $("#aStatus").textContent = `Updating access on the ledger — ${adds} granted, ${removes} revoked…`;
    await exec(tx, "update_scope");
    $("#aStatus").textContent = `✓ access updated for ${(person.name || addr.slice(0, 10)).split(" ·")[0]} — ${adds} granted, ${removes} revoked.`;
    ppExpanded.delete(addr);
  } catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
  finally { $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false); renderPeople(); }
}
// ---- DEAL ROOM (recipient browser) ----
// Load a manifest (the room's index) and browse it by folder. Access is read live
// from the ledger per chosen viewer; the room itself is hosted by no one — it's
// assembled here from sealed blobs + on-chain policy.
let roomManifest = null;
let roomViewer = "me"; // "me" (signed-in) or a 0x address from the roster
const escapeHtml = (s) => (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

// Stage the demo deal room by default — the tab opens already furnished, viewed as
// a recipient so the clean-team access wall is visible on arrival. A loaded manifest
// (from "Open a deal room…") takes over and is never overwritten.
let _roomStaged = false;
function stageDefaultRoom() {
  if (roomManifest || _roomStaged) return;
  if (!agentMems.length) return;
  tagDemoFolders();
  roomManifest = agentMems.map(({ label, folder, blobId, policyId, kind, name, ext }) => ({ label, folder: folder || null, blobId, policyId, kind, name, ext }));
  roomViewer = "me"; // single-user demo — always the signed-in owner's view (no "view as")
  _roomStaged = true;
  if ($("#roomMeta")) $("#roomMeta").textContent = `Demo deal room · ${roomManifest.length} documents`;
}

function roomMyAddr() {
  return (typeof zkSigner !== "undefined" && zkSigner?.address) || (typeof senderKeypair !== "undefined" && senderKeypair && senderKeypair.toSuiAddress()) || null;
}
function roomRefreshViewers() {
  const sel = $("#roomViewAs"); if (!sel) return;
  const opts = [`<option value="me">Me${roomMyAddr() ? "" : " (sign in)"}</option>`];
  for (const [addr, name] of Object.entries(peopleBook)) opts.push(`<option value="${addr}">${(name || addr).split(" ·")[0]}</option>`);
  sel.innerHTML = opts.join("");
  sel.value = roomViewer;
  sel.onchange = () => { roomViewer = sel.value; renderRoom(); };
}
const roomViewerAddr = () => roomViewer === "me" ? roomMyAddr() : roomViewer;

async function roomAccessFor(policyId, viewer) {
  try {
    const o = await suiClient.getObject({ id: policyId, options: { showContent: true } });
    const f = o?.data?.content?.fields;
    if (!f || f.revoked || f.destroyed) return "revoked";
    if (Number(f.expiry_ms) !== 0 && Date.now() >= Number(f.expiry_ms)) return "revoked";
    if (Number(f.max_opens) !== 0 && Number(f.opens) >= Number(f.max_opens)) return "revoked";
    const allow = f.allowlist || [];
    if (viewer && allow.includes(viewer)) return "open";
    if (!allow.length && Number(f.mode) === 0) return "open"; // bearer: anyone holding the manifest
    return "locked";
  } catch { return "locked"; }
}

// Folder-card → document-card browser. roomFolder=null shows the folder grid; set it to
// drill into a folder's documents. Access is read live per-viewer; locked documents are
// shown (the index isn't a secret) with a one-click "Request access" that opens Requests.
let roomFolder = null, roomOpenBlob = null;
let roomComments = {};
try { roomComments = JSON.parse(localStorage.getItem("elurDocComments") || "{}"); } catch {}
const roomCommentsPersist = () => { try { localStorage.setItem("elurDocComments", JSON.stringify(roomComments)); } catch {} };
const FOLDER_SVG = `<svg viewBox="0 0 24 24" width="22" height="22"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>`;

async function renderRoom() {
  const box = $("#roomList"); if (!box || !roomManifest) return;
  const viewer = roomViewerAddr();
  const groups = new Map();
  for (const d of roomManifest) { const k = d.folder || "Unfiled"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(d); }

  if (roomFolder === null) {
    // FOLDER GRID
    $("#roomDoc").innerHTML = "";
    box.innerHTML = `<p class="muted small">Reading the room from the ledger…</p>`;
    const cards = [];
    for (const [folder, docs] of groups) {
      const access = await Promise.all(docs.map((d) => d.policyId ? roomAccessFor(d.policyId, viewer) : Promise.resolve("locked")));
      const open = access.filter((a) => a === "open").length;
      cards.push(`<button class="foldercard" data-folder="${escapeHtml(folder)}">
        <div class="fcico">${FOLDER_SVG}</div>
        <div class="fcname">${escapeHtml(folder)}</div>
        <div class="fcmeta">${open} of ${docs.length} you can open</div>
      </button>`);
    }
    box.innerHTML = `<div class="foldergrid">${cards.join("")}</div>`;
    box.querySelectorAll("[data-folder]").forEach((b) => b.onclick = () => { roomFolder = b.dataset.folder; roomOpenBlob = null; renderRoom(); });
    return;
  }

  // DOCUMENT CARDS within the open folder
  $("#roomDoc").innerHTML = "";
  box.innerHTML = `<p class="muted small">Opening folder…</p>`;
  const docs = groups.get(roomFolder) || [];
  const access = await Promise.all(docs.map((d) => d.policyId ? roomAccessFor(d.policyId, viewer) : Promise.resolve("locked")));
  const cards = docs.map((d, i) => {
    const a = access[i];
    const badge = a === "open" ? `<span class="rmbadge open">shared with you</span>` : a === "revoked" ? `<span class="rmbadge rev">sealed</span>` : `<span class="rmbadge lock">not shared</span>`;
    const action = a === "open"
      ? `<button class="mini" data-open-r="${d.blobId}" data-pid="${d.policyId || ""}" data-lbl="${escapeHtml(d.label)}">Open</button>`
      : a === "revoked" ? "" : `<button class="mini" data-reqacc="${escapeHtml(d.label)}">Request access</button>`;
    const nc = (roomComments[d.label] || []).length;
    return `<div class="doccard ${a === "open" ? "" : "locked"}">
      <div class="dcico">${a === "open" ? "📄" : "🔒"}</div>
      <div class="dcmain"><div class="dcname">${escapeHtml(d.label)}</div><div class="dcmeta">${a === "open" ? "open and comment" : a === "revoked" ? "sealed — access ended" : "request access to review"}</div></div>
      ${nc ? `<span class="doccmt">💬 ${nc}</span>` : ""}${badge}${action}
    </div>`;
  });
  box.innerHTML = `<div class="docbreadcrumb"><button class="crumblink" id="roomBack">← All folders</button> <span class="crumbsep">/</span> <b>${escapeHtml(roomFolder)}</b></div><div class="doccards">${cards.join("")}</div>`;
  $("#roomBack").onclick = () => { roomFolder = null; roomOpenBlob = null; renderRoom(); };
  box.querySelectorAll("[data-open-r]").forEach((b) => b.onclick = () => roomOpen(b.dataset.openR, b.dataset.pid, b.dataset.lbl));
  box.querySelectorAll("[data-reqacc]").forEach((b) => b.onclick = () => requestDocAccess(b.dataset.reqacc));
  if (roomOpenBlob) { const d = docs.find((x) => x.blobId === roomOpenBlob); if (d) roomOpen(d.blobId, d.policyId, d.label); }
}

// Bundled demo content so the Documents room always opens to something real-looking,
// even offline / when previewing a counterparty's view (where the real key isn't on this
// device). Matched by the document's cleaned label. Real sealed docs still decrypt live;
// this is the fallback that keeps the demo working.
const DEMO_DOC_TEXT = {
  "term sheet": `PROJECT PÁRAMO — TERM SHEET (DRAFT, CONFIDENTIAL)

Acquirer: Andina Holdings S.A.S.
Target:   Páramo Logistics Inc.
Structure: Acquisition of 100% of outstanding shares (stock purchase)
Date:     June 2026

HEADLINE TERMS
• Consideration: 70% cash, 30% acquirer equity
• Exclusivity:   60-day no-shop from signing
• Escrow:        12% of price held 18 months against indemnities
• Retention:     founders on 24-month lock-up with earn-out

CONDITIONS TO CLOSE
• Satisfactory financial, legal and technical due diligence
• Board approval (both parties)
• No material adverse change prior to closing
• Regulatory clearance (SIC)

Non-binding except for the exclusivity and confidentiality provisions.
Distribution restricted to the deal team.`,
  "confidential budget": `PROJECT PÁRAMO — INTERNAL VALUATION & WALK-AWAY BUDGET
⚠ STRICTLY CONFIDENTIAL — ACQUIRER DEAL TEAM ONLY

OUR NUMBERS
• Opening offer:          USD 3.4M
• Target close:           USD 3.9M
• Hard walk-away ceiling: USD 4.2M  (do not exceed)
• 3-yr synergy estimate:  USD 1.1M

GUIDANCE
• Anchor low at 3.4M citing customer-concentration risk.
• If they push past 4.2M, we walk (alternative target available).

A leak of the 4.2M ceiling to the seller's side would cost us the entire
negotiating range. Single most sensitive item in the deal room.`,
  "due diligence summary": `PROJECT PÁRAMO — DUE DILIGENCE SUMMARY
Scope: financial, legal, commercial, technical

FINANCIAL
• Revenue (TTM) USD 6.8M · gross margin 31% · EBITDA USD 0.9M
• Customer concentration: top 3 = 54% of revenue (risk flag)
• Clean audit opinions FY23–FY25; no off-balance-sheet liabilities

LEGAL
• Cap table clean; option pool 8% as documented
• One pending dispute (USD 120k) — provisioned, low risk
• Contract #PL-2208 needs consent on change of control

COMMERCIAL · recurring logistics contracts, 18-mo avg tenure
TECHNICAL  · proprietary routing platform; SOC 2 in progress`,
  "legal counsel": `PROJECT PÁRAMO — DEAL CONTACTS & COUNSEL

LEAD COUNSEL (acquirer)
• Camila Duarte — Partner, Lex Andina
  SPA drafting, regulatory clearance, escrow agreement

DEAL TEAM (acquirer)
• Andrés Córdoba — deal lead
• Tomás Vega — financial diligence
• Lucía Marín — commercial diligence

CADENCE · weekly sync Thursdays 09:00 (Bogotá)
All counterparty communication routed through Camila Duarte.`,
  "board resolution": `PROJECT PÁRAMO — BOARD RESOLUTION (ACQUIRER)
Andina Holdings S.A.S. — Resolution of the Board of Directors

IT IS RESOLVED THAT:
1. Management is authorized to negotiate and execute a definitive Share
   Purchase Agreement on the approved term-sheet terms.
2. Cash consideration is authorized up to the internal ceiling, and no
   further, without returning to the Board.
3. Camila Duarte (Lex Andina) is confirmed as lead external counsel.
4. Andrés Córdoba is authorized to manage the deal room and team.

Certified a true copy of the resolution adopted by the Board.`,
};
const demoDocText = (label) => {
  const l = (label || "").trim().toLowerCase();
  if (DEMO_DOC_TEXT[l]) return DEMO_DOC_TEXT[l];
  const k = Object.keys(DEMO_DOC_TEXT).find((key) => l.includes(key) || key.includes(l));
  return k ? DEMO_DOC_TEXT[k] : null;
};

// Fetch a full-file document from Walrus and decrypt its bytes through the Seal gate.
async function roomRecallFile(blobId, policyId) {
  const raw = ub64(await platform.walrusRead(blobId));
  const pkg = JSON.parse(new TextDecoder().decode(raw));
  const ephemeral = new Ed25519Keypair();
  const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: SEAL_PKG, ttlMin: 10, signer: ephemeral, suiClient });
  const ck = await newSeal().decrypt({ data: ub64(pkg.ek), sessionKey, txBytes: await approvalTxBytes(pkg.policyId || policyId) });
  const { name, bytes } = await aesDecrypt(ub64(pkg.iv), ub64(pkg.ct), new Uint8Array(ck));
  return { name, bytes, ext: (pkg.ext || (name.match(/\.([^.]+)$/) || [])[1] || "").toLowerCase(), exportable: pkg.exportable !== false };
}

async function roomOpen(blobId, policyId, label) {
  roomOpenBlob = blobId;
  const doc = (roomManifest || []).find((d) => d.blobId === blobId) || {};
  const previewing = roomViewer !== "me";
  const who = (peopleBook[roomViewer] || "this identity").split(" ·")[0];

  // Full-file document → fetch ciphertext from Walrus, decrypt the bytes, render the real file.
  if (doc.kind === "file") {
    if (previewing) { $("#roomStatus").textContent = `You're previewing ${who}'s access — this document opens on their own device, signed by their key.`; roomOpenBlob = null; return; }
    $("#roomStatus").textContent = "Fetching from Walrus & opening through the gate…";
    try {
      const file = await roomRecallFile(blobId, policyId);
      $("#roomStatus").textContent = "";
      renderDocView(label, { bytes: file.bytes, name: file.name || doc.name || label, ext: file.ext || doc.ext, exportable: file.exportable });
    } catch (e) { $("#roomStatus").textContent = "🔒 The gate denied this open — you don't currently have access."; roomOpenBlob = null; }
    return;
  }

  // Text memory / demo document (with mock fallback so the demo always opens).
  $("#roomStatus").textContent = previewing ? "" : "Opening through the gate…";
  let text = null;
  if (!previewing) { try { text = await agentRecall(blobId, policyId); } catch (e) { text = null; } }
  if (text == null) text = demoDocText(label);
  if (text == null) {
    $("#roomStatus").textContent = previewing
      ? `You're previewing ${who}'s access — this document opens on their own device, where their key signs the gate.`
      : "🔒 The gate denied this open — you don't currently have access.";
    roomOpenBlob = null;
    return;
  }
  $("#roomStatus").textContent = previewing ? `Previewing ${who}'s view — in production this opens on their own device, signed by their key.` : "";
  renderDocView(label, { text });
}

// The open document (real file via paintContent, or text) + its comment thread. Comments
// are scoped (conceptually) to whoever can open the document — same gate. Interactive and
// persisted locally; cross-party DELIVERY rides Sui Stack Messaging (pending), said plainly.
function renderDocView(label, body) {
  const key = label;
  if (!roomComments[key] && (typeof DEMO_CAMILA !== "undefined" && DEMO_CAMILA in peopleBook) && /term sheet/i.test(label)) {
    roomComments[key] = [{ who: "Camila Duarte", text: "Clause 4 — can we widen the indemnity carve-out before we counter-sign?", at: Date.now() - 36e5 }];
    roomCommentsPersist();
  }
  const cmts = roomComments[key] || [];
  const thread = cmts.length ? cmts.map((c) => `<div class="cmt ${c.who === "You" ? "mine" : ""}"><div class="cmtwho">${escapeHtml(c.who)} <span class="cmtt">${ovTime(c.at)}</span></div><div class="cmtbody">${escapeHtml(c.text)}</div></div>`).join("") : `<p class="muted small" style="margin:4px 0">No comments yet — start the thread.</p>`;
  const isFile = !!body.bytes;
  const viewOnly = isFile && body.exportable === false;
  const dl = isFile ? (`<button class="mini" id="docExpand">⛶ Expand</button>` + (viewOnly
    ? `<span style="font:600 11px 'JetBrains Mono',ui-monospace,monospace;color:var(--bad);align-self:center;margin-left:4px">🔒 VIEW ONLY</span>`
    : `<button class="mini" id="docDownload" title="Downloads the sealed .elur — still governed: it re-opens only through the gate, and revoke still kills it">Download .elur</button>`)) : "";
  $("#roomDoc").innerHTML = `<div class="card pad" style="margin-top:14px">
    <div class="dochead"><div class="lab" style="margin:0">${escapeHtml(label)}</div><div style="display:flex;gap:6px">${dl}<button class="mini" id="docClose">Close</button></div></div>
    <div id="docBody" class="docbody"></div>
    <div class="cmtsec"><div class="ovsech">Comments <span class="ovhint">visible to people with access</span></div>
      <div class="cmtthread">${thread}</div>
      <div class="cmtcompose"><input class="inp" id="cmtInput" placeholder="Write a comment to the counterparty…" /><button class="mini" id="cmtSend">Send</button></div>
      <div class="cmtnote">ⓘ Saved here now. Cross-party delivery rides Sui Stack Messaging (pending) — gated to the same people who can open this document.</div>
    </div>
  </div>`;
  const bodyEl = $("#docBody");
  if (isFile) {
    paintContent(bodyEl, body.name || label, body.bytes, body.ext);
    if (viewOnly) {
      // View-only: stamp every view with the signed-in identity (leak tracing) + lock export.
      const when = new Date().toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      const viewer = (typeof zkSigner !== "undefined" && zkSigner && zkSigner.email) ? zkSigner.email : (roomMyAddr() ? roomMyAddr().slice(0, 12) + "…" : "this device");
      const wm = `ELUR · ${viewer} · ${when}`;
      applyWatermark(bodyEl, wm); lockDown(bodyEl);
      $("#docExpand").onclick = () => openFullscreen(body.name || label, body.bytes, body.ext, { viewOnly: true, watermark: wm });
    } else {
      $("#docExpand").onclick = () => openFullscreen(body.name || label, body.bytes, body.ext, {});
      // Download yields the SEALED .elur (never plaintext) — a downloaded copy stays governed.
      $("#docDownload") && ($("#docDownload").onclick = async () => {
        try {
          $("#roomStatus").textContent = "Preparing the sealed file…";
          const sealed = ub64(await platform.walrusRead(roomOpenBlob));
          await saveBytes(label.replace(/[^\w.-]+/g, "_") + ".elur", sealed);
          $("#roomStatus").textContent = "";
        } catch (e) { $("#roomStatus").textContent = "❌ " + ((e && e.message) || e); }
      });
    }
  } else {
    const p = document.createElement("pre"); p.className = "rmpre"; p.textContent = body.text; bodyEl.appendChild(p);
  }
  $("#docClose").onclick = () => { roomOpenBlob = null; $("#roomDoc").innerHTML = ""; };
  const send = () => {
    const v = ($("#cmtInput").value || "").trim(); if (!v) return;
    (roomComments[key] = roomComments[key] || []).push({ who: "You", text: v, at: Date.now() });
    roomCommentsPersist(); renderDocView(label, body);
  };
  $("#cmtSend").onclick = send;
  $("#cmtInput").addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });
}

// ---- add full-file documents to the room ----
// Seal a FULL file (bytes, with size-class padding) and store the ciphertext on Walrus,
// governed by a fresh Sui policy — the always-available, browsable data-room copy. Same
// encrypt → mint → Seal protocol as a .elur; only the destination differs.
async function sealFileToWalrus(path, folder, viewOnly) {
  const bytes = ub64(await platform.readPath(path));
  const name = baseName(path);
  const ext = ((name.match(/\.([^.]+)$/) || [])[1] || "").toLowerCase();
  const label = name.replace(/\.[^.]+$/, "").replace(/^\d+[_\-\s]*/, "").replace(/[_\-]+/g, " ").trim() || name;
  const ck = crypto.getRandomValues(new Uint8Array(32));
  const { iv, ct } = await aesEncrypt(bytes, name, ck);
  const mint = new Transaction();
  mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(0), mint.pure.u64(0), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
  const res = await exec(mint, "mint document");
  const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
  const capId = found(res.objectChanges, "::access::OwnerCap").objectId;
  const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });
  // The blob carries NO cleartext name/type — the filename lives inside the encrypted
  // AES frame (aesEncrypt embeds it), so Walrus learns nothing about the document.
  // exportable:false → the open path watermarks every view with the viewer's identity and
  // blocks export (leak-tracing, app-enforced).
  const pkg = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct), exportable: !viewOnly });
  const blobId = await platform.walrusStore(b64(new TextEncoder().encode(pkg)), 30);
  agentMems.push({ label, blobId, policyId, capId, folder, kind: "file", name, ext });
  return label;
}

// Seal a FULL file and save it as a local .elur — the sovereignty option: nothing is
// uploaded, you hand the sealed file off yourself. Still revocable (the key lives on Sui).
async function sealFileLocal(path) {
  const bytes = ub64(await platform.readPath(path));
  const name = baseName(path);
  const ck = crypto.getRandomValues(new Uint8Array(32));
  const { iv, ct } = await aesEncrypt(bytes, name, ck);
  const mint = new Transaction();
  mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(0), mint.pure.u64(0), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
  const res = await exec(mint, "mint document");
  const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
  const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });
  // No cleartext name/type in the file either — the filename is inside the encrypted frame.
  const pkg = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct), exportable: true });
  await saveBytes(name.replace(/\.[^.]+$/, "") + ".elur", new TextEncoder().encode(pkg));
}

// Pick files (or a whole folder), seal each as a full file, and store per the chosen
// destination: Walrus (joins the browsable room) or local .elur (saved to hand off).
async function roomAddDocs(folderPick) {
  const dest = ($("#roomStore") && $("#roomStore").value) || "walrus";
  let paths, folder = null;
  if (folderPick) {
    const dir = await platform.chooseFolder();
    if (!dir) return;
    try { paths = await platform.listDir(dir); } catch (e) { $("#roomStatus").textContent = "❌ " + (e.message || e); return; }
    if (!paths || !paths.length) { $("#roomStatus").textContent = "No readable documents found in that folder."; return; }
    folder = baseName(dir).replace(/[_\-]+/g, " ").trim() || "Documents";
  } else {
    const picked = await platform.chooseFiles([{ name: "Documents", extensions: REQ_DOC_EXT }]);
    if (!picked) return;
    paths = Array.isArray(picked) ? picked : [picked];
  }
  let ok = 0;
  for (let i = 0; i < paths.length; i++) {
    $("#roomStatus").textContent = `${dest === "walrus" ? "Sealing & storing on Walrus" : "Sealing"} “${baseName(paths[i])}” (${i + 1}/${paths.length})…`;
    try { const vo = !!($("#roomViewOnly") && $("#roomViewOnly").checked); if (dest === "walrus") await sealFileToWalrus(paths[i], folder, vo); else await sealFileLocal(paths[i]); ok++; } catch (e) { /* skip, keep going */ }
  }
  if (dest === "walrus") {
    tagDemoFolders();
    agentPersist();
    roomManifest = agentMems.map(({ label, folder, blobId, policyId, kind, name, ext }) => ({ label, folder: folder || null, blobId, policyId, kind, name, ext }));
    roomFolder = folder; roomOpenBlob = null;
    $("#roomStatus").textContent = `✓ ${ok} document${ok === 1 ? "" : "s"} sealed and stored on Walrus — now in your room${folder ? ` under “${folder}”` : ""}.`;
    renderRoom();
  } else {
    $("#roomStatus").textContent = `✓ ${ok} sealed file${ok === 1 ? "" : "s"} saved — send ${ok === 1 ? "it" : "them"} through your own channel. Nothing was uploaded; revoke anytime.`;
  }
}

// Locked document → jump to Requests with the document name pre-filled.
function requestDocAccess(label) {
  switchTab("Requests");
  const inp = $("#rqDoc"); if (inp) { inp.value = label; inp.focus(); }
  if ($("#rqMsg")) $("#rqMsg").innerHTML = `<span class="muted">Requesting <b>${escapeHtml(label)}</b> — choose the counterparty and a deadline, then Send.</span>`;
}

$("#roomLoad").onclick = async () => {
  const f = await pickFile([{ name: "Elur room manifest", extensions: ["json"] }]);
  if (!f) return;
  try {
    const m = JSON.parse(new TextDecoder().decode(f.bytes));
    if (!Array.isArray(m) || !m.length) throw new Error("empty");
    roomManifest = m;
    $("#roomMeta").textContent = `${f.name} · ${m.length} document${m.length > 1 ? "s" : ""}`;
    roomRefreshViewers();
    renderRoom();
  } catch (e) { $("#roomStatus").textContent = "That isn't a valid Elur room manifest (expected the JSON from Export manifest)."; }
};
$("#roomAddFiles") && ($("#roomAddFiles").onclick = () => roomAddDocs(false));
$("#roomAddFolder") && ($("#roomAddFolder").onclick = () => roomAddDocs(true));

$("#evRefresh").onclick = () => loadActivity(true);
$("#evSearch").addEventListener("input", () => renderActivity());

// ---- ACTIVITY (the Evidence room) ----
// Reads the contract's own events straight from a Sui full node and renders them
// as sentences. No server, no database: the audit view is a VIEWER of the public
// ledger, so it cannot be edited or faked — not by a counterparty, not by us.
const EVT_PKGS = [CALL_PKG, SEAL_PKG]; // v2 + v1 (events live under both since the upgrade)
function evLabel(policyId) {
  const m = agentMems.find((x) => x.policyId === policyId);
  if (m) return { name: m.label, kind: "memory" };
  const s = shares.find((x) => x.policyId === policyId);
  if (s) return { name: s.name, kind: "share" };
  return null;
}
const evShort = (a) => a ? a.slice(0, 8) + "…" + a.slice(-4) : "";
function evSentence(type, j, who) {
  const lbl = evLabel(j.policy);
  const name = lbl ? `“${lbl.name}”` : `a sealed document (${evShort(j.policy)})`;
  switch (type) {
    case "PolicyMinted": return { dot: "mint", text: `${name} sealed under governance` + (Number(j.mode) === 1 ? " (named identities only)" : "") };
    case "AccessGranted": return { dot: "open", text: `${name} opened by ${who}` + (Number(j.opens) ? ` — open #${j.opens}` : "") };
    case "Revoked": return { dot: "revoke", text: `${name} revoked — sealed for everyone, everywhere` };
    case "Reinstated": return { dot: "mint", text: `${name} re-granted — sealed, never lost` };
    case "ScopeUpdated": return { dot: "scope", text: `${name} — access rules changed by ${who}` };
    case "DeviceBound": return { dot: "scope", text: `${name} bound to its first device` };
    case "Destroyed": return { dot: "revoke", text: `${name} destroyed — permanent crypto-shred` };
    default: return { dot: "scope", text: `${name} — ${type}` };
  }
}
async function loadActivity(force) {
  const box = $("#evList");
  box.innerHTML = `<p class="muted small">Reading the ledger…</p>`;
  try {
    const batches = await Promise.all(EVT_PKGS.map((pkg) =>
      suiClient.queryEvents({ query: { MoveEventModule: { package: pkg, module: MODULE } }, order: "descending", limit: 40 })
        .then((r) => r?.data || []).catch(() => [])
    ));
    const seen = new Set();
    const evs = batches.flat()
      .filter((e) => { const k = e.id.txDigest + (e.id.eventSeq ?? ""); if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => Number(b.timestampMs || 0) - Number(a.timestampMs || 0))
      .slice(0, 40);
    evCache = evs;
    renderActivity();
  } catch (e) {
    box.innerHTML = `<p class="muted small">Couldn't read the ledger: ${String(e.message || e).slice(0, 140)}</p>`;
  }
}
let evCache = [];
function renderActivity() {
  const box = $("#evList");
  if (!evCache.length) { box.innerHTML = `<p class="muted small">No events yet — seal a document and the ledger starts writing.</p>`; return; }
  const me = (typeof zkSigner !== "undefined" && zkSigner?.address) || null;
  const q = ($("#evSearch")?.value || "").trim().toLowerCase();
  const evWho = (a) => a === me ? "you" : (nameOf(a) || evShort(a));
  // Your audit room shows YOUR governance: module-wide queries also return
  // other users' policies — hide events for documents this device doesn't hold.
  let hidden = 0;
  const mine = evCache.filter((e) => {
    const p = (e.parsedJson || {}).policy;
    if (!p || evLabel(p)) return true;
    hidden++; return false;
  });
  // Group bursts: consecutive ScopeUpdated by the same sender within 2 min
  // (one "grant badge to N docs" session) collapse into a single line.
  const groups = [];
  for (const e of mine) {
    const type = (e.type || "").split("::").pop();
    const ts = Number(e.timestampMs || 0);
    const last = groups[groups.length - 1];
    if (last && type === "ScopeUpdated" && last.type === "ScopeUpdated" &&
        last.sender === (e.sender || "") && Math.abs(last.ts - ts) < 120000) {
      last.events.push(e); last.ts = ts; continue;
    }
    groups.push({ type, sender: e.sender || "", ts, events: [e] });
  }
  const renderOne = (e) => {
    const type = (e.type || "").split("::").pop();
    const j = e.parsedJson || {};
    const who = j.who ? evWho(j.who) : evWho(e.sender || "");
    const s = evSentence(type, j, who);
    const t = e.timestampMs ? new Date(Number(e.timestampMs)).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
    const link = `https://suiscan.xyz/testnet/tx/${e.id.txDigest}`;
    return `<div class="evt"><span class="evdot ${s.dot}"></span><div class="evbody"><div class="evtext">${s.text}</div><div class="evmeta">${t} · by ${evWho(e.sender || "")} · <a href="${link}" target="_blank" rel="noreferrer">verify on the ledger ↗</a></div></div></div>`;
  };
  const rows = groups.map((g) => {
    const e = g.events[0];
    const key = e.id.txDigest + (e.id.eventSeq ?? "");
    const t = e.timestampMs ? new Date(Number(e.timestampMs)).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
    const hay = g.events.map((x) => {
      const xj = x.parsedJson || {};
      const lbl = evLabel(xj.policy);
      return `${lbl ? lbl.name : ""} ${xj.who || ""} ${xj.policy || ""} ${nameOf(x.sender || "") || ""} ${nameOf(xj.who || "") || ""}`;
    }).join(" ").toLowerCase() + ` ${g.type} ${g.sender} ${t}`.toLowerCase();
    if (q && !hay.includes(q)) return "";
    if (g.events.length > 1) {
      if (evExpanded.has(key)) {
        return `<div class="evt grp" data-gk="${key}" style="cursor:pointer"><span class="evdot scope"></span><div class="evbody"><div class="evtext">${g.events.length} actions by ${evWho(g.sender)} — itemized below · <span style="color:var(--brass)">click to collapse</span></div></div></div>` + g.events.map(renderOne).join("");
      }
      const names = g.events.map((x) => evLabel((x.parsedJson || {}).policy)).filter(Boolean);
      const first = names.length ? `“${names[0].name}”` : "documents";
      const who = evWho(g.sender);
      return `<div class="evt grp" data-gk="${key}" style="cursor:pointer" title="Click to itemize every action"><span class="evdot scope"></span><div class="evbody"><div class="evtext">${g.events.length} documents — access rules changed by ${who} (${first}${names.length > 1 ? ` +${g.events.length - 1} more` : ""})</div><div class="evmeta">${t} · by ${who} · <span style="color:var(--brass)">click to itemize</span></div></div></div>`;
    }
    return renderOne(e);
  }).filter(Boolean);
  const hiddenNote = hidden ? `<p class="muted small" style="margin-top:10px">${hidden} event${hidden > 1 ? "s" : ""} from other vaults on the network — not yours, not shown.</p>` : "";
  box.innerHTML = (rows.join("") || `<p class="muted small">Nothing matches “${q}” in the latest events.</p>`) + hiddenNote;
  box.querySelectorAll(".evt.grp").forEach((el) => el.onclick = () => {
    const k = el.dataset.gk;
    if (evExpanded.has(k)) evExpanded.delete(k); else evExpanded.add(k);
    renderActivity();
  });
}
const evExpanded = new Set();
$("#tabAgent").onclick = () => switchTab("Agent");

// ---- OPEN (recipient) ----
// opts.viewOnly  → sender chose "view only": no export, watermarked, drag/right-click blocked.
// opts.watermark → text tiled over the content (ties a leaked screenshot to this open).
const PREVIEWABLE_IMG = ["png", "jpg", "jpeg", "gif", "webp"];
// Paint the decrypted file into a container. Reused by the inline view and the
// fullscreen viewer so both look identical (and both stay watermarked/locked).
function paintContent(container, name, bytes, ext) {
  if (PREVIEWABLE_IMG.includes(ext)) { const i = document.createElement("img"); i.src = URL.createObjectURL(new Blob([bytes])); container.appendChild(i); }
  else if (ext === "pdf") { paintPdf(container, bytes); }
  else if (["txt", "md", "csv", "json", "log", "xml", "html"].includes(ext)) { const p = document.createElement("pre"); p.textContent = new TextDecoder().decode(bytes); container.appendChild(p); }
  else { container.innerHTML = `<p class="muted">No inline preview for this file type.</p>`; }
}

// PDF preview via pdf.js — render each page to a <canvas>. We do NOT hand the file to
// WebKit's native viewer: under `sandbox` WebKit blanks PDFs entirely (bug 118859), and
// unsandboxed it's an unhardened renderer. pdf.js is a pure-JS rasterizer with no Acrobat
// JS engine, so PDF-embedded JavaScript (OpenActions, submitForm/launchURL) is structurally
// ignored, and a same-buffer document triggers no outbound network request. This is the
// hardening the audit asked for — display-only, no scripts, no phone-home — and it renders
// identically across WebKit/Chromium. pdf.js is already loaded for text extraction.
async function paintPdf(container, bytes) {
  const wrap = document.createElement("div");
  wrap.className = "pdfdoc";
  container.appendChild(wrap);
  if (!window.pdfjsLib) {
    // Last-resort fallback if pdf.js didn't load: sandboxed iframe (may blank in WebKit,
    // but never runs scripts). Better a missing preview than an unhardened one.
    const f = document.createElement("iframe");
    f.setAttribute("sandbox", "");
    f.setAttribute("referrerpolicy", "no-referrer");
    f.src = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
    wrap.appendChild(f);
    return;
  }
  try {
    const data = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes);
    const pdf = await window.pdfjsLib.getDocument({
      data,
      isEvalSupported: false,   // never eval() — defangs any JS-bearing font/cmap path
      disableAutoFetch: true,   // don't speculatively fetch
      disableStream: true,      // we already hold the whole buffer
    }).promise;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const cw = wrap.clientWidth || container.clientWidth || 680;
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const scale = cw / page.getViewport({ scale: 1 }).width;
      const vp = page.getViewport({ scale: scale * dpr });
      const canvas = document.createElement("canvas");
      canvas.className = "pdfpage";
      canvas.width = vp.width; canvas.height = vp.height;
      canvas.style.width = "100%"; canvas.style.height = "auto";
      wrap.appendChild(canvas);
      await page.render({ canvasContext: canvas.getContext("2d"), viewport: vp }).promise;
    }
  } catch (e) {
    wrap.innerHTML = `<p class="muted">Couldn't render this PDF preview.</p>`;
  }
}
function lockDown(el) {
  el.addEventListener("dragstart", (e) => e.preventDefault());
  el.addEventListener("contextmenu", (e) => e.preventDefault());
}
// Fullscreen reader — essential for view-only files (can't export, so reading
// in-app must be comfortable). Preserves watermark + lockdown.
function openFullscreen(name, bytes, ext, opts) {
  const ov = document.createElement("div");
  ov.className = "viewer-overlay" + (opts.viewOnly ? " view-only" : "");
  ov.innerHTML = `<div class="viewer-bar"><span class="viewer-name">${name}</span><button class="viewer-close" id="vClose">✕ Close</button></div><div class="viewer-stage" id="vStage"></div>`;
  const stage = ov.querySelector("#vStage");
  paintContent(stage, name, bytes, ext);
  if (opts.viewOnly) { applyWatermark(stage, opts.watermark || "ELUR · view only"); lockDown(stage); }
  const close = () => { ov.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  ov.querySelector("#vClose").onclick = close;
  document.addEventListener("keydown", esc);
  document.body.appendChild(ov);
}
function render(name, bytes, opts = {}) {
  const viewOnly = !!opts.viewOnly;
  const ext = (name.split(".").pop() || "").toLowerCase();
  const icon = PREVIEWABLE_IMG.includes(ext) ? "🖼️" : ext === "pdf" ? "📕" : ext === "zip" ? "📦" : ["txt", "md", "csv", "json", "log"].includes(ext) ? "📄" : "🔒";
  const badge = viewOnly ? `<div class="badge ok">✓ decrypted on your device · view only</div>` : `<div class="badge ok">✓ decrypted on your device</div>`;
  const expandBtn = `<button class="btn ghost" id="expandBtn">⛶ Expand</button>`;
  const actions = viewOnly
    ? `<div style="display:flex;gap:8px;margin-top:14px">${expandBtn}</div><div class="vo-note">🔒 <b>View only.</b> The sender didn't allow exporting this file — it can't be saved or opened in another app, and every view is watermarked.</div>`
    : `<div style="display:flex;gap:8px;margin-top:14px">${expandBtn}<button class="btn" id="openNative">Open in its app</button><button class="btn ghost" id="saveDec">Save decrypted file</button></div>`;
  $("#oout").innerHTML = `<div class="filehead"><div class="fi">${icon}</div><div style="flex:1"><div class="nm">${name}</div>${badge}</div></div><div id="render"${viewOnly ? ' class="view-only"' : ''}></div>${actions}`;
  const r = $("#render");
  paintContent(r, name, bytes, ext);
  if (viewOnly) { applyWatermark(r, opts.watermark || "ELUR · view only"); lockDown(r); }
  $("#expandBtn").onclick = () => openFullscreen(name, bytes, ext, { viewOnly, watermark: opts.watermark });
  if (!viewOnly) {
    $("#saveDec").onclick = () => saveBytes(name, bytes);
    $("#openNative").onclick = () => platform.openInApp(name, b64(bytes)).catch((e) => { $("#ostatus").textContent = "Couldn't open: " + e; });
  }
}
// Tiled diagonal watermark over view-only content. Visible deterrent + attribution:
// a screenshot (or a phone photo of the screen) carries this identifier.
function applyWatermark(container, text) {
  container.style.position = "relative";
  // One rotated SVG tile, repeated as a background → perfectly even diagonal coverage
  // (data-room style), instead of a ragged flex grid. Opacity lives in the SVG fill.
  const TW = 400, TH = 150;
  const t = String(text).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' width='${TW}' height='${TH}'>` +
    `<text x='${TW / 2}' y='${TH / 2}' fill='#16243f' fill-opacity='0.09' ` +
    `font-family='ui-monospace,monospace' font-size='12' font-weight='600' letter-spacing='0.4' ` +
    `text-anchor='middle' dominant-baseline='middle' transform='rotate(-26 ${TW / 2} ${TH / 2})'>${t}</text></svg>`;
  const wm = document.createElement("div");
  wm.className = "watermark";
  wm.style.backgroundImage = `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
  container.appendChild(wm);
}
// max-opens accounting: the gate only READS opens, so we record an open separately.
// In this dev build the owner key records it; production uses a sponsored relayer.
// Count this open if the file is open-limited. Works for ANYONE — including an
// anonymous recipient with no wallet — by asking the sponsor backend's relayer
// to record it on-chain (and pay the gas). Best-effort (a determined client
// could skip it); the hard guarantee is revoke/expiry, enforced in the gate.
async function recordOpenIfLimited(policyId) {
  try {
    const pol = await suiClient.getObject({ id: policyId, options: { showContent: true } });
    const mo = Number(pol?.data?.content?.fields?.max_opens || 0);
    if (mo > 0) {
      await fetch(SPONSOR_URL + "/record-open", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policyId }),
      }).catch(() => {});
    }
  } catch {}
}

async function openYale() {
  const f = await pickFile([{ name: "Encrypted file", extensions: ["elur", "yale"] }]);
  if (!f) return;
  $("#oout").innerHTML = "";
  let o; try { o = JSON.parse(new TextDecoder().decode(f.bytes)); if (o.v !== 1 || (!o.policyId && !o.vault)) throw 0; }
  catch { $("#ostatus").textContent = ""; $("#oout").innerHTML = `<div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">That doesn't look like an Elur file.</div></div>`; return; }

  // ---- private vault file (owner-only, offline) ----
  if (o.vault) {
    try {
      $("#ostatus").textContent = "Opening your private vault…";
      const phrase = unlockedPhrase || await platform.keychainGet();
      if (!phrase) { $("#ostatus").textContent = ""; $("#oout").innerHTML = `<div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">Private vault file</div><div class="muted">Unlock on the Share tab first — only you can open this.</div></div>`; return; }
      const rawMk = o.mkSalt ? await deriveMasterKey(phrase, ub64(o.mkSalt)) : await deriveMasterKeyLegacy(phrase);
      const mkKey = await subtle.importKey("raw", rawMk, "AES-GCM", false, ["decrypt"]);
      const ck = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: ub64(o.wiv) }, mkKey, ub64(o.wk)));
      const { name, bytes } = await aesDecrypt(ub64(o.iv), ub64(o.ct), ck);
      $("#ostatus").textContent = ""; render(name, bytes);
      showPromote(o, ck, name);
    } catch (e) {
      $("#ostatus").textContent = "";
      $("#oout").innerHTML = `<div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">Can't open this vault file</div><div class="muted">It was encrypted under a different recovery phrase.</div></div>`;
    }
    return;
  }

  // ---- shared / governed file ----
  try {
    $("#ostatus").textContent = "Authorizing through the access gate…";
    const ephemeral = new Ed25519Keypair();
    const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: SEAL_PKG, ttlMin: 10, signer: ephemeral, suiClient });
    $("#ostatus").textContent = "Fetching the key from the key servers…";
    const ck = await newSeal().decrypt({ data: ub64(o.ek), sessionKey, txBytes: await approvalTxBytes(o.policyId) });
    $("#ostatus").textContent = "Decrypting on your device…";
    const { name, bytes } = await aesDecrypt(ub64(o.iv), ub64(o.ct), ck);
    // exportable defaults true for older files with no flag (backward compatible)
    const exportable = o.exportable !== false;
    // Attribution watermark: a signed-in viewer is stamped by identity (email);
    // an anonymous (bearer) viewer is stamped by the on-chain open — policy + time.
    const when = new Date().toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    const viewer = zkSigner && zkSigner.email ? zkSigner.email : `#${o.policyId.slice(-6)}`;
    const watermark = `ELUR · ${viewer} · ${when}`;
    $("#ostatus").textContent = ""; render(name, bytes, { viewOnly: !exportable, watermark });
    recordOpenIfLimited(o.policyId);
  } catch (e) {
    $("#ostatus").textContent = "";
    const m = (e && (e.message || String(e))) || "";
    const msg = /access|approve|denied|NoAccess|expired|maxopens/i.test(m) ? "Access has been revoked or expired — this file is sealed." : m.slice(0, 200);
    $("#oout").innerHTML = `<div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">Can't open this file</div><div style="color:#b91c1c;font-size:12.5px;margin-top:4px">${msg}</div></div>`;
  }
}
$("#openBtn").onclick = openYale;

// ---- vault → share promotion (encrypt once, govern forever) ----
// Re-wraps the SAME content key to a fresh on-chain policy. The encrypted body
// (iv/ct) is reused untouched — no re-encryption.
function showPromote(o, ck, realName) {
  const wrap = document.createElement("div");
  wrap.className = "card pad"; wrap.style.marginTop = "16px";
  if (!canSign()) {
    wrap.innerHTML = `<div class="lab">Share this file</div><p class="muted small" style="margin-top:0">This is your private vault file. To turn it into a governed share, <b>unlock on the Encrypt tab</b> first, then re-open it here.</p>`;
    $("#oout").appendChild(wrap);
    return;
  }
  wrap.innerHTML = `<div class="lab">Share this file</div>
    <p class="muted small" style="margin-top:0">Turn this vault file into a revocable share — no re-encryption, just a new key minted for your recipient.</p>
    <div class="scopes">
      <div class="scope"><label>Expires</label><select id="pExpiry"><option value="0">never</option><option value="8000">8 seconds (demo)</option><option value="3600000">1 hour</option><option value="86400000">1 day</option><option value="604800000" selected>7 days</option><option value="2592000000">30 days</option></select></div>
      <div class="scope"><label>Max opens</label><select id="pOpens"><option value="0">unlimited</option><option value="1">1</option><option value="3">3</option><option value="5">5</option></select></div>
    </div>
    <button class="btn primary block" id="promoteBtn" style="margin-top:14px">Mint share key &amp; save</button>
    <div class="status" id="pstatus"></div>
    <div id="pout"></div>`;
  $("#oout").appendChild(wrap);
  $("#promoteBtn").onclick = async () => {
    try {
      const expSel = Number($("#pExpiry").value);
      const expiryMs = expSel === 0 ? 0 : Date.now() + expSel;
      const maxOpens = Number($("#pOpens").value);
      $("#pstatus").textContent = "Minting your access key on the ledger…";
      const mint = new Transaction();
      mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(expiryMs), mint.pure.u64(maxOpens), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
      const res = await exec(mint, "mint");
      const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
      const capId = found(res.objectChanges, "::access::OwnerCap").objectId;
      $("#pstatus").textContent = "Sealing the key to your access policy…";
      const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });
      const yale = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: o.iv, ct: o.ct, exportable: true });
      const saveName = opaqueYaleName();
      shares.unshift({ name: realName, saveName, policyId, capId, yale, revoked: false, at: Date.now(), scope: fmtScope(expiryMs, maxOpens) });
      $("#pstatus").textContent = "";
      $("#pout").innerHTML = `<p style="margin-top:12px"><span class="badge ok">✓ Governed share created — revocable</span></p><p class="muted small">Saves under an opaque name (<b>${saveName}</b>). Send it to your recipient — they open it with no account; revoke anytime from the Encrypt tab.</p><button class="btn primary" id="savePromote">Save the encrypted file</button><div id="promoteSend"></div>`;
      $("#savePromote").onclick = async () => {
        const out = await saveBytes(saveName, new TextEncoder().encode(yale));
        if (!out) return;
        $("#promoteSend").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Saved. Now send it through any channel — email, WhatsApp, AirDrop.</p><button class="btn ghost" id="revealPromote">Reveal in Finder to send</button>`;
        $("#revealPromote").onclick = () => platform.revealInFinder(out);
      };
      renderShares();
    } catch (e) { $("#pstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
  };
}

// ---- private vault (offline self-encryption) ----
async function runVault(f) {
  const phrase = unlockedPhrase || await platform.keychainGet();
  if (!phrase) { $("#sstatus").textContent = "Unlock first so the vault can use your key."; return; }
  try {
    $("#sout").innerHTML = ""; $("#sstatus").textContent = "Encrypting for your eyes only…";
    const ck = crypto.getRandomValues(new Uint8Array(32));
    const { iv, ct } = await aesEncrypt(f.bytes, f.name, ck);
    const mkSalt = crypto.getRandomValues(new Uint8Array(16));
    const mkKey = await subtle.importKey("raw", await deriveMasterKey(phrase, mkSalt), "AES-GCM", false, ["encrypt"]);
    const wiv = crypto.getRandomValues(new Uint8Array(12));
    const wk = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: wiv }, mkKey, ck));
    const yale = JSON.stringify({ v: 1, vault: true, mkSalt: b64(mkSalt), wk: b64(wk), wiv: b64(wiv), iv: b64(iv), ct: b64(ct) });
    const saveName = opaqueYaleName();
    $("#sstatus").textContent = "";
    $("#sout").innerHTML = `<div class="filehead"><div class="fi">🔒</div><div style="flex:1"><div class="nm">${f.name}</div><div class="badge ok">private vault — only you can open it · offline</div></div></div><p class="muted small">Saves as <b>${saveName}</b> — opaque on disk; real name restored on open.</p><button class="btn primary" id="saveVault">Save encrypted file</button><div id="vaultAfter"></div>`;
    $("#saveVault").onclick = async () => {
      const out = await saveBytes(saveName, new TextEncoder().encode(yale));
      if (!out) return;
      $("#vaultAfter").innerHTML = `<p class="muted small" style="margin-top:14px">Encrypted copy saved. The <b>original is still on disk in plain text</b> — protecting it at rest means removing it.</p><button class="btn ghost" id="delOrig">Delete the original (you can recover it with your key)</button>`;
      $("#delOrig").onclick = async () => {
        try { await platform.deletePath(f.path); $("#vaultAfter").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Original removed — only the encrypted copy remains. Recover it anytime by opening the .elur file with your recovery phrase.</p>`; }
        catch (e) { $("#vaultAfter").innerHTML = `<p class="muted small" style="margin-top:14px">Couldn't delete the original: ${e}</p>`; }
      };
    };
  } catch (e) { $("#sstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}

// ---- SHARE (sender) ----
let senderKeypair = null;
let unlockedPhrase = null;
let zkSigner = null; // zkLogin (Google) session — alternative to the seed phrase
const canSign = () => !!(senderKeypair || zkSigner);
const shares = [];

// Master key for the private vault. PBKDF2-HMAC-SHA256, a SLOW, SALTED KDF, so an
// attacker who captures a vault file can't cheaply brute-force the recovery phrase
// offline (each guess costs PBKDF2_ITERS hash rounds). The salt is per-file, random,
// and stored in the vault file (salts aren't secret) so the owner can still recover
// from the phrase alone. PBKDF2 is native to Web Crypto — no WASM — so it works in the
// Tauri webview and the future browser build alike. (Argon2id, memory-hard, is the
// audit-time upgrade once we accept a WASM dependency.)
const PBKDF2_ITERS = 600000; // OWASP 2023 floor for PBKDF2-HMAC-SHA256
async function deriveMasterKey(phrase, salt) {
  const base = await subtle.importKey("raw", new TextEncoder().encode("yale-mk:" + phrase), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" }, base, 256);
  return new Uint8Array(bits);
}
// Legacy (pre-PBKDF2) vault files have no salt — derive the old way so they still open.
async function deriveMasterKeyLegacy(phrase) {
  const hash = await subtle.digest("SHA-256", new TextEncoder().encode("yale-mk:" + phrase));
  return new Uint8Array(hash);
}

async function exec(tx, label) {
  const options = { showEffects: true, showObjectChanges: true };
  const res = zkSigner
    ? await zkSigner.signAndExecute(suiClient, tx, options)
    : await suiClient.signAndExecuteTransaction({ signer: senderKeypair, transaction: tx, options });
  await suiClient.waitForTransaction({ digest: res.digest });
  if (res.effects?.status?.status !== "success") throw new Error(`${label} failed: ${JSON.stringify(res.effects?.status)}`);
  return res;
}
const found = (ch, ends) => ch?.find((c) => c.type === "created" && c.objectType?.endsWith(ends));

function uiUnlocked(addr, label) {
  // Identity lives in the rail's account corner now (one place, every room).
  // Friendly label (email for zkLogin); the Sui address is the click-to-copy tooltip.
  const display = label ? label.split("@")[0] : addr.slice(0, 10) + "…" + addr.slice(-6);
  $("#acctId").textContent = display;
  $("#acctId").title = (label ? label + " · " : "") + "Sui address " + addr + " — click to copy";
  $("#acctId").onclick = () => navigator.clipboard.writeText(addr);
  $("#acctBox").classList.remove("hidden");
  console.log("Elur sender address:", addr);
  $("#lockBox").style.display = "none"; $("#shareBox").style.display = "";
}
async function doUnlock(phrase) {
  senderKeypair = Ed25519Keypair.deriveKeypair(phrase);
  unlockedPhrase = phrase;
  uiUnlocked(senderKeypair.toSuiAddress());
}
$("#showPhrase").onclick = (e) => { e.preventDefault(); $("#phraseBox").classList.toggle("hidden"); };
$("#unlock").onclick = async () => {
  const phrase = $("#seed").value.trim().replace(/\s+/g, " ");
  if (phrase.split(" ").length < 6) { $("#lstatus").textContent = "Enter your full recovery phrase."; return; }
  try { await doUnlock(phrase); await platform.keychainSet(phrase); $("#seed").value = ""; }
  catch (e) { $("#lstatus").textContent = "Couldn't read that phrase."; }
};
$("#gsign").onclick = async () => {
  try {
    $("#lstatus").textContent = "";
    zkSigner = await signInWithGoogle((m) => { $("#lstatus").textContent = m; });
    $("#lstatus").textContent = "";
    uiUnlocked(zkSigner.address, zkSigner.email);
    // the vault still derives from the phrase; without one it stays phrase-gated
  } catch (e) { $("#lstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
};
async function signOut() {
  try { await platform.keychainClear(); } catch {}
  try { await zkSignOut(); } catch {}
  location.reload();
}
$("#signoutTop").onclick = signOut;

// auto-unlock: zkLogin session first, then a Keychain phrase
(async () => {
  try {
    zkSigner = await restoreZkSession();
    if (zkSigner) { uiUnlocked(zkSigner.address, zkSigner.email); return; }
    const saved = await platform.keychainGet();
    if (saved) await doUnlock(saved);
  } catch {}
})();

// ---- guided encrypt flow: file → mode → scope → encrypt ----
const ns = { file: null, mode: "share" };
function showChosen(f, isFolder) {
  ns.file = f;
  const fc = $("#fileChosen");
  fc.classList.remove("hidden");
  fc.innerHTML = `<span class="fi-sm">${isFolder ? "📦" : "📄"}</span><span class="nm">${f.name}</span><span class="muted small">${isFolder ? "folder · zipped" : "selected"}</span>`;
}
$("#pickFileBtn").onclick = async () => {
  const f = await pickFile();
  if (!f) return;
  showChosen(f, false);
};
$("#pickFolderBtn").onclick = async () => {
  try {
    $("#fileChosen").classList.remove("hidden");
    $("#fileChosen").innerHTML = `<span class="fi-sm">📦</span><span class="muted small">Zipping folder…</span>`;
    const f = await pickFolder();
    if (!f) { $("#fileChosen").classList.add("hidden"); return; }
    showChosen(f, true);
  } catch (e) {
    $("#fileChosen").innerHTML = `<span class="muted small">Couldn't zip that folder: ${(e.message || e).toString().slice(0, 120)}</span>`;
  }
};
function selMode(m) {
  ns.mode = m;
  $("#modeShare").classList.toggle("sel", m === "share");
  $("#modeVault").classList.toggle("sel", m === "vault");
  $("#scopeSec").style.display = m === "share" ? "" : "none";
  $("#encryptBtn").textContent = m === "share" ? "Encrypt & prepare to send" : "Encrypt to my vault";
}
$("#modeShare").onclick = () => selMode("share");
$("#modeVault").onclick = () => selMode("vault");
$("#encryptBtn").onclick = () => {
  if (!ns.file) { $("#sstatus").textContent = "Pick a file first (step 1)."; return; }
  if (ns.mode === "share") runShare(ns.file); else runVault(ns.file);
};

async function runShare(f) {
  try {
    $("#sout").innerHTML = ""; $("#sstatus").textContent = "Encrypting on your device…";
    const ck = crypto.getRandomValues(new Uint8Array(32));
    const { iv, ct } = await aesEncrypt(f.bytes, f.name, ck);

    const expSel = Number($("#nsExpiry").value);
    const expiryMs = expSel === 0 ? 0 : Date.now() + expSel;
    const maxOpens = Number($("#nsOpens").value);
    const exportable = $("#nsExport").value === "1";
    $("#sstatus").textContent = "Minting your access key on the ledger…";
    const mint = new Transaction();
    mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(expiryMs), mint.pure.u64(maxOpens), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
    const res = await exec(mint, "mint");
    const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
    const capId = found(res.objectChanges, "::access::OwnerCap").objectId;

    $("#sstatus").textContent = "Sealing the key to your access policy…";
    const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });

    const yale = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct), exportable });
    const saveName = opaqueYaleName();
    shares.unshift({ name: f.name, saveName, policyId, capId, yale, revoked: false, at: Date.now(), scope: fmtScope(expiryMs, maxOpens) + (exportable ? "" : " · view-only") });
    $("#sstatus").textContent = "";
    $("#sout").innerHTML = `<div class="filehead"><div class="fi">🔒</div><div style="flex:1"><div class="nm">${f.name}</div><div class="badge ok">Sealed. Governed — ready to send</div></div></div><p class="muted small">Saves under an opaque name (<b>${saveName}</b>) — the filename reveals nothing. The real name is restored inside, on open.</p><button class="btn primary" id="saveYale">Save the encrypted file</button><div id="sendStep"></div>`;
    $("#saveYale").onclick = async () => {
      const out = await saveBytes(saveName, new TextEncoder().encode(yale));
      if (!out) return;
      $("#sendStep").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Saved. <b>Now send this file to your recipient</b> — email, WhatsApp, AirDrop, anywhere. They open it with no account, and you can revoke access anytime.</p><button class="btn ghost" id="revealShare">Reveal in Finder to send</button>`;
      $("#revealShare").onclick = () => platform.revealInFinder(out);
    };
    renderShares();
  } catch (e) { $("#sstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}

function renderShares() {
  if (!shares.length) return;
  $("#sharesCard").style.display = "";
  $("#shares").innerHTML = shares.map((s, i) => {
    const t = s.at ? new Date(s.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
    const meta = `shared ${t} · ${s.scope || ""} · #${s.policyId.slice(-6)}`;
    return `<div class="share-wrap"><div class="share"><span class="fi-sm">🔒</span><div class="share-info"><div class="nm">${s.name}</div><div class="share-meta">${meta}</div></div>` +
      (s.revoked ? `<span class="st badge no">revoked</span>` :
        `<button class="mini" data-dl="${i}">save</button><button class="mini danger" data-rev="${i}">revoke</button>`) +
      `<button class="mini" data-act="${i}" title="What the public ledger says about this share">activity</button>` +
      `<button class="mini" data-led="${i}" title="Independently verify this share's full history on the public Sui ledger">ledger</button>` +
      `</div><div class="act-line" id="act${i}" style="display:none"></div></div>`;
  }).join("");
  $("#shares").querySelectorAll("[data-dl]").forEach((b) => b.onclick = () => { const s = shares[+b.dataset.dl]; saveBytes(s.saveName, new TextEncoder().encode(s.yale)); });
  $("#shares").querySelectorAll("[data-rev]").forEach((b) => b.onclick = () => revokeShare(+b.dataset.rev));
  $("#shares").querySelectorAll("[data-act]").forEach((b) => b.onclick = () => showShareActivity(+b.dataset.act));
  $("#shares").querySelectorAll("[data-led]").forEach((b) => b.onclick = () => platform.openUrl(`https://suiscan.xyz/testnet/object/${shares[+b.dataset.led].policyId}`));
}

// "Activity" = the owner's window into the public ledger: status, opens used,
// last on-chain touch. Read straight from the chain — Elur has no logs of its own.
async function showShareActivity(i) {
  const s = shares[i];
  const el = $("#act" + i);
  el.style.display = "";
  el.textContent = "Reading the public ledger…";
  try {
    const pol = await suiClient.getObject({ id: s.policyId, options: { showContent: true } });
    const f = pol?.data?.content?.fields || {};
    const opens = Number(f.opens || 0);
    const maxOpens = Number(f.max_opens || 0);
    const exp = Number(f.expiry_ms || 0);
    const sealed = !!f.revoked || !!f.destroyed;
    const expired = exp !== 0 && Date.now() > exp;
    const status = sealed ? "sealed — revoked" : expired ? "sealed — expired" : "active";
    let last = "";
    try {
      const txs = await suiClient.queryTransactionBlocks({ filter: { InputObject: s.policyId }, order: "descending", limit: 1 });
      const ts = Number(txs?.data?.[0]?.timestampMs || 0);
      if (ts) last = " · last activity " + new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    } catch {}
    el.textContent = `● ${status} · ${opens}${maxOpens ? " of " + maxOpens : ""} open${opens === 1 ? "" : "s"} recorded${last}`;
  } catch (e) {
    el.textContent = "Couldn't read the ledger: " + String(e.message || e).slice(0, 120);
  }
}
async function revokeShare(i) {
  const s = shares[i];
  try {
    $("#sstatus").textContent = "Revoking on the ledger…";
    const tx = new Transaction();
    tx.moveCall({ target: `${CALL_PKG}::${MODULE}::revoke`, arguments: [tx.object(s.capId), tx.object(s.policyId)] });
    await exec(tx, "revoke");
    s.revoked = true; $("#sstatus").textContent = "Revoked — that file is now sealed everywhere."; renderShares();
  } catch (e) { $("#sstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}

/* ---------- guided tour (onboarding coach-marks) ---------- */
(function(){
  const q = (s)=>document.querySelector(s);
  const TOUR_OPEN = [
    {sel:'#openBtn', n:'Opening a file', h:'No account needed', b:'Pick an encrypted .elur file someone sent you. It decrypts right here on your device — no sign-up, no app account, nothing uploaded.'},
    {sel:'#openBtn', n:'The key decides', h:'Their rules, live', b:'It only opens if the sender’s key still grants access. Revoked, expired, or past its open limit? This same file simply won’t open. They shared it — they still own it.'}
  ];
  // Full-app tour (signed-in): walks every room in product-story order, switching tabs as it goes.
  const TOUR_FULL = [
    {tab:'#tabOverview', sel:'#paneOverview .roomhead', n:'Welcome to Elur', h:'Your whole deal, governed', b:'Elur seals your documents and decides — live, on-chain — who can open them: people and AI agents alike. Here is the whole app in about a minute.'},
    {tab:'#tabShare', sel:'#paneShare .roomhead', n:'Encrypt', h:'Seal and share on your terms', b:'Encrypt any file on your device, then share it anywhere. Add an expiry, cap the opens, or make it view-only and watermarked. Gas is sponsored — no wallet, no crypto.'},
    {tab:'#tabOpen', sel:'#paneOpen .roomhead', n:'Open', h:'No account needed', b:'Anyone you send to opens the file right here — no sign-up, nothing uploaded. It unlocks only while your key still allows it. They hold it; you still own it.'},
    {tab:'#tabAgent', sel:'#paneAgent .roomhead', n:'Access control', h:'The heart of Elur', b:'Grant or revoke every identity that can open your documents — people and AI agents on one list. An agent is just an identity you can switch off.'},
    {tab:'#tabAgent', sel:'#ppAddr', n:'Add a person or agent', h:'Grant by on-chain identity', b:'Each identity is a Sui address. The other side signs into their own Elur and copies their address (top-right — “click to copy”); paste it here, name it, and Add identity. No counterparty handy? Use “generate a test identity” to try the whole flow yourself. Granting and revoking are signed on the ledger.'},
    {tab:'#tabAgent', sel:'#aExport', n:'Connect an AI agent', h:'Governed memory over MCP', b:'Export the manifest (labels + blob ids — no content, no keys) and point Claude Desktop or Cursor at Elur’s MCP server (see agent/CONNECT.md). The agent reads these documents through the same gate as the identity you granted; revoke its badge and its next read returns access denied.'},
    {tab:'#tabRoom', sel:'#paneRoom .roomhead', n:'Documents', h:'An always-available deal room', b:'Browse the deal by folder and open exactly what is shared with you, stored on Walrus. Locked files still show — request access in a click. Revoke, and it re-seals everywhere.'},
    {tab:'#tabRequests', sel:'#paneRequests .roomhead', n:'Requests', h:'Two-way document negotiation', b:'Ask a counterparty for what you need with a deadline, and fulfil what they ask of you. Fulfilling a request is a real on-chain grant — scoped to expire when the review window closes.'},
    {tab:'#tabQA', sel:'#paneQA .roomhead', n:'Q&A', h:'Coming next · preview', b:'A governed deal conversation behind the same gate as the documents. Fully designed; it switches on once its messaging SDK catches up to our stack.'},
    {tab:'#tabActivity', sel:'#paneActivity .roomhead', n:'Activity', h:'Every access, signed', b:'Grants, opens, and revocations recorded on the public ledger — evidence neither party can edit. Not even Elur. That permanence is the product.'}
  ];
  let TOUR = TOUR_FULL;
  let ti = 0;
  function place(i){
    const step = TOUR[i];
    const el = step && document.querySelector(step.sel);
    if(!el || el.offsetParent === null) return false;
    const spot = q('#tourSpot'), tip = q('#tourTip');
    const r = el.getBoundingClientRect(), pad = 8;
    const docTop = window.scrollY + r.top, docLeft = window.scrollX + r.left;
    spot.style.display='block';
    spot.style.top = (docTop - pad)+'px';
    spot.style.left = (docLeft - pad)+'px';
    spot.style.width = (r.width + pad*2)+'px';
    spot.style.height = (r.height + pad*2)+'px';
    q('#tourN').textContent = step.n; q('#tourH').textContent = step.h; q('#tourB').textContent = step.b;
    q('#tourDots').innerHTML = TOUR.map((_,k)=>'<span class="dot'+(k===i?' on':'')+'"></span>').join('');
    q('#tourNext').textContent = i===TOUR.length-1 ? 'Done' : 'Next';
    tip.style.display='block';
    const tw = tip.offsetWidth;
    // always anchor the box BELOW its element, so it can never cover the steps above it
    let left = docLeft;
    const maxLeft = window.scrollX + document.documentElement.clientWidth - tw - 14;
    if(left > maxLeft) left = maxLeft;
    if(left < window.scrollX + 12) left = window.scrollX + 12;
    tip.style.top = (docTop + r.height + 12)+'px';
    tip.style.left = left+'px';
    // bring the element near the top of the window so there's room for the box below
    window.scrollTo({ top: Math.max(0, docTop - 110), behavior: 'smooth' });
    return true;
  }
  function show(i){
    ti = i;
    const step = TOUR[ti];
    if(!step) return end();
    if(step.tab){ const t = q(step.tab); if(t) t.click(); }       // switch to the room first
    setTimeout(()=>{
      if(!place(ti)){ if(ti < TOUR.length-1) show(ti+1); else end(); }  // skip a missing element
    }, step.tab ? 200 : 0);                                        // let the pane render
  }
  function next(){ if(ti >= TOUR.length-1) end(); else show(ti+1); }
  function end(){ const s=q('#tourSpot'), t=q('#tourTip'); if(s)s.style.display='none'; if(t)t.style.display='none'; }
  function start(){
    // Signed-in (all rooms visible) → full app tour; recipient/guest view → the Open mini-tour.
    const fullApp = q('#tabAgent') && q('#tabAgent').offsetParent !== null;
    TOUR = fullApp ? TOUR_FULL : TOUR_OPEN;
    ti = 0;
    show(0);
  }
  const tb=q('#tourBtn'); if(tb) tb.onclick = start;
  const tn=q('#tourNext'); if(tn) tn.onclick = next;
  const tk=q('#tourSkip'); if(tk) tk.onclick = end;
  window.addEventListener('resize', ()=>{ const t=q('#tourTip'); if(t && t.style.display==='block') place(ti); });
})();

// ════════════════════════════════════════════════════════════════════
// AGENT TAB — governed, revocable memory for an AI agent.
// Reuses the app's engine (mint via exec, Seal wrap/unwrap, sponsored gas,
// zkLogin identity) + Walrus storage (native walrus CLI via Rust) + a local
// model via Ollama. The signed-in identity owns and revokes the memories.
// ════════════════════════════════════════════════════════════════════
const AGENT_MODEL = "llama3.2";
const AGENT_SYSTEM =
  "You are an assistant whose memories are governed on-chain and can be revoked by the owner. " +
  "Answer using ONLY the memories listed as accessible. Do NOT use outside or general knowledge, " +
  "and do NOT suggest where else to look. If the question is about a memory listed as REVOKED, " +
  "say in one short sentence that it was revoked and you no longer have access to it. " +
  "Keep answers to 1-2 sentences.";

// Persisted across reloads/restarts — losing this list mid-demo would orphan the
// OwnerCaps in the UI (the objects live on-chain; the app just forgets it has them).
let agentMems = [];            // [{ label, blobId, policyId, capId, folder }]
try { agentMems = JSON.parse(localStorage.getItem("elurAgentMems") || "[]"); } catch {}
const agentPersist = () => { try { localStorage.setItem("elurAgentMems", JSON.stringify(agentMems)); } catch {} };
// Everything is a demo: the canonical documents arrive already sorted into folders,
// so the workspace is populated the moment you open it — no setup button to press.
const DEMO_FOLDERS = { "term sheet": "Corporate", "board resolution": "Corporate", "legal counsel": "Legal", "deal contacts": "Legal", "counsel": "Legal", "legal opinion": "Legal", "opinion": "Legal", "due diligence": "Financial", "confidential budget": "Financial" };
let _foldersTagged = false;
function tagDemoFolders() {
  for (const m of agentMems) {
    if (m.folder) continue;
    const key = Object.keys(DEMO_FOLDERS).find((k) => (m.label || "").toLowerCase().includes(k));
    if (key) m.folder = DEMO_FOLDERS[key];
  }
  if (!_foldersTagged) { _foldersTagged = true; agentPersist(); }
}
tagDemoFolders();
const agentTextCache = new Map(); // blobId -> plaintext

// Memory size-class padding — hide blob size on public Walrus. The true length
// lives INSIDE the encrypted frame ([len(4) | bytes | zero-pad]), so the cleartext
// package leaks nothing; padding to coarse buckets makes different-length memories
// produce equal-size blobs. Smaller buckets than the file flow (memories are text).
function memSizeClass(n) { const b = [4096, 65536, 1048576]; for (const x of b) if (n <= x) return x; return Math.ceil(n / 1048576) * 1048576; }
async function memEncryptPadded(text, ck) {
  const bytes = new TextEncoder().encode(text);
  const frame = new Uint8Array(memSizeClass(4 + bytes.length));
  new DataView(frame.buffer).setUint32(0, bytes.length);
  frame.set(bytes, 4);
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, frame));
  return { iv, ct };
}
async function memDecryptPadded(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  const frame = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  const len = new DataView(frame.buffer).getUint32(0);
  return new TextDecoder().decode(frame.subarray(4, 4 + len));
}
// v:1 back-compat — decrypt unpadded memories stored before the padding fix.
async function memDecrypt(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  return new TextDecoder().decode(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

async function agentIsActive(policyId) {
  try {
    const o = await suiClient.getObject({ id: policyId, options: { showContent: true } });
    const f = o?.data?.content?.fields;
    if (!f || f.revoked || f.destroyed) return false;
    if (Number(f.expiry_ms) !== 0 && Date.now() >= Number(f.expiry_ms)) return false;
    if (Number(f.max_opens) !== 0 && Number(f.opens) >= Number(f.max_opens)) return false;
    return true;
  } catch { return false; }
}

// remember: encrypt → mint policy (sponsored) → Seal-wrap → store on Walrus
async function agentRemember(label, text, folder = null) {
  const ck = crypto.getRandomValues(new Uint8Array(32));
  const { iv, ct } = await memEncryptPadded(text, ck);
  const mint = new Transaction();
  mint.moveCall({ target: `${CALL_PKG}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(0), mint.pure.u64(0), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
  const res = await exec(mint, "mint memory");
  const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
  const capId = found(res.objectChanges, "::access::OwnerCap").objectId;
  const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: SEAL_PKG, id: policyId, data: ck });
  const pkg = JSON.stringify({ v: 2, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct) });
  const blobId = await platform.walrusStore(b64(new TextEncoder().encode(pkg)), 30);
  agentMems.push({ label, blobId, policyId, capId, folder });
}

// recall a memory's text through the Seal gate (throws if revoked)
async function agentRecall(blobId, policyId) {
  if (agentTextCache.has(blobId)) return agentTextCache.get(blobId);
  const raw = ub64(await platform.walrusRead(blobId));
  const pkg = JSON.parse(new TextDecoder().decode(raw));
  const ephemeral = new Ed25519Keypair();
  const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: SEAL_PKG, ttlMin: 10, signer: ephemeral, suiClient });
  const ck = await newSeal().decrypt({ data: ub64(pkg.ek), sessionKey, txBytes: await approvalTxBytes(pkg.policyId) });
  const text = (pkg.v >= 2)
    ? await memDecryptPadded(ub64(pkg.iv), ub64(pkg.ct), new Uint8Array(ck))
    : await memDecrypt(ub64(pkg.iv), ub64(pkg.ct), new Uint8Array(ck));
  agentTextCache.set(blobId, text);
  return text;
}

async function agentView() {
  const accessible = [], sealed = [];
  for (const m of agentMems) {
    if (await agentIsActive(m.policyId)) {
      try { accessible.push({ label: m.label, text: await agentRecall(m.blobId, m.policyId) }); }
      catch { sealed.push(m.label); }
    } else sealed.push(m.label);
  }
  return { accessible, sealed };
}

async function agentRevoke(label) {
  const m = agentMems.find((x) => x.label === label);
  if (!m) return;
  const tx = new Transaction();
  tx.moveCall({ target: `${CALL_PKG}::${MODULE}::revoke`, arguments: [tx.object(m.capId), tx.object(m.policyId)] });
  await exec(tx, "revoke memory");
}

async function agentThink(question, accessible, sealed) {
  const ctx =
    "ACCESSIBLE memories:\n" + (accessible.map((m) => `- ${m.label}: ${m.text}`).join("\n") || "(none)") +
    "\n\nREVOKED memories (no access):\n" + (sealed.map((l) => `- ${l}`).join("\n") || "(none)");
  try {
    const r = await fetch("http://localhost:11434/api/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: AGENT_MODEL, stream: false, messages: [
        { role: "system", content: AGENT_SYSTEM },
        { role: "user", content: `My memories:\n${ctx}\n\nQuestion: ${question}` },
      ] }),
    });
    if (!r.ok) throw new Error();
    const d = await r.json();
    return (d.message?.content || "").trim() || "(no answer)";
  } catch {
    if (accessible.length) return "I can access: " + accessible.map((m) => `${m.label} (${m.text})`).join("; ") + ".";
    if (sealed.length) return "That memory was revoked — I no longer have access to it.";
    return "I have no memory I'm allowed to access about that.";
  }
}

// ---- agent UI ----
function agentRefreshAuth() {
  const ok = canSign();
  $("#agentGate").style.display = ok ? "none" : "";
  $("#agentMain").style.display = ok ? "" : "none";
  if (ok) {
    tagDemoFolders();
    agentRenderMems();
    renderPeople();
    // castDemoIfNeeded();  // disabled: keep demo docs BEARER (open to anyone) so the hosted
    // web demo and the agent quickstart open for anonymous judges. Identity-gating is shown
    // via manual grant/revoke in Access control, and the Confidential Budget denies via revoke.
  }
}
function aBusy(on, txt) {
  $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = on);
  $("#aStatus").textContent = on ? txt : "";
}
async function agentRenderMems() {
  agentPersist(); // every render follows a state change — cheapest reliable hook
  const box = $("#aMems");
  if (!agentMems.length) { box.innerHTML = `<p class="muted small">No documents yet. Add a folder or a file above.</p>`; return; }
  box.innerHTML = "";
  // Group by folder (loose docs last under no header), preserving insertion order.
  const groups = new Map();
  for (const m of agentMems) { const k = m.folder || ""; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(m); }
  const ordered = [...groups.entries()].sort((a, b) => (a[0] ? 0 : 1) - (b[0] ? 0 : 1));
  for (const [folder, mems] of ordered) {
    if (folder) {
      const h = document.createElement("div");
      h.className = "memfolder";
      h.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" style="vertical-align:-2px"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" fill="none" stroke="currentColor" stroke-width="1.6"/></svg> ${folder} <span class="memfoldern">${mems.length}</span>`;
      box.appendChild(h);
    }
    for (const m of mems) {
      const active = await agentIsActive(m.policyId);
      const el = document.createElement("div");
      el.className = "amem" + (folder ? " infolder" : "");
      el.innerHTML = `<div class="atop"><span class="albl">${m.label}</span><span class="abadge ${active ? "on" : "off"}">${active ? "● active" : "● revoked"}</span></div>
        <div class="abid" data-bid="${m.blobId}" title="Click to copy the full Walrus ID" style="cursor:pointer">walrus:${m.blobId.length > 14 ? m.blobId.slice(0, 6) + "…" + m.blobId.slice(-6) : m.blobId}</div>
        ${active ? `<button class="arev" data-l="${m.label}">Revoke on ledger</button>` : `<span class="asealed">sealed — the agent can't read this</span> <button class="arev" data-r="${m.label}" style="color:#2a7">Re-grant on ledger</button>`}
        <button class="arev" data-del="${m.blobId}" style="color:var(--faint);border-color:#e2dccd;margin-left:6px" title="Remove this document from the room. The on-chain policy isn't destroyed — use Revoke first to end access.">Remove</button>`;
      box.appendChild(el);
    }
  }
  box.querySelectorAll(".arev[data-l]").forEach((b) => b.onclick = () => agentDoRevoke(b.dataset.l));
  box.querySelectorAll(".arev[data-r]").forEach((b) => b.onclick = () => agentDoReinstate(b.dataset.r));
  box.querySelectorAll(".arev[data-del]").forEach((b) => b.onclick = () => agentRemoveMem(b.dataset.del));
  box.querySelectorAll(".abid[data-bid]").forEach((el) => el.onclick = async () => {
    try { await navigator.clipboard.writeText(el.dataset.bid); const old = el.textContent; el.textContent = "✓ copied"; setTimeout(() => { el.textContent = old; }, 900); } catch {}
  });
}
// Reinstate = the proof that revocation is a seal, not destruction: the data was
// never lost, only locked. Same cap, one call, access returns everywhere at once.
async function agentDoReinstate(label) {
  const m = agentMems.find((x) => x.label === label);
  if (!m) return;
  aBusy(true, `re-granting “${label}” on the ledger…`);
  try {
    const tx = new Transaction();
    tx.moveCall({ target: `${CALL_PKG}::${MODULE}::reinstate`, arguments: [tx.object(m.capId), tx.object(m.policyId)] });
    await exec(tx, "reinstate memory");
    await agentRenderMems();
    $("#aStatus").textContent = `✓ “${label}” re-granted — sealed, never lost. The agent can read it again.`;
  } catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
  finally { $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false); }
}
// Remove a document from the room — local list only. The sealed blob and its on-chain
// policy are untouched; use "Revoke on ledger" first if you want to actually end access.
function agentRemoveMem(blobId) {
  const m = agentMems.find((x) => x.blobId === blobId);
  if (!m) return;
  if (!confirm(`Remove “${m.label}” from this room?\n\nIt comes off your list. The sealed blob and its on-chain policy stay as they are — if you want to END access, use “Revoke on ledger” first. You can add the document again anytime.`)) return;
  agentMems = agentMems.filter((x) => x.blobId !== blobId);
  agentPersist();
  try { agentTextCache.delete(blobId); } catch {}
  if (roomManifest) roomManifest = roomManifest.filter((d) => d.blobId !== blobId);
  agentRenderMems();
  try { if ($("#paneRoom") && $("#paneRoom").style.display !== "none") renderRoom(); } catch {}
}
async function agentTeach(label, text) {
  aBusy(true, `sealing “${label}” to a policy and storing on Walrus…`);
  try { await agentRemember(label, text); await agentRenderMems(); $("#aStatus").textContent = ""; }
  catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
  finally { $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false); }
}
async function agentDoRevoke(label) {
  aBusy(true, `revoking “${label}” on the ledger…`);
  try { await agentRevoke(label); await agentRenderMems(); $("#aStatus").textContent = `✓ “${label}” revoked on the ledger — your connected agent's next read of it returns access denied.`; }
  catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
  finally { $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false); }
}

// ---- document text extraction (PDFs via pdf.js; Office files parsed natively — they're ZIPs of XML, no deps needed) ----

// Minimal ZIP reader (docx/xlsx/pptx). Inflate via the browser's DecompressionStream.
async function zipOpen(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 65536); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a zip file");
  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const entries = {};
  for (let k = 0; k < count; k++) {
    if (dv.getUint32(off, true) !== 0x02014b50) break;
    const method = dv.getUint16(off + 10, true);
    const csize = dv.getUint32(off + 20, true);
    const nlen = dv.getUint16(off + 28, true), elen = dv.getUint16(off + 30, true), clen = dv.getUint16(off + 32, true);
    const lho = dv.getUint32(off + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(off + 46, off + 46 + nlen));
    entries[name] = { method, csize, lho };
    off += 46 + nlen + elen + clen;
  }
  async function read(name) {
    const e = entries[name]; if (!e) return null;
    const nl = dv.getUint16(e.lho + 26, true), el = dv.getUint16(e.lho + 28, true);
    const data = bytes.subarray(e.lho + 30 + nl + el, e.lho + 30 + nl + el + e.csize);
    if (e.method === 0) return new TextDecoder().decode(data);
    const out = new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw")));
    return new TextDecoder().decode(await out.arrayBuffer());
  }
  return { entries, read };
}
const xmlUnescape = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#x?([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, m[2] === "x" || m[2] === "X" ? 16 : 10)));
const xmlText = (xml) => xmlUnescape(xml.replace(/<[^>]+>/g, " ")).replace(/[ \t]+/g, " ").replace(/ ?\n ?/g, "\n").trim();

async function docxToText(bytes) {
  const zip = await zipOpen(bytes);
  const xml = await zip.read("word/document.xml");
  if (!xml) throw new Error("no document.xml — not a Word file?");
  return xmlText(xml.replace(/<\/w:p>/g, "\n"));
}
async function pptxToText(bytes) {
  const zip = await zipOpen(bytes);
  const names = Object.keys(zip.entries).filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n))
    .sort((a, b) => +a.match(/\d+/)[0] - +b.match(/\d+/)[0]);
  let out = "";
  for (const n of names) {
    const texts = [...(await zip.read(n)).matchAll(/<a:t>([\s\S]*?)<\/a:t>/g)].map((m) => xmlUnescape(m[1]));
    if (texts.length) out += `[slide ${n.match(/\d+/)[0]}] ` + texts.join(" ") + "\n";
  }
  return out.trim();
}
async function xlsxToText(bytes) {
  const zip = await zipOpen(bytes);
  const ssXml = zip.entries["xl/sharedStrings.xml"] ? await zip.read("xl/sharedStrings.xml") : "";
  const shared = [...ssXml.matchAll(/<si>([\s\S]*?)<\/si>/g)].map((m) => xmlText(m[1]));
  let out = "";
  const sheets = Object.keys(zip.entries).filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n))
    .sort((a, b) => +a.match(/\d+/)[0] - +b.match(/\d+/)[0]);
  for (const name of sheets) {
    const xml = await zip.read(name);
    for (const row of xml.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)) {
      const cells = [...row[1].matchAll(/<c([^>]*)>([\s\S]*?)<\/c>/g)].map((c) => {
        const v = c[2].match(/<v>([\s\S]*?)<\/v>/)?.[1] ?? c[2].match(/<t[^>]*>([\s\S]*?)<\/t>/)?.[1] ?? "";
        return /t="s"/.test(c[1]) ? (shared[+v] ?? "") : xmlUnescape(v);
      });
      const line = cells.join(" | ").trim();
      if (line.replace(/[|\s]/g, "")) out += line + "\n";
    }
    out += "\n";
  }
  return out.trim();
}
const rtfToText = (s) => s.replace(/\\'([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
  .replace(/\\par[d]?\b/g, "\n").replace(/\\[a-z]+-?\d* ?/gi, "").replace(/[{}]/g, "").replace(/\n{3,}/g, "\n\n").trim();
// vtt/srt meeting transcripts: drop cue numbers + timestamps, keep who-said-what.
const vttToText = (s) => s.replace(/^WEBVTT[^\n]*\n/, "").split("\n")
  .filter((l) => !/^\d+\s*$/.test(l) && !/-->/.test(l) && !/^(NOTE|STYLE|REGION)\b/.test(l.trim()))
  .join("\n").replace(/<v\s+([^>]+)>/g, "$1: ").replace(/<[^>]+>/g, "").replace(/\n{3,}/g, "\n\n").trim();
// eml: keep the headers that matter + the body (light quoted-printable + HTML handling).
function emlToText(s) {
  s = s.replace(/\r\n/g, "\n");
  const i = s.indexOf("\n\n");
  const head = i < 0 ? s : s.slice(0, i), body = i < 0 ? "" : s.slice(i + 2);
  const keep = head.split(/\n(?!\s)/).filter((h) => /^(from|to|cc|subject|date):/i.test(h)).join("\n")
    .replace(/=\?utf-8\?q\?([\s\S]*?)\?=/gi, (_, q) => decodeURIComponent(q.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, "%$1")))
    .replace(/=\?utf-8\?b\?([\s\S]*?)\?=/gi, (_, b) => { try { return new TextDecoder().decode(ub64(b)); } catch { return b; } });
  let b = body.replace(/=\n/g, "").replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  b = b.split("\n").filter((l) => !(l.length > 200 && /^[A-Za-z0-9+/=]+$/.test(l.trim()))).join("\n"); // drop base64 attachment blobs
  if (/<\/(p|div|br|td|html|body)>/i.test(b)) b = xmlText(b.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<\/(p|div|li|h[1-6]|tr|br)>/gi, "\n"));
  return (keep + "\n\n" + b).trim();
}

async function pdfToText(bytes) {
  const pdf = await window.pdfjsLib.getDocument({ data: bytes }).promise;
  let text = "";
  for (let i = 1; i <= pdf.numPages; i++) {
    const content = await (await pdf.getPage(i)).getTextContent();
    text += content.items.map((it) => it.str).join(" ") + "\n";
  }
  return text.trim();
}
async function extractText(path) {
  const bytes = ub64(await platform.readPath(path));
  const ext = (path.match(/\.([^.\/]+)$/)?.[1] || "").toLowerCase();
  if (ext === "pdf") {
    if (!window.pdfjsLib) throw new Error("PDF reader not loaded — vendor pdf.js into public/pdfjs/ or check the network (see index.html)");
    return await pdfToText(bytes);
  }
  if (ext === "docx" || ext === "docm") return await docxToText(bytes);
  if (ext === "pptx" || ext === "pptm") return await pptxToText(bytes);
  if (ext === "xlsx" || ext === "xlsm") return await xlsxToText(bytes);
  if (ext === "rtf") return rtfToText(new TextDecoder().decode(bytes));
  if (ext === "vtt" || ext === "srt") return vttToText(new TextDecoder().decode(bytes));
  if (ext === "eml") return emlToText(new TextDecoder().decode(bytes));
  if (ext === "xml") return xmlText(new TextDecoder().decode(bytes));
  if (ext === "html" || ext === "htm") return xmlText(new TextDecoder().decode(bytes).replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<\/(p|div|li|h[1-6]|tr|br)>/gi, "\n"));
  if (["doc", "xls", "ppt"].includes(ext)) throw new Error(`legacy .${ext} not supported — save as .${ext}x and retry`);
  // everything else: treat as text; refuse binaries instead of sealing garbage
  const text = new TextDecoder().decode(bytes);
  const junk = (text.match(/[\uFFFD\u0000]/g) || []).length;
  if (junk > Math.max(8, text.length * 0.05)) throw new Error(`.${ext || "?"} looks binary — can't extract text`);
  return text.trim();
}

// Ingest a list of file paths as governed memories (shared by file + folder pickers).
// `folder` groups them in the workspace and enables folder-level access grants.
async function agentIngest(paths, folder = null) {
  $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = true);
  try {
    let n = 0, ok = 0;
    const skipped = [];
    for (const p of paths) {
      const label = baseName(p).replace(/\.[^.]+$/, "").replace(/^\d+[_\-\s]*/, "").replace(/[_\-]+/g, " ").trim() || baseName(p);
      $("#aStatus").textContent = `reading & sealing “${label}” to a policy, storing on Walrus… (${++n}/${paths.length})`;
      let text;
      try { text = await extractText(p); } catch (e) { skipped.push(`${baseName(p)} (${(e.message || e).toString().slice(0, 60)})`); continue; }
      if (!text) { skipped.push(`${baseName(p)} (no text found)`); continue; }
      await agentRemember(label, text, folder);
      ok++;
      await agentRenderMems();
    }
    $("#aStatus").textContent = (ok ? `✓ ${ok} document${ok > 1 ? "s" : ""} now governed — grant access in “Who holds a key,” then connect your agent.` : "No documents could be read.")
      + (skipped.length ? ` Skipped: ${skipped.join("; ")}` : "");
  } catch (e) {
    $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160);
  } finally {
    $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false);
  }
}
// Give the agent a whole FOLDER of documents.
async function agentPickFolder() {
  const dir = await platform.chooseFolder();
  if (!dir) return;
  let files;
  try { files = await platform.listDir(dir); }
  catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)); return; }
  if (!files || !files.length) { $("#aStatus").textContent = `No readable documents (pdf/docx/xlsx/pptx/md/txt/…) found in: ${dir}`; return; }
  const folder = baseName(dir).replace(/[_\-]+/g, " ").trim() || "Documents";
  await agentIngest(files, folder);
}
// Give the agent one or more individual documents.
async function agentPickFile() {
  const picked = await platform.chooseFiles([{ name: "Documents", extensions: ["pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "rtf", "html", "htm", "md", "txt", "csv", "tsv", "json", "log", "markdown", "yaml", "yml", "xml", "toml", "ini", "tex", "vtt", "srt", "eml"] }]);
  if (!picked) return;
  await agentIngest(Array.isArray(picked) ? picked : [picked]);
}
$("#aDocs").onclick = agentPickFolder;
$("#aDocsFile").onclick = (e) => { e.preventDefault(); agentPickFile(); };

$("#aSignin").onclick = async () => {
  try { $("#aGateStatus").textContent = "Opening Google sign-in…"; zkSigner = await signInWithGoogle((m) => $("#aGateStatus").textContent = m); $("#aGateStatus").textContent = ""; uiUnlocked(zkSigner.address, zkSigner.email); agentRefreshAuth(); }
  catch (e) { $("#aGateStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
};
$("#aTeach").onclick = () => { const l = $("#aLabel").value.trim(), t = $("#aText").value.trim(); if (l && t) { $("#aLabel").value = ""; $("#aText").value = ""; agentTeach(l, t); } };
$("#aReset").onclick = () => {
  if (!confirm("Clear the demo from this app so you can add your own documents? The demo policies on the ledger are NOT revoked — they're just removed from this list. You can add a folder or files afterward.")) return;
  agentMems = []; agentPersist(); agentTextCache.clear(); localStorage.removeItem("elurDemoCast"); agentRenderMems();
};
// Export the share manifest: labels + blob ids only — zero content, zero keys.
// This tiny file is what a sender hands to a counterparty; their agent's Elur
// MCP server reads it and opens each file through the on-chain gate.
$("#aExport").onclick = async () => {
  if (!agentMems.length) { $("#aStatus").textContent = "Nothing to export — give the agent some documents first."; return; }
  const manifest = agentMems.map(({ label, blobId, policyId, folder, kind, name, ext }) => ({ label, blobId, policyId, folder: folder || null, kind, name, ext }));
  try {
    const path = await saveBytes("elur-manifest.json", new TextEncoder().encode(JSON.stringify(manifest, null, 2)));
    if (path) $("#aStatus").textContent = `✓ manifest exported (${manifest.length} file${manifest.length > 1 ? "s" : ""}, no content) — point any agent's Elur MCP server at it.`;
  } catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
};
// Badge governance: grant or revoke a named agent identity across ALL current
// memories in ONE on-chain transaction (N add_recipient/remove_recipient calls).
// Contract property worth knowing: bearer (anonymous) opens are only allowed while
// the allowlist is EMPTY — so granting the first badge automatically ends anonymous
// access to these documents, and revoking the badge kills that agent's access to
// everything at once while the documents stay live for everyone still listed.
async function badgeAll(addr, fn) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(addr)) { $("#aStatus").textContent = "That doesn't look like a Sui address (0x + 64 hex characters)."; return; }
  if (!agentMems.length) { $("#aStatus").textContent = "No governed documents yet — give the agent something first."; return; }
  $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = true);
  try {
    $("#aStatus").textContent = `${fn === "add_recipient" ? "granting badge" : "revoking badge"} ${addr.slice(0, 10)}… across ${agentMems.length} document${agentMems.length > 1 ? "s" : ""} (one ledger transaction)…`;
    const tx = new Transaction();
    for (const m of agentMems) {
      if (fn === "add_recipient") {
        // Flip to IDENTITY mode alongside the first grant. Crucial difference:
        // bearer + empty allowlist = anyone may open, but identity + empty
        // allowlist = NOBODY but the owner. Without this, revoking the last
        // badge would silently reopen the anonymous door. (Agent memories are
        // minted with expiry 0 / max_opens 0, which update_scope preserves here.)
        tx.moveCall({ target: `${CALL_PKG}::${MODULE}::update_scope`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.u8(1), tx.pure.u64(0), tx.pure.u64(0)] });
      }
      tx.moveCall({ target: `${CALL_PKG}::${MODULE}::${fn}`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.address(addr)] });
    }
    await exec(tx, fn);
    $("#aStatus").textContent = fn === "add_recipient"
      ? `✓ badge granted — ${addr.slice(0, 10)}… can open all ${agentMems.length} documents. Anonymous access is now OFF for these files.`
      : `✓ badge revoked — ${addr.slice(0, 10)}… is cut off from every document at once.`;
  } catch (e) { $("#aStatus").textContent = "❌ " + (e.message || String(e)).slice(0, 160); }
  finally { $("#paneAgent").querySelectorAll("button,input").forEach((b) => b.disabled = false); }
}
// Grant one identity access to a SUBSET of documents (matched by label) — the
// realism behind the demo cast: each deal role holds only the docs they'd really
// see. One ledger tx; flips each target to identity mode (same bearer-hole fix).
async function grantSubset(addr, labelKeywords) {
  const targets = agentMems.filter((m) => labelKeywords.some((k) => (m.label || "").toLowerCase().includes(k)));
  if (!targets.length) return 0;
  const tx = new Transaction();
  for (const m of targets) {
    tx.moveCall({ target: `${CALL_PKG}::${MODULE}::update_scope`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.u8(1), tx.pure.u64(0), tx.pure.u64(0)] });
    tx.moveCall({ target: `${CALL_PKG}::${MODULE}::add_recipient`, arguments: [tx.object(m.capId), tx.object(m.policyId), tx.pure.address(addr)] });
  }
  await exec(tx, "add_recipient");
  return targets.length;
}
// Populate the demo deal automatically the first time the room opens with the
// canonical documents present — grants each role its realistic subset, once.
// Runs at most once (flagged), skips if you've cleared the demo for your own docs.
async function castDemoIfNeeded() {
  if (localStorage.getItem("elurDemoCast") === "1") return;
  const isCanonical = agentMems.some((m) => Object.keys(DEMO_FOLDERS).some((k) => (m.label || "").toLowerCase().includes(k)));
  if (!agentMems.length || !isCanonical) return; // their own docs, or nothing yet — leave it alone
  try {
    $("#aStatus").textContent = "Setting up the demo deal on the ledger…";
    await grantSubset(DEMO_MARGAUX, ["term sheet", "confidential budget", "due diligence", "legal counsel", "board resolution"]);
    await grantSubset(DEMO_CAMILA,  ["term sheet", "due diligence", "legal counsel", "board resolution"]);
    await grantSubset(DEMO_NIKOS,   ["confidential budget", "due diligence", "term sheet"]);
    await grantSubset(DEMO_CROSBY,  ["term sheet", "due diligence", "board resolution"]);
    localStorage.setItem("elurDemoCast", "1");
    await renderPeople();
    $("#aStatus").textContent = "";
  } catch (e) { $("#aStatus").textContent = ""; } // leave unflagged so it retries next open
}
