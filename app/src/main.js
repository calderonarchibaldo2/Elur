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

const PACKAGE_ID = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
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

// ---- native file I/O (via Rust commands + dialog plugin) ----
async function pickFile(filters) {
  const path = await openDialog({ multiple: false, ...(filters ? { filters } : {}) });
  if (!path) return null;
  const bytes = ub64(await invoke("read_path", { path }));
  return { name: baseName(path), bytes, path };
}
// Pick a whole folder → zip it (macOS system zip, in Rust) → treat it as one
// "FolderName.zip" file. Everything downstream (encrypt/share/open) is unchanged:
// a folder is just a .zip from here on. (Modest folders only for now — a huge
// folder hits the same in-memory limit as a huge file; streaming is later.)
async function pickFolder() {
  const path = await openDialog({ directory: true, multiple: false });
  if (!path) return null;
  const zipB64 = await invoke("zip_path", { folder: path });
  const bytes = ub64(zipB64);
  return { name: baseName(path) + ".zip", bytes, path };
}
async function saveBytes(defaultName, bytes) {
  let path = await saveDialog({ defaultPath: defaultName });
  if (!path) return null;
  // keep the original extension even if the save dialog strips it, so the file opens naturally
  const dot = defaultName.lastIndexOf(".");
  const ext = dot > 0 ? defaultName.slice(dot) : "";
  if (ext && !path.toLowerCase().endsWith(ext.toLowerCase())) path += ext;
  await invoke("write_path", { path, b64: b64(bytes) });
  return path;
}

// ---- crypto (identical to the web viewer) ----
function approvalTxBytes(policyId) {
  const tx = new Transaction();
  tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
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
$("#tabOpen").onclick = () => { $("#tabOpen").classList.add("on"); $("#tabShare").classList.remove("on"); $("#paneOpen").style.display = ""; $("#paneShare").style.display = "none"; };
$("#tabShare").onclick = () => { $("#tabShare").classList.add("on"); $("#tabOpen").classList.remove("on"); $("#paneShare").style.display = ""; $("#paneOpen").style.display = "none"; };

// ---- OPEN (recipient) ----
// opts.viewOnly  → sender chose "view only": no export, watermarked, drag/right-click blocked.
// opts.watermark → text tiled over the content (ties a leaked screenshot to this open).
const PREVIEWABLE_IMG = ["png", "jpg", "jpeg", "gif", "webp"];
// Paint the decrypted file into a container. Reused by the inline view and the
// fullscreen viewer so both look identical (and both stay watermarked/locked).
function paintContent(container, name, bytes, ext) {
  if (PREVIEWABLE_IMG.includes(ext)) { const i = document.createElement("img"); i.src = URL.createObjectURL(new Blob([bytes])); container.appendChild(i); }
  else if (ext === "pdf") { const f = document.createElement("iframe"); f.src = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" })); container.appendChild(f); }
  else if (["txt", "md", "csv", "json", "log", "xml", "html"].includes(ext)) { const p = document.createElement("pre"); p.textContent = new TextDecoder().decode(bytes); container.appendChild(p); }
  else { container.innerHTML = `<p class="muted">No inline preview for this file type.</p>`; }
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
    $("#openNative").onclick = () => invoke("open_in_default_app", { name, b64: b64(bytes) }).catch((e) => { $("#ostatus").textContent = "Couldn't open: " + e; });
  }
}
// Tiled diagonal watermark over view-only content. Visible deterrent + attribution:
// a screenshot (or a phone photo of the screen) carries this identifier.
function applyWatermark(container, text) {
  container.style.position = "relative";
  const wm = document.createElement("div");
  wm.className = "watermark";
  let inner = "";
  for (let i = 0; i < 60; i++) inner += `<span>${text}</span>`;
  wm.innerHTML = inner;
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
      const phrase = unlockedPhrase || await invoke("keychain_get");
      if (!phrase) { $("#ostatus").textContent = ""; $("#oout").innerHTML = `<div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">Private vault file</div><div class="muted">Unlock on the Share tab first — only you can open this.</div></div>`; return; }
      const mkKey = await subtle.importKey("raw", await deriveMasterKey(phrase), "AES-GCM", false, ["decrypt"]);
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
    const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: PACKAGE_ID, ttlMin: 10, signer: ephemeral, suiClient });
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
      $("#pstatus").textContent = "Minting your access key on-chain…";
      const mint = new Transaction();
      mint.moveCall({ target: `${PACKAGE_ID}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(expiryMs), mint.pure.u64(maxOpens), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
      const res = await exec(mint, "mint");
      const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
      const capId = found(res.objectChanges, "::access::OwnerCap").objectId;
      $("#pstatus").textContent = "Sealing the key to your access policy…";
      const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: PACKAGE_ID, id: policyId, data: ck });
      const yale = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: o.iv, ct: o.ct, exportable: true });
      const saveName = opaqueYaleName();
      shares.unshift({ name: realName, saveName, policyId, capId, yale, revoked: false, at: Date.now(), scope: fmtScope(expiryMs, maxOpens) });
      $("#pstatus").textContent = "";
      $("#pout").innerHTML = `<p style="margin-top:12px"><span class="badge ok">✓ Governed share created — revocable</span></p><p class="muted small">Saves under an opaque name (<b>${saveName}</b>). Send it to your recipient — they open it with no account; revoke anytime from the Encrypt tab.</p><button class="btn primary" id="savePromote">Save the encrypted file</button><div id="promoteSend"></div>`;
      $("#savePromote").onclick = async () => {
        const out = await saveBytes(saveName, new TextEncoder().encode(yale));
        if (!out) return;
        $("#promoteSend").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Saved. Now send it through any channel — email, WhatsApp, AirDrop.</p><button class="btn ghost" id="revealPromote">Reveal in Finder to send</button>`;
        $("#revealPromote").onclick = () => invoke("reveal_in_finder", { path: out });
      };
      renderShares();
    } catch (e) { $("#pstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
  };
}

// ---- private vault (offline self-encryption) ----
async function runVault(f) {
  const phrase = unlockedPhrase || await invoke("keychain_get");
  if (!phrase) { $("#sstatus").textContent = "Unlock first so the vault can use your key."; return; }
  try {
    $("#sout").innerHTML = ""; $("#sstatus").textContent = "Encrypting for your eyes only…";
    const ck = crypto.getRandomValues(new Uint8Array(32));
    const { iv, ct } = await aesEncrypt(f.bytes, f.name, ck);
    const mkKey = await subtle.importKey("raw", await deriveMasterKey(phrase), "AES-GCM", false, ["encrypt"]);
    const wiv = crypto.getRandomValues(new Uint8Array(12));
    const wk = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: wiv }, mkKey, ck));
    const yale = JSON.stringify({ v: 1, vault: true, wk: b64(wk), wiv: b64(wiv), iv: b64(iv), ct: b64(ct) });
    const saveName = opaqueYaleName();
    $("#sstatus").textContent = "";
    $("#sout").innerHTML = `<div class="filehead"><div class="fi">🔒</div><div style="flex:1"><div class="nm">${f.name}</div><div class="badge ok">private vault — only you can open it · offline</div></div></div><p class="muted small">Saves as <b>${saveName}</b> — opaque on disk; real name restored on open.</p><button class="btn primary" id="saveVault">Save encrypted file</button><div id="vaultAfter"></div>`;
    $("#saveVault").onclick = async () => {
      const out = await saveBytes(saveName, new TextEncoder().encode(yale));
      if (!out) return;
      $("#vaultAfter").innerHTML = `<p class="muted small" style="margin-top:14px">Encrypted copy saved. The <b>original is still on disk in plain text</b> — protecting it at rest means removing it.</p><button class="btn ghost" id="delOrig">Delete the original (you can recover it with your key)</button>`;
      $("#delOrig").onclick = async () => {
        try { await invoke("delete_path", { path: f.path }); $("#vaultAfter").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Original removed — only the encrypted copy remains. Recover it anytime by opening the .elur file with your recovery phrase.</p>`; }
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

// master key for the private vault: derived deterministically from the phrase
async function deriveMasterKey(phrase) {
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
  // Friendly identity up front (email for zkLogin); the address lives in the
  // tooltip and click-to-copy for whoever actually needs it.
  $("#addr").textContent = "· " + (label || addr.slice(0, 6) + "…" + addr.slice(-4));
  $("#addr").title = "Sui address: " + addr + " — click to copy";
  $("#addr").style.cursor = "pointer";
  $("#addr").onclick = () => navigator.clipboard.writeText(addr);
  console.log("Elur sender address:", addr);
  $("#lockBox").style.display = "none"; $("#shareBox").style.display = "";
  $("#signoutTop").classList.remove("hidden");
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
  try { await doUnlock(phrase); await invoke("keychain_set", { value: phrase }); $("#seed").value = ""; }
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
  try { await invoke("keychain_clear"); } catch {}
  try { await zkSignOut(); } catch {}
  location.reload();
}
$("#lock").onclick = signOut;
$("#signoutTop").onclick = signOut;

// auto-unlock: zkLogin session first, then a Keychain phrase
(async () => {
  try {
    zkSigner = await restoreZkSession();
    if (zkSigner) { uiUnlocked(zkSigner.address, zkSigner.email); return; }
    const saved = await invoke("keychain_get");
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
    $("#sstatus").textContent = "Minting your access key on-chain…";
    const mint = new Transaction();
    mint.moveCall({ target: `${PACKAGE_ID}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(expiryMs), mint.pure.u64(maxOpens), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
    const res = await exec(mint, "mint");
    const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
    const capId = found(res.objectChanges, "::access::OwnerCap").objectId;

    $("#sstatus").textContent = "Sealing the key to your access policy…";
    const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: PACKAGE_ID, id: policyId, data: ck });

    const yale = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct), exportable });
    const saveName = opaqueYaleName();
    shares.unshift({ name: f.name, saveName, policyId, capId, yale, revoked: false, at: Date.now(), scope: fmtScope(expiryMs, maxOpens) + (exportable ? "" : " · view-only") });
    $("#sstatus").textContent = "";
    $("#sout").innerHTML = `<div class="filehead"><div class="fi">🔒</div><div style="flex:1"><div class="nm">${f.name}</div><div class="badge ok">encrypted &amp; governed — ready to send</div></div></div><p class="muted small">Saves under an opaque name (<b>${saveName}</b>) — the filename reveals nothing. The real name is restored inside, on open.</p><button class="btn primary" id="saveYale">Save the encrypted file</button><div id="sendStep"></div>`;
    $("#saveYale").onclick = async () => {
      const out = await saveBytes(saveName, new TextEncoder().encode(yale));
      if (!out) return;
      $("#sendStep").innerHTML = `<p class="muted small" style="margin-top:14px">✓ Saved. <b>Now send this file to your recipient</b> — email, WhatsApp, AirDrop, anywhere. They open it with no account, and you can revoke access anytime.</p><button class="btn ghost" id="revealShare">Reveal in Finder to send</button>`;
      $("#revealShare").onclick = () => invoke("reveal_in_finder", { path: out });
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
      `<button class="mini" data-act="${i}" title="What the on-chain ledger says about this share">activity</button>` +
      `<button class="mini" data-led="${i}" title="Independently verify this share's full history on the public Sui ledger">ledger</button>` +
      `</div><div class="act-line" id="act${i}" style="display:none"></div></div>`;
  }).join("");
  $("#shares").querySelectorAll("[data-dl]").forEach((b) => b.onclick = () => { const s = shares[+b.dataset.dl]; saveBytes(s.saveName, new TextEncoder().encode(s.yale)); });
  $("#shares").querySelectorAll("[data-rev]").forEach((b) => b.onclick = () => revokeShare(+b.dataset.rev));
  $("#shares").querySelectorAll("[data-act]").forEach((b) => b.onclick = () => showShareActivity(+b.dataset.act));
  $("#shares").querySelectorAll("[data-led]").forEach((b) => b.onclick = () => invoke("open_url", { url: `https://suiscan.xyz/testnet/object/${shares[+b.dataset.led].policyId}` }));
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
    $("#sstatus").textContent = "Revoking on-chain…";
    const tx = new Transaction();
    tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::revoke`, arguments: [tx.object(s.capId), tx.object(s.policyId)] });
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
  const TOUR_ENCRYPT = [
    {sel:'.tabs', n:'Welcome to Elur', h:'Two things live here', b:'“Open a file” reads something sent to you. “Encrypt a file” seals and shares your own. Let’s walk the encrypt side.'},
    {sel:'#pickFileBtn', n:'Step 1 · File', h:'Pick any file — or a folder', b:'Choose a file, or “…encrypt a whole folder 📦”. It’s encrypted on your Mac before anything ever leaves your device.'},
    {sel:'.modes', n:'Step 2 · Mode', h:'Send it, or keep it', b:'“Send to someone” — they open with no account, and you can revoke anytime. Or “Private vault” — sealed offline, only you.'},
    {sel:'#scopeSec', n:'Step 3 · Access', h:'Set the rules', b:'Add an expiry, cap the number of opens, or make it view-only and watermarked. Your on-chain key enforces every rule.'},
    {sel:'#encryptBtn', n:'Step 4 · Encrypt', h:'Seal it on Sui', b:'Your key is minted on the Sui blockchain — owned by you. Gas is sponsored, so there’s nothing to pay and no wallet to set up.'},
    {sel:'#tabOpen', n:'Opening files', h:'No account needed', b:'Anyone you send to opens the file right here — no sign-up, no app account. The on-chain key decides if it still unlocks.'},
    {sel:'#sharesCard', n:'The whole point', h:'Revoke after sending', b:'Every file you share lands in “Your shares.” Revoke any time and it re-seals everywhere — even on a copy already sent. You shared it; you still own it.'}
  ];
  let TOUR = TOUR_ENCRYPT;
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
    ti = i; let guard = 0;
    while(ti < TOUR.length && !place(ti) && guard < TOUR.length){ ti++; guard++; }
    if(ti >= TOUR.length) end();
  }
  function next(){ if(ti >= TOUR.length-1) end(); else show(ti+1); }
  function end(){ const s=q('#tourSpot'), t=q('#tourTip'); if(s)s.style.display='none'; if(t)t.style.display='none'; }
  function start(){
    const openActive = q('#tabOpen') && q('#tabOpen').classList.contains('on');
    if(openActive){ TOUR = TOUR_OPEN; }
    else { TOUR = TOUR_ENCRYPT; const ts = q('#tabShare'); if(ts) ts.click(); }
    setTimeout(()=>show(0), 140);
  }
  const tb=q('#tourBtn'); if(tb) tb.onclick = start;
  const tn=q('#tourNext'); if(tn) tn.onclick = next;
  const tk=q('#tourSkip'); if(tk) tk.onclick = end;
  window.addEventListener('resize', ()=>{ const t=q('#tourTip'); if(t && t.style.display==='block') place(ti); });
})();
