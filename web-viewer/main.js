// Yale web app — Open (recipient) + Share (sender) + Revoke, all in the browser.
// Open needs no identity (ephemeral, bearer gate). Share needs the sender's identity
// to sign/pay the mint tx (dev: from seed; prod: sponsored gas + zkLogin).

import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";

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

function approvalTxBytes(policyId) {
  const tx = new Transaction();
  tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
  return tx.build({ client: suiClient, onlyTransactionKind: true });
}
function sizeClass(n) { const b = [16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864]; for (const x of b) if (n <= x) return x; return Math.ceil(n / 67108864) * 67108864; }
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
function download(name, bytes) {
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([bytes])); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 600);
}

// ============ tabs ============
$("#tabOpen").onclick = () => { $("#tabOpen").classList.add("on"); $("#tabShare").classList.remove("on"); $("#paneOpen").style.display = ""; $("#paneShare").style.display = "none"; };
$("#tabShare").onclick = () => { $("#tabShare").classList.add("on"); $("#tabOpen").classList.remove("on"); $("#paneShare").style.display = ""; $("#paneOpen").style.display = "none"; };

// ============ OPEN (recipient) ============
function render(name, bytes) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const icon = ["png","jpg","jpeg","gif","webp"].includes(ext) ? "🖼️" : ext === "pdf" ? "📕" : ["txt","md","csv","json","log"].includes(ext) ? "📄" : "🔒";
  $("#oout").innerHTML = `<div class="card"><div class="filehead"><div class="fi">${icon}</div><div style="flex:1"><div class="nm">${name}</div><div class="badge ok">✓ decrypted on your device</div></div></div><div id="render"></div></div>`;
  const r = $("#render"); const blob = new Blob([bytes]);
  if (["png","jpg","jpeg","gif","webp"].includes(ext)) { const i = document.createElement("img"); i.src = URL.createObjectURL(blob); r.appendChild(i); }
  else if (ext === "pdf") { const f = document.createElement("iframe"); f.src = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" })); r.appendChild(f); }
  else if (["txt","md","csv","json","log","xml","html"].includes(ext)) { const p = document.createElement("pre"); p.textContent = new TextDecoder().decode(bytes); r.appendChild(p); }
  else { const a = document.createElement("a"); a.className = "btn"; a.href = URL.createObjectURL(blob); a.download = name; a.textContent = "⬇ Download " + name; r.appendChild(a); }
}
async function openYale(text) {
  $("#oout").innerHTML = "";
  let o; try { o = JSON.parse(text); if (o.v !== 1 || !o.policyId) throw 0; } catch { $("#ostatus").textContent = ""; $("#oout").innerHTML = `<div class="card"><div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">That doesn't look like a Yale file.</div></div></div>`; return; }
  try {
    $("#ostatus").textContent = "Authorizing through the access gate…";
    const ephemeral = new Ed25519Keypair();
    const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: PACKAGE_ID, ttlMin: 10, signer: ephemeral, suiClient });
    $("#ostatus").textContent = "Fetching the key from the key servers…";
    const ck = await newSeal().decrypt({ data: ub64(o.ek), sessionKey, txBytes: await approvalTxBytes(o.policyId) });
    $("#ostatus").textContent = "Decrypting on your device…";
    const { name, bytes } = await aesDecrypt(ub64(o.iv), ub64(o.ct), ck);
    $("#ostatus").textContent = ""; render(name, bytes);
  } catch (e) {
    $("#ostatus").textContent = "";
    const m = (e && (e.message || String(e))) || "";
    const msg = /access|approve|denied|NoAccess/i.test(m) ? "Access has been revoked by the sender — this file is sealed." : m.slice(0, 200);
    $("#oout").innerHTML = `<div class="card"><div class="denied"><div class="ic">🔒</div><div style="font-weight:600;margin-top:8px">Can't open this file</div><div style="color:var(--fwd2);font-size:12.5px;margin-top:4px">${msg}</div></div></div>`;
  }
}
wireDrop("odrop", "ofile", (f) => f.text().then(openYale));

// ============ SHARE (sender) ============
let senderKeypair = null;
const shares = []; // { name, policyId, capId, yale, revoked }

async function exec(tx, label) {
  const res = await suiClient.signAndExecuteTransaction({ signer: senderKeypair, transaction: tx, options: { showEffects: true, showObjectChanges: true } });
  await suiClient.waitForTransaction({ digest: res.digest });
  if (res.effects?.status?.status !== "success") throw new Error(`${label} failed: ${JSON.stringify(res.effects?.status)}`);
  return res;
}
const found = (ch, ends) => ch?.find((c) => c.type === "created" && c.objectType?.endsWith(ends));

$("#unlock").onclick = () => {
  const phrase = $("#seed").value.trim().replace(/\s+/g, " ");
  if (phrase.split(" ").length < 6) { $("#sstatus").textContent = "Enter your full recovery phrase."; return; }
  try {
    senderKeypair = Ed25519Keypair.deriveKeypair(phrase);
    $("#seed").value = "";
    $("#addr").textContent = "· " + senderKeypair.toSuiAddress().slice(0, 10) + "…";
    $("#lockBox").style.display = "none"; $("#shareBox").style.display = "";
  } catch (e) { $("#sstatus").textContent = "Couldn't read that phrase."; }
};
$("#lock").onclick = () => { senderKeypair = null; location.reload(); };

async function shareFile(file) {
  try {
    $("#sout").innerHTML = ""; $("#sstatus").textContent = "Encrypting on your device…";
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const ck = crypto.getRandomValues(new Uint8Array(32));
    const { iv, ct } = await aesEncrypt(fileBytes, file.name, ck);

    $("#sstatus").textContent = "Minting your access token on-chain…";
    const mint = new Transaction();
    mint.moveCall({ target: `${PACKAGE_ID}::${MODULE}::mint`, arguments: [mint.pure.u8(0), mint.pure.u64(0), mint.pure.u64(0), mint.pure.vector("u8", [1]), mint.object(CLOCK)] });
    const res = await exec(mint, "mint");
    const policyId = found(res.objectChanges, "::access::AccessPolicy").objectId;
    const capId = found(res.objectChanges, "::access::OwnerCap").objectId;

    $("#sstatus").textContent = "Sealing the key to your token…";
    const { encryptedObject } = await newSeal().encrypt({ threshold: 1, packageId: PACKAGE_ID, id: policyId, data: ck });

    const yale = JSON.stringify({ v: 1, policyId, ek: b64(encryptedObject), iv: b64(iv), ct: b64(ct) });
    const yaleName = file.name + ".yale";
    shares.unshift({ name: yaleName, policyId, capId, yale, revoked: false });
    $("#sstatus").textContent = "";
    $("#sout").innerHTML = `<div class="card"><div class="filehead"><div class="fi">🔒</div><div style="flex:1"><div class="nm">${yaleName}</div><div class="badge ok">encrypted &amp; governed — ready to send</div></div></div><button class="btn" id="dl">⬇ Download ${yaleName}</button></div>`;
    $("#dl").onclick = () => download(yaleName, new TextEncoder().encode(yale));
    renderShares();
  } catch (e) { $("#sstatus").textContent = "❌ " + (e.message || String(e)).slice(0, 200); }
}
wireDrop("sdrop", "sfile", shareFile);

function renderShares() {
  if (!shares.length) return;
  $("#sharesCard").style.display = "";
  $("#shares").innerHTML = shares.map((s, i) =>
    `<div class="share"><span class="nm">${s.name}</span>` +
    (s.revoked ? `<span class="st badge no">revoked</span>` :
      `<button class="btn ghost" style="padding:6px 11px;font-size:12px" data-dl="${i}">save</button><button class="btn danger" style="padding:6px 11px;font-size:12px" data-rev="${i}">revoke</button>`) +
    `</div>`).join("");
  $("#shares").querySelectorAll("[data-dl]").forEach((b) => b.onclick = () => { const s = shares[+b.dataset.dl]; download(s.name, new TextEncoder().encode(s.yale)); });
  $("#shares").querySelectorAll("[data-rev]").forEach((b) => b.onclick = () => revokeShare(+b.dataset.rev));
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

// shared drop helper
function wireDrop(dropId, inputId, handler) {
  const d = $("#" + dropId), inp = $("#" + inputId);
  d.onclick = () => inp.click();
  inp.onchange = (e) => { if (e.target.files[0]) handler(e.target.files[0]); };
  ["dragover", "dragleave", "drop"].forEach((ev) => d.addEventListener(ev, (e) => { e.preventDefault(); d.style.borderColor = ev === "dragover" ? "var(--gold)" : ""; }));
  d.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]); });
}
