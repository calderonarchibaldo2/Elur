// Browser implementation of the Tauri `invoke(cmd, args)` surface used by the app.
// Every native command the desktop Rust backend provides is emulated here with web
// primitives: File API (reads), downloads (writes), Walrus HTTP (store/read),
// localStorage (Keychain/kv). main.js is unchanged — Vite aliases @tauri-apps/api/core
// to this module for the web build.

import JSZip from "jszip";
import { getEntry, pickOne, pickMany, pickDir, saveName } from "./vfs.js";

const AGG = "https://aggregator.walrus-testnet.walrus.space/v1/blobs/";
const PUB = "https://publisher.walrus-testnet.walrus.space/v1/blobs";
const LS = "elur:kv:";

const b64 = (u8) => { let s = ""; const C = 0x8000; for (let i = 0; i < u8.length; i += C) s += String.fromCharCode.apply(null, u8.subarray(i, i + C)); return btoa(s); };
const ub64 = (str) => { const s = atob(str); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
const baseName = (p) => (p || "download").split(/[\\/]/).pop();

function download(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes]));
  const a = document.createElement("a");
  a.href = url; a.download = name || "download"; a.style.display = "none";
  document.body.appendChild(a); a.click();
  setTimeout(() => { try { a.remove(); } catch {} URL.revokeObjectURL(url); }, 1500);
}

async function readPath(path) {
  const e = getEntry(path);
  if (!e) throw new Error("file not found");
  if (e.dir) throw new Error("path is a directory");
  return b64(new Uint8Array(await e.arrayBuffer()));
}
async function zipPath(folder) {
  const e = getEntry(folder);
  if (!e || !e.dir) throw new Error("not a folder");
  const zip = new JSZip();
  for (const f of e.files) {
    const rel = f.webkitRelativePath || f.name;
    const inner = rel.split("/").slice(1).join("/") || f.name; // strip top folder
    zip.file(inner, await f.arrayBuffer());
  }
  return b64(await zip.generateAsync({ type: "uint8array" }));
}
function listDir(path) {
  const e = getEntry(path);
  if (!e || !e.dir) return [];
  return e.files.map((f) => f.webkitRelativePath || f.name);
}
async function walrusStore(b64v, epochs) {
  const r = await fetch(`${PUB}?epochs=${epochs || 1}`, { method: "PUT", body: ub64(b64v) });
  if (!r.ok) throw new Error("Walrus publish failed (" + r.status + ")");
  const j = await r.json();
  const id = j?.newlyCreated?.blobObject?.blobId || j?.alreadyCertified?.blobId;
  if (!id) throw new Error("Walrus: no blobId in response");
  return id;
}
async function walrusRead(id) {
  const r = await fetch(AGG + id);
  if (!r.ok) throw new Error("Walrus read failed (" + r.status + ")");
  return b64(new Uint8Array(await r.arrayBuffer()));
}

export async function invoke(cmd, args = {}) {
  switch (cmd) {
    case "read_path": return readPath(args.path);
    case "write_path": download(baseName(args.path), ub64(args.b64)); return;
    case "zip_path": return zipPath(args.folder);
    case "list_dir": return listDir(args.path);
    case "delete_path": return; // no filesystem to delete from in the browser
    case "walrus_store": return walrusStore(args.b64, args.epochs);
    case "walrus_read": return walrusRead(args.id);
    case "open_url": window.open(args.url, "_blank", "noopener"); return;
    case "open_in_default_app": download(args.name, ub64(args.b64)); return;
    case "reveal_in_finder": return;
    case "keychain_get": return localStorage.getItem(LS + "phrase");
    case "keychain_set": localStorage.setItem(LS + "phrase", args.value); return;
    case "keychain_clear": localStorage.removeItem(LS + "phrase"); return;
    case "kv_get": return localStorage.getItem(LS + (args.account || "kv"));
    case "kv_set": localStorage.setItem(LS + (args.account || "kv"), args.value); return;
    case "kv_clear": localStorage.removeItem(LS + (args.account || "kv")); return;
    default: throw new Error("Not available in the web app: " + cmd);
  }
}

// Re-exported for the dialog shim (shares the same vfs).
export { pickOne, pickMany, pickDir, saveName };
