// Elur agent — shared library.
// Step 1 scope: Elur's AES-GCM crypto (Node port of the app's engine) + Walrus
// storage driven through the proven `walrus` CLI. No Seal/chain yet — that lands
// in step 2 (governed, revocable memory).

import { webcrypto } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const execFileP = promisify(execFile);
const subtle = webcrypto.subtle;
const BIG = 1024 * 1024 * 128; // 128MB stdout buffer ceiling

// ---- Elur crypto (same AES-256-GCM as the app; no size-class padding here —
// agent memories are small and we don't need file-metadata hiding for them) ----
export function randomKey() {
  return webcrypto.getRandomValues(new Uint8Array(32));
}
export async function aesEncrypt(plaintextBytes, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["encrypt"]);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes));
  return { iv, ct };
}
export async function aesDecrypt(iv, ct, ck) {
  const key = await subtle.importKey("raw", ck, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

// ---- Walrus storage via the CLI (proven in the step-0 probe) ----
// Recursively dig a blobId out of whatever JSON shape `walrus store --json` returns.
function digBlobId(node) {
  if (!node || typeof node !== "object") return null;
  for (const [k, v] of Object.entries(node)) {
    if (/^blobId$/i.test(k) && typeof v === "string") return v;
    if (typeof v === "object") { const found = digBlobId(v); if (found) return found; }
  }
  return null;
}

export async function walrusStore(bytes, epochs = 5) {
  const dir = await mkdtemp(join(tmpdir(), "elur-store-"));
  const f = join(dir, "blob.bin");
  await writeFile(f, Buffer.from(bytes));
  const { stdout } = await execFileP("walrus", ["store", f, "--epochs", String(epochs), "--json"], { maxBuffer: BIG });
  let parsed;
  try { parsed = JSON.parse(stdout); }
  catch { throw new Error("walrus store: could not parse JSON.\nRaw output:\n" + stdout.slice(0, 800)); }
  const blobId = digBlobId(parsed);
  if (!blobId) throw new Error("walrus store: no blobId found in:\n" + JSON.stringify(parsed, null, 2).slice(0, 800));
  return blobId;
}

export async function walrusRead(blobId) {
  const dir = await mkdtemp(join(tmpdir(), "elur-read-"));
  const f = join(dir, "out.bin");
  // --out writes the raw blob bytes to a file (cleaner than mixing binary into stdout)
  await execFileP("walrus", ["read", blobId, "--out", f], { maxBuffer: BIG });
  return new Uint8Array(await readFile(f));
}
