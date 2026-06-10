// The agent's governed memory store. It keeps only a small index of blob ids +
// policy ids locally; the memories themselves live encrypted on Walrus, gated by
// Seal. Crucially, `accessibleMemories()` re-reads from Walrus and re-passes the
// on-chain gate EVERY time — so a revoked memory is gone because the chain says so,
// not because we hid it locally.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { remember, recall, forget } from "./memory.mjs";
import { isPolicyActive } from "./chain.mjs";

const INDEX = new URL("./.memories.json", import.meta.url);
const load = () => (existsSync(INDEX) ? JSON.parse(readFileSync(INDEX, "utf8")) : []);
const save = (m) => writeFileSync(INDEX, JSON.stringify(m, null, 2));

// Decrypted-text cache so repeated asks don't re-download + re-decrypt from Walrus.
// The on-chain gate (isPolicyActive) is still checked on EVERY ask, so a revoke
// still takes effect immediately — we only skip the redundant ciphertext fetch.
const textCache = new Map(); // blobId -> plaintext

export function reset() { save([]); textCache.clear(); }
export function listMemories() { return load(); }

// Teach the agent something — stored as a governed memory on Walrus.
export async function learn(label, text) {
  const { blobId, policyId, capId } = await remember(text, { epochs: 5 });
  const mem = load();
  mem.push({ label, blobId, policyId, capId });
  save(mem);
  return { label, blobId, policyId };
}

// Everything the agent can ACTUALLY access right now. Each memory is fetched from
// Walrus and run through the Seal gate; revoked ones throw and are silently dropped.
export async function accessibleMemories() {
  return (await memoryView()).accessible;
}

// Full view: what the agent can read now, AND which memories exist but are sealed
// (revoked/expired). Telling the brain about sealed labels lets it answer "that
// memory was revoked — I no longer have access" instead of feigning ignorance.
export async function memoryView() {
  const accessible = [], sealed = [];
  for (const m of load()) {
    if (await isPolicyActive(m.policyId)) {            // on-chain gate, checked every time
      if (textCache.has(m.blobId)) { accessible.push({ label: m.label, text: textCache.get(m.blobId) }); continue; }
      try { const text = await recall(m.blobId); textCache.set(m.blobId, text); accessible.push({ label: m.label, text }); }
      catch { sealed.push(m.label); }
    } else {
      sealed.push(m.label);                            // revoked/expired → the agent has forgotten it
    }
  }
  return { accessible, sealed };
}

// The governance action: revoke a memory by its label. The blob stays on Walrus
// but becomes unreadable to the agent.
export async function revokeByLabel(label) {
  const mem = load();
  const m = mem.find((x) => x.label === label);
  if (!m) throw new Error("no memory labeled '" + label + "'");
  const digest = await forget(m.capId, m.policyId);
  return { ...m, digest };
}
