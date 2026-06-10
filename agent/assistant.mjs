// The agent's governed memory store. It keeps only a small index of blob ids +
// policy ids locally; the memories themselves live encrypted on Walrus, gated by
// Seal. Crucially, `accessibleMemories()` re-reads from Walrus and re-passes the
// on-chain gate EVERY time — so a revoked memory is gone because the chain says so,
// not because we hid it locally.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { remember, recall, forget } from "./memory.mjs";

const INDEX = new URL("./.memories.json", import.meta.url);
const load = () => (existsSync(INDEX) ? JSON.parse(readFileSync(INDEX, "utf8")) : []);
const save = (m) => writeFileSync(INDEX, JSON.stringify(m, null, 2));

export function reset() { save([]); }
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
  const out = [];
  for (const m of load()) {
    try { out.push({ label: m.label, text: await recall(m.blobId) }); }
    catch { /* gate sealed → the agent simply no longer has this memory */ }
  }
  return out;
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
