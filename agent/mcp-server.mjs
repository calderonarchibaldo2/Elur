// Elur MCP server — the door that lets ANY agent open governed files through the gate.
//
// Exposes two tools over the Model Context Protocol (stdio):
//   elur_list_files  → the share manifest: labels + on-chain policy status. No content.
//   elur_open_file   → fetch blob from Walrus → pass the Seal gate → decrypt → text.
//                      If the owner has revoked, the gate refuses and the agent gets nothing.
//
// The protocol is newline-delimited JSON-RPC over stdin/stdout — small enough that we
// implement it directly (no SDK, no new deps; reuses agent/'s installed @mysten stack).
//
// Connect from Claude Desktop / Cursor / any MCP client:
//   { "mcpServers": { "elur": {
//       "command": "node",
//       "args": ["/ABSOLUTE/PATH/TO/Yale/agent/mcp-server.mjs"],
//       "env": { "ELUR_MANIFEST": "/ABSOLUTE/PATH/TO/elur-manifest.json" } } } }
//
// The manifest is the thing a sender actually shares — tiny, content-free:
//   [ { "label": "term sheet", "blobId": "nX98x5O-3mCa19PyRXhWcWmY7FQ9NAkN-SpUzYYAZMw" }, ... ]
// (The encrypted package on Walrus carries its own policyId; blobId is all a recipient needs.)

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { sealUnwrap, isPolicyActive, AGENT_ADDRESS } from "./chain.mjs";
import { aesDecrypt, walrusRead } from "./lib.mjs";

// ---- manifest ----
const MANIFEST_PATH = process.env.ELUR_MANIFEST || new URL("./elur-manifest.json", import.meta.url).pathname;
function loadManifest() {
  try { return JSON.parse(readFileSync(MANIFEST_PATH, "utf8")); }
  catch (e) { throw new Error(`Could not read manifest at ${MANIFEST_PATH}: ${e.message}`); }
}

// ---- opening a governed file (the entire product, in one function) ----
// Accepts both package encodings: the macOS app stores ek/iv/ct as base64 strings,
// the Node agent stores them as plain number arrays.
const asBytes = (x) => typeof x === "string" ? new Uint8Array(Buffer.from(x, "base64")) : new Uint8Array(x);

async function readBlob(blobId) {
  // Aggregator FIRST: plain HTTPS, fast, zero local setup — a recipient's machine
  // won't have the walrus CLI. The CLI is only a fallback for aggregator outages.
  try {
    const r = await fetch(`https://aggregator.walrus-testnet.walrus.space/v1/blobs/${blobId}`, { signal: AbortSignal.timeout(20000) });
    if (!r.ok) throw new Error(`aggregator HTTP ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  } catch (aggErr) {
    try { return await walrusRead(blobId); } // walrus CLI, if installed & on PATH
    catch { throw new Error(`Walrus unreachable for ${blobId} (${String(aggErr.message || aggErr).slice(0, 80)})`); }
  }
}

async function openFile(entry) {
  const pkg = JSON.parse(new TextDecoder().decode(await readBlob(entry.blobId)));
  const ck = await sealUnwrap(pkg.policyId, asBytes(pkg.ek)); // ← the gate. Throws if revoked/expired.
  const plain = await aesDecrypt(asBytes(pkg.iv), asBytes(pkg.ct), ck);
  return new TextDecoder().decode(plain);
}

// ---- MCP tool definitions ----
const TOOLS = [
  {
    name: "elur_list_files",
    description: "List the governed Elur files shared with this agent: label, blob id, and live on-chain access status. Contains no file content.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "elur_open_file",
    description: "Open a governed Elur file by its label (or blob id). The content is fetched encrypted from Walrus and only decrypts if the on-chain policy allows it RIGHT NOW — the owner can revoke at any time, after which this tool returns access-denied. Treat the content as leased, not owned: do not store it elsewhere.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "The file's label from elur_list_files (or its blob id)" } },
      required: ["name"],
    },
  },
];

async function callTool(name, args) {
  if (name === "elur_list_files") {
    const manifest = loadManifest();
    const rows = [];
    for (const m of manifest) {
      // Live status read straight from chain — cheap, no Seal round-trip.
      let status = "unknown";
      try {
        const pkg = JSON.parse(new TextDecoder().decode(await readBlob(m.blobId)));
        status = (await isPolicyActive(pkg.policyId)) ? "active" : "SEALED (revoked/expired)";
      } catch { status = "unreachable"; }
      rows.push(`- ${m.label} [${status}] (blob: ${m.blobId})`);
    }
    return `This agent's identity (badge): ${AGENT_ADDRESS}\n(The owner can grant or revoke this address — revoking the badge cuts off every file at once.)\n\nGoverned files shared with this agent:\n${rows.join("\n") || "(none)"}`;
  }
  if (name === "elur_open_file") {
    const q = (args?.name || "").trim().toLowerCase();
    if (!q) throw new Error("Give me the file's label (see elur_list_files).");
    const manifest = loadManifest();
    const entry = manifest.find((m) => m.label.toLowerCase() === q) || manifest.find((m) => m.blobId === args.name) || manifest.find((m) => m.label.toLowerCase().includes(q));
    if (!entry) throw new Error(`No governed file matching "${args.name}". Use elur_list_files to see what's shared.`);
    // Separate the failure modes honestly: a fetch problem is not a gate denial.
    let pkg;
    try { pkg = JSON.parse(new TextDecoder().decode(await readBlob(entry.blobId))); }
    catch (e) { throw new Error(`FETCH FAILED for "${entry.label}" — could not read blob ${entry.blobId} from Walrus (${String(e.message || e).slice(0, 120)}). Check the manifest's blobId.`); }
    try {
      const ck = await sealUnwrap(pkg.policyId, asBytes(pkg.ek)); // ← the gate
      const plain = await aesDecrypt(asBytes(pkg.iv), asBytes(pkg.ct), ck);
      return `[${entry.label}] — governed content (leased via the Elur gate; access can be revoked at any time):\n\n${new TextDecoder().decode(plain)}`;
    } catch (e) {
      // The headline behaviour: a revoked policy means the key servers refuse. Say so plainly,
      // but carry the underlying reason for debugging.
      throw new Error(`ACCESS DENIED for "${entry.label}" — the on-chain gate refused (revoked, expired, or not permitted for this identity). There is nothing cached to fall back on. [detail: ${String(e.message || e).slice(0, 160)}]`);
    }
  }
  throw new Error(`Unknown tool: ${name}`);
}

// ---- minimal MCP / JSON-RPC plumbing (stdio, newline-delimited) ----
const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
const reply = (id, result) => send({ jsonrpc: "2.0", id, result });
const replyErr = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

const rl = createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  line = line.trim();
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method, params } = msg;
  try {
    if (method === "initialize") {
      reply(id, {
        protocolVersion: params?.protocolVersion || "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "elur", version: "0.1.0" },
      });
    } else if (method === "notifications/initialized" || method?.startsWith("notifications/")) {
      // notifications carry no id and expect no reply
    } else if (method === "ping") {
      reply(id, {});
    } else if (method === "tools/list") {
      reply(id, { tools: TOOLS });
    } else if (method === "tools/call") {
      try {
        const text = await callTool(params?.name, params?.arguments || {});
        reply(id, { content: [{ type: "text", text }], isError: false });
      } catch (e) {
        // Tool-level failures (incl. gate denials) are results, not protocol errors —
        // the agent should read and reason about them.
        reply(id, { content: [{ type: "text", text: String(e.message || e) }], isError: true });
      }
    } else if (id !== undefined) {
      replyErr(id, -32601, `Method not found: ${method}`);
    }
  } catch (e) {
    if (id !== undefined) replyErr(id, -32603, String(e.message || e));
  }
});

process.stderr.write(`[elur-mcp] governed-file server up · badge: ${AGENT_ADDRESS} · manifest: ${MANIFEST_PATH}\n`);
