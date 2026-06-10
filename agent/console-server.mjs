// Elur Agent Console — local HTTP server.
// A thin wrapper over the PROVEN agent (assistant.mjs + brain.mjs). It serves the
// console UI and four JSON endpoints. No new logic: it just gives the agent a face.
//   GET  /api/state           → brain label + current memories (with live gate status)
//   POST /api/learn  {label,text}
//   POST /api/ask    {question} → answer + which memories were accessible
//   POST /api/revoke {label}
//   POST /api/reset
//
// Run:  node console-server.mjs   → open http://localhost:4000

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { reset, learn, memoryView, revokeByLabel, listMemories } from "./assistant.mjs";
import { think, describeBrain } from "./brain.mjs";
import { isPolicyActive } from "./chain.mjs";

const PORT = 4000;

// Live status of each memory — a fast on-chain read of the policy's revoked flag.
async function memoriesWithStatus() {
  const out = [];
  for (const m of listMemories()) {
    out.push({ label: m.label, blobId: m.blobId, policyId: m.policyId, active: await isPolicyActive(m.policyId) });
  }
  return out;
}

const json = (res, code, obj) => {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(obj));
};
const body = async (req) => { let s = ""; for await (const c of req) s += c; return s ? JSON.parse(s) : {}; };

createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === "GET" && url.pathname === "/") {
      const html = await readFile(new URL("./console.html", import.meta.url), "utf8");
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(html);
    }
    if (req.method === "GET" && url.pathname === "/api/state") {
      return json(res, 200, { brain: await describeBrain(), memories: await memoriesWithStatus() });
    }
    if (req.method === "POST" && url.pathname === "/api/learn") {
      const { label, text } = await body(req);
      if (!label || !text) return json(res, 400, { error: "label and text required" });
      const r = await learn(label, text);
      return json(res, 200, { ok: true, ...r });
    }
    if (req.method === "POST" && url.pathname === "/api/ask") {
      const { question } = await body(req);
      if (!question) return json(res, 400, { error: "question required" });
      const { accessible, sealed } = await memoryView();
      const answer = await think(question, accessible, sealed);
      return json(res, 200, { answer, used: accessible.map((m) => m.label) });
    }
    if (req.method === "POST" && url.pathname === "/api/revoke") {
      const { label } = await body(req);
      const r = await revokeByLabel(label);
      return json(res, 200, { ok: true, digest: r.digest });
    }
    if (req.method === "POST" && url.pathname === "/api/reset") {
      reset();
      return json(res, 200, { ok: true });
    }
    json(res, 404, { error: "not found" });
  } catch (e) {
    json(res, 500, { error: (e && (e.message || String(e))) || "error" });
  }
}).listen(PORT, "127.0.0.1", () => {
  console.log(`\n🧊 Elur Agent Console → http://localhost:${PORT}\n   (local agent · encrypted memory on Walrus · on-chain governance)\n`);
});
