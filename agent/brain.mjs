// The agent's reasoning. Orthogonal to the memory layer on purpose: the project is
// about GOVERNED MEMORY, not the model. Three brains, in priority order:
//   1. Local model via Ollama (default) — free, private, on-brand: nothing leaves
//      the machine except encrypted blobs. This is the recommended demo brain.
//   2. Claude via API — if ANTHROPIC_API_KEY is set.
//   3. Transparent fallback — shows accessible memories; needs no setup.
// In every case the agent can only reason over memories the on-chain gate still allows.

const KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ELUR_MODEL || "claude-3-5-haiku-latest";
const OLLAMA_URL = process.env.OLLAMA_URL || "http://localhost:11434";
const OLLAMA_MODEL = process.env.ELUR_OLLAMA_MODEL || "llama3.2";

const SYSTEM =
  "You are an assistant whose memories are governed on-chain and can be revoked by the owner. " +
  "Answer using ONLY the memories listed as accessible. Do NOT use outside or general knowledge, " +
  "and do NOT suggest where else to look. If the question is about a memory listed as REVOKED, " +
  "say in one short sentence that that memory has been revoked and you no longer have access to it. " +
  "If it is about something you simply never knew, say you don't have a memory of it. " +
  "Keep every answer to 1–2 sentences.";

function buildContext(memories, sealed = []) {
  const acc = memories.length ? memories.map((m) => `- ${m.label}: ${m.text}`).join("\n") : "(none)";
  const rev = sealed.length ? sealed.map((l) => `- ${l}`).join("\n") : "(none)";
  return `ACCESSIBLE memories:\n${acc}\n\nREVOKED memories (you no longer have access to these):\n${rev}`;
}

async function ollamaReachable() {
  try {
    const r = await fetch(OLLAMA_URL + "/api/tags", { signal: AbortSignal.timeout(800) });
    return r.ok;
  } catch { return false; }
}

export async function describeBrain() {
  if (KEY) return "Claude via API";
  if (await ollamaReachable()) return `local model via Ollama (${OLLAMA_MODEL}) — nothing leaves the machine`;
  return "transparent fallback (run Ollama or set ANTHROPIC_API_KEY for a real agent)";
}

async function viaClaude(question, context) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL, max_tokens: 300, system: SYSTEM,
      messages: [{ role: "user", content: `My accessible memories:\n${context}\n\nQuestion: ${question}` }],
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error("Claude error: " + JSON.stringify(data).slice(0, 200));
  return data.content?.[0]?.text?.trim() || "(no answer)";
}

async function viaOllama(question, context) {
  const res = await fetch(OLLAMA_URL + "/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: OLLAMA_MODEL, stream: false,
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: `My accessible memories:\n${context}\n\nQuestion: ${question}` },
      ],
    }),
  });
  if (!res.ok) throw new Error("Ollama error: " + res.status);
  const data = await res.json();
  return data.message?.content?.trim() || "(no answer)";
}

function fallback(memories, sealed) {
  const parts = [];
  if (memories.length) parts.push("I can access: " + memories.map((m) => `${m.label} (${m.text})`).join("; "));
  if (sealed.length) parts.push("Revoked — I no longer have access to: " + sealed.join(", "));
  return parts.length ? parts.join(". ") + "." : "I have no memory I'm currently allowed to access about that.";
}

export async function think(question, memories, sealed = []) {
  const context = buildContext(memories, sealed);
  if (KEY) return viaClaude(question, context);
  if (await ollamaReachable()) {
    try { return await viaOllama(question, context); } catch { /* fall through */ }
  }
  return fallback(memories, sealed);
}
