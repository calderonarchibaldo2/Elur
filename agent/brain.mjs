// The agent's reasoning. Orthogonal to the memory layer on purpose: the point of
// the project is GOVERNED MEMORY, not the model. Uses Claude if ANTHROPIC_API_KEY
// is set; otherwise a transparent fallback that simply shows accessible memories —
// either way, the agent can only reason over memories the on-chain gate still allows.

const KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.ELUR_MODEL || "claude-3-5-haiku-latest";

export const usingLLM = !!KEY;

export async function think(question, memories) {
  const context = memories.length
    ? memories.map((m) => `- ${m.label}: ${m.text}`).join("\n")
    : "(no accessible memories)";

  if (!KEY) {
    if (!memories.length) return "I have no memory I'm currently allowed to access about that.";
    return "Based on the memories I can currently access:\n" + context;
  }

  const system =
    "You are an assistant that may ONLY use the memories explicitly provided to you. " +
    "Answer the user's question using only those memories. If the information needed is " +
    "not in your accessible memories, clearly say you don't have access to it. Be concise.";

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 300,
      system,
      messages: [{ role: "user", content: `My accessible memories:\n${context}\n\nQuestion: ${question}` }],
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error("LLM error: " + JSON.stringify(data).slice(0, 200));
  return data.content?.[0]?.text?.trim() || "(no answer)";
}
