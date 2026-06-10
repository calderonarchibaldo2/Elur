// The demo: an AI deal-assistant with governed memory.
// It remembers sensitive facts → answers from them → you revoke one on-chain →
// it can no longer recall it. The agent kept what you allow, forgot what you revoked.

import { reset, learn, accessibleMemories, revokeByLabel } from "./assistant.mjs";
import { think, usingLLM } from "./brain.mjs";

const L = (s = "") => console.log(s);
async function ask(q) {
  const mems = await accessibleMemories();
  const a = await think(q, mems);
  L("🧑  " + q);
  L("🤖  " + a + "\n");
}

L("\n══════════════════════════════════════════════════════");
L("  Elur — an AI deal-assistant with GOVERNED memory");
L("  (brain: " + (usingLLM ? "Claude via API" : "local fallback — set ANTHROPIC_API_KEY for the full agent") + ")");
L("══════════════════════════════════════════════════════");

reset(); // start each demo run with a clean memory

L("\n① Teaching the agent two confidential facts (stored as governed memories on Walrus)…");
await learn("budget", "Our maximum acquisition budget is $4.2M — strictly confidential.");
await learn("counsel", "Our lead counsel is Maria Restrepo at Lex Andina.");
L("   ✓ both sealed to on-chain policies and stored on Walrus.\n");

L("② Ask the agent — every memory is accessible:");
await ask("What is our maximum budget, and who is our lead counsel?");

L("③ You revoke ONLY the confidential budget memory, on-chain…");
const { digest } = await revokeByLabel("budget");
L("   ✓ revoked. tx: " + digest + "\n");

L("④ Ask the exact same question — the agent has forgotten the budget:");
await ask("What is our maximum budget, and who is our lead counsel?");

L("══════════════════════════════════════════════════════");
L("  The agent kept what you allowed, and forgot what you revoked.");
L("  Don't trust the agent's memory. Govern it.");
L("══════════════════════════════════════════════════════\n");
