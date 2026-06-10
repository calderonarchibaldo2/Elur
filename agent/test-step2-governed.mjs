// Step 2 — the centerpiece: governed, revocable agent memory, end to end.
//
//   1. The agent stores a sensitive memory (encrypted, sealed to an on-chain
//      policy, ciphertext on Walrus).
//   2. The agent recalls it — the gate is open, the key is released, it reads.
//   3. YOU revoke the policy on-chain.
//   4. The agent tries to recall again — it can still FETCH the blob from Walrus,
//      but Seal refuses the key. The memory is unreadable. The agent has forgotten.

import { remember, recall, forget } from "./memory.mjs";
import { AGENT_ADDRESS } from "./chain.mjs";

const line = (s = "") => console.log(s);

line("\n──────────────────────────────────────────────");
line(" Elur · governed, revocable memory for AI agents");
line("──────────────────────────────────────────────");
line(" Agent identity: " + AGENT_ADDRESS);

const secret = "Acquisition price ceiling is $4.2M. Never disclose to the seller's side.";
line("\n🧠 The agent learns something sensitive:");
line("   " + JSON.stringify(secret));

line("\n① Storing as governed memory (encrypt → seal to policy → Walrus)…");
const { blobId, policyId, capId } = await remember(secret, { epochs: 5 });
line("   ✓ blob:   " + blobId);
line("   ✓ policy: " + policyId);

line("\n② Agent recalls the memory (gate OPEN)…");
const first = await recall(blobId);
line("   → " + JSON.stringify(first));

line("\n③ YOU revoke the policy on-chain (one transaction)…");
const digest = await forget(capId, policyId);
line("   ✓ revoked. tx: " + digest);

line("\n④ Agent tries to recall again (gate SEALED)…");
try {
  const again = await recall(blobId);
  line("   → " + JSON.stringify(again));
  line("   ❌ FAIL — it should not have been able to read this!");
  process.exit(1);
} catch (e) {
  line("   ⛔ DENIED. The agent fetched the blob from Walrus but Seal refused the key.");
  line("      The memory is now unreadable — the agent has forgotten.");
  line("      (" + (e.message || String(e)).slice(0, 100) + ")");
}

line("\n✅ Governed, revocable agent memory — proven end to end.");
line("   Don't trust the agent's memory. Govern it.\n");
