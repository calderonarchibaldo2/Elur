// One-command setup for connecting your own agent to Elur.
//   npm install && npm run setup
// Generates (or reuses) an agent identity key and prints a ready-to-paste MCP config block
// with absolute paths filled in. No values to edit by hand.

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const keyPath = join(here, "my-agent-key.json");
const manifestPath = process.env.ELUR_MANIFEST || join(here, "elur-manifest.json");
const serverPath = join(here, "mcp-server.mjs");

let kp;
if (existsSync(keyPath)) {
  kp = Ed25519Keypair.fromSecretKey(JSON.parse(readFileSync(keyPath, "utf8")).exportedPrivateKey);
  console.log("\nReusing your existing agent key (" + keyPath + ").");
} else {
  kp = new Ed25519Keypair();
  writeFileSync(keyPath, JSON.stringify({ exportedPrivateKey: kp.getSecretKey() }, null, 2));
  console.log("\nGenerated a new agent key -> " + keyPath);
}

const block = { mcpServers: { elur: { command: "node", args: [serverPath],
  env: { ELUR_MANIFEST: manifestPath, ELUR_KEY: keyPath } } } };

console.log("\n  Your agent's badge address:\n  " + kp.toSuiAddress());
console.log("\n  Paste this into Claude Desktop (claude_desktop_config.json)\n  or Cursor (.cursor/mcp.json):\n");
console.log(JSON.stringify(block, null, 2));
console.log("\n  Restart the client, then ask your agent:");
console.log('    "What Elur files do I have?"');
console.log('    "Open the term sheet."            (opens through the gate)');
console.log('    "Open the confidential budget."   (ACCESS DENIED — revoked on-chain)\n');
