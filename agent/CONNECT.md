# Connect any agent to Elur

Elur is the governance layer for what AI agents can access. Your agent gets two tools;
the on-chain gate decides — at every single open — whether they work. The owner can
grant or revoke your agent's access at any time, from anywhere, without touching your
machine.

## Quickstart (~5 minutes, no app)

```bash
git clone <repo> && cd elur/agent     # or just copy the agent/ folder
npm install
npm run setup                         # makes your agent key + prints a ready config block
```

Paste the printed block into Claude Desktop's `claude_desktop_config.json` (or Cursor's
`.cursor/mcp.json`), restart the client, and ask your agent:

- *"What Elur files do I have?"* — it lists the governed deal-room documents (labels + live
  on-chain status; no content).
- *"Open the term sheet."* — it fetches the blob from Walrus and decrypts **through the gate**.
- *"Open the confidential budget."* — **ACCESS DENIED**: that document is **revoked on-chain**,
  so the key servers refuse and nothing is cached.

A bundled demo manifest (`elur-manifest.json`) points at **real Walrus testnet blobs**, so this
runs against live infrastructure with zero setup on your side. That contrast — one document opens,
the revoked one is refused, for *your own* agent — is the whole feature. The sections below explain
each piece.

## What your agent gets

- `elur_list_files` — the shared documents: labels + live on-chain status. No content.
- `elur_open_file` — fetches the encrypted blob from Walrus and decrypts it **only if
  the policy allows it right now**. Revoked = access denied, nothing cached.

## What you need

1. **Node 18+** (no other dependencies — the server is a single file).
2. **The Elur repo** (or just the `agent/` folder).
3. **A manifest** — the tiny JSON the document owner shares with you (labels + blob ids,
   zero content, zero keys). Save it anywhere.
4. **An identity key (badge)** — your agent's address. Generate one:
   ```bash
   cd agent
   node --input-type=module -e "
   import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
   import { writeFileSync } from 'node:fs';
   const kp = new Ed25519Keypair();
   writeFileSync('./my-agent-key.json', JSON.stringify({ exportedPrivateKey: kp.getSecretKey() }, null, 2));
   console.log('Your agent badge:', kp.toSuiAddress());"
   ```
   Send the printed address to the document owner. They grant it (or revoke it) in Elur.

## Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "elur": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/agent/mcp-server.mjs"],
      "env": {
        "ELUR_MANIFEST": "/ABSOLUTE/PATH/TO/elur-manifest.json",
        "ELUR_KEY": "/ABSOLUTE/PATH/TO/my-agent-key.json"
      }
    }
  }
}
```

Restart Claude Desktop. Ask: *"What Elur files do I have?"*

## Cursor

`.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally) — same JSON block
as above.

## Any other MCP client (OpenClaw, custom agents, …)

The server speaks standard MCP over stdio. Launch command:

```bash
ELUR_MANIFEST=/path/to/elur-manifest.json ELUR_KEY=/path/to/my-agent-key.json node mcp-server.mjs
```

## The deal your agent is accepting

Content arrives **leased, not owned**: it decrypts through an on-chain gate that the
document's owner controls. Revocation kills every future open, everywhere, instantly.
Every open your identity makes is signed and recorded on-chain — an audit trail neither
side can edit. Treat governed content accordingly: read it, reason about it, don't
re-store it.

*Testnet note: blob reads use the public Walrus testnet aggregator; no wallet, gas, or
tokens are needed to read. Your badge key signs Seal session requests only.*
