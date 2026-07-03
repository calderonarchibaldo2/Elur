# Elur Agent — You Decide What AI Agents Read

### Owner-governed, revocable access to your documents — for any agent, over MCP.

**Sui Overflow 2026 · Walrus Track**

AI agents read everything now. Point one at your files and it ingests contracts,
health records, deal terms — and from that moment, *you* have no way to take it
back. You cannot expire what it holds, revoke it, or prove it is gone. In a world
of autonomous agents, **"the agent keeps everything, forever, and the owner can't
stop it"** is exactly the wrong default.

Elur inverts it: **the owner holds the leash.** Anything an agent may read is
encrypted on your device, its key sealed to an **on-chain access policy**, and the
ciphertext stored on **Walrus**. The agent can read it — and re-read it, and use it
as memory if you choose — only while *your* policy allows. Revoke, and the agent can
still fetch the blob from Walrus — but **Seal refuses the key, and the data becomes
unreadable. Access over. Provably.**

---

## The mechanism

```
 remember(text)                              recall(blobId)
 ──────────────                              ──────────────
 1. AES-256-GCM encrypt (key never leaves)   1. fetch ciphertext from Walrus
 2. mint an on-chain AccessPolicy (Sui)      2. ask Seal key servers for the key
 3. Seal-wrap the AES key to that policy        → they dry-run seal_approve on-chain
 4. store {policy, sealed-key, ciphertext}      → released ONLY if the policy allows
    as one blob on Walrus  → blob id         3. AES-decrypt locally

                       forget(policy)  →  revoke on-chain
                       ───────────────────────────────────
                       seal_approve now aborts on the `revoked` check first.
                       Key servers refuse. Every copy of the blob, anywhere,
                       is now unreadable. Nothing was deleted — it was sealed.
```

The governance is enforced **on every single recall**, by the chain — not by local
bookkeeping. The agent re-reads from Walrus and re-passes the Seal gate each time, so
a revoked memory is gone because Sui says so, not because the app chose to hide it.

## The full Sui stack, working together

| Layer | Role in the agent's memory |
|-------|----------------------------|
| **Walrus** | Verifiable storage for the encrypted memory blobs (the memory layer) |
| **Seal** | Threshold encryption; releases the key only if the on-chain policy passes |
| **Sui (Move)** | The `AccessPolicy` token — expiry, revoke, reinstate, destroy |
| **zkLogin + Enoki** | (in the companion macOS app) human sign-in with no wallet/gas |

## Run it

```bash
cd agent
npm install

# one-time: export your testnet key for the agent to sign with (gitignored)
sui keytool export --key-identity <your-testnet-address> --json > .agent-key.json

# the headline demo: an AI deal-assistant that forgets on command
node demo-assistant.mjs

# optional — natural-language answers instead of a memory list:
ANTHROPIC_API_KEY=sk-ant-... node demo-assistant.mjs
```

You'll need a little testnet **SUI** (gas) and **WAL** (Walrus storage):
`walrus get-wal --amount 100000000` swaps 0.1 SUI for plenty of WAL.

### What the demo shows

The agent learns two confidential facts, answers a question using both, then **you
revoke the budget memory on-chain** — and asked the very same question again, the
agent can only recall the counsel. It kept what you allowed and forgot what you
revoked.

## Files

- `lib.mjs` — Elur's AES-256-GCM crypto + Walrus storage (via the `walrus` CLI)
- `chain.mjs` — Sui + Seal: mint, revoke, seal-wrap, seal-unwrap (gate-enforced)
- `memory.mjs` — `remember` / `recall` / `forget`
- `assistant.mjs` — the agent's governed memory index
- `brain.mjs` — reasoning (Claude if a key is set; transparent fallback otherwise)
- `demo-assistant.mjs` — the scripted demo
- `test-step1-walrus-crypto.mjs`, `test-step2-governed.mjs` — incremental proofs

## On-chain (Sui testnet)

- Access-control package (`access` module, with the hardened `record_open` guard):
  `0xe69d8597d9cdec396acd3c8f76f7a4e5eb1de52d07ec2344289b279ee995bb3b`
- Seal identity namespace (original package id): `0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff`

## Status & honest limits

Testnet, pre-audit — **not for real secrets yet** (a professional audit is the
gate before that). The agent and the companion macOS app share one engine; this
repo's `contracts/`, `mac-app-v2/`, `server/`, and `web-viewer/` are that engine.

> *You shared it. You still own it.* — and now, so does your agent's memory.
