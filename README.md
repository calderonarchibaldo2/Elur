# Elur

**Non-custodial, governed document sharing — for people and AI agents.** Sharing becomes a
**revocable lease, not a permanent gift**: you see who opened a file, set it to expire, and
revoke it so it re-seals everywhere — even on a copy already downloaded. And Elur **can't read
your files** — not "won't," *can't* — because it's never in the custody path. Your documents
never become training data and never teach anyone's model your business — not as a promise,
as a **property of the architecture**.

**Three questions every provider should have to answer — ours have provable answers.**
*Who can see it?* Only who you allow, for as long as you allow. *Where is it cached?*
Nowhere — what leaves your device is ciphertext. *Did it train something?* Never — nothing
upstream can read it, so nothing upstream can learn from it. You own the means of production
of your own documents.

## ▶ Try the live demo → **[elur.io/suioverflow2026demo](https://elur.io/suioverflow2026demo)**

A live deal room on **Sui testnet** — an **evaluation build** that runs in your browser so you can
try Elur without installing anything. Open a document: it decrypts through the on-chain gate. Open
the **Confidential Budget**: it's revoked on-chain, and you'll watch the gate refuse it. Sign in with
Google (zkLogin) and **encrypt your own file** end to end — gas sponsored, no wallet. Nothing is mocked.

> **This browser build is for evaluation.** In production, **Elur ships as a native desktop app** —
> same code, same on-chain gate, but your keys live in your OS keychain and nothing runs in a browser.
> That's where the security guarantees are strongest; the web build just lowers the bar to try it.

## What it is

A custodian normally bundles three powers — it **stores** your file, holds the **key**, and
**governs** access. Elur splits them across three decentralized layers so no single party
(including Elur) holds more than one:

- **Walrus** stores the encrypted blob — no key, learns nothing.
- **Seal** holds the content key across **threshold** key servers — released only if an on-chain
  rule passes.
- **Sui** holds that rule: a Move contract (`AccessPolicy`) governing who may open, expiry,
  max-opens, and revocation. The whole guarantee is one read-only function, **`seal_approve`**.

Encrypt → share → open → revoke, for files and folders. Identity via **zkLogin** (Google sign-in,
no wallet, sponsored gas). And **governed agent access**: AI agents read everything now — with
Elur, *you* decide what any agent may read. An agent gets its own on-chain badge and reads through
the same gate over **MCP** — revoke the badge and its next read is refused, provably, everywhere.

## Ways to see it

- **The product — a native desktop app.** Elur ships as a native **macOS / Tauri** app, where keys
  live in the OS keychain and files are encrypted locally — the trust boundary a security product
  needs. Run from source: `cd app && npm install && npm run tauri dev` (needs Rust/Tauri + your own
  Enoki/OAuth keys). The submission **video** shows it end to end.
- **The evaluation build, in a browser** — to make it easy to try, the *same app* also runs as a web
  build with no Rust toolchain (`cd app && npm run web`); the Tauri layer is swapped for browser shims
  ([`app/web/`](app/web/)). This is what the [live demo](https://elur.io/suioverflow2026demo) hosts —
  for evaluation, not the shipped product.
- **Connect your own agent** — point Claude Desktop / Cursor at a governed manifest via the Elur MCP
  server (~5 min, no app): [`agent/CONNECT.md`](agent/CONNECT.md). One document opens; the revoked
  one is refused — for *your* agent, against live testnet.

## The contract — the heart of it

[`contracts/sources/access.move`](contracts/sources/access.move): the `AccessPolicy` object and the
read-only **`seal_approve`** gate. Every key release, for every reader — person or agent — passes here.

## Status & honesty

Live on **Sui testnet**. Hard guarantees (revoke, expiry, authorization) are enforced in the gate at
every key release. Best-effort properties (open-counting, audit-log completeness) and the path to
hardening them are documented openly. No real clients until an independent security audit.

## Repository

| Path | What |
|------|------|
| `web-demo/` | The hosted, no-install judge demo (Vite). |
| `app/` | The full app — web build (`npm run web`) and native Tauri build. |
| `app/web/` | The browser shim layer that runs the app with no Rust. |
| `contracts/` | The Move access contract (`yale::access`) — the `seal_approve` gate. |
| `agent/` | The MCP server + quickstart for governed agent access. |
| `server/` | The zkLogin gas-sponsor backend (zero-custody — auth/gas only, never file keys). |
