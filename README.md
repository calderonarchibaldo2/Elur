# Elur

**Non-custodial, governed document sharing — for people and AI agents.** Sharing becomes a
**revocable lease, not a permanent gift**: you see who opened a file, set it to expire, and
revoke it so it re-seals everywhere — even on a copy already downloaded. And Elur **can't read
your files** — not "won't," *can't* — because it's never in the custody path.

## ▶ Try it now — no install, no account → **[elur.io/suioverflow2026demo](https://elur.io/suioverflow2026demo)**

A live deal room on **Sui testnet**. Open a document — it decrypts **in your browser**, through the
on-chain gate. Then open the **Confidential Budget**: it's been revoked on-chain, and you'll watch
the gate refuse it. You can also **sign in with Google (zkLogin)** and **encrypt your own file** end
to end — gas sponsored, no wallet. Nothing is mocked, nothing is installed.

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
no wallet, sponsored gas). And **governed agent memory**: an AI agent gets its own on-chain badge
and reads through the same gate over **MCP** — revoke the badge and it provably forgets.

## Three ways to see it

- **The web demo** ([elur.io/suioverflow2026demo](https://elur.io/suioverflow2026demo)) — recipient
  decryption + live revocation, plus encrypt-your-own via zkLogin. No install. Source: [`web-demo/`](web-demo/).
- **The full app, in a browser** — the entire product (Encrypt, Open, Access control, Documents,
  Requests, Activity) runs as a web build with **no Rust toolchain**:
  `cd app && npm install && npm run web`. It's the *same source* as the native app; the Tauri layer
  is swapped for browser shims ([`app/web/`](app/web/)).
- **Connect your own agent** — point Claude Desktop / Cursor at a governed manifest via the Elur MCP
  server (~5 min, no app): [`agent/CONNECT.md`](agent/CONNECT.md). One document opens; the revoked
  one is refused — for *your* agent, against live testnet.

## The contract — the heart of it

[`contracts/sources/access.move`](contracts/sources/access.move): the `AccessPolicy` object and the
read-only **`seal_approve`** gate. Every key release, for every reader — person or agent — passes here.

## The native app (optional)

The same app also ships as a native **macOS / Tauri** build (`cd app && npm run tauri dev`), which
adds Keychain-backed vaults and deeper OS file integration. It needs Rust/Tauri plus your own
Enoki/OAuth keys; the submission **video** shows it running end-to-end.

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
