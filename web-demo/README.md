# Elur — web demo (hosted judge demo)

A no-install, no-account **recipient deal room**. A visitor opens documents that decrypt
**live in the browser** through the real on-chain gate: the encrypted blob is fetched from
**Walrus**, **Seal**'s key servers check `seal_approve` on **Sui**, and the key is released
only if the policy allows. The **Confidential Budget** is revoked on-chain, so it denies live.
Nothing is mocked.

Built on the proven `web-viewer` crypto core; uses the same package config as the app that
sealed the demo documents.

## Run / build / deploy
```bash
cd web-demo
npm install
npm run dev          # local preview at localhost:5173
npm run build        # -> dist/  (static; deploy this)
```
Deploy `dist/` to **elur.io** (Cloudflare Pages, or `wrangler pages deploy dist`).

## The ONE decision before it works — how a visitor opens a doc
Open `config.js` and choose:

- **Option A — anonymous bearer (recommended for a public demo).** Leave `recipientSecret: null`.
  This only opens documents minted in **bearer mode** (mode 0, empty allowlist). If the demo-room
  docs are identity-gated (because the demo cast was granted), mint **1–2 fresh bearer "sample"
  docs** in the app, drop their `blobId`s into `config.js`, and visitors open those anonymously.
- **Option B — open as a granted counterparty.** Put a **throwaway testnet** `suiprivkey1...`
  (an identity that's on the docs' allowlist) in `recipientSecret`. The page then opens the docs
  shared with that identity. Demo identity only — never a real key.

Either way, the **revoked Confidential Budget denies for everyone** — that's the showcase.

## If the browser can't reach Walrus (CORS)
If `fetch` to the Walrus aggregator is blocked by CORS in the browser, add a tiny same-origin
proxy on elur.io (a Cloudflare Worker that forwards `/blob/:id` to
`https://aggregator.walrus-testnet.walrus.space/v1/blobs/:id` with `Access-Control-Allow-Origin: *`),
then set `CONFIG.walrusAggregator` to that proxy path. (Most Walrus testnet aggregators already
send permissive CORS, so try without the proxy first.)

## Notes
- `blobId`s in `config.js` are the real Walrus testnet blobs from `agent/elur-manifest.json`.
- Package config in `main.js` (`CALL_PKG` for `seal_approve`, `SEAL_PKG` for the Seal session)
  matches the deployed contract; don't change unless the contract is re-upgraded.

## "Try it on your own document" (zkLogin + sponsored gas)

A second tab lets a visitor seal **their own** file end-to-end: sign in with Google (zkLogin),
encrypt locally, mint a policy + Seal-wrap the key (gas sponsored), open it, then revoke it and
watch it deny — real on testnet, no wallet, no SUI. Reuses the desktop app's Enoki flow; the only
difference is a same-page OAuth redirect.

Toggle in `config.js` with `enableSender`. **Three setup steps (yours):**

1. **Register the redirect URI.** The page's own URL (e.g. `https://elur.io/demo`) must be added as
   an authorized redirect URI in **both** the Google OAuth client *and* the Enoki portal. Today only
   `http://localhost:8765–8767` are registered (desktop). Set `oauthRedirect` if it differs from the
   page URL.
2. **Deploy the sponsor backend.** `server/server.mjs` holds the private sponsor key. Deploy it to a
   public **HTTPS** URL, **open CORS** to the demo origin, **fund its wallet** with testnet SUI, and
   put the URL in `config.js` → `sponsorUrl`. (`localhost` won't work once hosted.)
3. `enokiPublicKey` and `googleClientId` are public (testnet, zkLogin-only) and already filled from
   the desktop app's `enoki.js`.

If any of that isn't ready by submission, set `enableSender: false` — the recipient demo stands on
its own (and proves real decryption + live revocation; the sealed package for the sender self-test
is held in memory, so no Walrus write is needed).
