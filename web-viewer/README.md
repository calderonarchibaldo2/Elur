# Yale web viewer — recipient path

> **PROVEN (testnet) — full loop in the browser.** Two tabs: **Open** (recipient, no install/login) and **Share** (sender: unlock with seed → encrypt → mint token on-chain → seal key → download `.yale`, with per-share **revoke**). Verified end to end in the UI: encrypted a file in Share, the `.yale` wouldn't open by double-click (real ciphertext), opened perfectly in the viewer, then **revoke → it no longer opens.** The entire Yale promise — encrypt → share → open → revoke → sealed — with no terminal.
>
> Dev note: the Share tab uses the seed to sign/pay gas. Production replaces that with **sponsored gas + zkLogin sign-in** (ADR-11) — no phrase, no gas for the user. "Your shares" is in-memory (lost on reload) until persistence is added.


A no-install browser app: drop in a `.yale` file you received, and it decrypts and renders it — *if* the sender's token still grants access. Revoked → it won't open. No account, no login, no gas (recipients only read).

## Run (on your Mac)

```bash
cd "/Users/andresc/Documents/Claude/Projects/Yale/web-viewer"
npm install
npm run dev
```
Open the URL it prints (usually http://localhost:5173).

## Full test loop (with the CLI)

1. Make a governed file with the client:
   ```bash
   cd ../client
   export SUI_MNEMONIC="PASTE A FUNDED TESTNET WALLET PHRASE HERE"
   echo "hello from a governed file" > note.txt
   node yale.mjs share note.txt        # -> note.txt.yale  + note.txt.owner.json
   ```
2. In the viewer (browser): drop in `client/note.txt.yale` → it decrypts and shows the text.
3. Revoke it (ids are in `note.txt.owner.json`):
   ```bash
   node yale.mjs revoke <policyId> <capId>
   ```
4. Reload the viewer, drop the same file again → **denied** (sealed by revocation).

That's the cross-tool flow: CLI shares the file, the web viewer opens it with nothing installed, and revocation cuts it off.

## Notes
- Uses an **ephemeral identity** per open (recipient needs no account); bearer-mode policies let it through, and revocation still denies it.
- If `npm run dev` errors on a Node global / wasm in the browser, paste the error — the fix goes in `vite.config.js`.
