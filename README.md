# Elur
 
### You shared it. You still own it.
 
**Elur is governed, revocable, non-custodial file sharing — built on [Seal](https://seal.mystenlabs.com/), [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin), and [Enoki](https://docs.enoki.mystenlabs.com/) on Sui.**
 
You encrypt a file on your own device and share it however you already do — email, WhatsApp, AirDrop, a link. But you keep the key. You can **revoke access, set an expiry, or limit the number of opens at any time — even after you've hit send.** Seal it again, and no copy opens again, for anyone.
 
> Encrypt once, govern forever.
 
---
 
## The problem
 
When you send a file — a contract, a medical record, a deal document — it's gone. You can't un-send it, can't expire it, can't take it back if it lands in the wrong hands. Email, links, and attachments all share the same flaw: once a file leaves your hands, you've lost control of it forever.
 
Existing tools force a trade-off. Tools that **govern** your files (enterprise IRM, virtual data rooms, Gmail Confidential Mode) hold your data on their servers — you trade control for custody. Tools that **encrypt** (end-to-end cloud storage) can't revoke a file once it's been sent. Nothing offers both, non-custodially, at a price an individual can afford.
 
Elur is the missing option: **governed _and_ non-custodial at once.** You keep control after sending, and no one else — not even Elur — ever holds your key.
 
---
 
## How it works
 
**1. Encrypt.** Drop in any file. It is encrypted on your device with AES-256-GCM. A fresh random content key is generated per file; the plaintext never leaves your machine, and Elur never sees it.
 
**2. Share anywhere.** Send the encrypted file however you already do. The recipient opens it in Elur's viewer with one tap — no account needed (bearer mode), or a single zkLogin sign-in when the sender locks a file to a named identity.
 
**3. Govern forever.** Set an expiry, cap the number of opens, watermark each view, or revoke entirely — any time, from your dashboard. The ciphertext is never re-encrypted; only the access policy changes.
 
---
 
## How Elur uses Seal
 
Seal is the heart of the product. Here is the exact flow:
 
- Each file is encrypted with a random **AES-256 content key**, generated on the device.
- That content key is then **wrapped with Seal** — threshold, identity-based encryption — to an identity that *is* the object ID of an **`AccessPolicy`** object minted on Sui.
- When a recipient opens the file, Seal's **key servers** don't simply hand the key back. They first evaluate Elur's on-chain Move function **`seal_approve`** against the live policy: *Is it revoked? Expired? Over its open limit? Is the caller's identity allowed?* Only if the gate passes do the key servers release their threshold key shares, which the client reconstructs to decrypt locally.
- **Revocation** is a single owner-only transaction that flips `revoked = true` on the policy. Because every decryption, anywhere, must pass `seal_approve` first, the file is sealed everywhere the moment the transaction lands — the inbox copy, the downloaded copy, even a copy on a stolen laptop. Nothing is deleted; revocation is reversible, which is what proves the data was *sealed*, not destroyed.
 
**Seal is the lock; Elur's on-chain policy is the rulebook the lock consults.**
 
The full surrounding stack:
 
- **zkLogin** lets users sign in with an account they already have (Google today; Apple and other providers next) — no wallet, no seed phrase in daily use. A Sui identity materializes behind the scenes via a zero-knowledge proof, without putting the identity on-chain.
- **Enoki** sponsors gas, so users never hold SUI and never see a transaction fee.
- **Move** package on Sui defines the `AccessPolicy` object, the `seal_approve` gate, and `mint` / `revoke` / `update_scope` functions, emitting on-chain events as a tamper-evident access log.
 
---
 
## Architecture at a glance
 
```
Sender (zkLogin) ──encrypt on device──▶ encrypted file kept by the user
       │                                  (their drive / their cloud / any channel)
       │ mint / revoke
       ▼
  Sui: Elur Move package ── AccessPolicy objects (the "tokens") + events
       ▲ seal_approve (policy check)
       │
  Seal key servers (t-of-n) ── release key shares only if the gate passes
```
 
- **Elur stores nothing** — not plaintext, not ciphertext. The encrypted file is the user's to keep and send. There is no upload endpoint and no honeypot to breach.
- The only backend is a thin **gas sponsor** that relays transaction bytes (mint a policy, revoke one) — it never sees file content or keys.
- Trust is pushed into the chain (the policy) and the threshold key-server set (decryption), and custody is pushed entirely to the user.
 
---
 
## Status
 
A native **macOS app** running on **Sui testnet**, with the full loop verified end-to-end:
 
**encrypt → mint on-chain `AccessPolicy` → open (no account needed) → revoke → sealed everywhere.**
 
Plus: expiry, max-opens, an offline private vault, identity-stamped view-only files (every view, and any screenshot of it, carries the viewer's identity and a timestamp so a leak traces back to who opened it), and an on-chain activity view.
 
The Move package is deployed and publicly verifiable on Sui testnet:
`0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff`
 
---
 
## Trust & security posture
 
- **You hold the only key.** Your files and keys never touch an Elur server. Lose your device and one recovery phrase restores everything — no cloud escrow, nothing to breach.
- **Standard cryptography.** AES-256-GCM via the platform's native crypto (no home-rolled algorithms); content keys wrapped with Seal (threshold IBE) for recipients and under the owner's master key for the owner — so revocation can never lock the owner out of their own file.
- **Abuse-resistant by design.** There are no anonymous public links — the vector that turned Firefox Send into a malware-distribution channel. Access is identity-bound and revocable, and every file is owner-recoverable, so Elur can never act as ransomware.
- **No lock-in.** The file format is standard and a free, offline decryptor is planned, so you can always recover your own files even if Elur disappears entirely.
 
---
 
## Roadmap
 
- **iOS, then Windows & Android** — the same cross-platform engine; iOS is the mainstream unlock.
- **Time-locked & conditional release** — inheritance, a child's milestone birthday, a journalist's insurance file. (The contract spine already supports it.)
- **Recipient "trust dial"** — per file: open to anyone, sign-in required, or locked to named people, watermarked into every view.
- **Independent Seal key-server set** before any "you don't have to trust us" claim is marketed.
 
---
 
## Tech stack
 
Sui · Move · Seal (threshold encryption + on-chain `seal_approve`) · zkLogin · Enoki (sponsored gas) · AES-256-GCM · Tauri (macOS).
 
---
 
*Elur — the market pays enterprise prices for custody it doesn't want. Elur sells control without custody.*
 
