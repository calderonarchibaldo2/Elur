# Yale — Key Architecture

*How the keys actually compose. The blueprint the on-chain layer is built from.*
*Reconciles ADR-1 (Seal threshold), ADR-6 (no custody), ADR-7 (owner recovery), ADR-8 (seed root + zkLogin, no cloud), ADR-9 (crypto-shred), plus opaque tokens and filename/size sealing.*

-----

## 1. The core idea: two roots, three key types

Yale has **two independent roots** that are easy to conflate — keeping them separate is the whole design.

**Root 1 — Identity (who you are).** Your Sui address, derived via **zkLogin** (OAuth + private salt). Used for: logging in, signing transactions, and being named in or approved by an access policy (as owner *or* recipient). The chain only ever sees an address / salted commitment — never your Google account.

**Root 2 — Encryption Master Key / MK (what you can open that you hold yourself).** Derived from your **seed phrase** (Argon2id → MK). Used to wrap the content keys of your own files. **Yale never sees it; the seed is its only root.**

And one per-file key:

**Content Key / CK.** A fresh **random** 256-bit key for every file. AES-256-GCM encrypts the payload = `file bytes + filename + type + true size`, zero-padded to a size class. (This is the layer the working engine already implements.) CK is never reused and never *derived* from anything — it's random — which is precisely what lets it be destroyed (crypto-shred) by destroying the CK material.

Everything else is about **how CK is protected, and who is allowed to get it.**

-----

## 2. Encrypt once, govern forever — one mutable token per file

**Decided principle:** a file's ciphertext is created exactly once and never touched again. **Every file has a token (access policy) from the moment it's encrypted, and all control happens by modifying that token** — private → shared → revoked → re-shared → scope changes — never by re-encrypting.

This works because the file is encrypted with its content key (CK), and CK is tiny. Changing access never re-encrypts the file; it only re-wraps the small CK and edits the small token. So "encrypt privately today, modify permissions and share a week later" is: unwrap CK locally with your MK → Seal-wrap that *same* CK to the new policy → update the token. The big ciphertext never moves.

So the two "paths" below are not file types — they are **states of one mutable token**:
- **Private state:** token says "only me"; CK wrapped under your MK.
- **Shared state:** you modify the same token (add recipients, scope) → CK gets Seal-wrapped to the policy. Same file, untouched.
- **Onward:** keep editing the token (add/remove people, change expiry, revoke, reinstate, re-share). The file stays inert ciphertext throughout.

**Where the token lives (recommended): local-until-shared.** The token exists from creation but stays **local (in the `.yale`, offline) while the file is private**, and gets **anchored on-chain the moment of first share**. A private file thus needs no chain, no connectivity, no cost — pure sovereign vault — yet its token is always present and modifiable; sharing simply *promotes* it on-chain. (Alternative: anchor every token on-chain from day one — gives an immediate on-chain record of everything, at the cost of a chain dependency on the private/offline core. Recommendation: local-until-shared.)

-----

## 2b. The two states in detail

A file's CK is protected per the token's current state.

### Path A — Private file (self only): self-wrap, no chain
- CK is wrapped by your **MK** (AES-GCM key-wrap). The wrapped CK rides in the `.yale` next to the ciphertext.
- Open: derive MK from seed (or device-cached MK) → unwrap CK → decrypt.
- **No Seal, no Sui, no token.** You don't need a chain to open a file only you open. This is the engine we already built (cleaned up: MK-wraps-CK instead of phrase-derived-per-file).
- Recovery: seed → MK → unwrap. Lose the seed = gone (ADR-8).

### Path B — Shared file (governed access for others): Seal-gated + owner dual-wrap
- CK is **Seal-encrypted to an on-chain policy identity** (namespaced to Yale's Move package). Recipients obtain CK from the **threshold key servers** *only if* `seal_approve` passes for their identity/device.
- CK is **also** wrapped under the **owner's MK** (an "owner copy"), so the owner can always open their own file directly — independent of key-server liveness or policy state. This satisfies ADR-7 (owner never locked out).
- Revocation: flip the on-chain policy → `seal_approve` fails → key servers stop releasing CK → no recipient can decrypt again. (Owner still can, via the owner copy, until they crypto-shred.)
- The shared reference carries the **Seal ciphertext of CK + the policy id**. No file bytes — Yale stores nothing.

-----

## 3. Who needs the seed, and who doesn't (the elegant part)

- **You, opening your own files** (private, or files you own and shared): need your MK → your seed (or the device-cached MK). Self-custody.
- **A recipient opening a file shared *to* them:** needs **only their zkLogin identity** plus passing `seal_approve`. The threshold key servers hand them CK. **No seed, no account setup, nothing installed.**

So the seed is the burden of **ownership/origination — never of reception.** This is exactly what makes "one tap, no account" real for recipients, and why *sharing* needs the chain while *private files* don't.

-----

## 4. The token (on-chain AccessPolicy) — what it holds

Opaque, **fixed-length**, no filename/type/size. Fields:
- opaque policy id;
- scope: expiry, max-opens, opens count, revoked flag, binding mode (bearer / identity);
- recipient(s) as **salted commitments** (never raw email/address);
- bound device fingerprint **hash** (set on first open in bearer mode);
- watermark seed;
- pointer to the Seal identity namespace.

It does **not** hold CK, the file, or any plaintext. It is the rulebook `seal_approve` reads. (The Seal ciphertext of CK travels with the shared file/reference, not the plaintext file.)

-----

## 5. Operation flows

| Operation | Flow | Chain? | Seed? |
|---|---|---|---|
| Encrypt private | random CK → AES-GCM encrypt payload → wrap CK under MK → write `.yale` | no | yes (MK) |
| Share | random CK → encrypt payload → Seal-encrypt CK to a freshly-minted policy **+** wrap CK under owner MK → deliver encrypted file + policy id via chosen channel | yes (mint policy) | yes (owner MK) |
| Receive (recipient) | zkLogin → request CK from key servers → they eval `seal_approve` → release CK iff approved → decrypt locally in viewer | yes (policy check) | **no** |
| Open your own | unwrap CK with MK → decrypt (works offline, no key servers) | no | yes |
| Revoke | owner tx flips `policy.revoked` → future `seal_approve` fails → recipients sealed everywhere | yes | no |
| Reinstate | owner tx clears `revoked` → access restored (data never deleted) | yes | no |
| Crypto-shred (destroy) | destroy the CK material; for shared, also kill the policy so Seal can't release it | maybe | yes (step-up) |
| New device / recovery | seed → MK → re-derive & re-cache; zkLogin re-login for identity | no | yes |

Crypto-shred works because CK is random and stored only wrapped/Sealed — destroy it and the AES ciphertext is permanently unrecoverable. Honest limit: a recipient who already decrypted *and exported* plaintext is out of reach (view-only mode closes that).

-----

## 6. Device convenience layer

Daily, you don't retype the seed. On a **trusted device** the MK is cached in the OS secure store (Apple Secure Enclave / Keychain, Android Keystore), unlocked by biometric/passkey; zkLogin provides the session identity. The seed is touched only at first setup and new-device recovery. (This preserves ADR-8's "no seed in daily use" feel while keeping the seed as the sole root, no cloud.)

-----

## 7. The picture in one paragraph

Every file gets a random content key (CK) that AES-encrypts it. If the file is **private**, CK is wrapped by your seed-derived master key and that's it — no chain. If you **share** it, CK is additionally Seal-encrypted to an on-chain policy so recipients can get it *only* while the policy approves them (and you can revoke that anytime), while a copy stays wrapped under your own master key so you're never locked out. Your **identity** (zkLogin) is who policies name and approve; your **seed** is what protects what you hold yourself; and a recipient needs only their identity — never your seed — to open what you shared. The token on-chain holds none of the data — just the opaque, fixed-length rulebook the key servers consult.

-----

## 8. Open questions to validate (before writing the Move contract)

1. **zkLogin identity ↔ Seal access binding.** For identity-mode sharing to a *named* person, the recipient's Seal-approved identity must map to their zkLogin identity. Confirm exactly how against Seal's API (does the recipient's zkLogin `sub`/address become the identity `seal_approve` checks?). **#1 thing to validate** — the whole sharing path depends on it.
2. **Owner copy vs owner-as-policy-member.** **DECIDED: dual-wrap** (owner copy under MK) so owner access never depends on key-server liveness. (Fork 1, confirmed.)
3. **KDF.** Use **Argon2id** for seed→MK (memory-hard) in production. (Prototype used PBKDF2 — fine for the demo, not the bar for real secrets.)
4. **Crypto-shred reach** when an attacker physically holds a device with a cached MK — shred must also invalidate the cached MK / the specific CK. Precise mechanics to design.
5. **Every file has a mutable token from creation — DECIDED (Fork 2).** Encrypt once, govern forever: control is always via token edits, never re-encryption. Token stays **local while private, anchored on-chain at first share** — *decided* (local-until-shared). Private files stay offline/free/dependency-free until you choose to share.
