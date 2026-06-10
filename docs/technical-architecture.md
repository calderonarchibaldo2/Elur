# Yale — Technical Architecture Spec

*Codename Yale · v0.1 · Drafted May 2026*
*Target chain: Sui · Encryption: Seal · Storage: user-owned (Yale stores nothing — ADR-6) · Auth: zkLogin*

-----

## 1. Purpose of this document

The founding document describes *what* Yale does and the promise it makes to users. This document describes *how* it can actually be built, and where the honest engineering limits are. It maps every claim in the founding document onto concrete primitives, names the parts that are real today versus the parts that require new work, and lays out a phased path from a centralized MVP to a fully Sui-native system.

The guiding principle from the founding document holds at the architecture level: **the token is the lock, and the lock travels with the file — not with the platform.** On Sui, that sentence becomes literally true. The "lock" is an on-chain access policy; the "file" is an encrypted blob that is meaningless without it.

-----

## 2. Why Sui is the right substrate

Four Sui primitives do most of the heavy lifting. None of them existed in usable form a few years ago; all four are live on mainnet today.

**Seal — encryption as the gate, policy as the key.** Seal is Mysten Labs' decentralized secrets-management layer. Data is encrypted with identity-based encryption against a set of independent *key servers*, using *t-of-n threshold* encryption. Decryption keys are only released when an on-chain access policy — a Move function called `seal_approve` — returns success. The policy is code you write and control. This is the core of Yale: the file is sealed by default and only opens when Yale's policy says it may.

**Storage — not Yale's problem (ADR-6).** Yale stores **no files** — not plaintext, not ciphertext. It encrypts client-side and hands the encrypted file back to the user, who keeps it wherever they already store things (local drive, their own cloud) and/or sends it through any channel. Because ciphertext is meaningless without the live token, it doesn't matter where or how many copies exist — revocation kills them all at once. The deliverable is the encrypted file; a hosted link is optional and points only at storage the *user* controls. (Decentralized storage like **Walrus** remains available as a *user's* optional choice for those who want it, but Yale neither operates nor requires any storage.)

**zkLogin — "one tap, no account, no password."** zkLogin lets a user transact from a Sui address derived from an ordinary OAuth login (Google, Apple, etc.) plus a private salt, using a zero-knowledge proof so the OAuth identity is never publicly linked to the address. This is how a recipient opens a file with one tap and no app or seed phrase — they sign in the way they already do, and a Sui identity materializes behind the scenes. It is itself a 2-factor scheme (recent OAuth credential + salt the provider never sees).

**The object & capability model — tokens as owned objects.** On Sui, everything is a typed object with an owner. The natural expression of a Yale "token" is a Move object (a *capability*) that encodes scope — recipient, device binding, expiry, max opens — and that the sender owns and can mutate or revoke. Capabilities are the idiomatic Sui pattern for "holding this object grants this right."

Put together: **Seal is the lock, the policy object is the key's rulebook, zkLogin is how a human walks up to the door — and the sealed file lives wherever the user keeps it, never with Yale.**

-----

## 3. Concept mapping — founding document → architecture

| Founding-doc concept | Sui-native implementation |
|---|---|
| The file | Encrypted with Seal client-side; the **encrypted file is the user's** to store/send. Yale stores nothing (ADR-6). |
| The token | A Move `AccessPolicy` object owned by the sender; defines who/which device/how long/how many |
| Delivery | The encrypted file travels through the user's channel (or sits in their own storage). An optional link carries a **policy object ID** (+ a pointer to user-owned storage), never a decryption key and never Yale-hosted bytes. |
| Recipient opens with one tap | zkLogin OAuth flow → ephemeral Sui identity → Seal key request |
| "Yale generates a token at upload" | `encrypt()` under a Seal identity namespaced to Yale's Move package + `mint_policy()` transaction |
| Device fingerprint as second factor | Fingerprint hash bound into the policy object on first authorized open; checked inside `seal_approve` |
| Access log "belongs to the sender" | Sui events emitted on every `seal_approve` evaluation + access attempt; optionally mirrored to Walrus for durable audit |
| Revoke "one tap, re-encrypts everywhere" | Sender transaction flips/destroys the policy → key servers stop approving → file can no longer be re-derived (see §6 for the honest version) |
| Watermark per view | Rendered client-side in Yale's viewer, keyed to the active policy + identity |
| "Encrypted at rest, meaningless without token" | Literally true — the Seal ciphertext sits in the user's own storage; no policy approval, no plaintext, no matter how many copies exist |
| "Yale never reads your files" | Yale's servers never hold plaintext or the threshold of keys; key servers are independent and t-of-n |

-----

## 4. Core architecture

### 4.1 Components

```
┌────────────┐     ┌─────────────────────────────────────────────┐
│  Sender    │     │                 SUI CHAIN                    │
│  (zkLogin) │     │  ┌─────────────┐   ┌──────────────────────┐ │
└─────┬──────┘     │  │ Yale Move   │   │  AccessPolicy objects │ │
      │            │  │  package    │   │  (the "tokens")        │ │
      │ upload     │  │ seal_approve│   │  + emitted Events      │ │
      ▼            │  └─────────────┘   └──────────────────────┘ │
┌────────────┐     └───────▲─────────────────────▲───────────────┘
│ Yale client│             │ policy check        │ mint / revoke
│ (encrypt)  │             │                     │
└─────┬──────┘     ┌───────┴───────┐     ┌───────┴────────┐
      │ ciphertext │  Seal key     │     │  Yale backend  │
      ▼            │  servers      │     │ (orchestration,│
┌────────────┐     │  (t-of-n)     │     │  notifications,│
│  WALRUS    │     │  release key  │     │  link service) │
│  blob store│     │  iff approve  │     └────────────────┘
└────────────┘     └───────────────┘
```

The Yale backend is deliberately thin. It mints/updates policies, sends notifications, and serves the viewer code — but it **never holds any file bytes** (plaintext or ciphertext) and never holds enough key material to decrypt anything (ADR-6). Encryption happens on the client; the encrypted file goes straight to the user's own storage or channel. Trust is pushed into the chain (policy) and the key-server set (threshold decryption); custody is pushed entirely to the user.

### 4.2 The Yale Move package

A single upgradeable Move package defines:

- `AccessPolicy` — the token object. Fields: `owner`, `recipient_id` (zkLogin-derived or allowlist), `bound_fingerprint: Option<vector<u8>>`, `expiry: u64`, `max_opens: u64`, `opens: u64`, `revoked: bool`, `blob_id`, `watermark_seed`.
- `seal_approve(id, policy, fingerprint, clock)` — the gate Seal key servers call. Returns success **only if** `!revoked` AND `now < expiry` AND `opens < max_opens` AND (`bound_fingerprint` is empty OR matches the presented fingerprint) AND caller identity matches `recipient_id`.
- `mint_policy(...)` — creates a token at upload.
- `bind_device(policy, fingerprint)` — on first authorized open, writes the fingerprint into the policy (trust-on-first-use).
- `revoke(policy)` / `revoke_all_for(recipient)` — sender-only; flips `revoked` and/or destroys the object. The "one action kills every token I issued to this person" promise is a loop over the sender's policies filtered by `recipient_id`.
- Events: `PolicyMinted`, `AccessGranted`, `AccessDenied`, `DeviceBound`, `Revoked`.

Because access logic lives in Move code anchored on Sui, the audit trail is on-chain and tamper-evident, which is stronger than scattered server logs — this is exactly the property Seal is designed to give.

### 4.3 Delivery — the encrypted file, link optional (ADR-6)

The deliverable is the **encrypted file itself**. The sender stores it and/or sends it through any channel; the recipient opens it in Yale's viewer/app, which decrypts locally only after `seal_approve` passes. Yale hosts none of it.

A share **link is optional** (off by default). When used, it carries the Sui `policy_id` (plus, if the user chose, a pointer to *their own* storage) — **never a decryption key, never Yale-hosted bytes**. Either way the principle holds: the ciphertext is "ungiftable" because forwarding it forwards a locked object, not a key — without passing `seal_approve` from an authorized identity and device, it stays opaque, and one revocation kills every copy wherever it sits.

-----

## 5. Sequence flows

### 5.1 Upload & mint (sender)

1. Sender signs in (zkLogin) and selects a file.
2. Client generates a symmetric content key, encrypts the file (body + filename + content-type), and wraps the content key with **Seal** under an identity namespaced to the Yale package (`[PkgId][policy_id]`).
3. The **encrypted file is returned to the sender** — saved to their own storage and/or sent through their chosen channel. Yale stores no bytes (ADR-6).
4. Transaction: `mint_policy(recipient, scope…)` → creates the `AccessPolicy` object, emits `PolicyMinted`.
5. Transient upload metadata is purged; for a private file, nothing is retained at all.

### 5.2 Authorized open (intended recipient)

1. Recipient receives the encrypted file (or an optional link) and opens it in Yale's viewer/app → zkLogin → ephemeral Sui identity. The ciphertext comes from the channel/storage it arrived through — never from Yale.
2. Viewer computes a **device fingerprint** (see §6.3) and requests decryption keys from the Seal key servers, presenting identity + fingerprint.
3. Each key server independently evaluates `seal_approve` against live chain state. First open: policy has no bound fingerprint → approve, then `bind_device` writes it (trust-on-first-use). Emits `AccessGranted` + `DeviceBound`.
4. ≥ t key servers release partial keys → client reconstructs the content key → decrypts → renders in viewer with watermark.
5. Plaintext lives only in the viewer's memory for the duration of the view; it is never written to disk by Yale.

### 5.3 Forward attempt (unauthorized device)

1. Someone else taps the forwarded link → different zkLogin identity and/or different fingerprint.
2. Key servers evaluate `seal_approve`: identity mismatch or fingerprint mismatch → **deny**. No keys released. Emits `AccessDenied` with the attempting fingerprint.
3. Yale backend turns that event into a real-time notification to the sender ("opened from an unrecognized device — revoke?").

### 5.4 Revoke (sender)

1. Sender taps revoke → transaction sets `revoked = true` (or destroys the policy object).
2. Every subsequent `seal_approve` for that policy returns failure. Key servers will never again release keys for that blob.
3. Because Yale's viewer re-derives keys from the key servers on each open and never persists plaintext, a revoked file cannot be re-opened on *any* device — including ones that opened it before. This is the architecturally-true version of "re-encrypts on every device." (See §6.1 for the precise honest framing.)

-----

## 6. Threat model & honest limitations

The founding document is admirably honest; the architecture must be too. Here is what this design genuinely delivers and where the hard edges are.

### 6.1 The "re-encrypt everywhere instantly" claim — precise version

What is literally true: after revocation, **no new decryption can occur** anywhere, because key servers stop approving and Yale's viewer holds no persistent key or plaintext. A device that is offline mid-view loses access the moment it needs to re-derive keys.

What is *not* literally true for anyone: bytes that a recipient already decrypted and exfiltrated *before* revocation cannot be reached back out into the world — no system can do that. Seal's own framing is exact: *"if the policy didn't approve, the data never decrypted."* It governs decryption, not memory that already exists. Yale's honest claim is therefore: **revocation makes the file permanently unopenable through Yale, on every device, immediately — and everything Yale ever showed was watermarked and logged.** Marketing should not promise retroactive un-seeing.

### 6.2 The camera-pointed-at-screen problem

Unchanged from the founding document and unsolvable in software. Mitigations are the same: in-viewer screenshot suppression on supported platforms, visible degradation of any external photo, and **per-view invisible watermarking** keyed to the active policy and identity so any leaked frame is traceable to the exact token. Yale makes casual capture hard and determined capture *traceable*, not impossible.

### 6.3 Device fingerprinting is a heuristic, not a cryptographic identity

Browser/device fingerprints can be spoofed or can drift (browser updates, network changes), causing both false accepts and false rejects. Design consequences: treat the fingerprint as a *second factor layered on top of zkLogin identity*, not the sole gate; allow the sender to set tolerance (strict device-bound vs. identity-bound); and on a near-miss, prefer "challenge + notify sender" over silent hard-fail. Where a platform offers hardware attestation (Passkeys / WebAuthn, Secure Enclave), prefer it over heuristic fingerprinting.

### 6.4 Key-server trust and liveness

Seal is t-of-n: you trust that no more than t−1 key servers collude and that at least t are live. Yale must choose a server set (including possibly running some itself or via partners), document the threshold, and accept that decryption availability depends on key-server liveness. This is strictly better than a single custodian but is not "trustless" — it is *distributed* trust. State this plainly.

### 6.5 Metadata — what's encrypted, what leaks, what to do

Metadata splits into three tiers, and the design must treat them differently.

**Tier 1 — inside the file (encrypted).** EXIF, GPS, document author/revision history, and everything embedded in the file's bytes are sealed inside the Walrus ciphertext. Nothing to do; it's covered by content encryption.

**Tier 2 — descriptive metadata (MUST be encrypted — this is a requirement, not an option).** The **filename, content-type/MIME, and any user-supplied label** are sensitive on their own — `layoffs-Q3.pdf` or `divorce-settlement.pdf` leaks the story even when the contents are sealed. These must NOT be stored as plaintext fields for dashboard convenience. Requirement: encrypt filename + content-type + labels into an encrypted metadata envelope alongside the blob; the dashboard decrypts them **client-side** for display. Yale's servers (Phase 1) and the chain (Phase 2+) never see them in clear. This is cheap and belongs in the MVP.

**Tier 3 — the token / governance record (opaque by default).** The on-chain token carries only an opaque policy ID, scope (expiry, max-opens, revoked), a fingerprint hash, a watermark seed, and the recipient as a **salted commitment**. By requirement it carries **no filename, no content-type, and no file size** — nothing content-inferable. **Every token is also a fixed, uniform length** — the record serializes to a constant size regardless of recipient or scope (every field is fixed-width by construction: 32-byte object ID, fixed-size hashes/commitments, small fixed-size scope integers; no variable-length field is ever included), so even the token's length is uninformative and all tokens look identical. Two further defaults, not opt-ins:
- **Salted commitments** for every human identifier, always — the chain never sees a raw email/address.
- **Size-class padding** on the ciphertext, always — the encrypted file is rounded to fixed buckets so its length reveals nothing about the real size. (A malicious actor holding the file learns neither name nor size.)

The one honest residual is **event timing**: the ledger shows that *some* opaque token was minted and opened at certain times. It carries no name, type, size, identity, or content, and the commitments keep it unlinkable to a person; batching blunts it further. For most users this is invisible; for the highest-threat personas it's the only remaining surface, flagged plainly (ADR-4) rather than denied.

### 6.6 Package upgradeability is a double-edged sword

An upgradeable Move package lets Yale evolve policy logic, but the package owner can change access rules for the namespace. That key must be governance-controlled (multisig / timelock), and the trust assumption disclosed, or sophisticated users will (rightly) not trust it.

-----

## 7. The second-brain / document-as-node model

The longer-term vision — every document is a node in an Obsidian-style graph — fits Sui's object model cleanly, because **on Sui a document is *already* an object.** The same `AccessPolicy`/blob pair that governs a shared file is also a node in a knowledge graph.

**Node = governed document object.** Each document is a Sui object carrying: its Walrus `blob_id` (content), its Seal identity (lock), its owner, metadata (title, tags, timestamps), and a set of typed edges. Sharing and knowledge-graph membership are the same underlying object viewed two ways — which is exactly the founding document's "two entry points into the same world" idea (Yale standalone vs. Octant-native).

**Edges = links between nodes.** Obsidian's `[[wikilinks]]` become typed references between document objects: `links_to`, `derived_from`, `cited_by`, `supersedes`. Because edges are on-chain object references, the graph is portable and verifiable, and governance composes: a policy can say "anyone who can open node A can open everything tagged `gold/*`" — Seal already ships allowlist/tag patterns that express exactly this.

**Inherited governance.** A node can inherit or override its neighbors' access policy. Share a parent node and you can optionally extend a scoped, revocable token to its linked children — the whole subgraph travels as governed content, and one revoke can seal a branch.

**Local-first, chain-anchored.** Obsidian's value is the local plaintext vault. The reconciliation: the *vault stays local and fast* (plaintext on the user's device, the working copy), while Yale anchors each note's **sealed ciphertext on Walrus and its governance object on Sui** for anything that is shared or needs an audit trail. Private notes never need leave the device; the moment a note is shared, it becomes a Yale-governed node. This keeps the editing experience local-first while making *sharing* the governed, revocable act.

**Octant tie-in.** In Octant OS, document creation mints the node by default — every document is a Yale-governed node from birth. Standalone Yale mints the node lazily, at first share. Same object schema, two entry points.

-----

## 8. MVP → mainnet roadmap

The mistake would be to start by writing Move contracts. Start by proving the *experience* and the *trust model* with the least crypto that still tells the truth, then push trust into the chain phase by phase.

**Phase 0 — Experience prototype (done).** The clickable HTML prototype simulates the full loop. No crypto. Purpose: validate UX and the demo narrative.

**Phase 1 — Centralized-but-honest MVP.** Real encryption, centralized key custody. Files encrypted client-side; content keys held by a Yale key service; access policy enforced by Yale's backend; zkLogin (via Enoki) for passwordless recipient open; real device fingerprinting; real watermarking; access log in a normal database. Revocation = backend stops releasing keys. This ships fast and is genuinely useful — but Yale is the trusted party. Be explicit about that in-product. *Deliverable: working web app, single key custodian, no chain.*

**Phase 2 — Sui testnet: policy on-chain.** Move the `AccessPolicy` object and `seal_approve` logic onto Sui testnet. Mint/revoke become transactions; access events become on-chain events. Storage moves to Walrus (testnet). Keys still semi-centralized while integrating the Seal SDK. *Deliverable: tokens and audit trail are on-chain and tamper-evident; Yale no longer the sole logger.*

**Phase 3 — Seal threshold keys on mainnet.** Replace custodied keys with Seal's t-of-n key servers. Now Yale cannot unilaterally decrypt anything. Walrus mainnet for storage. Governance-controlled package upgrades (multisig/timelock). *Deliverable: the founding document's trust claim becomes architecturally real — "you don't have to trust Yale."*

**Phase 4 — Second-brain graph.** Document-as-node schema, typed edges, subgraph-scoped governance, local-first vault sync, Octant-native minting. *Deliverable: the knowledge-graph vision on top of the governed-sharing core.*

-----

## 9. Resolved decisions

These five were the load-bearing open questions; they are now decided. Full rationale and revisit triggers live in `decisions.md` (ADR-1 … ADR-5). Summary:

1. **Key-server set (ADR-1)** — independence-weighted mix. Yale runs at most one or two Seal key servers; `t` is set so Yale alone can *never* decrypt. Mysten-hosted servers are acceptable in Phase 2 for speed; the independent mix must be live before the trust claim is marketed.
2. **Recipient identity (ADR-2)** — bearer-by-default, lockable to identity. Default to trust-on-first-use device binding (short window, sender notified on claim); senders can flip on strict zkLogin identity binding for high-stakes sends. This is the spine of §3–§5 and is the first thing to lock in code.
3. **Device recognition (ADR-3)** — attestation-first (WebAuthn/Passkeys), heuristic fingerprint as fallback, never the sole gate; near-miss → challenge + notify, not hard-fail.
4. **Whistleblower mode (ADR-4)** — not built in Phase 1, but Phase 1 is designed compatible: no raw human identifiers on-chain (salted commitments only), size-padding kept as a switchable flag. Full mode ships Phase 3+.
5. **Audit logs (ADR-5)** — on-chain events as tamper-evident source of truth, fast off-chain index for the UI, durable Walrus archival as a paid enterprise tier.
6. **Zero file custody (ADR-6)** — Yale stores no files; stateless pipe; opaque, fixed-length, user-owned token.
7. **Anti-ransomware line (ADR-7)** — the invariant is *owner key recovery* (always, device-independent), not "don't encrypt in place." In-place/bulk "Lockdown mode" is allowed and safe *because* the owner can always recover. See §12.2.

**Gating order:** lock ADR-2 in code first (all flow logic depends on it); commit ADR-1's configuration before marketing the trust claim. ADR-3/4/5 layer on top.

-----

## 10. One-paragraph summary

Yale is a governed-sharing layer where the file is Seal-encrypted on the client and **kept by the user wherever they like — Yale stores nothing (ADR-6)**, the "token" is a Move `AccessPolicy` object on Sui, the encrypted file (or an optional link carrying only public pointers, never a key) travels through any channel, recipients open passwordlessly via zkLogin, every access is an on-chain event the sender owns, and revocation is a sender transaction that stops the threshold key servers from ever approving decryption again — killing every copy of the ciphertext at once, no matter where it sits. It delivers the founding document's promise precisely — *casual misuse impossible, determined misuse traceable, the file never leaves your control* — and it is honest about the two things no software can do: stop a camera pointed at a screen, and un-see bytes already decrypted before you revoked. The build path starts centralized-but-honest and pushes trust onto the chain in stages until "you don't have to trust Yale" is literally true.

-----

## 11. Two delivery modes — web link vs in-app-only

Every send chooses a delivery mode. Both ride the *same* governed token, encryption, and revocation described above — what differs is **the viewer environment**, and therefore how much capture Yale can actually control. This is a control-vs-reach dial, and it has real engineering consequences worth stating before building.

### 11.1 Cross-channel link (web viewer)

The link travels via any channel and opens in Yale's **web viewer** in the recipient's browser. Maximum reach, zero install, no account in bearer mode.

The hard truth about browsers: **a web page cannot block a screenshot.** There is no web API to prevent the OS-level screenshot or screen-recording of a tab. So in this mode capture control is *best-effort*: the invisible per-view watermark always applies (traceability), DevTools/right-click/print are discouraged, and on a few platforms `getDisplayMedia`-based recording can be detected — but a plain OS screenshot cannot be stopped. We should never imply otherwise in-product. The governance that *is* real here remains real: revocation, device-binding, expiry, and the access log all work fully.

### 11.2 In-app-only view (native app)

The document can be opened **only inside the Yale native mobile app**. This is the mode that earns the "we control screenshots" claim — but only because native OS APIs exist that browsers lack:

- **Android** — `FLAG_SECURE` on the window genuinely prevents screenshots and screen recording and blanks the app in the recents switcher. This is a hard block.
- **iOS** — there is no API to *prevent* a still screenshot, but the app can **detect** it (`userDidTakeScreenshot`) and react (log it to the access trail, notify the sender, watermark more aggressively), and can **block screen recording** by detecting `isCaptured` and blanking the protected view. Sensitive content can also be rendered in a secure layer that does not appear in captures.

The cost is friction and reach: the recipient must install and open the Yale app, and you can only send in-app-only to people willing to do that. So this mode is for the highest-sensitivity sends, not the default.

**Engineering consequence — flag this clearly:** in-app-only mode means Yale commits to **building and maintaining native iOS and Android apps**, not just a web viewer. That is a materially larger surface (app-store review, OS-version drift, native crypto/Seal integration on device). It belongs in a later phase than the web MVP. The web link mode ships first; in-app-only is the premium, higher-control follow-on.

### 11.3b Mutual-app mode — both parties on the app (strongest tier)

There is a third, strongest configuration above the two above: **both sender and recipient are on the Yale app.** When both endpoints are Yale-controlled, the protection is no longer one-sided:

- **True end-to-end.** The content key can be wrapped directly to the recipient's device identity (or, on-chain, sealed so only their device passes `seal_approve`). Plaintext exists only inside two trusted app sandboxes — never a browser, never a generic viewer.
- **Capture control on both ends.** Screenshot/screen-record blocking (Android `FLAG_SECURE`, iOS detection) applies to the recipient *and* any in-app preview the sender sees. Neither side leaks through a browser.
- **Stronger revocation and presence.** Both apps maintain a live session with the key layer, so revocation propagates to an open view in real time, and the sender gets richer signals (app foreground/background, capture attempts).
- **The cost is mutual friction:** it only works between two people who both have the app — so it's the mode for ongoing, high-trust, high-sensitivity relationships (a founder ↔ counsel, an artist ↔ label, two parties to a deal), not for sending to a stranger.

Think of it as a tier ladder: **cross-channel link** (anyone, web, best-effort) → **in-app-only** (recipient on app, real capture control) → **mutual-app** (both on app, true E2E + two-sided control). Each step trades reach for control.

### 11.3 The shared, honest ceiling

Neither mode — not even Android `FLAG_SECURE` — can stop **a second phone photographing the screen.** That is unsolvable in any software. In both modes the answer is the same as the founding document's: the capture is visibly degraded, and the invisible watermark identifies exactly whose token was active. Casual capture is blocked (fully in-app, partially on web); determined physical capture is made *traceable*, never impossible.

| | Cross-channel link (web) | In-app-only (native) | Mutual-app (both on app) |
|---|---|---|---|
| Reach | Anyone, any channel, no install | Only Yale-app users | Both parties must have the app |
| Token / revoke / expiry / log | Full | Full | Full + live session |
| Encryption | Sealed, web-viewer decrypt | Sealed, in-app decrypt | True E2E, device-to-device |
| Screenshot block | Not possible (web limitation) | Android: hard block · iOS: detect + react | Both ends blocked |
| Screen-record block | Best-effort detection | Yes (both platforms) | Yes, both ends |
| Camera-at-screen | Not preventable (watermark traces it) | Not preventable (watermark traces it) | Not preventable (watermark traces it) |
| Build cost | Web viewer (MVP) | Native iOS + Android (later phase) | Native apps + E2E key exchange (later phase) |

-----

## 12. Distribution, antivirus & abuse-prevention

Two distinct risks for an encryption client: being *misflagged* as malware, and being *misused* as malware. Both are designed against.

### 12.1 Not being flagged by antivirus

Encrypted data is high-entropy and resembles packed malware to AV heuristics; the mitigations differ by surface.

**The encrypted files.** Keep `.yale` a **pure, inert data file** — never executable, no scripts/macros, nothing runnable (this alone avoids most flags, since AV is lenient with data vs. code). Give it a **fixed magic-number header** and build on a recognized encryption-envelope standard (JWE / COSE / PKCS#7-style) so scanners read it as a *known encrypted-document format*, not an unknown obfuscated blob. **Register the extension + MIME type** and submit samples to the major AV vendors' false-positive / allowlist programs. Cloud reputation (SmartScreen et al.) rewards documented, signed, prevalent formats over time.

**The app / viewer / installer** (where most real flags occur). **Code-sign and notarize everything** — Windows Authenticode (an EV cert earns near-instant SmartScreen reputation), Apple notarization, signed Android builds. **Never pack or obfuscate** the binary (packers are a top false-positive trigger). **Behave cleanly** — no process injection, no hooking, minimal permissions. Where possible prefer the **web viewer** so nothing installs on the recipient's machine and endpoint AV never engages.

**Deliverability.** Some mail gateways block encrypted attachments they can't scan; sending through the user's own channel or linking to the user's own storage with a web-viewer open sidesteps that.

### 12.2 Not being usable as ransomware (ADR-7)

The line between Yale and ransomware is **owner recoverability**, not "don't encrypt in place." Ransomware needs the owner to *lose* the key; Yale makes that impossible. In-place and bulk encryption are *permitted* (required for the legitimate Lockdown use case); producing ciphertext the owner can't recover is what's forbidden.

The absolute invariant: **the legitimate owner can always recover the key and decrypt, independently of the encrypting/seized device** (key bound to their zkLogin identity, recoverable from any device — never retrievable only from the machine that encrypted). Supporting invariants: identity-bound + auditable; **no silent/headless trigger** (bulk/in-place requires strong interactive auth + explicit confirmation, rate-limited and anomaly-monitored); revocation scoped only to what the owner shared.

**Encryption-by-default + scoped disclosure** — the posture is *proactive policy*, not reactive: encrypt all sensitive data at rest as standing corporate policy (like full-disk encryption), so a seizure is a non-event yielding ciphertext as normal hygiene. Authorized staff open frictionlessly via zkLogin; the same machinery covers offboarding and lost/compromised devices. For lawful disclosure: grant a **scoped, time-limited, view-only** token whose lifetime equals the legal authorization window — it expires by the terms of the grant (not an after-the-fact clawback), and because it's view-only, every governed copy goes inert when the window ends, defeating the malicious-insider-keeps-a-copy threat. Nothing is destroyed; everything stays recoverable (clear of preservation/legal-hold). Honest boundary: plaintext lawfully *exported* during the window is beyond reach (so disclose view-only), and a matter that proceeds to prosecution may leave a persistent court record — counsel territory. Enterprise recovery uses org-level multi-admin / Shamir-split keys (extends ADR-8); Yale still holds nothing.

Two honest tensions: (1) this *will* trip behavioral AV (Controlled Folder Access, EDR) that is built to stop in-place bulk encryptors — needs signing, explicit OS consent, vendor allowlisting; (2) it is legally sensitive and jurisdiction-dependent — frame as preserve-everything + due-process-scoped disclosure, and get real legal counsel (not legal advice here). See ADR-7 for the full treatment.

-----

### Sources

- [Seal — Mysten Labs](https://seal.mystenlabs.com/) · [How it works](https://seal.mystenlabs.com/how-it-works) · [Seal docs](https://seal-docs.wal.app/)
- [Seal: Programmable Access Control for Real-World Apps — Sui Blog](https://blog.sui.io/seal-programmable-access-control/)
- [Seal Mainnet Launch — Mysten Labs](https://www.mystenlabs.com/blog/seal-mainnet-launch-privacy-access-control)
- [Announcing Walrus — Mysten Labs](https://www.mystenlabs.com/blog/announcing-walrus-a-decentralized-storage-and-data-availability-protocol) · [How Walrus blob storage works](https://blog.walrus.xyz/how-walrus-blob-storage-works/) · [Walrus docs](https://docs.wal.app/)
- [Data Storage Using Walrus — Sui Docs](https://docs.sui.io/sui-stack/walrus/sui-stack-walrus)
- [What is zkLogin? — Sui Docs](https://docs.sui.io/concepts/cryptography/zklogin) · [zkLogin — Sui](https://www.sui.io/zklogin)
