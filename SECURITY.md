# Security & threat model

Elur is a security product, so we treat its threat model as a first-class part of the repo. This
document states what the system guarantees, where it stops, the weak spots we already know about, and
our planned path to hardening each one before any mainnet or real-client deployment. We'd rather hand
reviewers the soft spots than have them find them.

> Status: **testnet / hackathon build.** Several settings below are deliberately tuned for
> buildability on testnet, not for production security. No real clients until an independent audit.

---

## What actually enforces access

Access is enforced by a single read-only Move function — **`seal_approve`** in
[`contracts/sources/access.move`](contracts/sources/access.move). Seal's key servers dry-run it before
releasing a file's content key; if it aborts (revoked, expired, open-limit reached, or the caller is
not allow-listed), **no key is released and the file cannot be decrypted.** Change the on-chain policy
→ future opens stop.

Everything else — per-view watermarks, view-only mode, device-binding — is a **client-side deterrent
and attribution aid, never the gate.** We are careful never to describe them as cryptographic
guarantees.

---

## Known limitations (the parts to scrutinize)

1. **Seal threshold is `1`-of-`2` with `verifyKeyServers: false`.** Testnet buildability, not security.
   With threshold 1, a single malicious/compromised key server could release a key against the policy.
2. **The allowlist stores raw zkLogin addresses** on a public chain, so an observer can see *who* was
   granted. The contract itself flags this as open question #1.
3. **`bind_device` and open-counting are off-chain / best-effort.** `seal_approve` is read-only, so it
   can't inspect a device fingerprint or atomically increment a counter; `max_opens` is therefore
   best-effort, device-binding is client/relayer-enforced.
4. **Bearer mode is an open capability — the gate does not restrict it to one opener or device.** With
   an empty allowlist, `seal_approve` returns success for *any* caller (subject only to
   revoked / expired / max-opens). `bind_device` writes a `bound_fingerprint`, but **`seal_approve`
   never reads it** — so device-binding for bearer files is a client-side honor-system hint, not
   enforced on-chain. In effect: anyone holding the ciphertext can open a bearer file. Use **identity
   mode** for anything that must be restricted to specific recipients.
5. **The gas sponsor (Enoki + our backend) is a liveness dependency, not a security one** — it can only
   sponsor our package, so it can't forge access or be drained.
6. **The package `UpgradeCap` is the most powerful key in the system.** Whoever holds it can upgrade the
   code that *is* the gate — on mainnet, an unmanaged or compromised cap is effectively a full backdoor.
   On testnet it sits on a single deploy key.
7. **Vestigial state:** the policy carried a `watermark_seed` field that nothing reads (the watermark is
   rendered client-side, keyed to identity). It implied an enforcement link that doesn't exist.
8. We trust **Sui consensus** for policy state and **Walrus** for blob availability (storage is paid in
   epochs; blob expiry is an availability concern, separate from access).

---

## Planned hardening before mainnet

Each known limitation has an owner and a fix. Priority order:

1. **Raise the Seal threshold to t-of-n (t > 1) and `verifyKeyServers: true`,** running independent key
   servers. *(Addresses #1 — our top item.)*
2. **Freeze the gate: make `seal_approve` immutable.** The power to upgrade `seal_approve` is the power
   to retroactively break access for every sealed file, so before mainnet we will isolate the gate
   (`seal_approve` + the `AccessPolicy` it reads) in its own minimal package and call
   `package::make_immutable` on it — **after** a real mainnet bake-in window with a bug bounty, on a
   committed public date. Operational, `OwnerCap`-gated calls (mint, scope edits, `record_open`) can
   stay upgradeable. An immutable gate is necessary but not sufficient, so it ships **together with**
   the t-of-n key-server fix above. *(Addresses #1 + #6.)*
3. **Govern the `UpgradeCap` in the interim:** hold it in a multisig of independent keyholders, tighten
   the upgrade policy to additive-only (`package::only_additive_upgrades`), and add a public timelock so
   any upgrade is announced before it can take effect. *(Addresses #6.)*
4. **Replace raw allowlist addresses with salted commitments + a proof,** so the chain no longer reveals
   who was granted. *(Addresses #2.)*
5. **Remove the dead `watermark_seed` field** from `AccessPolicy` and `mint`/`mint_policy`. Done in our
   working source; lands at the next package publish (a dropped struct field requires a fresh package,
   not an in-place upgrade), bundled with the client mint-call change. *(Addresses #7.)*
6. **Make bearer mode honest, or remove it.** Either relabel it as an explicit *open link* and drop the
   unenforced `bind_device` / `bound_fingerprint` (same dead-state class as the watermark seed), relying
   on max-opens + watermark + revocation as best-effort controls; or, if true first-opener / device
   restriction is required, implement it via a relayer that promotes the first opener into the allowlist
   (identity mode) on first open — a trusted component with a documented race window. For sensitive
   sharing, prefer **identity mode**, which the gate *does* enforce. *(Addresses #3, #4.)*

---

## What revocation does and doesn't guarantee

**Guarantees:** after revoke / expiry / max-opens / destroy, the key servers will not release the
content key again — no *new* decryption is possible, for a person or an agent — and the plaintext never
traverses our infrastructure.

**Does not guarantee:** that a reader who *already decrypted* a file while authorized can't keep that
copy. Revocation cuts **future** access, not the past. View-only mode, watermarks, and device-binding
are deterrents and attribution, not cryptographic guarantees.

---

## Reporting

Found something? Please open an issue or contact the maintainer privately before public disclosure.
We genuinely want to be told where this is wrong.
