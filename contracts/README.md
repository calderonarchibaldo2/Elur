# Yale — on-chain access layer (Sui Move)

The **token** from the architecture: an `AccessPolicy` object that governs whether Seal's key servers may release a file's content key. The file is never on-chain (ADR-6) — only this opaque rulebook.

## What's here
- `sources/access.move` — the `AccessPolicy` shared object, `OwnerCap`, the read-only `seal_approve` gate, and the mutate/revoke/reinstate/destroy surface.
- `Move.toml` — package manifest (Sui framework dependency).

## Map to the design
- **Encrypt once, govern forever (ADR-10):** the file's content key is wrapped once; access changes only by editing this object (`update_scope`, `add_recipient`, `revoke`, `reinstate`, `destroy`). The ciphertext never moves.
- **The gate is read-only (Seal constraint):** `seal_approve` can only *read* chain state, so open-counting (`record_open`) and first-open device binding (`bind_device`) are separate transactions; the gate reads the resulting state.
- **Revoke = reversible suspension (ADR-7); destroy = terminal crypto-shred (ADR-9).**
- **Owner recoverability (ADR-7)** is enforced *off-chain* via dual-wrap (owner copy under the master key); this module only gates *recipients*.

## Build & deploy (needs the Sui toolchain — not run in this repo)
```bash
sui move build                 # compile + type-check against the Sui framework
sui move test                  # (add tests under tests/)
sui client publish --gas-budget 100000000   # deploy to the active network (testnet first)
```
Install the toolchain: https://docs.sui.io/guides/developer/getting-started/sui-install

## Seams to validate before mainnet (honest list)
1. **zkLogin identity ↔ `seal_approve` binding (open question #1).** This v0 allow-lists raw recipient *addresses* and checks `ctx.sender()`. For privacy you'd switch to **salted commitments + a proof**, and confirm exactly how a recipient's zkLogin identity is presented to the key servers. This is the #1 thing to get right.
2. **Seal key-server set / threshold (ADR-1)** — choose the `t`-of-`n` server set; not encoded in this module.
3. **Device fingerprint** can't be verified on-chain; binding lives at the client/key-server layer. `bind_device` only records the hash for the audit trail.
4. **Gas / object model** — `AccessPolicy` is a shared object (so key servers can read it); confirm shared-object contention is acceptable at scale, or shard.
5. **Unit tests** — add `#[test]` coverage for revoked/expired/max-opens/allowlist/destroy before trusting it.

Status: written to current Sui Move (2024) conventions; **needs `sui move build` to compile and a testnet deploy to exercise.** Not yet compiled or deployed.
