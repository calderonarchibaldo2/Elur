/// Yale — on-chain access layer.
///
/// This module is the "token" from the architecture: an `AccessPolicy` object that
/// governs whether Seal's key servers may release a file's content key. The file
/// itself is NEVER on-chain (ADR-6, zero custody) — only this opaque rulebook is.
///
/// Design anchors:
///  - ADR-10  Encrypt once, govern forever: one mutable token per file. The
///            ciphertext never changes; access changes by editing this object.
///  - ADR-7   Owner recoverability: enforced off-chain via dual-wrap (owner copy
///            under the owner's master key). On-chain we only gate *recipients*.
///  - ADR-9   Crypto-shred: `destroy` permanently denies key release (terminal).
///  - Opaque/fixed: this object carries no filename, type, or size.
///
/// IMPORTANT Seal constraint: `seal_approve*` is evaluated read-only by the key
/// servers (side-effect free). So open-counting and first-open device binding can
/// NOT happen inside the gate — they are separate transactions (`record_open`,
/// `bind_device`) and the gate only *reads* the resulting state.
module yale::access;

use sui::clock::Clock;
use sui::event;

// ---- modes ----
const MODE_BEARER: u8 = 0;   // first authorized open claims it (device bound off-chain)
const MODE_IDENTITY: u8 = 1; // only allow-listed identities (zkLogin addresses) may open

// ---- error codes ----
const EWrongPolicy: u64 = 0;      // requested id doesn't belong to this policy
const ERevoked: u64 = 1;          // suspended or destroyed
const EExpired: u64 = 2;          // past expiry
const EMaxOpens: u64 = 3;         // open limit reached
const ENoAccess: u64 = 4;         // caller not authorized
const ENotThisPolicy: u64 = 5;    // OwnerCap doesn't match this policy
const EBadMode: u64 = 6;          // mode must be bearer or identity

/// The token. A shared object so Seal key servers can read it during `seal_approve`.
/// Mutations require the matching `OwnerCap`.
public struct AccessPolicy has key {
    id: UID,
    owner: address,
    mode: u8,
    /// Allow-listed recipient identities (zkLogin-derived addresses) for identity mode.
    /// NOTE (open question #1): for privacy these should be salted commitments + a
    /// proof rather than raw addresses; raw addresses used here for a buildable v0.
    allowlist: vector<address>,
    /// Device fingerprint hash bound on first authorized open (bearer mode). Empty until bound.
    bound_fingerprint: vector<u8>,
    expiry_ms: u64,   // 0 = never
    max_opens: u64,   // 0 = unlimited
    opens: u64,
    revoked: bool,    // reversible suspension (ADR-7) — reinstatable
    destroyed: bool,  // terminal crypto-shred marker (ADR-9)
    watermark_seed: vector<u8>,
    created_ms: u64,
}

/// Holds the right to mutate one policy. Held by the owner; never on-chain-public.
public struct OwnerCap has key, store {
    id: UID,
    policy: ID,
}

// ---- events (the sender-owned audit trail) ----
public struct PolicyMinted has copy, drop { policy: ID, owner: address, mode: u8 }
public struct ScopeUpdated has copy, drop { policy: ID }
public struct DeviceBound  has copy, drop { policy: ID }
public struct AccessGranted has copy, drop { policy: ID, who: address, opens: u64 }
public struct Revoked   has copy, drop { policy: ID }
public struct Reinstated has copy, drop { policy: ID }
public struct Destroyed  has copy, drop { policy: ID }

// =====================================================================
// THE GATE — read-only. Seal key servers dry-run this; success releases the key.
// =====================================================================

/// `id` is the requested Seal identity minus the package prefix; it must equal this
/// policy's object id. Aborts (no return) if access is denied.
entry fun seal_approve(id: vector<u8>, policy: &AccessPolicy, clock: &Clock, ctx: &TxContext) {
    assert!(id == policy.id.to_bytes(), EWrongPolicy);
    assert!(!policy.revoked && !policy.destroyed, ERevoked);
    let now = clock.timestamp_ms();
    assert!(policy.expiry_ms == 0 || now < policy.expiry_ms, EExpired);
    assert!(policy.max_opens == 0 || policy.opens < policy.max_opens, EMaxOpens);

    let s = ctx.sender();
    let is_owner = s == policy.owner;
    let is_listed = policy.allowlist.contains(&s);
    // Identity mode: must be owner or allow-listed.
    // Bearer mode with an empty allowlist: trust-on-first-use (first opener may decrypt);
    //   the single-device binding is enforced off-chain via `bind_device` + the viewer,
    //   since the gate cannot inspect a device fingerprint on-chain.
    let bearer_open = policy.mode == MODE_BEARER && policy.allowlist.is_empty();
    assert!(is_owner || is_listed || bearer_open, ENoAccess);
}

// =====================================================================
// MINT
// =====================================================================

/// Create a policy (shared) and return its OwnerCap. Off-chain, the client Seal-wraps
/// the file's content key to this policy's id (and keeps the owner copy under the MK).
public fun mint_policy(
    mode: u8, expiry_ms: u64, max_opens: u64, watermark_seed: vector<u8>,
    clock: &Clock, ctx: &mut TxContext,
): OwnerCap {
    assert!(mode == MODE_BEARER || mode == MODE_IDENTITY, EBadMode);
    let policy = AccessPolicy {
        id: object::new(ctx), owner: ctx.sender(), mode,
        allowlist: vector[], bound_fingerprint: vector[],
        expiry_ms, max_opens, opens: 0, revoked: false, destroyed: false,
        watermark_seed, created_ms: clock.timestamp_ms(),
    };
    let pid = object::id(&policy);
    event::emit(PolicyMinted { policy: pid, owner: ctx.sender(), mode });
    let cap = OwnerCap { id: object::new(ctx), policy: pid };
    transfer::share_object(policy);
    cap
}

/// Convenience entry: mint and send the cap to the sender.
entry fun mint(mode: u8, expiry_ms: u64, max_opens: u64, watermark_seed: vector<u8>, clock: &Clock, ctx: &mut TxContext) {
    let cap = mint_policy(mode, expiry_ms, max_opens, watermark_seed, clock, ctx);
    transfer::public_transfer(cap, ctx.sender());
}

// =====================================================================
// MUTATE — the "govern forever" surface (owner only, via cap)
// =====================================================================

fun assert_cap(cap: &OwnerCap, policy: &AccessPolicy) {
    assert!(cap.policy == object::id(policy), ENotThisPolicy);
}

/// Edit scope at any time (ADR-10). Same file, new rules.
entry fun update_scope(cap: &OwnerCap, policy: &mut AccessPolicy, mode: u8, expiry_ms: u64, max_opens: u64) {
    assert_cap(cap, policy);
    assert!(mode == MODE_BEARER || mode == MODE_IDENTITY, EBadMode);
    policy.mode = mode; policy.expiry_ms = expiry_ms; policy.max_opens = max_opens;
    event::emit(ScopeUpdated { policy: object::id(policy) });
}

entry fun add_recipient(cap: &OwnerCap, policy: &mut AccessPolicy, who: address) {
    assert_cap(cap, policy);
    if (!policy.allowlist.contains(&who)) policy.allowlist.push_back(who);
    event::emit(ScopeUpdated { policy: object::id(policy) });
}

entry fun remove_recipient(cap: &OwnerCap, policy: &mut AccessPolicy, who: address) {
    assert_cap(cap, policy);
    let (found, i) = policy.allowlist.index_of(&who);
    if (found) { policy.allowlist.remove(i); };
    event::emit(ScopeUpdated { policy: object::id(policy) });
}

/// Bind the device fingerprint on first authorized open (bearer). Separate tx because
/// the gate is read-only. Set once (trust-on-first-use).
entry fun bind_device(cap: &OwnerCap, policy: &mut AccessPolicy, fingerprint: vector<u8>) {
    assert_cap(cap, policy);
    if (policy.bound_fingerprint.is_empty()) {
        policy.bound_fingerprint = fingerprint;
        event::emit(DeviceBound { policy: object::id(policy) });
    }
}

/// Record an open (for max_opens accounting + the audit trail). Separate tx; the gate
/// only reads `opens`.
entry fun record_open(policy: &mut AccessPolicy, ctx: &TxContext) {
    policy.opens = policy.opens + 1;
    event::emit(AccessGranted { policy: object::id(policy), who: ctx.sender(), opens: policy.opens });
}

// =====================================================================
// REVOKE / REINSTATE / DESTROY
// =====================================================================

/// Reversible suspension. Future `seal_approve` fails; data is NOT deleted (ADR-7).
entry fun revoke(cap: &OwnerCap, policy: &mut AccessPolicy) {
    assert_cap(cap, policy);
    policy.revoked = true;
    event::emit(Revoked { policy: object::id(policy) });
}

/// Undo a suspension — proves non-destruction (the data was only sealed, never lost).
entry fun reinstate(cap: &OwnerCap, policy: &mut AccessPolicy) {
    assert_cap(cap, policy);
    assert!(!policy.destroyed, ERevoked); // a destroyed token can never come back
    policy.revoked = false;
    event::emit(Reinstated { policy: object::id(policy) });
}

/// Crypto-shred (ADR-9): terminal. On-chain this permanently denies key release; the
/// content key / Seal share is what's actually destroyed off-chain. The two-step +
/// step-up-auth ceremony (ADR-9) is enforced in the client before this tx is signed.
entry fun destroy(cap: &OwnerCap, policy: &mut AccessPolicy) {
    assert_cap(cap, policy);
    policy.destroyed = true;
    policy.revoked = true;
    event::emit(Destroyed { policy: object::id(policy) });
}

// ---- read-only getters (handy for the client/dashboard) ----
public fun is_active(p: &AccessPolicy, now_ms: u64): bool {
    !p.revoked && !p.destroyed && (p.expiry_ms == 0 || now_ms < p.expiry_ms) && (p.max_opens == 0 || p.opens < p.max_opens)
}
public fun opens(p: &AccessPolicy): u64 { p.opens }
public fun owner(p: &AccessPolicy): address { p.owner }
