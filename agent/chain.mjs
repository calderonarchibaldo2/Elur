// Elur agent — Sui + Seal layer.
// Mirrors the proven macOS app exactly (same SDK versions, same Seal config, same
// package id for the Seal namespace) so behaviour matches what already works.
//
// Governance model (same as the app's bearer shares):
//   - mint a BEARER-mode AccessPolicy (the agent holds the OwnerCap → can revoke)
//   - Seal-wrap the content key to that policy
//   - recall = pass seal_approve (bearer_open) → key servers release the key
//   - revoke = flip the policy → seal_approve aborts on the `revoked` check first →
//     key servers refuse → the agent can still FETCH the blob but cannot decrypt it.

import { readFileSync } from "node:fs";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";

// Seal identity namespace = original-id (constant across the v2 upgrade), exactly
// as the app uses it. mint/revoke also run here (logic unchanged in v2).
export const PACKAGE_ID = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
const MODULE = "access";
const CLOCK = "0x6";
const SERVER_CONFIGS = [
  { objectId: "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98", weight: 1, aggregatorUrl: "https://seal-aggregator-testnet.mystenlabs.com" },
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
];

export const suiClient = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl("testnet"), network: "testnet" });

// Agent identity — loaded from the gitignored key file the user exported.
const keyFile = JSON.parse(readFileSync(new URL("./.agent-key.json", import.meta.url), "utf8"));
export const keypair = Ed25519Keypair.fromSecretKey(keyFile.exportedPrivateKey);
export const AGENT_ADDRESS = keypair.toSuiAddress();

const seal = () => new SealClient({ suiClient, serverConfigs: SERVER_CONFIGS, verifyKeyServers: false });

// Mint a bearer-mode policy; the agent receives the OwnerCap (revoke power).
export async function mintPolicy({ expiryMs = 0, maxOpens = 0 } = {}) {
  const tx = new Transaction();
  tx.moveCall({
    target: `${PACKAGE_ID}::${MODULE}::mint`,
    arguments: [tx.pure.u8(0), tx.pure.u64(expiryMs), tx.pure.u64(maxOpens), tx.pure.vector("u8", [1]), tx.object(CLOCK)],
  });
  const res = await suiClient.signAndExecuteTransaction({ signer: keypair, transaction: tx, options: { showObjectChanges: true } });
  await suiClient.waitForTransaction({ digest: res.digest });
  const oc = res.objectChanges || [];
  const policyId = oc.find((c) => c.objectType?.includes("::access::AccessPolicy"))?.objectId;
  const capId = oc.find((c) => c.objectType?.includes("::access::OwnerCap"))?.objectId;
  if (!policyId || !capId) throw new Error("mint: could not find policy/cap in object changes");
  return { policyId, capId, digest: res.digest };
}

// Revoke (reversible seal) — the governance action that makes the agent forget.
export async function revokePolicy(capId, policyId) {
  const tx = new Transaction();
  tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::revoke`, arguments: [tx.object(capId), tx.object(policyId)] });
  const res = await suiClient.signAndExecuteTransaction({ signer: keypair, transaction: tx, options: { showEffects: true } });
  await suiClient.waitForTransaction({ digest: res.digest });
  return res.digest;
}

// Seal-wrap a 32-byte content key to a policy id. Returns the encrypted object bytes.
export async function sealWrap(policyId, ck) {
  const { encryptedObject } = await seal().encrypt({ threshold: 1, packageId: PACKAGE_ID, id: policyId, data: ck });
  return encryptedObject; // Uint8Array
}

// Fast, cheap on-chain status read (no Seal round-trip) — mirrors the contract's
// `is_active`. Used to show memory badges and to skip recalling sealed memories.
export async function isPolicyActive(policyId) {
  try {
    const o = await suiClient.getObject({ id: policyId, options: { showContent: true } });
    const f = o?.data?.content?.fields;
    if (!f) return false;
    if (f.revoked || f.destroyed) return false;
    const now = Date.now();
    if (Number(f.expiry_ms) !== 0 && now >= Number(f.expiry_ms)) return false;
    if (Number(f.max_opens) !== 0 && Number(f.opens) >= Number(f.max_opens)) return false;
    return true;
  } catch { return false; }
}

// Seal-unwrap: asks the key servers for the key, which they release only if
// seal_approve passes. Throws if the policy is revoked/expired/denied.
export async function sealUnwrap(policyId, encryptedObject) {
  const ephemeral = new Ed25519Keypair(); // fresh session identity, as in the app
  const sessionKey = await SessionKey.create({ address: ephemeral.toSuiAddress(), packageId: PACKAGE_ID, ttlMin: 10, signer: ephemeral, suiClient });
  const tx = new Transaction();
  tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
  const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
  return await seal().decrypt({ data: encryptedObject, sessionKey, txBytes }); // Uint8Array
}
