// Cross-party NAMED-IDENTITY grant — proves the access-control branch's headline
// move end to end, the same path applyAccess() drives in the app:
//
//   A mints an IDENTITY-mode policy → A grants B (add_recipient) → B opens (gate
//   lets the named identity through) → A removes B (remove_recipient) → B is
//   denied, while A (owner) still opens. Seal is in-memory here; the full
//   Walrus round-trip is already proven by test-step2-governed.mjs.
//
// Run:  node test-crossparty-grant.mjs
// (A = ./.agent-key.json, B = ./counterparty-key.json — both on this machine.)

import { readFileSync } from "node:fs";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";
import { randomKey, aesEncryptPadded, aesDecryptPadded } from "./lib.mjs";

const PACKAGE_ID = "0x5bbbc73ce94e4cfd0f53bf6749e29203c88fd2d33fe4316a34027c976054b4ff";
const MODULE = "access", CLOCK = "0x6", MODE_IDENTITY = 1;
const SERVER_CONFIGS = [
  { objectId: "0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98", weight: 1, aggregatorUrl: "https://seal-aggregator-testnet.mystenlabs.com" },
  { objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", weight: 1 },
];
const suiClient = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl("testnet"), network: "testnet" });
const seal = () => new SealClient({ suiClient, serverConfigs: SERVER_CONFIGS, verifyKeyServers: false });
const loadKey = (f) => Ed25519Keypair.fromSecretKey(JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8")).exportedPrivateKey);
const line = (s = "") => console.log(s);

const A = loadKey("./.agent-key.json");
const B = loadKey("./counterparty-key.json");
const Aaddr = A.toSuiAddress(), Baddr = B.toSuiAddress();

async function send(signer, build, label) {
  const tx = new Transaction(); build(tx);
  const res = await suiClient.signAndExecuteTransaction({ signer, transaction: tx, options: { showObjectChanges: true } });
  await suiClient.waitForTransaction({ digest: res.digest });
  return res;
}

// Try to open the sealed key AS `who`. Resolves to the plaintext, or throws if the gate refuses.
async function openAs(who, policyId, ek, iv, ct) {
  const sessionKey = await SessionKey.create({ address: who.toSuiAddress(), packageId: PACKAGE_ID, ttlMin: 10, signer: who, suiClient });
  const tx = new Transaction();
  tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::seal_approve`, arguments: [tx.pure.vector("u8", fromHex(policyId)), tx.object(policyId), tx.object(CLOCK)] });
  const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
  const ck = await seal().decrypt({ data: ek, sessionKey, txBytes });
  return new TextDecoder().decode(await aesDecryptPadded(iv, ct, new Uint8Array(ck)));
}

let fail = 0;
const expectOpen = async (who, name, ...args) => { try { const t = await openAs(who, ...args); line(`   ✓ ${name} opened → ${JSON.stringify(t.slice(0, 42))}…`); } catch (e) { fail++; line(`   ❌ ${name} was DENIED but should have opened (${(e.message||e).toString().slice(0,70)})`); } };
const expectDenied = async (who, name, ...args) => { try { await openAs(who, ...args); fail++; line(`   ❌ ${name} OPENED but should have been denied!`); } catch { line(`   ⛔ ${name} denied (correct)`); } };

line("\n──────────────────────────────────────────────");
line(" Elur · cross-party named-identity grant test");
line("──────────────────────────────────────────────");
line(" A (owner) : " + Aaddr);
line(" B (counterparty) : " + Baddr);

const secret = "Clean-team only: walk-away ceiling $4.2M. Not for buyer corp dev.";

line("\n① A mints an IDENTITY-mode policy + seals the secret to it…");
const mintRes = await send(A, (tx) => tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::mint`, arguments: [tx.pure.u8(MODE_IDENTITY), tx.pure.u64(0), tx.pure.u64(0), tx.pure.vector("u8", [1]), tx.object(CLOCK)] }), "mint");
const policyId = (mintRes.objectChanges || []).find((c) => c.objectType?.includes("::access::AccessPolicy"))?.objectId;
const capId = (mintRes.objectChanges || []).find((c) => c.objectType?.includes("::access::OwnerCap"))?.objectId;
if (!policyId || !capId) { line("   ❌ could not find policy/cap"); process.exit(1); }
const ck = randomKey();
const { encryptedObject: ek } = await seal().encrypt({ threshold: 1, packageId: PACKAGE_ID, id: policyId, data: ck });
const { iv, ct } = await aesEncryptPadded(new TextEncoder().encode(secret), ck);
line("   ✓ policy: " + policyId);

line("\n② Before any grant — B must NOT get in (identity mode, empty allowlist):");
await expectDenied(B, "B (not yet granted)", policyId, ek, iv, ct);

line("\n③ A grants B (add_recipient)…");
await send(A, (tx) => tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::add_recipient`, arguments: [tx.object(capId), tx.object(policyId), tx.pure.address(Baddr)] }), "add_recipient");
line("\n   Now B should open, and A (owner) always opens:");
await expectOpen(B, "B (granted)", policyId, ek, iv, ct);
await expectOpen(A, "A (owner)", policyId, ek, iv, ct);

line("\n④ A removes B (remove_recipient)…");
await send(A, (tx) => tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::remove_recipient`, arguments: [tx.object(capId), tx.object(policyId), tx.pure.address(Baddr)] }), "remove_recipient");
line("\n   B must be denied now; A still opens (revocation reaches only B):");
await expectDenied(B, "B (removed)", policyId, ek, iv, ct);
await expectOpen(A, "A (owner, still in)", policyId, ek, iv, ct);

line("\n⑤ Cleanup — A revokes the policy…");
await send(A, (tx) => tx.moveCall({ target: `${PACKAGE_ID}::${MODULE}::revoke`, arguments: [tx.object(capId), tx.object(policyId)] }), "revoke");
line("   ✓ revoked.");

line(`\n${fail ? "❌ FAIL — " + fail + " assertion(s) wrong" : "✅ Named-identity grant/revoke — proven end to end."}`);
line(fail ? "" : "   Grant reaches one party; removing one party leaves the rest untouched.\n");
process.exit(fail ? 1 : 0);
