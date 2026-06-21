// Elur agent — governed memory API.
// remember() → store an encrypted, on-chain-governed memory on Walrus.
// recall()   → fetch + pass the gate + decrypt (throws if the gate is sealed).
// forget()   → revoke the policy on-chain; every copy goes dark.

import { randomKey, aesDecrypt, aesEncryptPadded, aesDecryptPadded, walrusStore, walrusRead } from "./lib.mjs";
import { mintPolicy, revokePolicy, sealWrap, sealUnwrap } from "./chain.mjs";

// Store a governed memory. The plaintext never leaves this machine; only the
// Seal-wrapped, AES-encrypted package goes to Walrus.
export async function remember(text, opts = {}) {
  const ck = randomKey();
  const { iv, ct } = await aesEncryptPadded(new TextEncoder().encode(text), ck);
  const { policyId, capId } = await mintPolicy(opts);
  const ek = await sealWrap(policyId, ck);
  const pkg = JSON.stringify({ v: 2, policyId, ek: [...ek], iv: [...iv], ct: [...ct] });
  const blobId = await walrusStore(new TextEncoder().encode(pkg), opts.epochs || 5);
  return { blobId, policyId, capId };
}

// Recall a memory by its Walrus blob id. Throws if access has been revoked/expired.
export async function recall(blobId) {
  const bytes = await walrusRead(blobId);
  const pkg = JSON.parse(new TextDecoder().decode(bytes));
  const ck = await sealUnwrap(pkg.policyId, new Uint8Array(pkg.ek)); // gate enforced here
  const plain = (pkg.v >= 2)
    ? await aesDecryptPadded(new Uint8Array(pkg.iv), new Uint8Array(pkg.ct), ck)
    : await aesDecrypt(new Uint8Array(pkg.iv), new Uint8Array(pkg.ct), ck); // v:1 back-compat
  return new TextDecoder().decode(plain);
}

// Make the agent forget — revoke the on-chain policy. The blob stays on Walrus
// but becomes permanently unreadable (until/unless the owner reinstates).
export async function forget(capId, policyId) {
  return await revokePolicy(capId, policyId);
}
