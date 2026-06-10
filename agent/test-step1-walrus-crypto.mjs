// Step 1 test: an "agent memory" round-trips through Elur crypto + Walrus.
// Encrypt a memory → store ciphertext on Walrus → read it back by blob ID →
// decrypt → confirm it matches. Proves the encrypted-data-on-Walrus pipe in Node,
// with NO plaintext ever leaving this machine (only ciphertext goes to Walrus).

import { randomKey, aesEncrypt, aesDecrypt, walrusStore, walrusRead } from "./lib.mjs";

const memory = "The acquisition price ceiling is $4.2M. Never disclose to the seller's side.";

console.log("\n🧠 Agent memory to store:\n   " + JSON.stringify(memory) + "\n");

// 1. Encrypt the memory with a fresh content key (the plaintext stays local)
const ck = randomKey();
const { iv, ct } = await aesEncrypt(new TextEncoder().encode(memory), ck);
console.log("🔒 Encrypted locally (AES-256-GCM). Ciphertext is " + ct.length + " bytes.");

// 2. Package {iv, ct} as one blob and store ONLY the ciphertext on Walrus
const pkg = JSON.stringify({ v: 1, iv: [...iv], ct: [...ct] });
console.log("☁️  Storing ciphertext on Walrus…");
const blobId = await walrusStore(new TextEncoder().encode(pkg), 5);
console.log("✅ Stored. Blob ID: " + blobId);

// 3. Fetch the blob back by ID (this is what an agent would do to recall)
console.log("\n📥 Reading the blob back from Walrus by ID…");
const fetched = await walrusRead(blobId);
const got = JSON.parse(new TextDecoder().decode(fetched));

// 4. Decrypt with the content key → should match the original memory
const plain = await aesDecrypt(new Uint8Array(got.iv), new Uint8Array(got.ct), ck);
const recovered = new TextDecoder().decode(plain);
console.log("🔓 Decrypted recovered memory:\n   " + JSON.stringify(recovered));

console.log("\n" + (recovered === memory
  ? "🎉 ROUND-TRIP OK — encrypted agent memory stored on Walrus and recovered intact."
  : "❌ MISMATCH — recovered text does not equal the original."));
console.log("   (Next: Seal-gate the key so revoke makes the agent forget.)\n");
