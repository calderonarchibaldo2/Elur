// Regression: Walrus blob-size padding (the agent-memory size leak fix).
// Proves: (1) different-length memories yield EQUAL-size ciphertext within a
// bucket, (2) round-trip is exact, (3) the unpadded path leaked size, (4) v:1
// blobs still decrypt. Run: node agent/test-padding.mjs
import { randomKey, aesEncrypt, aesDecrypt, aesEncryptPadded, aesDecryptPadded, memSizeClass } from "./lib.mjs";

let pass = 0, fail = 0;
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
function ok(name, cond) { if (cond) { pass++; console.log("  ✓ " + name); } else { fail++; console.error("  ✗ " + name); } }

const ck = randomKey();

// 1. Equal-size blobs: two very different lengths land in the same 4 KB bucket.
const a = await aesEncryptPadded(enc("hi"), ck);
const b = await aesEncryptPadded(enc("x".repeat(2000)), ck);
ok("2-byte and 2000-byte memories produce equal-size ciphertext", a.ct.length === b.ct.length);
ok("that size is the 4 KB bucket + GCM tag (4112)", a.ct.length === 4096 + 16);

// 2. Round-trip across buckets.
for (const s of ["", "hi", "a short memory", "y".repeat(5000), "z".repeat(70000)]) {
  const { iv, ct } = await aesEncryptPadded(enc(s), ck);
  const back = dec(await aesDecryptPadded(iv, ct, ck));
  ok(`round-trip exact (${s.length} bytes → ${ct.length - 16} padded)`, back === s);
}

// 3. Demonstrate the bug the fix removes: the UNPADDED path leaks length.
const u1 = await aesEncrypt(enc("hi"), ck);
const u2 = await aesEncrypt(enc("x".repeat(2000)), ck);
ok("unpadded ciphertext sizes DIFFER (the leak we fixed)", u1.ct.length !== u2.ct.length);

// 4. v:1 back-compat: an old unpadded blob still decrypts via aesDecrypt.
const legacy = await aesEncrypt(enc("legacy memory"), ck);
ok("v:1 unpadded blob still decodes", dec(await aesDecrypt(legacy.iv, legacy.ct, ck)) === "legacy memory");

// 5. Bucket boundaries.
ok("memSizeClass buckets", memSizeClass(1) === 4096 && memSizeClass(4096) === 4096 && memSizeClass(4097) === 65536 && memSizeClass(2_000_000) === 2097152);

console.log(`\n${fail ? "❌" : "✅"} padding regression: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
