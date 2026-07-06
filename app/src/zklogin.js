// Elur — zkLogin via Enoki (passwordless sign-in).
//
// Flow: ephemeral keypair → Enoki nonce → Google sign-in in the SYSTEM browser
// (Google blocks OAuth inside embedded webviews) → redirect lands on a temporary
// localhost server → JWT → Enoki derives the Sui address + ZK proof → we can sign.
//
// Security model unchanged: Enoki = auth + (later) gas only. It NEVER sees file
// keys or content. The ephemeral key signs transactions; the proof binds it to
// the Google identity. Session persists in the macOS Keychain until maxEpoch.

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { getZkLoginSignature } from "@mysten/sui/zklogin";
import { toBase64, fromBase64 } from "@mysten/sui/utils";
import { invoke } from "@tauri-apps/api/core";
import { start, cancel, onUrl } from "@fabianlars/tauri-plugin-oauth";
import { ENOKI_PUBLIC_KEY, GOOGLE_CLIENT_ID, OAUTH_PORTS, SPONSOR_URL } from "./enoki.js";

const API = "https://api.enoki.mystenlabs.com";
const NETWORK = "testnet";
const KC_ACCOUNT = "zklogin-session";

async function enoki(path, { method = "GET", jwt, body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Authorization: "Bearer " + ENOKI_PUBLIC_KEY,
      ...(jwt ? { "zklogin-jwt": jwt } : {}),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Enoki ${path} (${res.status}): ${JSON.stringify(json).slice(0, 300)}`);
  return json.data;
}

// Page served by the localhost catcher. The plugin injects its own script into
// <head> that forwards the FULL redirect URL (fragment included) back to the
// server via a "Full-Url" header — so this page is presentation only.
const RESPONSE_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Elur sign-in</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#f6f7f9;color:#111827">
<div style="text-align:center"><div style="font-size:42px">&#10052;&#65039;</div><h2 id="m" style="font-weight:700">Finishing sign-in&hellip;</h2><p style="color:#5b6573">You can close this tab when it confirms.</p></div>
<script>setTimeout(function () { document.getElementById('m').textContent = 'Done \\u2014 you can close this tab and return to Elur.'; }, 900);</script>
</body></html>`;

function zkSig(s, eph, txBytes) {
  return eph.signTransaction(txBytes).then(({ signature: userSignature }) =>
    getZkLoginSignature({ inputs: s.proof, maxEpoch: s.maxEpoch, userSignature }),
  );
}

// Preferred path: the sponsor backend pays gas (user needs zero SUI).
async function sponsoredExec(suiClient, tx, s, eph, options) {
  const kindBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
  const r1 = await fetch(SPONSOR_URL + "/sponsor", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jwt: s.jwt, transactionKindBytes: toBase64(kindBytes) }),
  });
  if (!r1.ok) throw new Error("sponsor: " + (await r1.text()).slice(0, 200));
  const { bytes, digest } = await r1.json();
  const signature = await zkSig(s, eph, fromBase64(bytes));
  const r2 = await fetch(SPONSOR_URL + "/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ digest, signature }),
  });
  if (!r2.ok) throw new Error("execute: " + (await r2.text()).slice(0, 200));
  await suiClient.core.waitForTransaction({ digest });
  return suiClient.core.getTransaction({ digest, include: options });
}

// Read the user-facing identity (email) out of the JWT — decoded locally, never sent anywhere.
function jwtClaims(jwt) {
  try {
    return JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return {};
  }
}

function makeSigner(s) {
  const eph = Ed25519Keypair.fromSecretKey(s.ephSecret);
  return {
    address: s.address,
    email: jwtClaims(s.jwt).email || null,
    maxEpoch: s.maxEpoch,
    async signAndExecute(suiClient, tx, options) {
      // Try sponsored gas first; fall back to self-paid if the backend is off.
      try {
        return await sponsoredExec(suiClient, tx, s, eph, options);
      } catch (e) {
        console.warn("Sponsor unavailable, paying gas from the zkLogin address:", e.message);
      }
      tx.setSender(s.address);
      const bytes = await tx.build({ client: suiClient });
      const signature = await zkSig(s, eph, bytes);
      return suiClient.executeTransactionBlock({ transactionBlock: bytes, signature, options });
    },
  };
}

export async function signInWithGoogle(onStatus = () => {}) {
  // 1. Ephemeral keypair + Enoki nonce (binds the key into the OAuth flow)
  onStatus("Preparing sign-in…");
  const eph = new Ed25519Keypair();
  const ephPub = eph.getPublicKey().toSuiPublicKey();
  const { nonce, randomness, maxEpoch, estimatedExpiration } = await enoki("/v1/zklogin/nonce", {
    method: "POST",
    body: { network: NETWORK, ephemeralPublicKey: ephPub, additionalEpochs: 7 },
  });

  // 2. Localhost catcher + Google in the system browser
  const port = await start({ ports: OAUTH_PORTS, response: RESPONSE_PAGE });
  let unlisten = null;
  const jwt = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      try { unlisten && unlisten(); } catch {}
      cancel(port).catch(() => {});
      reject(new Error("Sign-in timed out — try again."));
    }, 180000);
    onUrl((url) => {
      try {
        // Google returns the token in the URL fragment: http://localhost:PORT/#id_token=…
        const u = new URL(url);
        const fromHash = new URLSearchParams(u.hash.startsWith("#") ? u.hash.slice(1) : "");
        const tok = fromHash.get("id_token") || u.searchParams.get("id_token");
        if (!tok) return;
        clearTimeout(timer);
        try { unlisten && unlisten(); } catch {}
        cancel(port).catch(() => {});
        resolve(tok);
      } catch {}
    }).then((u) => { unlisten = u; });

    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    auth.searchParams.set("redirect_uri", `http://localhost:${port}`);
    auth.searchParams.set("response_type", "id_token");
    auth.searchParams.set("scope", "openid email");
    auth.searchParams.set("nonce", nonce);
    auth.searchParams.set("prompt", "select_account");
    onStatus("Waiting for Google in your browser…");
    invoke("open_url", { url: auth.toString() }).catch(reject);
  });

  // 3. JWT → Sui address + ZK proof (Enoki holds the salt; keys stay ours)
  onStatus("Deriving your Sui address…");
  const { address } = await enoki("/v1/zklogin", { jwt });
  onStatus("Generating your zero-knowledge proof…");
  const proof = await enoki("/v1/zklogin/zkp", {
    method: "POST",
    jwt,
    body: { network: NETWORK, ephemeralPublicKey: ephPub, maxEpoch, randomness },
  });

  // 4. Persist the session in the Keychain (no re-login every test)
  const session = {
    address,
    jwt,
    maxEpoch,
    randomness,
    proof,
    ephSecret: eph.getSecretKey(),
    expiresAt: estimatedExpiration,
  };
  await invoke("kv_set", { account: KC_ACCOUNT, value: JSON.stringify(session) });
  return makeSigner(session);
}

export async function restoreZkSession() {
  try {
    const raw = await invoke("kv_get", { account: KC_ACCOUNT });
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (s.expiresAt && Date.now() > s.expiresAt - 60000) {
      await invoke("kv_clear", { account: KC_ACCOUNT });
      return null;
    }
    return makeSigner(s);
  } catch {
    return null;
  }
}

export async function zkSignOut() {
  try { await invoke("kv_clear", { account: KC_ACCOUNT }); } catch {}
}
