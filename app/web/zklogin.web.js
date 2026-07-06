// Elur — zkLogin for the WEB build. Same Enoki flow as the desktop, but OAuth is a
// SAME-PAGE redirect (Google blocks embedded webviews; the browser has no localhost
// catcher). Because the redirect destroys the JS context, we:
//   1. signInWithGoogle()  → stash the ephemeral state in sessionStorage, redirect to Google.
//   2. restoreZkSession()  → on the way back, read the id_token from the URL hash, finish
//      the proof, persist the session. main.js already calls restoreZkSession() on boot,
//      so the redirect completes itself with no extra wiring.
// Exports match the desktop API exactly: signInWithGoogle / restoreZkSession / zkSignOut.

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { getZkLoginSignature } from "@mysten/sui/zklogin";
import { toBase64, fromBase64 } from "@mysten/sui/utils";
import { ENOKI_PUBLIC_KEY, GOOGLE_CLIENT_ID, SPONSOR_URL, OAUTH_REDIRECT } from "./enoki.web.js";

const API = "https://api.enoki.mystenlabs.com";
const NETWORK = "testnet";
const PENDING = "elur:zk:pending";   // sessionStorage — survives the redirect, dies with the tab
const SESSION = "elur:zk:session";   // localStorage — persists across visits until maxEpoch

const redirectUri = () => OAUTH_REDIRECT || (location.origin + location.pathname);

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

function zkSig(s, eph, txBytes) {
  return eph.signTransaction(txBytes).then(({ signature: userSignature }) =>
    getZkLoginSignature({ inputs: s.proof, maxEpoch: s.maxEpoch, userSignature }),
  );
}

async function sponsoredExec(suiClient, tx, s, eph, options) {
  const kindBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
  const r1 = await fetch(SPONSOR_URL + "/sponsor", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jwt: s.jwt, transactionKindBytes: toBase64(kindBytes) }),
  });
  if (!r1.ok) throw new Error("sponsor: " + (await r1.text()).slice(0, 200));
  const { bytes, digest } = await r1.json();
  const signature = await zkSig(s, eph, fromBase64(bytes));
  const r2 = await fetch(SPONSOR_URL + "/execute", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ digest, signature }),
  });
  if (!r2.ok) throw new Error("execute: " + (await r2.text()).slice(0, 200));
  await suiClient.core.waitForTransaction({ digest });
  return suiClient.core.getTransaction({ digest, include: options });
}

function jwtClaims(jwt) {
  try { return JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); }
  catch { return {}; }
}

function makeSigner(s) {
  const eph = Ed25519Keypair.fromSecretKey(s.ephSecret);
  return {
    address: s.address,
    email: jwtClaims(s.jwt).email || null,
    maxEpoch: s.maxEpoch,
    async signAndExecute(suiClient, tx, options) {
      try { return await sponsoredExec(suiClient, tx, s, eph, options); }
      catch (e) { console.warn("Sponsor unavailable, paying gas from the zkLogin address:", e.message); }
      tx.setSender(s.address);
      const bytes = await tx.build({ client: suiClient });
      const signature = await zkSig(s, eph, bytes);
      return suiClient.core.executeTransaction({ transaction: bytes, signatures: [signature], include: options });
    },
  };
}

export async function signInWithGoogle(onStatus = () => {}) {
  onStatus("Preparing sign-in…");
  const eph = new Ed25519Keypair();
  const ephPub = eph.getPublicKey().toSuiPublicKey();
  const { nonce, randomness, maxEpoch, estimatedExpiration } = await enoki("/v1/zklogin/nonce", {
    method: "POST",
    body: { network: NETWORK, ephemeralPublicKey: ephPub, additionalEpochs: 7 },
  });
  // Stash everything the return trip needs (the page is about to be destroyed).
  sessionStorage.setItem(PENDING, JSON.stringify({
    ephSecret: eph.getSecretKey(), ephPub, randomness, maxEpoch, estimatedExpiration,
  }));
  const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  auth.searchParams.set("client_id", GOOGLE_CLIENT_ID);
  auth.searchParams.set("redirect_uri", redirectUri());
  auth.searchParams.set("response_type", "id_token");
  auth.searchParams.set("scope", "openid email");
  auth.searchParams.set("nonce", nonce);
  auth.searchParams.set("prompt", "select_account");
  onStatus("Redirecting to Google…");
  location.assign(auth.toString());
  return new Promise(() => {}); // never resolves; the page navigates away
}

// If we just came back from Google, finish the flow and persist the session.
async function completeFromHash() {
  const h = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  if (!h) return null;
  const tok = new URLSearchParams(h).get("id_token");
  if (!tok) return null;
  const pend = JSON.parse(sessionStorage.getItem(PENDING) || "null");
  if (!pend) return null;
  history.replaceState(null, "", location.origin + location.pathname + location.search); // wipe the token from the URL
  const { address } = await enoki("/v1/zklogin", { jwt: tok });
  const proof = await enoki("/v1/zklogin/zkp", {
    method: "POST", jwt: tok,
    body: { network: NETWORK, ephemeralPublicKey: pend.ephPub, maxEpoch: pend.maxEpoch, randomness: pend.randomness },
  });
  const session = {
    address, jwt: tok, maxEpoch: pend.maxEpoch, randomness: pend.randomness,
    proof, ephSecret: pend.ephSecret, expiresAt: pend.estimatedExpiration,
  };
  localStorage.setItem(SESSION, JSON.stringify(session));
  sessionStorage.removeItem(PENDING);
  // The soft gate overlay rendered before this async completion finished, so tell it
  // to dismiss now that we're signed in (otherwise it sits on top → sign-in loop).
  try { window.dispatchEvent(new Event("elur:signed-in")); } catch {}
  return makeSigner(session);
}

export async function restoreZkSession() {
  try { const back = await completeFromHash(); if (back) return back; }
  catch (e) { console.warn("zkLogin redirect completion failed:", e); }
  try {
    const raw = localStorage.getItem(SESSION);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (s.expiresAt && Date.now() > s.expiresAt - 60000) { localStorage.removeItem(SESSION); return null; }
    return makeSigner(s);
  } catch { return null; }
}

export async function zkSignOut() {
  try { localStorage.removeItem(SESSION); } catch {}
}
