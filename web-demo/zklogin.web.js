// Web zkLogin via Enoki + sponsored gas. Same flow as the desktop app, but the OAuth
// step is a same-page redirect (no localhost catcher): we stash the ephemeral key +
// nonce in sessionStorage, redirect to Google, and on return read the id_token from the
// URL fragment and finish. Enoki = auth + gas only; it never sees file keys or content.

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { getZkLoginSignature } from "@mysten/sui/zklogin";
import { toBase64, fromBase64 } from "@mysten/sui/utils";
import { CONFIG } from "./config.js";

const API = "https://api.enoki.mystenlabs.com", NETWORK = "testnet";
const SS = "elur_zk_pending", LS = "elur_zk_session";

async function enoki(path, { method = "GET", jwt, body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { Authorization: "Bearer " + CONFIG.enokiPublicKey,
      ...(jwt ? { "zklogin-jwt": jwt } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Enoki ${path} (${res.status}): ${JSON.stringify(json).slice(0, 200)}`);
  return json.data;
}
const jwtClaims = (jwt) => { try { return JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); } catch { return {}; } };
const zkSig = (s, eph, txBytes) => eph.signTransaction(txBytes).then(({ signature }) => getZkLoginSignature({ inputs: s.proof, maxEpoch: s.maxEpoch, userSignature: signature }));

async function sponsoredExec(suiClient, tx, s, eph, options) {
  const kindBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
  const r1 = await fetch(CONFIG.sponsorUrl + "/sponsor", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jwt: s.jwt, transactionKindBytes: toBase64(kindBytes) }) });
  if (!r1.ok) throw new Error("sponsor: " + (await r1.text()).slice(0, 200));
  const { bytes, digest } = await r1.json();
  const signature = await zkSig(s, eph, fromBase64(bytes));
  const r2 = await fetch(CONFIG.sponsorUrl + "/execute", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ digest, signature }) });
  if (!r2.ok) throw new Error("execute: " + (await r2.text()).slice(0, 200));
  await suiClient.waitForTransaction({ digest });
  return suiClient.getTransactionBlock({ digest, options });
}
function makeSigner(s) {
  const eph = Ed25519Keypair.fromSecretKey(s.ephSecret);
  return { address: s.address, email: jwtClaims(s.jwt).email || null, maxEpoch: s.maxEpoch,
    signAndExecute: (suiClient, tx, options) => sponsoredExec(suiClient, tx, s, eph, options) };
}
const redirectUri = () => CONFIG.oauthRedirect || (location.origin + location.pathname);

// Kick off Google sign-in (redirects the page away).
export async function beginSignIn(onStatus = () => {}) {
  onStatus("Preparing sign-in…");
  const eph = new Ed25519Keypair();
  const ephPub = eph.getPublicKey().toSuiPublicKey();
  const { nonce, randomness, maxEpoch, estimatedExpiration } =
    await enoki("/v1/zklogin/nonce", { method: "POST", body: { network: NETWORK, ephemeralPublicKey: ephPub, additionalEpochs: 7 } });
  sessionStorage.setItem(SS, JSON.stringify({ ephSecret: eph.getSecretKey(), ephPub, randomness, maxEpoch, estimatedExpiration }));
  const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  auth.searchParams.set("client_id", CONFIG.googleClientId);
  auth.searchParams.set("redirect_uri", redirectUri());
  auth.searchParams.set("response_type", "id_token");
  auth.searchParams.set("scope", "openid email");
  auth.searchParams.set("nonce", nonce);
  auth.searchParams.set("prompt", "select_account");
  location.href = auth.toString();
}
// On page load: if we just returned from Google, finish and return a signer.
export async function completeRedirect(onStatus = () => {}) {
  const hash = new URLSearchParams(location.hash.startsWith("#") ? location.hash.slice(1) : "");
  const jwt = hash.get("id_token"); if (!jwt) return null;
  history.replaceState(null, "", location.pathname + location.search);
  const pend = JSON.parse(sessionStorage.getItem(SS) || "null"); if (!pend) return null;
  sessionStorage.removeItem(SS);
  onStatus("Deriving your Sui address…");
  const { address } = await enoki("/v1/zklogin", { jwt });
  onStatus("Generating your zero-knowledge proof…");
  const proof = await enoki("/v1/zklogin/zkp", { method: "POST", jwt,
    body: { network: NETWORK, ephemeralPublicKey: pend.ephPub, maxEpoch: pend.maxEpoch, randomness: pend.randomness } });
  const session = { address, jwt, maxEpoch: pend.maxEpoch, randomness: pend.randomness, proof, ephSecret: pend.ephSecret, expiresAt: pend.estimatedExpiration };
  localStorage.setItem(LS, JSON.stringify(session));
  return makeSigner(session);
}
export function restoreSession() {
  try { const s = JSON.parse(localStorage.getItem(LS) || "null"); if (!s) return null;
    if (s.expiresAt && Date.now() > s.expiresAt - 60000) { localStorage.removeItem(LS); return null; }
    return makeSigner(s); } catch { return null; }
}
export function signOut() { try { localStorage.removeItem(LS); } catch {} }
