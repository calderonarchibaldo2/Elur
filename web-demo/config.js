// ── Elur web demo — the one place you plug in your demo data ──────────────────
//
// HOW A JUDGE OPENS A DOC (pick ONE; see README):
//  A) recipientSecret = null  → opens as an anonymous bearer. Works only for docs
//     minted in BEARER mode (mode 0, empty allowlist). Truly no-account.
//  B) recipientSecret = "suiprivkey1..."  → a THROWAWAY testnet key that is on the
//     allowlist of the shared docs, so the page opens them "as the granted
//     counterparty." Fine for a demo identity; never use a real key.
//
// The revoked doc denies for EVERYONE regardless of A/B — that's the point.

export const CONFIG = {
  dealName: "Project Páramo",
  subtitle: "A live deal room on Sui testnet. No install, no account — documents open in your browser, through the on-chain gate.",

  recipientSecret: null, // ← paste a throwaway suiprivkey1... for option B, or leave null for A

  // blobIds are the REAL Walrus testnet blobs (from agent/elur-manifest.json).
  // NOTE: the original 5 demo blobs expired (testnet GC). Re-store them via the app
  // (now 30-epoch) and paste the fresh blobIds back here. Live doc for the plumbing proof:
  docs: [
    { label: "Breathing Square (sample)", folder: "Demo", blobId: "7RwnalmEk_MavI47vXpWmvNO0OvZoQy92yO6Dyc7tbk", name: "breathing-square.html", ext: "html" },
  ],

  // Walrus testnet aggregator (HTTP read). If CORS blocks it in the browser, set this
  // to a same-origin proxy path (see README — a tiny Cloudflare Worker on elur.io).
  walrusAggregator: "https://aggregator.walrus-testnet.walrus.space/v1/blobs/",

  // ── "Try it on your own document" (zkLogin + sponsored gas) ──────────────────
  // Public, safe to ship (testnet, zkLogin-only) — same values as the desktop app's enoki.js.
  enableSender: true,
  enokiPublicKey: "enoki_public_35cc22134e57a0ddac55a90e9c904992",
  googleClientId: "428451150364-oavmhaaqn706u8e1gk0hsvv5a082r61v.apps.googleusercontent.com",
  // ⚠ DEPLOY server/server.mjs to a public HTTPS URL, open CORS to this demo's origin, FUND its
  // wallet, and put the URL here (localhost won't work when hosted).
  sponsorUrl: "https://REPLACE-WITH-DEPLOYED-SPONSOR",
  // ⚠ Register THIS demo's URL as an authorized redirect URI in BOTH the Google OAuth client and
  // the Enoki portal (today only http://localhost:8765-8767 are registered). "" = use the page URL.
  oauthRedirect: "",
};
