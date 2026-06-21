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
  dealName: "Project Snowfall",
  subtitle: "A live M&A deal room on Sui testnet. No install, no account — documents open in your browser, through the on-chain gate. Try the Confidential Budget: it's been revoked, and you'll watch the gate refuse it.",

  recipientSecret: null, // bearer — these docs are mode 0 / empty allowlist, so anyone opens them

  // REAL Walrus testnet blobs (30-epoch), sealed from the Project Snowfall deal docs.
  // The Confidential Budget is revoked on-chain → it DENIES for everyone (the showcase).
  docs: [
    { label: "Term Sheet",            folder: "Corporate", blobId: "HCjfF3MKP8WAUzu9RMo3adzGIy3rtO1dYLQrII4S6qQ", name: "01_Term_Sheet.pdf",                ext: "pdf" },
    { label: "Board Resolution",      folder: "Corporate", blobId: "6am577nKNTz45kgzIkxEIZAzZ87IGG3KLWWQekaaXV4", name: "05_Board_Resolution.pdf",          ext: "pdf" },
    { label: "Due Diligence Summary", folder: "Financial", blobId: "lbE_MfAtLuPE0sjzT25X-QliPrrXHm-Q4DVl8T1v82M", name: "03_Due_Diligence_Summary.pdf",     ext: "pdf" },
    { label: "Deal Contacts & Counsel", folder: "Legal",   blobId: "cuKC39fmyXXGhwWUN0g67taQHWpHxN_C-jLxkk31Tyg", name: "04_Deal_Contacts_and_Counsel.pdf", ext: "pdf" },
    { label: "Privileged Legal Opinion", folder: "Legal",  blobId: "tZdXTcvYNnE75Tl8Xgb4Kb_lMWPX0yQEr3wb02-fJNM", name: "06_Privileged_Legal_Opinion.pdf",  ext: "pdf", note: "privileged · view-only in the app" },
    { label: "Confidential Budget",   folder: "Financial", blobId: "ZhAGnUsaC-Mm1ItIswLVU80NFaYdrPwWuu9JmUN3QdA", name: "02_Confidential_Budget.xlsx",     ext: "xlsx", note: "acquirer-only — try it" },
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
