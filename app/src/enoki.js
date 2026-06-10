// Elur — Enoki (zkLogin + sponsored gas) configuration.
// PUBLIC key: safe to ship in the client app. Scoped: Testnet only, zkLogin only.
// The PRIVATE key (sponsored transactions) lives ONLY in the backend — never here.

export const ENOKI_PUBLIC_KEY = "enoki_public_35cc22134e57a0ddac55a90e9c904992";

// Google OAuth client (Google Cloud project "Elur", type: Web application).
// Registered as Auth Provider in the Enoki portal.
// Redirect URIs registered: http://localhost:8765 / 8766 / 8767
export const GOOGLE_CLIENT_ID =
  "428451150364-oavmhaaqn706u8e1gk0hsvv5a082r61v.apps.googleusercontent.com";
export const OAUTH_PORTS = [8765, 8766, 8767];

// Sponsor backend (holds the PRIVATE key; pays gas for zkLogin users).
// Dev: runs locally — `node server/server.mjs`. Production: a deployed URL.
export const SPONSOR_URL = "http://127.0.0.1:3777";
