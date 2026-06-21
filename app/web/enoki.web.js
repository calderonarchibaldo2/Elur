// Elur — Enoki config for the WEB build (zkLogin + sponsored gas).
// Same public values as the desktop enoki.js; the difference is OAuth uses a
// same-page redirect (no localhost catcher) and the sponsor must be reachable
// from the browser (CORS + a public URL when deployed).

export const ENOKI_PUBLIC_KEY = "enoki_public_35cc22134e57a0ddac55a90e9c904992";

export const GOOGLE_CLIENT_ID =
  "428451150364-oavmhaaqn706u8e1gk0hsvv5a082r61v.apps.googleusercontent.com";

// Sponsor backend (holds the PRIVATE key; pays gas for zkLogin users).
//  • Local dev: run `node server/server.mjs` and open CORS to the web app's origin.
//  • Deploy:    replace with the public HTTPS URL of the deployed sponsor.
export const SPONSOR_URL = "http://127.0.0.1:3777";

// OAuth redirect for the web flow. "" = use the current page URL
// (location.origin + location.pathname) — must be registered in Google + Enoki.
export const OAUTH_REDIRECT = "";

// Unused on web (the desktop localhost catcher); kept so any stray import resolves.
export const OAUTH_PORTS = [];
