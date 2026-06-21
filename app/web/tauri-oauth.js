// Stub for @fabianlars/tauri-plugin-oauth (the desktop localhost OAuth catcher).
// The web build swaps zklogin.js for zklogin.web.js (same-page redirect), so these
// are never called — provided only so any stray import resolves cleanly.
export const start = async () => { throw new Error("OAuth catcher is desktop-only; web uses a redirect."); };
export const cancel = async () => {};
export const onUrl = async () => () => {};
