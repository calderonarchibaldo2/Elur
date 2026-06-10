import { defineConfig } from "vite";

// Vite serves the frontend that Tauri loads. Port 1420 matches tauri.conf.json devUrl.
// `define global` is needed by the Sui/Seal SDKs in a webview (same as the web viewer).
export default defineConfig({
  clearScreen: false,
  define: { global: "globalThis" },
  server: { port: 1420, strictPort: true },
});
