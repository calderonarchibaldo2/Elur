import { defineConfig } from "vite";

// Minimal config. If the Sui/Seal SDKs complain about Node globals in the browser,
// the usual fixes go here (define global, optimizeDeps). Starting clean.
export default defineConfig({
  define: { global: "globalThis" },
});
