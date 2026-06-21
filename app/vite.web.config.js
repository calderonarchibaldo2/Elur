// Web build of the Elur app — the SAME index.html / src/main.js / src/style.css the
// desktop uses, with the Tauri-only modules swapped for browser shims (web/). The
// desktop build is untouched: it runs plain `vite` / tauri; this config is only used
// via `npm run web` (dev) and `npm run web:build` (deploy).
//
//   dev:    npm run web        → http://localhost:5174
//   build:  npm run web:build  → ../web-app-dist  (deploy these static files)

import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const web = (p) => resolve(__dirname, "web", p);

// Web-only soft login gate (injected into index.html for the web build ONLY — the
// desktop build never runs this config, so its UX is unchanged). Shows a front door
// for signed-out visitors; returning/signed-in users skip straight to the app; and a
// secondary link preserves Elur's no-account recipient path.
const GATE = `
<div id="webgate" style="position:fixed;inset:0;z-index:99999;background:#16243f;color:#f4efe4;display:flex;align-items:center;justify-content:center;font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif">
  <div style="max-width:430px;text-align:center;padding:32px">
    <div style="font:600 12px/1 'JetBrains Mono',ui-monospace,monospace;letter-spacing:3px;color:#c9a24a;text-transform:uppercase;margin-bottom:18px">ELUR · live on Sui testnet</div>
    <h1 style="font-family:Fraunces,Georgia,serif;font-size:38px;font-weight:500;margin:0 0 12px;letter-spacing:-.5px">Your files, sealed.</h1>
    <p style="color:#aeb6c6;font-size:15.5px;line-height:1.55;margin:0 0 28px">Encrypt, govern, and revoke documents — and the AI agents that read them — live on-chain. Sign in to enter the full app. No wallet, no crypto; gas is sponsored.</p>
    <button id="webgateSignin" style="display:inline-flex;align-items:center;gap:10px;background:#f4efe4;color:#16243f;border:none;border-radius:11px;padding:13px 22px;font:600 15px Inter,sans-serif;cursor:pointer">
      <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#16243f" d="M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.7-.4-3.9z"/></svg>
      Sign in with Google
    </button>
    <div id="webgateStatus" style="font:13px 'JetBrains Mono',ui-monospace,monospace;color:#c9a24a;min-height:18px;margin-top:14px"></div>
    <p style="margin-top:22px;font-size:13.5px"><a href="#" id="webgateSkip" style="color:#8b93a7;text-decoration:underline">Just opening a shared file? Continue without an account &rarr;</a></p>
  </div>
</div>
<script>
(function(){
  var SK="elur:zk:session";
  function el(id){return document.getElementById(id);}
  function hideGate(){var g=el("webgate"); if(g) g.style.display="none";}
  function showGate(){var g=el("webgate"); if(g) g.style.display="flex";}
  // Every tab EXCEPT Open — these require a signed-in identity.
  var LOCKED=["tabOverview","tabShare","tabAgent","tabRequests","tabRoom","tabQA","tabActivity"];
  function setLockedTabs(on){ LOCKED.forEach(function(id){ var t=el(id); if(t) t.style.display = on ? "none" : ""; }); }
  function lockToOpen(){
    setLockedTabs(true);
    var o=el("tabOpen"); if(o) o.click();          // recipient view only
    var host=document.querySelector(".side-pills");
    if(host && !el("guestSignin")){
      var b=document.createElement("button");
      b.id="guestSignin"; b.className="pill pill-btn"; b.textContent="Sign in to unlock";
      b.onclick=function(){ setLockedTabs(false); showGate(); };
      host.insertBefore(b, host.firstChild);
    }
  }
  if(localStorage.getItem(SK)){ hideGate(); return; }   // signed in: full app, no gate
  function wire(){
    var btn=el("webgateSignin"), skip=el("webgateSkip"), st=el("webgateStatus");
    if(!btn){ return setTimeout(wire,50); }
    btn.onclick=function(){
      st.textContent="Opening Google sign-in…"; var n=0;
      (function go(){ var g=el("gsign"); if(g && g.onclick){ g.click(); } else if(n++<40){ setTimeout(go,100);} else { st.textContent="Still loading — try again in a moment."; } })();
    };
    skip.onclick=function(e){ e.preventDefault(); hideGate(); lockToOpen(); };
  }
  wire();
})();
</script>`;

// Redirect the Tauri-only imports (and the desktop zklogin/enoki) to the web shims,
// and inject the soft login gate into index.html.
const shim = {
  name: "elur-web-shim",
  enforce: "pre",
  resolveId(source) {
    if (source === "@tauri-apps/api/core") return web("tauri-core.js");
    if (source === "@tauri-apps/plugin-dialog") return web("tauri-dialog.js");
    if (source === "@fabianlars/tauri-plugin-oauth") return web("tauri-oauth.js");
    if (/(^|\/)zklogin\.js$/.test(source)) return web("zklogin.web.js");
    if (/(^|\/)enoki\.js$/.test(source)) return web("enoki.web.js");
    return null;
  },
  transformIndexHtml(html) {
    return html.replace("</body>", GATE + "\n</body>");
  },
};

export default defineConfig({
  root: __dirname,          // mac-app-v2 — uses its index.html + src/ + node_modules
  base: "./",               // relative asset paths so it works under any deploy subpath
  plugins: [shim],
  server: { port: 5174 },   // distinct from the web-demo (5173) and tauri dev
  build: { outDir: resolve(__dirname, "../web-app-dist"), emptyOutDir: true },
});
