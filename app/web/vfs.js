// Browser "virtual file system" — bridges the desktop app's path-based file model
// to the browser's File API. A native "path" becomes an opaque token "/vfs/<id>/<name>"
// so that baseName(path) still returns the real filename, and read_path(token) finds
// the picked File. Cancel is detected via the window-focus fallback (no native event).

const map = new Map();
let n = 0;
const tok = (id, name) => `/vfs/${id}/${name}`;
const idOf = (p) => { const m = /^\/vfs\/([^/]+)\//.exec(p || ""); return m ? m[1] : null; };

export function getEntry(path) { const id = idOf(path); return id ? map.get(id) : null; }

function pickInput(accept, multiple, dir) {
  return new Promise((resolve) => {
    const el = document.createElement("input");
    el.type = "file";
    if (multiple) el.multiple = true;
    if (dir) el.webkitdirectory = true;
    if (accept) el.accept = accept;
    el.style.position = "fixed"; el.style.left = "-9999px";
    document.body.appendChild(el);
    let done = false;
    const finish = (files) => { if (done) return; done = true; try { el.remove(); } catch {} resolve(files); };
    el.onchange = () => finish(Array.from(el.files || []));
    // cancel has no event — when focus returns and no change fired, treat as cancel
    const onFocus = () => { setTimeout(() => { window.removeEventListener("focus", onFocus); finish([]); }, 500); };
    window.addEventListener("focus", onFocus);
    el.click();
  });
}

function acceptFrom(filters) {
  if (!filters || !filters.length) return "";
  const exts = [];
  for (const f of filters) for (const e of f.extensions || []) exts.push("." + e);
  return exts.join(",");
}

export async function pickOne(filters) {
  const files = await pickInput(acceptFrom(filters), false, false);
  if (!files.length) return null;
  const id = "f" + ++n; map.set(id, files[0]); return tok(id, files[0].name);
}
export async function pickMany(filters) {
  const files = await pickInput(acceptFrom(filters), true, false);
  if (!files.length) return null;
  return files.map((f) => { const id = "f" + ++n; map.set(id, f); return tok(id, f.name); });
}
export async function pickDir() {
  const files = await pickInput("", true, true);
  if (!files.length) return null;
  const rel = files[0].webkitRelativePath || files[0].name;
  const name = (rel.split("/")[0]) || "folder";
  const id = "d" + ++n; map.set(id, { dir: true, files, name }); return tok(id, name);
}
export function saveName(defaultPath) { return defaultPath || "download"; }
