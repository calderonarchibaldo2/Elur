// Browser implementation of @tauri-apps/plugin-dialog (open/save).
// Returns the same shape main.js expects: a path token (or array) from open(),
// and a filename string from save(). Actual bytes flow through tauri-core's
// read_path / write_path, which share the vfs.

import { pickOne, pickMany, pickDir, saveName } from "./tauri-core.js";

export async function open(opts = {}) {
  if (opts.directory) return pickDir();
  if (opts.multiple) return pickMany(opts.filters);
  return pickOne(opts.filters);
}
export async function save(opts = {}) {
  return saveName(opts.defaultPath);
}
