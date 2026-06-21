# Yale macOS app — setup & run (on your Mac)

This step's goal: **get the app to launch** and confirm the two new native pieces work —
reading/writing files on disk, and storing a key in the macOS Keychain. The encryption
engine gets ported on top **after** this runs. No Apple Developer account needed for any of this.

## One-time toolchain install

Open **Terminal** and run these once:

```bash
# 1. Apple command-line tools (compiler etc.) — a window may pop up; click Install
xcode-select --install

# 2. Rust (the native layer is Rust). Accept the default option (press Enter).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. Close and reopen Terminal so Rust is on your PATH, then check:
rustc --version
node --version     # you already have Node from the web viewer
```

## Run the app

```bash
cd app
npm install
npm run tauri dev
```

- The **first** `npm run tauri dev` compiles the Rust side — that takes a few minutes. Later runs are fast.
- A native **Yale** window should open with two test panels.

## What to check

1. **Pick a file** → choose any file → it should report "Read N bytes from …". 
2. **Save a test file** → choose where → it writes a small text file. Open it to confirm.
3. **Keychain**: type something → **Store** → **Read** (should show it back) → **Clear**.

If all three work, the native foundation is solid and I'll port the encryption engine onto it next.

## If something errors

Copy the red error text from the Terminal (or the on-screen "Error: …") and paste it back to me.
First runs of native apps almost always need one or two small fixes — exactly like the Seal
version issue we sorted on the web viewer. We'll iterate.

## Notes

- This scaffold deliberately does **not** include the Sui/Seal crypto libraries yet — that keeps the
  first build simple. They come in the next step when we port the engine.
- **Icons (for later):** when you want to build a distributable, run
  `npm run tauri icon ./app-icon.png` once to generate the icon set. Not needed for `npm run tauri dev`.
- **Signing (for later):** distributing to other people needs the $99/year Apple Developer account.
  Running it yourself here does not.
