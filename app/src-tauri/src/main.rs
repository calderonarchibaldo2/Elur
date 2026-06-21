// Yale macOS — native layer.
// The frontend (bundled into the signed app) calls these commands.
// read_path/write_path do the actual disk I/O; the dialog plugin only picks paths.
// Keychain commands store the user's key in the macOS Keychain (not browser storage).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::{engine::general_purpose::STANDARD, Engine};

const SERVICE: &str = "com.yale.app";
const ACCOUNT: &str = "master";

#[tauri::command]
fn read_path(path: String) -> Result<String, String> {
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(bytes))
}

#[tauri::command]
fn write_path(path: String, b64: String) -> Result<(), String> {
    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::write(&path, bytes).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_path(path: String) -> Result<(), String> {
    std::fs::remove_file(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal_in_finder(path: String) -> Result<(), String> {
    std::process::Command::new("open")
        .args(["-R", &path])
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// Zip a folder into a single archive using macOS's built-in `zip`, return the
// archive as base64. No new crate — just the system tool (Elur is macOS-only).
// Zips from the folder's parent so the archive contains the folder itself
// (e.g. "MyFolder/file.txt"), so it unzips back into a folder.
#[tauri::command]
fn zip_path(folder: String) -> Result<String, String> {
    let src = std::path::Path::new(&folder);
    let name = src
        .file_name()
        .ok_or("invalid folder")?
        .to_string_lossy()
        .to_string();
    let parent = src.parent().ok_or("folder has no parent")?;
    let mut out = std::env::temp_dir();
    out.push(format!("elur-{}.zip", std::process::id()));
    let out_str = out.to_string_lossy().to_string();

    let status = std::process::Command::new("zip")
        .args(["-r", "-q", "-X", &out_str, &name])
        .current_dir(parent)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("zip command failed".into());
    }
    let bytes = std::fs::read(&out).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&out);
    Ok(STANDARD.encode(bytes))
}

// ---- Walrus (agent memory storage) ----
// Shell out to the `walrus` CLI, exactly like zip_path uses `zip`. GUI apps don't
// inherit the shell PATH, so resolve the suiup-installed binary explicitly.
fn walrus_bin() -> String {
    if let Ok(home) = std::env::var("HOME") {
        let p = format!("{}/.local/bin/walrus", home);
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }
    "walrus".to_string()
}

fn extract_blob_id(s: &str) -> Option<String> {
    // tolerant of `"blobId":"X"` and `"blobId": "X"`
    let i = s.find("blobId")?;
    let after = &s[i + 6..];
    let colon = after.find(':')?;
    let after = &after[colon + 1..];
    let q1 = after.find('"')?;
    let after = &after[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

// List the text documents in a folder (for "give the agent a folder as memory").
#[tauri::command]
fn list_dir(path: String) -> Result<Vec<String>, String> {
    let exts = ["md", "txt", "csv", "tsv", "json", "log", "markdown", "pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "rtf", "html", "htm", "yaml", "yml", "xml", "toml", "ini", "tex", "vtt", "srt", "eml"];
    let mut out: Vec<String> = vec![];
    for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
        let e = entry.map_err(|e| e.to_string())?;
        let p = e.path();
        if p.is_file() {
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_lowercase();
            if exts.contains(&ext.as_str()) {
                out.push(p.to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

#[tauri::command]
fn walrus_store(b64: String, epochs: u32) -> Result<String, String> {
    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("elur-mem-{}.bin", std::process::id()));
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    let out = std::process::Command::new(walrus_bin())
        .args([
            "store",
            &tmp.to_string_lossy(),
            "--epochs",
            &epochs.to_string(),
            "--json",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    extract_blob_id(&stdout).ok_or_else(|| {
        format!(
            "could not parse blobId. stderr: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        )
    })
}

#[tauri::command]
fn walrus_read(id: String) -> Result<String, String> {
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("elur-read-{}.bin", std::process::id()));
    let out = std::process::Command::new(walrus_bin())
        .args(["read", &id, "--out", &tmp.to_string_lossy()])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "walrus read failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    let bytes = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    Ok(STANDARD.encode(bytes))
}

#[tauri::command]
fn keychain_set(value: String) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())
}

#[tauri::command]
fn keychain_get() -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn keychain_clear() -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// Generic account-scoped Keychain storage (e.g. the zkLogin session).
#[tauri::command]
fn kv_set(account: String, value: String) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())
}

#[tauri::command]
fn kv_get(account: String) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn kv_clear(account: String) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// Write decrypted bytes to a temp file and open it with the user's default app
// (PDF → Preview/Acrobat, docx → Word, …). The plaintext copy lives in the temp
// dir; macOS clears it periodically. Returns the path used.
#[tauri::command]
fn open_in_default_app(name: String, b64: String) -> Result<String, String> {
    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
    // keep only a safe base filename (no path tricks)
    let safe: String = name
        .replace(['/', '\\'], "_")
        .trim_start_matches('.')
        .to_string();
    let mut dir = std::env::temp_dir();
    dir.push(format!("elur-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(if safe.is_empty() { "file".into() } else { safe });
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    std::process::Command::new("open")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

// Open the user's default browser (zkLogin sign-in happens there, not in the webview —
// Google blocks OAuth inside embedded webviews).
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://accounts.google.com/")
        || url.starts_with("https://appleid.apple.com/")
        || url.starts_with("https://suiscan.xyz/"))
    {
        return Err("URL not allowed".into());
    }
    std::process::Command::new("open")
        .arg(&url)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_oauth::init())
        .invoke_handler(tauri::generate_handler![
            read_path,
            write_path,
            delete_path,
            reveal_in_finder,
            zip_path,
            list_dir,
            walrus_store,
            walrus_read,
            keychain_set,
            keychain_get,
            keychain_clear,
            kv_set,
            kv_get,
            kv_clear,
            open_url,
            open_in_default_app
        ])
        .run(tauri::generate_context!())
        .expect("error while running Elur");
}
