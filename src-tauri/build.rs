use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == ".venv" || name == "__pycache__")
        .unwrap_or(false)
}

fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        if should_skip(&path) {
            continue;
        }
        let target = dest.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target)?;
        } else if path.is_file() {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

fn sync_backend_resources() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let root_dir = manifest_dir
        .parent()
        .ok_or("Missing repo root")?
        .to_path_buf();
    let src = root_dir.join("backend");
    let dest = manifest_dir.join("resources").join("backend");

    if dest.exists() {
        fs::remove_dir_all(&dest)?;
    }

    if src.exists() {
        copy_dir(&src, &dest)?;
    } else {
        fs::create_dir_all(&dest)?;
    }

    Ok(())
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Missing manifest dir"));
    env::set_current_dir(&manifest_dir).expect("Failed to set build working directory");
    sync_backend_resources().expect("Failed to sync backend resources");
    tauri_build::build()
}
