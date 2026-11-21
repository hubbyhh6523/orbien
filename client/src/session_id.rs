use std::path::{Path, PathBuf};

pub fn path_for(config_path: &Path) -> PathBuf {
    let mut p = config_path.to_path_buf();
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!("{e}.session_id"))
        .unwrap_or_else(|| "session_id".into());
    p.set_extension(ext);
    p
}

/// Path of the resume-secret file: `<config>.resume_secret`, kept separate
/// from the session id file so old clients reading the id file never see
/// a second line (#11).
pub fn resume_secret_path_for(config_path: &Path) -> PathBuf {
    let mut p = config_path.to_path_buf();
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!("{e}.resume_secret"))
        .unwrap_or_else(|| "resume_secret".into());
    p.set_extension(ext);
    p
}

fn read_valid_id(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| {
            !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        })
}

pub fn load(config_path: &Path) -> String {
    let path = path_for(config_path);
    tighten_permissions(&path);
    read_valid_id(&path).unwrap_or_default()
}

pub fn save(config_path: &Path, session_id: &str) -> std::io::Result<()> {
    let path = path_for(config_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(&path, session_id)
}

/// The resume secret is 32 bytes, hex-encoded (64 chars).
pub fn load_resume_secret(config_path: &Path) -> String {
    let path = resume_secret_path_for(config_path);
    tighten_permissions(&path);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_default()
}

pub fn save_resume_secret(config_path: &Path, secret: &str) -> std::io::Result<()> {
    let path = resume_secret_path_for(config_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(&path, secret)
}

/// Write a file readable only by its owner (#11). On Unix the file is
/// created with mode 0600; on other platforms this is a plain write
/// (documented limitation, same as the server's resume-secret handling).
fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// If the file exists with permissions wider than 0600, tighten it (#11).
/// Best-effort: a failure to tighten must not break login.
fn tighten_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_for_replaces_extension() {
        let p = path_for(Path::new("/tmp/foo.toml"));
        assert_eq!(p, PathBuf::from("/tmp/foo.toml.session_id"));
    }

    #[test]
    fn path_for_without_extension() {
        let p = path_for(Path::new("/tmp/foo"));
        assert_eq!(p, PathBuf::from("/tmp/foo.session_id"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir();
        let cfg = dir.join("orbien_runid_test.toml");
        save(&cfg, "ebe14e38ff3f4073").unwrap();
        assert_eq!(load(&cfg), "ebe14e38ff3f4073");
        std::fs::remove_file(path_for(&cfg)).ok();
    }

    /// Step 6 (#11): saved session id and resume secret files are
    /// owner-only (mode 0600) on Unix.
    #[test]
    #[cfg(unix)]
    fn save_creates_owner_only_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("orbien-s6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        save(&cfg, "ebe14e38ff3f4073").unwrap();
        let mode = std::fs::metadata(path_for(&cfg))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "session id file must be 0600, got {mode:o}");
        let secret = "ab".repeat(32);
        save_resume_secret(&cfg, &secret).unwrap();
        let mode = std::fs::metadata(resume_secret_path_for(&cfg))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "resume secret file must be 0600, got {mode:o}");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Step 6 (#11): loading a file created with mode 0644 tightens it
    /// to 0600, for both the session id and the resume secret.
    #[test]
    #[cfg(unix)]
    fn load_tightens_wide_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("orbien-s6-tighten-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        let id_path = path_for(&cfg);
        std::fs::write(&id_path, "ebe14e38ff3f4073").unwrap();
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load(&cfg), "ebe14e38ff3f4073");
        let mode = std::fs::metadata(&id_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "session id file must be tightened to 0600");
        let secret_path = resume_secret_path_for(&cfg);
        let secret = "cd".repeat(32);
        std::fs::write(&secret_path, &secret).unwrap();
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_resume_secret(&cfg), secret);
        let mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "resume secret file must be tightened to 0600");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn resume_secret_roundtrip() {
        let dir = std::env::temp_dir();
        let cfg = dir.join("orbien_runid_secret_test.toml");
        let secret = "ab".repeat(32);
        save_resume_secret(&cfg, &secret).unwrap();
        assert_eq!(load_resume_secret(&cfg), secret);
        std::fs::remove_file(resume_secret_path_for(&cfg)).ok();
    }

    #[test]
    fn load_rejects_invalid() {
        let dir = std::env::temp_dir();
        let cfg = dir.join("orbien_runid_invalid.toml");
        // Write a value with invalid chars (space) directly to the run_id file.
        let p = path_for(&cfg);
        std::fs::write(&p, "has space here").unwrap();
        assert_eq!(load(&cfg), "");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn load_missing_returns_empty() {
        let cfg = Path::new("/nonexistent/dir/config.toml");
        assert_eq!(load(cfg), "");
    }
}
