use orbien_client::{check_config, ClientConfig, ClientHandle, ClientStatus};

struct ConfigFile(std::path::PathBuf);

impl ConfigFile {
    fn new(text: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "orbien-step3-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test directory: {e}"),
            }
        };
        let path = dir.join("config.toml");
        std::fs::write(&path, text).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

#[test]
fn offline_preflight_runs_without_a_runtime_and_does_not_write_pins() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let file = ConfigFile::new("server = 'must-not-resolve.invalid:9527'");
    let mut cfg = ClientConfig::load(&file.0).unwrap();
    let store = file.0.parent().unwrap().join("pins.txt");
    cfg.transport.tls.tofu_store_file = store.to_string_lossy().into_owned();
    check_config(&cfg).unwrap();
    assert!(!store.exists());
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[test]
fn plugin_headers_are_checked_by_the_actual_plugin_constructor() {
    let file = ConfigFile::new(r#"
[[tunnels]]
name = 'web'
protocol = 'https'
domains = ['web.example']
[tunnels.plugin]
type = 'tls-term'
service = '127.0.0.1:8080'
[tunnels.plugin.requestHeaders.set]
X-Any-Custom-Name = 'accepted'
"#);
    let mut cfg = ClientConfig::load(&file.0).unwrap();
    check_config(&cfg).unwrap();
    cfg.tunnels[0].plugin.as_mut().unwrap().request_headers.set
        .insert("X-Forwarded-Proto".to_owned(), "https".to_owned());
    let error = format!("{:#}", check_config(&cfg).unwrap_err());
    assert!(error.contains("protected"), "{error}");
}

#[test]
fn referenced_tls_files_are_required_by_preflight() {
    let file = ConfigFile::new("[transport.tls]\ntrustedCaFile = 'missing-ca.pem'");
    let cfg = ClientConfig::load(&file.0).unwrap();
    let error = format!("{:#}", check_config(&cfg).unwrap_err());
    assert!(error.contains("transport.tls preflight"), "{error}");
    assert!(error.contains("missing-ca.pem"), "{error}");
}

#[test]
fn invalid_start_does_not_mutate_handle_or_spawn_a_task() {
    let file = ConfigFile::new("[transport.tls]\ntrustedCaFile = 'missing-ca.pem'");
    let cfg = ClientConfig::load(&file.0).unwrap();
    let handle = ClientHandle::new();
    assert!(handle.start(cfg, file.0.clone()).is_err());
    assert_eq!(handle.status(), ClientStatus::Stopped);
    assert!(handle.last_error().is_none());
    assert!(handle.drain_logs().is_empty());
}
