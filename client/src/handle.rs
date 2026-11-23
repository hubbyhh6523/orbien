use crate::service::Service;
use anyhow::{bail, Result};
use orbien_core::config::ClientConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    Stopped,
    Starting,
    Running,
    Reconnecting,
    Stopping,
}

impl ClientStatus {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Running | Self::Reconnecting | Self::Stopping
        )
    }
}

#[derive(Debug, Default)]
struct TunnelRemoteState {
    gen: u64,
    by_name: HashMap<String, String>,
}

struct Inner {
    status: Mutex<ClientStatus>,
    last_error: Mutex<Option<String>>,
    pending_logs: Mutex<Vec<String>>,
    tunnel_remotes: Mutex<TunnelRemoteState>,
    cancel: Mutex<Option<CancellationToken>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct ClientHandle {
    inner: Arc<Inner>,
}

impl Default for ClientHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                status: Mutex::new(ClientStatus::Stopped),
                last_error: Mutex::new(None),
                pending_logs: Mutex::new(Vec::new()),
                tunnel_remotes: Mutex::new(TunnelRemoteState::default()),
                cancel: Mutex::new(None),
                join: Mutex::new(None),
            }),
        }
    }

    pub fn status(&self) -> ClientStatus {
        *self.inner.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn last_error(&self) -> Option<String> {
        self.inner
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn push_log(&self, line: impl Into<String>) {
        self.enqueue_log(line.into());
    }

    pub fn drain_logs(&self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .inner
                .pending_logs
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }

    pub fn tunnel_remotes_if_changed(
        &self,
        since_gen: u64,
    ) -> Option<(u64, HashMap<String, String>)> {
        let g = self
            .inner
            .tunnel_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if g.gen == since_gen {
            return None;
        }
        Some((g.gen, g.by_name.clone()))
    }

    pub fn clear_tunnel_remotes(&self) {
        let mut g = self
            .inner
            .tunnel_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        g.by_name.clear();
        g.gen = g.gen.wrapping_add(1);
    }

    fn set_tunnel_remote(&self, name: String, remote_addr: String) {
        if name.is_empty() {
            return;
        }
        let mut g = self
            .inner
            .tunnel_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if g.by_name.get(&name) == Some(&remote_addr) {
            return;
        }
        g.by_name.insert(name, remote_addr);
        g.gen = g.gen.wrapping_add(1);
    }

    fn enqueue_log(&self, line: String) {
        if let Ok(mut g) = self.inner.pending_logs.lock() {
            const MAX_PENDING: usize = 500;
            if g.len() >= MAX_PENDING {
                let drop_n = g.len() - MAX_PENDING + 1;
                g.drain(0..drop_n);
            }
            g.push(line);
        }
    }

    fn set_status(&self, s: ClientStatus) {
        if let Ok(mut g) = self.inner.status.lock() {
            *g = s;
        }
    }

    fn set_error(&self, e: Option<String>) {
        if let Ok(mut g) = self.inner.last_error.lock() {
            *g = e;
        }
    }

    pub async fn run_foreground(self, mut cfg: ClientConfig, config_path: PathBuf) -> Result<()> {
        cfg.prepare_runtime(&config_path);
        crate::check_config(&cfg)?;
        // #12: verify-by-default is a config error, not a retryable dial
        // failure — refuse to start instead of looping in reconnect
        // backoff with the reason hidden in the (desktop-only) log queue.
        crate::connector::require_server_trust(&cfg)?;
        let cancel = CancellationToken::new();
        self.set_status(ClientStatus::Starting);
        self.set_error(None);
        self.clear_tunnel_remotes();
        let result = Service::new(cfg, config_path)
            .run(
                cancel.clone(),
                {
                    let h = self.clone();
                    move |st| h.set_status(st)
                },
                {
                    let h = self.clone();
                    move |line| {
                        h.enqueue_log(line);
                    }
                },
                {
                    let h = self.clone();
                    Arc::new(move |name, remote| h.set_tunnel_remote(name, remote))
                },
                {
                    let h = self.clone();
                    Arc::new(move || h.clear_tunnel_remotes())
                },
            )
            .await;
        self.clear_tunnel_remotes();
        self.set_status(ClientStatus::Stopped);
        if let Err(ref e) = result {
            self.set_error(Some(e.to_string()));
        }
        result
    }

    pub fn start(&self, mut cfg: ClientConfig, config_path: PathBuf) -> Result<()> {
        if self.status().is_active() {
            bail!("client already running");
        }
        cfg.prepare_runtime(&config_path);
        crate::check_config(&cfg)?;
        let cancel = CancellationToken::new();
        *self.inner.cancel.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancel.clone());
        self.set_status(ClientStatus::Starting);
        self.set_error(None);
        self.clear_tunnel_remotes();

        let handle = self.clone();
        let join = tokio::spawn(async move {
            let on_status = {
                let h = handle.clone();
                move |st| h.set_status(st)
            };
            let on_log = {
                let h = handle.clone();
                move |line: String| {
                    h.enqueue_log(line);
                }
            };
            let on_tunnel_remote: Arc<dyn Fn(String, String) + Send + Sync> = {
                let h = handle.clone();
                Arc::new(move |name: String, remote: String| h.set_tunnel_remote(name, remote))
            };
            let on_remotes_clear: Arc<dyn Fn() + Send + Sync> = {
                let h = handle.clone();
                Arc::new(move || h.clear_tunnel_remotes())
            };
            let result = Service::new(cfg, config_path)
                .run(
                    cancel,
                    on_status,
                    on_log,
                    on_tunnel_remote,
                    on_remotes_clear,
                )
                .await;
            if let Err(e) = result {
                tracing::error!(error = %e, "client service ended with error");
                handle.set_error(Some(e.to_string()));
            }
            handle.clear_tunnel_remotes();
            handle.set_status(ClientStatus::Stopped);
            *handle
                .inner
                .cancel
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        });
        *self.inner.join.lock().unwrap_or_else(|e| e.into_inner()) = Some(join);
        Ok(())
    }

    pub async fn stop(&self) {
        if matches!(self.status(), ClientStatus::Stopped) {
            return;
        }
        self.set_status(ClientStatus::Stopping);
        if let Some(token) = self
            .inner
            .cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            token.cancel();
        }
        let join = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(join) = join {
            let abort = join.abort_handle();
            match tokio::time::timeout(std::time::Duration::from_secs(5), join).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "client task join error"),
                Err(_) => {
                    tracing::warn!("client stop timed out after 5s — aborting task");
                    abort.abort();
                    self.set_status(ClientStatus::Stopped);
                }
            }
        } else {
            self.set_status(ClientStatus::Stopped);
        }
        self.clear_tunnel_remotes();
    }
}
