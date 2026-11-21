use super::{HttpTunnel, HttpsTunnel, TcpTunnel, UdpTunnel};
use std::collections::HashMap;

pub enum RegisteredTunnel {
    Tcp(TcpTunnel),
    Http(HttpTunnel),
    Https(HttpsTunnel),
    Udp(UdpTunnel),
}

impl RegisteredTunnel {
    pub fn tunnel_type(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Http(_) => "http",
            Self::Https(_) => "https",
            Self::Udp(_) => "udp",
        }
    }

    pub async fn close(&self) {
        match self {
            Self::Tcp(p) => p.close().await,
            Self::Http(p) => p.close().await,
            Self::Https(p) => p.close().await,
            Self::Udp(p) => p.close().await,
        }
    }
}

struct TunnelEntry {
    tunnel: RegisteredTunnel,
    local_addr: String,
}

pub struct TunnelManager {
    tunnels: HashMap<String, TunnelEntry>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
        }
    }

    pub async fn insert(
        &mut self,
        name: String,
        tunnel: RegisteredTunnel,
        local_addr: String,
    ) -> Option<&'static str> {
        let entry = TunnelEntry { tunnel, local_addr };
        if let Some(old) = self.tunnels.insert(name, entry) {
            let ty = old.tunnel.tunnel_type();
            old.tunnel.close().await;
            Some(ty)
        } else {
            None
        }
    }

    pub async fn remove(&mut self, name: &str) -> Option<&'static str> {
        if let Some(entry) = self.tunnels.remove(name) {
            let ty = entry.tunnel.tunnel_type();
            entry.tunnel.close().await;
            Some(ty)
        } else {
            None
        }
    }

    pub async fn close_all(&mut self) -> Vec<(String, &'static str)> {
        let mut closed = Vec::with_capacity(self.tunnels.len());
        for (name, entry) in self.tunnels.drain() {
            closed.push((name, entry.tunnel.tunnel_type()));
            entry.tunnel.close().await;
        }
        closed
    }

    pub fn summaries(&self) -> Vec<TunnelSummary> {
        self.tunnels
            .iter()
            .map(|(name, entry)| {
                let (tunnel_type, remote_addr) = match &entry.tunnel {
                    RegisteredTunnel::Tcp(t) => ("tcp".into(), format!(":{}", t.remote_port)),
                    RegisteredTunnel::Http(h) => ("http".into(), h.domains.join(",")),
                    RegisteredTunnel::Https(h) => ("https".into(), h.domains.join(",")),
                    RegisteredTunnel::Udp(u) => ("udp".into(), format!(":{}", u.remote_port)),
                };
                TunnelSummary {
                    name: name.clone(),
                    tunnel_type,
                    remote_addr,
                    local_addr: entry.local_addr.clone(),
                    status: "online".into(),
                }
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tunnels.contains_key(name)
    }
}

pub fn format_local_addr(ip: &str, port: i32) -> String {
    let ip = ip.trim();
    if ip.is_empty() && port <= 0 {
        return String::new();
    }
    if ip.is_empty() {
        return format!(":{port}");
    }
    if port <= 0 {
        return ip.to_string();
    }
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TunnelSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub tunnel_type: String,
    #[serde(rename = "remoteAddr")]
    pub remote_addr: String,
    #[serde(rename = "localAddr")]
    pub local_addr: String,
    pub status: String,
}
