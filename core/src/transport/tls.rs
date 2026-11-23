use super::stream::{boxed_stream, DynStream};
use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const ALPN_ORBIEN: &[u8] = b"orbien";
pub const TLS_HANDSHAKE_TYPE: u8 = 0x16;

pub struct GeneratedCert {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivatePkcs8KeyDer<'static>,
}

pub fn generate_self_signed_cert(common_name: &str) -> Result<GeneratedCert> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])?;
    params
        .subject_alt_names
        .push(SanType::DnsName(common_name.try_into()?));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    Ok(GeneratedCert {
        certs: vec![cert_der],
        key: key_der,
    })
}

#[derive(Debug)]
pub struct SkipServerVerification;

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn install_ring_provider() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(())
}

// ── H1: Trust-On-First-Use server certificate pinning ────────────────────────

/// SHA-256 over the end-entity certificate DER, hex encoded.
///
/// Note: this pins the *certificate*, not the bare SPKI — renewing a cert with
/// the same key (e.g. Let's Encrypt renewal) changes the fingerprint and
/// triggers a re-pin. This is conservative and safe; the alternative (parsing
/// the SPKI out of the DER) needs an x509 parser dependency.
fn cert_fingerprint(end_entity: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(end_entity.as_ref());
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// In-process fingerprint cache so concurrent connections to the same host
/// within one process don't each rewrite the store file.
type FingerprintCache = Mutex<HashMap<String, String>>;

/// TOFU verifier: accepts the server certificate on first contact (recording
/// the whole-certificate hash), then requires an exact match on every later connection.
/// A mismatch is a hard failure — that's a potential MITM.
#[derive(Debug)]
struct TofuServerVerifier {
    store_path: PathBuf,
    cache: FingerprintCache,
    base_verify_schemes: Vec<SignatureScheme>,
}

impl TofuServerVerifier {
    fn new(store_path: PathBuf) -> Result<Self> {
        // Signature schemes don't depend on verification mode.
        let base = SkipServerVerification::new();
        let schemes = base.supported_verify_schemes();
        let mut cache = HashMap::new();
        if store_path.exists() {
            let raw = std::fs::read_to_string(&store_path)
                .with_context(|| format!("read TOFU store {}", store_path.display()))?;
            for line in raw.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Format: "<server_name|ip:port>\t<sha256-hex>"
                if let Some((host, fp)) = line.split_once('\t') {
                    cache.insert(host.to_string(), fp.to_string());
                }
            }
        }
        Ok(Self {
            store_path,
            cache: Mutex::new(cache),
            base_verify_schemes: schemes,
        })
    }

    /// Returns (fingerprint, is_first_use). Persists newly pinned fingerprints.
    fn check_and_pin(&self, host_key: &str, fingerprint: &str) -> Result<bool> {
        let mut cache = self.cache.lock().expect("tofu cache poisoned");
        match cache.get(host_key) {
            Some(pinned) => {
                if pinned == fingerprint {
                    Ok(false)
                } else {
                    bail!(
                        "TOFU mismatch for {host_key}: pinned {pinned} but server presented {fingerprint}. \
                         This may be a man-in-the-middle attack, or the server key was rotated. \
                         To accept the new key, remove the entry from {}",
                        self.store_path.display()
                    );
                }
            }
            None => {
                cache.insert(host_key.to_string(), fingerprint.to_string());
                // Persist: sorted lines, header comment for humans.
                let mut entries: Vec<(String, String)> =
                    cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                entries.sort();
                let mut out = String::from(
                    "# orbien TOFU store — <host>\\t<sha256 of server cert>\n# delete a line to re-pin on next connect\n",
                );
                for (k, v) in entries {
                    out.push_str(&format!("{k}\t{v}\n"));
                }
                let tmp = self.store_path.with_extension("tmp");
                std::fs::write(&tmp, out.as_bytes())
                    .and_then(|_| std::fs::rename(&tmp, &self.store_path))
                    .with_context(|| format!("write TOFU store {}", self.store_path.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = std::fs::set_permissions(
                        &self.store_path,
                        std::fs::Permissions::from_mode(0o600),
                    ) {
                        tracing::warn!(path = %self.store_path.display(), "TOFU store chmod failed: {e}");
                    }
                }
                Ok(true)
            }
        }
    }
}

impl ServerCertVerifier for TofuServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Host key: DNS name or IP literal as presented by the connector.
        let host_key = server_name.to_str().to_string();
        let fingerprint = cert_fingerprint(end_entity);
        match self.check_and_pin(&host_key, &fingerprint) {
            Ok(true) => {
                tracing::warn!(
                    host = %host_key,
                    fingerprint = %fingerprint,
                    "TOFU: pinning new server certificate on first connection"
                );
                Ok(ServerCertVerified::assertion())
            }
            Ok(false) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(rustls::Error::General(e.to_string())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TOFU only governs the trust anchor; signature checks use the ring
        // provider's algorithm table (same semantics as webpki verification).
        let algs = &rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algs = &rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base_verify_schemes.clone()
    }
}

pub fn load_pem_cert_key(
    cert_file: &str,
    key_file: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Prevent path traversal: reject paths containing '..' components.
    let cert_path = Path::new(cert_file);
    if cert_path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        bail!("Invalid certFile path (path traversal detected): {}", cert_path.display());
    }
    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("open certFile {cert_file}"))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certificate PEM")?
        .into_iter()
        .collect();
    if certs.is_empty() {
        bail!("no certificates in {cert_file}");
    }

    // Prevent path traversal: reject paths containing '..' components.
    let key_path = Path::new(key_file);
    if key_path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        bail!("Invalid keyFile path (path traversal detected): {}", key_path.display());
    }
    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("open keyFile {key_file}"))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key in {key_file}"))?;

    Ok((certs, key))
}

fn load_ca_roots(ca_path: &str) -> Result<RootCertStore> {
    let mut reader = BufReader::new(
        File::open(Path::new(ca_path)).with_context(|| format!("open trustedCaFile {ca_path}"))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse CA PEM")?
        .into_iter()
        .collect();
    if certs.is_empty() {
        bail!("no CA certificates in {ca_path}");
    }
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|e| anyhow::anyhow!("add CA cert: {e}"))?;
    }
    Ok(roots)
}

pub fn new_server_tls_config(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
) -> Result<Arc<ServerConfig>> {
    install_ring_provider()?;

    let (certs, key) = if cert_file.trim().is_empty() || key_file.trim().is_empty() {
        tracing::info!(
            "transport.tls: no certFile/keyFile — generating ephemeral self-signed cert"
        );
        let gen = generate_self_signed_cert("orbien-server")?;
        (gen.certs, PrivateKeyDer::Pkcs8(gen.key))
    } else {
        load_pem_cert_key(cert_file, key_file)?
    };

    let builder = if ca_path.trim().is_empty() {
        ServerConfig::builder().with_no_client_auth()
    } else {
        let roots = load_ca_roots(ca_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build client cert verifier")?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    };

    let cfg = builder
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")?;

    Ok(Arc::new(cfg))
}

pub fn new_client_tls_config(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
) -> Result<Arc<ClientConfig>> {
    new_client_tls_config_inner(cert_file, key_file, ca_path, None)
}

/// H1 (TOFU): builds a client TLS config with Trust-On-First-Use pinning.
///
/// When `tofu_store` is `Some(path)` (and no explicit `ca_path` is set), the
/// server's certificate SHA-256 hash is compared against the store:
///   - first connection: fingerprint recorded, connection allowed (warned),
///   - subsequent matches: allowed silently,
///   - mismatch: connection refused (potential MITM).
///
/// Explicit CA verification always takes precedence when `ca_path` is set.
///
/// # Scope
/// Applies to TCP, WebSocket and KCP dials (they share `TlsDialOpts`).
/// QUIC dials also participate when `client_crypto_with_tofu` is used to
/// build their crypto config (see `quic.rs`); the legacy `client_crypto_from_tls_files`
/// path does NOT pin and is kept for backward compatibility.
pub fn new_client_tls_config_tofu(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
    tofu_store: Option<&std::path::Path>,
) -> Result<Arc<ClientConfig>> {
    new_client_tls_config_inner(cert_file, key_file, ca_path, tofu_store)
}

fn new_client_tls_config_inner(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
    tofu_store: Option<&std::path::Path>,
) -> Result<Arc<ClientConfig>> {
    install_ring_provider()?;

    let builder = if !ca_path.trim().is_empty() {
        // Explicit CA verification has highest priority.
        let roots = load_ca_roots(ca_path)?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .context("build server cert verifier")?;
        ClientConfig::builder().with_webpki_verifier(verifier)
    } else if let Some(store_path) = tofu_store {
        let verifier = Arc::new(TofuServerVerifier::new(store_path.to_path_buf())?);
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
    } else {
        // Legacy insecure path: no CA, no TOFU store.
        tracing::warn!(
            "transport.tls: no trustedCaFile and no tofuStoreFile — skipping server certificate verification (MITM possible)"
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
    };

    let cfg = if !cert_file.trim().is_empty() && !key_file.trim().is_empty() {
        let (certs, key) = load_pem_cert_key(cert_file, key_file)?;
        builder
            .with_client_auth_cert(certs, key)
            .context("load client certificate")?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Arc::new(cfg))
}

pub fn server_crypto_from_tls_files(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
) -> Result<quinn::crypto::rustls::QuicServerConfig> {
    let mut cfg = (*new_server_tls_config(cert_file, key_file, ca_path)?).clone();
    cfg.alpn_protocols = vec![ALPN_ORBIEN.to_vec()];

    quinn::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|e| anyhow::anyhow!("QuicServerConfig: {e}"))
}

pub fn client_crypto_from_tls_files(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
) -> Result<quinn::crypto::rustls::QuicClientConfig> {
    let mut cfg = (*new_client_tls_config(cert_file, key_file, ca_path)?).clone();
    cfg.alpn_protocols = vec![ALPN_ORBIEN.to_vec()];
    quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
        .map_err(|e| anyhow::anyhow!("QuicClientConfig: {e}"))
}

pub fn server_crypto(
    certs: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
) -> Result<quinn::crypto::rustls::QuicServerConfig> {
    install_ring_provider()?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .context("build rustls ServerConfig")?;
    cfg.alpn_protocols = vec![ALPN_ORBIEN.to_vec()];
    quinn::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|e| anyhow::anyhow!("QuicServerConfig: {e}"))
}

pub fn client_crypto_insecure() -> Result<quinn::crypto::rustls::QuicClientConfig> {
    client_crypto_from_tls_files("", "", "")
}

/// H1 (TOFU): build a QUIC client crypto config with certificate pinning.
/// Same TOFU semantics as the TCP/WS/KCP path; when `tofu_store` is None the
/// behaviour falls back to `client_crypto_from_tls_files` unchanged.
pub fn client_crypto_with_tofu(
    cert_file: &str,
    key_file: &str,
    ca_path: &str,
    tofu_store: Option<&std::path::Path>,
) -> Result<quinn::crypto::rustls::QuicClientConfig> {
    let mut cfg = (*new_client_tls_config_tofu(cert_file, key_file, ca_path, tofu_store)?).clone();
    cfg.alpn_protocols = vec![ALPN_ORBIEN.to_vec()];
    quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
        .map_err(|e| anyhow::anyhow!("QuicClientConfig: {e}"))
}

pub async fn client_enable_tls(
    stream: DynStream,
    tls_cfg: Arc<ClientConfig>,
    server_name: &str,
) -> Result<DynStream> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid tls serverName {server_name}: {e}"))?;
    let connector = TlsConnector::from(tls_cfg);
    let tls = connector
        .connect(name, stream)
        .await
        .context("client TLS handshake")?;
    Ok(boxed_stream(tls))
}

pub async fn check_and_enable_tls(
    mut stream: DynStream,
    tls_cfg: Arc<ServerConfig>,
    force: bool,
) -> Result<DynStream> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .context("peek TLS first byte")?;

    match first[0] {
        TLS_HANDSHAKE_TYPE => {
            let stream = PrefixedByteStream {
                prefix: Some(first[0]),
                inner: stream,
            };
            let acceptor = TlsAcceptor::from(tls_cfg);
            let tls = acceptor
                .accept(boxed_stream(stream))
                .await
                .context("server TLS handshake")?;
            Ok(boxed_stream(tls))
        }
        _ if force => {
            bail!(
                "transport.tls.force=true but first byte is 0x{:02x} (expected TLS handshake 0x16)",
                first[0]
            );
        }
        _ => Ok(boxed_stream(PrefixedByteStream {
            prefix: Some(first[0]),
            inner: stream,
        })),
    }
}

struct PrefixedByteStream {
    prefix: Option<u8>,
    inner: DynStream,
}

impl AsyncRead for PrefixedByteStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(b) = self.prefix.take() {
            if buf.remaining() > 0 {
                buf.put_slice(&[b]);
                return std::task::Poll::Ready(Ok(()));
            }
            self.prefix = Some(b);
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedByteStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
