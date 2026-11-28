//! Dashboard API keys (#3, slice 2).
//!
//! Config-file keys (`[[dashboard.apiKeys]]`, `{ name, key, scope }`) are
//! validated in `DashboardConfig::validate`; this store is the runtime
//! representation, and it holds **only SHA-256 hashes** — via
//! `orbien_core::auth::token_id`, the same pattern as #11 client tokens.
//! A plaintext key never lives here, in a log line, or in a response.
//! Logs and scope denials carry only the short id (first 16 hex chars of
//! the hash, via `short_token_id`).
//!
//! Lookup is hash-then-map: the presented key is hashed and the digest is
//! the map key, so no raw secret is ever compared. The live store is owned
//! by `Service` (like the #15 access policy) and swapped atomically by
//! config reload, so a key added to or removed from the file takes effect
//! on reload with no restart.

use orbien_core::auth::{short_token_id, token_id};
use orbien_core::config::{ApiKeyConfig, ApiKeyScope};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ApiKeyEntry {
    pub name: String,
    /// First 16 hex chars of the SHA-256 of the key — for logs only.
    pub id: String,
    pub scope: ApiKeyScope,
}

/// Hash-only runtime store for dashboard API keys.
///
/// Custom `Debug`: the map keys are full SHA-256 digests, and a derived
/// `Debug` would print them — a digest is not the plaintext, but there is
/// no reason to ever print it, so only short ids are shown.
#[derive(Default)]
pub struct ApiKeyStore {
    by_hash: HashMap<String, ApiKeyEntry>,
}

impl std::fmt::Debug for ApiKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entries: Vec<&ApiKeyEntry> = self.by_hash.values().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        f.debug_struct("ApiKeyStore")
            .field("keys", &entries)
            .finish()
    }
}

impl ApiKeyStore {
    pub fn from_config(keys: &[ApiKeyConfig]) -> Self {
        let mut by_hash = HashMap::with_capacity(keys.len());
        for k in keys {
            let key = k.key.trim();
            by_hash.insert(
                token_id(key),
                ApiKeyEntry {
                    name: k.name.trim().to_string(),
                    id: short_token_id(key),
                    scope: k.scope,
                },
            );
        }
        Self { by_hash }
    }

    /// Look up a presented key. Returns `None` for an empty presentation
    /// without hashing.
    pub fn lookup(&self, presented: &str) -> Option<&ApiKeyEntry> {
        let presented = presented.trim();
        if presented.is_empty() {
            return None;
        }
        self.by_hash.get(&token_id(presented))
    }

    /// Sorted `(name, hash, scope)` triples, for reload change detection.
    pub fn fingerprint(&self) -> Vec<(String, String, ApiKeyScope)> {
        let mut out: Vec<_> = self
            .by_hash
            .iter()
            .map(|(hash, entry)| (entry.name.clone(), hash.clone(), entry.scope))
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Vec<ApiKeyConfig> {
        vec![
            ApiKeyConfig {
                name: "ops".into(),
                key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                scope: ApiKeyScope::ReadWrite,
            },
            ApiKeyConfig {
                name: "ro".into(),
                key: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .into(),
                scope: ApiKeyScope::Read,
            },
        ]
    }

    #[test]
    fn lookup_hit_miss_and_empty() {
        let store = ApiKeyStore::from_config(&cfg());
        let entry = store
            .lookup("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("ops key must match");
        assert_eq!(entry.name, "ops");
        assert_eq!(entry.scope, ApiKeyScope::ReadWrite);
        assert_eq!(entry.id.len(), 16);
        assert!(store.lookup("0123456789abcdef0123456789abcdef").is_none());
        assert!(store.lookup("").is_none());
        assert!(store.lookup("   ").is_none());
        assert_eq!(store.fingerprint().len(), 2);
    }

    #[test]
    fn store_never_contains_plaintext() {
        let store = ApiKeyStore::from_config(&cfg());
        let debug = format!("{store:?}");
        for k in cfg() {
            assert!(!debug.contains(&k.key), "plaintext key leaked into Debug");
            assert!(!debug.contains(&token_id(&k.key)[16..]), "full hash in Debug");
        }
        // The short id is the only key-derived value present.
        assert!(debug.contains(&short_token_id(&cfg()[0].key)));
    }

    #[test]
    fn fingerprint_changes_on_key_scope_or_membership() {
        let a = ApiKeyStore::from_config(&cfg());
        let mut changed_scope = cfg();
        changed_scope[0].scope = ApiKeyScope::Read;
        assert_ne!(a.fingerprint(), ApiKeyStore::from_config(&changed_scope).fingerprint());
        let mut removed = cfg();
        removed.pop();
        assert_ne!(a.fingerprint(), ApiKeyStore::from_config(&removed).fingerprint());
        assert_eq!(a.fingerprint(), ApiKeyStore::from_config(&cfg()).fingerprint());
    }
}
