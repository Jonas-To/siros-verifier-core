//! Pluggable configuration interfaces.
//!
//! The verifier's boot resolves each configuration category through a
//! **provider trait** declared here; the concrete, operational
//! implementations (environment variables, files, a client roster) live
//! in the service and adapters — the sans-I/O core defines the effect
//! interface, the host supplies the resolution (see AGENTS.md: transport,
//! storage, and key resolution belong to the host).
//!
//! The key principle (following SUNET/vc #935): a container platform hands
//! a process a credential as an **environment variable backed by a
//! Secret** — not as a sidecar-rendered secrets file. The config names the
//! source of each secret (`pdp_bearer_token_env = "VC_PDP_TOKEN"`), the
//! provider resolves it at boot, and the platform (a k8s
//! `secretKeyRef`, a Fly secret, a compose `environment:` entry) owns the
//! Secret itself. Per-field explicit references, not derived names —
//! derived names collide on opaque identifiers. Two sources named for one
//! value are refused at boot: two sources is two different beliefs about
//! where a value comes from.
//!
//! - [`SecretProvider`] resolves one secret value from its named source.
//! - [`ClientRegistrationProvider`] produces an OIDC frontend's client
//!   roster. Dynamic client registration is a property of the backend
//!   implementation, not the trait.

use serde_json::Value;

use crate::error::Error;
use crate::Result;

// ---- secrets ----------------------------------------------------------------

/// Where one secret value comes from. The config names the source
/// explicitly per field; the provider resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretSource {
    /// An environment variable. The platform-native channel: a k8s
    /// Secret's `env.valueFrom.secretKeyRef`, a Fly secret, a compose
    /// `environment:` entry.
    Env(String),
    /// A file path. The k8s Secret volume-mount model: the Secret's keys
    /// materialize as files, one per key. `external-secrets.io`, the
    /// Vault Agent and the CSI driver all materialize files too.
    ///
    /// Relative paths resolve against the provider's base directory (a
    /// mount point or the config directory), not the process working
    /// directory.
    File(String),
}

impl SecretSource {
    /// A short human name for error messages: names the entry AND the
    /// variable or file involved.
    pub fn describe(&self) -> String {
        match self {
            SecretSource::Env(name) => format!("env var {name}"),
            SecretSource::File(path) => format!("secret file {path}"),
        }
    }
}

/// Resolves one secret value at boot.
///
/// Fail-fast contract: a missing or empty value is an error naming the
/// entry and the source involved — never a silent default. An empty value
/// is as useless as a missing one, and an empty file is a mounted key that
/// was never filled in. Implementations must not cache across boots: the
/// process restarts to pick up rotated secrets.
pub trait SecretProvider: Send + Sync {
    fn resolve(&self, source: &SecretSource) -> Result<String>;
}

/// Resolve a scalar secret-bearing field: at most one of the inline value,
/// the `_env` reference and the `_file` reference may be present.
///
/// This is the per-field pattern every secret-bearing deployment field
/// follows. Two sources named for one value is two different beliefs
/// about where the value comes from — refused with the field named.
pub fn resolve_secret_field(
    field: &str,
    inline: Option<&str>,
    env: Option<&str>,
    file: Option<&str>,
    provider: &dyn SecretProvider,
) -> Result<Option<String>> {
    let named: Vec<&str> = [env, file].into_iter().flatten().collect();
    if inline.is_some() && !named.is_empty() {
        return Err(Error::Policy(format!(
            "config field {field}: both an inline value and a {} reference are set — pick one source",
            if env.is_some() { "_env" } else { "_file" }
        )));
    }
    if env.is_some() && file.is_some() {
        return Err(Error::Policy(format!(
            "config field {field}: both _env and _file references are set — pick one source"
        )));
    }
    match (inline, env, file) {
        (Some(value), None, None) => Ok(Some(value.to_string())),
        (None, Some(name), None) => Ok(Some(
            provider
                .resolve(&SecretSource::Env(name.to_string()))
                .map_err(|e| Error::Policy(format!("config field {field}: {e}")))?,
        )),
        (None, None, Some(name)) => Ok(Some(
            provider
                .resolve(&SecretSource::File(name.to_string()))
                .map_err(|e| Error::Policy(format!("config field {field}: {e}")))?,
        )),
        (None, None, None) => Ok(None),
        // unreachable: the guards above refuse every combination with
        // more than one source; kept exhaustive anyway.
        _ => Err(Error::Policy(format!(
            "config field {field}: conflicting secret sources"
        ))),
    }
}

// ---- client registration ----------------------------------------------------

/// Manages an OIDC frontend's registered clients.
///
/// The default implementation (in the service) is config+secret
/// management: the `[[frontend.config.clients]]` block with per-entry
/// `client_secret_env` overrides. A cluster deployment can swap in a
/// database roster (clients in the flow-storage database, managed
/// through an admin API) or an external registration API (RFC 7591
/// against an authorization server's registration endpoint).
///
/// Dynamic client registration is a property of the backend
/// implementation, not of the trait.
pub trait ClientRegistrationProvider: Send + Sync {
    /// The resolved roster: one JSON object per client, its `_env`
    /// references already resolved to inline values, ready for the
    /// consumer's strict parser (which rejects unknown fields, so a
    /// misspelled key still fails the boot).
    fn clients(&self) -> Result<Vec<Value>>;
}
