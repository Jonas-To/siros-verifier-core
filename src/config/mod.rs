//! Pluggable configuration providers.
//!
//! The verifier's boot resolves each configuration category through a
//! provider trait, with a default implementation that preserves the
//! current file/env behavior. A deployment selects alternative providers
//! without forking the boot code.
//!
//! The key principle (following SUNET/vc #935): a container platform hands
//! a process a credential as an **environment variable backed by a
//! Secret** — not as a sidecar-rendered secrets file. The config names
//! the source of each secret (`pdp_bearer_token_env = "VC_PDP_TOKEN"`),
//! the provider resolves it at boot, and the platform (a k8s
//! `secretKeyRef`, a Fly secret, a compose `environment:` entry) owns
//! the Secret itself.
//!
//! Per-field explicit references, not derived names — derived names
//! collide on opaque identifiers. Two sources named for one value are
//! refused at boot: two sources is two different beliefs about where a
//! value comes from.
//!
//! - [`SecretProvider`] resolves one secret value. The env-var
//!   implementation is the default; the file implementation covers the
//!   Secret volume-mount model (including external-secrets.io, Vault
//!   Agent and the CSI driver, all of which materialize files).
//! - [`ClientRegistrationProvider`] produces an OIDC frontend's client
//!   roster. The default reads the config block (with `_env` credential
//!   overrides); a database or an external registration API are further
//!   implementations. Dynamic client registration is a property of the
//!   backend, not the trait.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

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
    /// Relative paths resolve against the provider's base directory (the
    /// mount point), not the process working directory.
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
/// entry and the source involved — never a silent default. Implementations
/// must not cache across boots: the process restarts to pick up rotated
/// secrets.
pub trait SecretProvider: Send + Sync {
    fn resolve(&self, source: &SecretSource) -> Result<String>;
}

/// The env-var implementation: the platform-native secret channel.
///
/// A k8s Secret reaches the process as an env var through
/// `secretKeyRef`; the provider just reads it. This is the default.
pub struct EnvVarSecretProvider;

impl SecretProvider for EnvVarSecretProvider {
    fn resolve(&self, source: &SecretSource) -> Result<String> {
        match source {
            SecretSource::Env(name) => match std::env::var(name) {
                Ok(value) if !value.is_empty() => Ok(value),
                Ok(_) => Err(Error::Policy(format!(
                    "secret provider: env var {name} is set to the empty string"
                ))),
                Err(_) => Err(Error::Policy(format!(
                    "secret provider: env var {name} is not set"
                ))),
            },
            SecretSource::File(path) => Err(Error::Policy(format!(
                "secret provider: this provider resolves env vars only, not the secret file {path}"
            ))),
        }
    }
}

/// The file implementation: the k8s Secret volume-mount model.
///
/// A mounted Secret materializes its keys as files under one directory;
/// [`FileSecretProvider`] resolves a relative source against that base
/// directory. Absolute paths resolve as-given. An empty file is an
/// error (a mounted key that was never filled in), a missing file an
/// error (the mount is not what the config believes).
pub struct FileSecretProvider {
    /// The mount point: a mounted Secret's directory, or the config
    /// directory for sibling secret files.
    base: PathBuf,
}

impl FileSecretProvider {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn path(&self, source: &str) -> PathBuf {
        let p = Path::new(source);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base.join(p)
        }
    }
}

impl SecretProvider for FileSecretProvider {
    fn resolve(&self, source: &SecretSource) -> Result<String> {
        match source {
            SecretSource::File(name) => {
                let path = self.path(name);
                std::fs::read_to_string(&path).map_err(|e| {
                    Error::Policy(format!(
                        "secret provider: reading {} for {name}: {e}",
                        path.display()
                    ))
                })
            }
            SecretSource::Env(name) => Err(Error::Policy(format!(
                "secret provider: this provider resolves secret files only, not env var {name}"
            ))),
        }
    }
}

/// Both platform channels in one provider: `_env` references resolve
/// through the environment, `_file` references against a base directory
/// (the config directory, so a relative file sits beside the config the
/// way sibling paths resolve). Serves a config that mixes the two
/// reference styles — a k8s deployment with some Secrets as
/// `secretKeyRef` env vars and some as volume mounts.
pub struct PlatformSecretProvider {
    env: EnvVarSecretProvider,
    files: FileSecretProvider,
}

impl PlatformSecretProvider {
    /// `file_base` is the directory relative `_file` references resolve
    /// against — the config file's directory in the service boot.
    pub fn new(file_base: impl Into<PathBuf>) -> Self {
        Self {
            env: EnvVarSecretProvider,
            files: FileSecretProvider::new(file_base),
        }
    }
}

impl SecretProvider for PlatformSecretProvider {
    fn resolve(&self, source: &SecretSource) -> Result<String> {
        match source {
            SecretSource::Env(_) => self.env.resolve(source),
            SecretSource::File(_) => self.files.resolve(source),
        }
    }
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
/// The default implementation is config+secret management: the
/// `[[frontend.config.clients]]` block with per-entry `_env` credential
/// overrides ([`ConfigClientRegistration`]). A cluster deployment can
/// swap in a database roster (clients in the flow-storage database,
/// managed through an admin API) or an external registration API (RFC
/// 7591 against an authorization server's registration endpoint).
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

/// The default [`ClientRegistrationProvider`]: the config block plus a
/// secret provider.
///
/// Each entry may carry its credential as an inline `client_secret`, as
/// a `client_secret_env` reference, or not at all (a `none`/`private_key_jwt`
/// client). The `_env` reference is resolved through the secret provider
/// at boot and stripped from the entry before it reaches the consumer's
/// parser — the downstream client model never learns about `_env`
/// fields. Both an inline secret and an `_env` reference on one entry is
/// refused, as is a duplicate `client_id` across the roster (the
/// consumer's store keys by id and would silently keep only the last).
pub struct ConfigClientRegistration {
    entries: Vec<Value>,
    secrets: std::sync::Arc<dyn SecretProvider>,
}

impl ConfigClientRegistration {
    /// Build from the raw config block (the `[[frontend.config.clients]]`
    /// array as the config system handed it to the boot).
    pub fn new(entries: Vec<Value>, secrets: std::sync::Arc<dyn SecretProvider>) -> Self {
        Self { entries, secrets }
    }

    /// Resolve one entry: validate the secret source combination, resolve
    /// the credential, strip the `_env` field.
    fn resolve_entry(&self, entry: Value) -> Result<Value> {
        let id = entry
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing client_id>")
            .to_string();
        let object = match entry {
            Value::Object(map) => map,
            _ => {
                return Err(Error::Policy(format!(
                    "client {id}: the roster entry is not a JSON object"
                )))
            }
        };
        let inline = object.get("client_secret").cloned();
        let env = object.get("client_secret_env").cloned();
        if inline.is_some() && env.is_some() {
            return Err(Error::Policy(format!(
                "client {id}: both client_secret and client_secret_env are set — two sources for one value"
            )));
        }
        let mut object = object;
        if let Some(env) = env {
            let name = env.as_str().ok_or_else(|| {
                Error::Policy(format!("client {id}: client_secret_env is not a string"))
            })?;
            let secret = self
                .secrets
                .resolve(&SecretSource::Env(name.to_string()))
                .map_err(|e| Error::Policy(format!("client {id}: {e}")))?;
            if secret.is_empty() {
                return Err(Error::Policy(format!(
                    "client {id}: client_secret_env {name} is set to the empty string"
                )));
            }
            object.insert("client_secret".into(), Value::String(secret));
        }
        object.remove("client_secret_env");
        Ok(Value::Object(object))
    }
}

impl ClientRegistrationProvider for ConfigClientRegistration {
    fn clients(&self) -> Result<Vec<Value>> {
        let mut resolved = Vec::with_capacity(self.entries.len());
        let mut seen: HashSet<String> = HashSet::with_capacity(self.entries.len());
        for entry in self.entries.clone() {
            let value = self.resolve_entry(entry)?;
            let id = value
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Policy("client roster entry has no string client_id".into()))?
                .to_string();
            if !seen.insert(id.clone()) {
                return Err(Error::Policy(format!(
                    "duplicate client_id '{id}' across the client roster: the consumer's store keys by id and would silently keep only the last"
                )));
            }
            resolved.push(value);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A fake provider for deterministic tests: hands out canned values
    /// for the sources it knows, refuses everything else.
    struct FakeProvider {
        env: Vec<(&'static str, &'static str)>,
    }

    impl SecretProvider for FakeProvider {
        fn resolve(&self, source: &SecretSource) -> Result<String> {
            match source {
                SecretSource::Env(name) => self
                    .env
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.to_string())
                    .ok_or_else(|| {
                        Error::Policy(format!("secret provider: env var {name} is not set"))
                    }),
                SecretSource::File(path) => Err(Error::Policy(format!(
                    "secret provider: env vars only, not the secret file {path}"
                ))),
            }
        }
    }

    fn provider() -> std::sync::Arc<dyn SecretProvider> {
        std::sync::Arc::new(FakeProvider {
            env: vec![("VC_TEST_SECRET", "s3cret")],
        })
    }

    #[test]
    fn a_roster_entry_with_an_env_reference_resolves_and_strips_it() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret_env": "VC_TEST_SECRET",
                "redirect_uris": ["https://rp.example.org/callback"],
            })],
            provider(),
        );
        let clients = reg.clients().expect("resolution succeeds");
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0]["client_secret"], "s3cret");
        assert!(clients[0].get("client_secret_env").is_none());
        assert_eq!(
            clients[0]["redirect_uris"][0],
            "https://rp.example.org/callback"
        );
    }

    #[test]
    fn an_inline_secret_passes_through_untouched() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret": "inline-value",
            })],
            provider(),
        );
        let clients = reg.clients().expect("resolution succeeds");
        assert_eq!(clients[0]["client_secret"], "inline-value");
    }

    #[test]
    fn an_entry_without_a_secret_passes_through() {
        // A `none` or `private_key_jwt` client carries no client_secret at all.
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "token_endpoint_auth_method": "private_key_jwt",
            })],
            provider(),
        );
        let clients = reg.clients().expect("resolution succeeds");
        assert!(clients[0].get("client_secret").is_none());
    }

    #[test]
    fn the_full_client_shape_survives_the_env_resolution() {
        // The tunnelbana OIDC frontend's Client fields (redirect_uris,
        // response_types, grant_types, token_endpoint_auth_method, ...)
        // must survive the `_env` roundtrip untouched — the provider
        // resolves the credential and strips only the `_env` field; the
        // strict downstream parser sees the same entry it would have
        // seen with an inline secret.
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret_env": "VC_TEST_SECRET",
                "redirect_uris": ["https://rp.example.org/callback"],
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_basic",
                "client_name": "Example RP",
            })],
            provider(),
        );
        let clients = reg.clients().expect("resolution succeeds");
        assert_eq!(clients[0]["client_secret"], "s3cret");
        assert_eq!(
            clients[0]["redirect_uris"][0],
            "https://rp.example.org/callback"
        );
        assert_eq!(clients[0]["response_types"][0], "code");
        assert_eq!(clients[0]["grant_types"][1], "refresh_token");
        assert_eq!(
            clients[0]["token_endpoint_auth_method"],
            "client_secret_basic"
        );
        assert_eq!(clients[0]["client_name"], "Example RP");
        assert!(clients[0].get("client_secret_env").is_none());
    }

    #[test]
    fn both_an_inline_secret_and_an_env_reference_are_refused() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret": "inline-value",
                "client_secret_env": "VC_TEST_SECRET",
            })],
            provider(),
        );
        let err = reg.clients().expect_err("two sources must be refused");
        assert!(
            err.to_string()
                .contains("both client_secret and client_secret_env"),
            "the error names the conflict: {err}"
        );
    }

    #[test]
    fn a_missing_env_variable_is_refused_with_the_client_and_variable_named() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret_env": "VC_NEVER_SET",
            })],
            provider(),
        );
        let err = reg
            .clients()
            .expect_err("a missing variable must be refused");
        assert!(
            err.to_string().contains("client rp") && err.to_string().contains("VC_NEVER_SET"),
            "the error names the client and the variable: {err}"
        );
    }

    #[test]
    fn an_empty_env_variable_is_refused() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret_env": "VC_EMPTY",
            })],
            std::sync::Arc::new(FakeProvider {
                env: vec![("VC_EMPTY", "")],
            }),
        );
        let err = reg
            .clients()
            .expect_err("an empty variable must be refused");
        assert!(
            err.to_string().contains("empty string"),
            "the error names the emptiness: {err}"
        );
    }

    #[test]
    fn a_duplicate_client_id_across_the_roster_is_refused() {
        let reg = ConfigClientRegistration::new(
            vec![
                json!({ "client_id": "rp", "client_secret": "a" }),
                json!({ "client_id": "rp", "client_secret": "b" }),
            ],
            provider(),
        );
        let err = reg.clients().expect_err("a duplicate id must be refused");
        assert!(
            err.to_string().contains("duplicate client_id 'rp'"),
            "the error names the duplicate: {err}"
        );
    }

    #[test]
    fn a_non_object_roster_entry_is_refused() {
        let reg = ConfigClientRegistration::new(vec![json!("just a string")], provider());
        let err = reg
            .clients()
            .expect_err("a non-object entry must be refused");
        assert!(
            err.to_string().contains("not a JSON object"),
            "the error names the shape: {err}"
        );
    }

    #[test]
    fn a_scalar_field_resolves_its_env_reference() {
        let got = resolve_secret_field(
            "pdp_bearer_token",
            None,
            Some("VC_TEST_SECRET"),
            None,
            &*provider(),
        )
        .expect("resolution succeeds");
        assert_eq!(got.as_deref(), Some("s3cret"));
    }

    #[test]
    fn a_scalar_field_resolves_its_file_reference() {
        let tmp = std::env::temp_dir().join("svc-test-file-provider");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        std::fs::write(tmp.join("pdp-token"), "file-secret").expect("write");
        let file_provider = FileSecretProvider::new(&tmp);
        let got = resolve_secret_field(
            "pdp_bearer_token",
            None,
            None,
            Some("pdp-token"),
            &file_provider,
        )
        .expect("resolution succeeds");
        assert_eq!(got.as_deref(), Some("file-secret"));
    }

    #[test]
    fn a_scalar_field_with_an_inline_value_and_a_reference_is_refused() {
        let err = resolve_secret_field(
            "pdp_bearer_token",
            Some("inline"),
            Some("VC_TEST_SECRET"),
            None,
            &*provider(),
        )
        .expect_err("two sources must be refused");
        assert!(
            err.to_string().contains("config field pdp_bearer_token"),
            "the error names the field: {err}"
        );
    }

    #[test]
    fn a_scalar_field_with_both_env_and_file_references_is_refused() {
        let err = resolve_secret_field(
            "pdp_bearer_token",
            None,
            Some("VC_TEST_SECRET"),
            Some("/secrets/pdp-token"),
            &*provider(),
        )
        .expect_err("two sources must be refused");
        assert!(
            err.to_string().contains("both _env and _file"),
            "the error names the conflict: {err}"
        );
    }

    #[test]
    fn a_scalar_field_with_no_source_is_none() {
        let got = resolve_secret_field("pdp_bearer_token", None, None, None, &*provider())
            .expect("no source is not an error");
        assert_eq!(got, None);
    }

    #[test]
    fn the_env_provider_refuses_a_missing_variable() {
        let err = EnvVarSecretProvider
            .resolve(&SecretSource::Env("VC_CONFIG_TEST_DEFINITELY_UNSET".into()))
            .expect_err("a missing variable must be refused");
        assert!(
            err.to_string().contains("VC_CONFIG_TEST_DEFINITELY_UNSET"),
            "the error names the variable: {err}"
        );
    }

    #[test]
    fn the_env_provider_refuses_a_file_source() {
        let err = EnvVarSecretProvider
            .resolve(&SecretSource::File("/secrets/x".into()))
            .expect_err("the env provider must refuse file sources");
        assert!(
            err.to_string().contains("env vars only"),
            "the error names the limitation: {err}"
        );
    }

    #[test]
    fn the_file_provider_refuses_an_env_source() {
        let err = FileSecretProvider::new("/secrets")
            .resolve(&SecretSource::Env("VC_X".into()))
            .expect_err("the file provider must refuse env sources");
        assert!(
            err.to_string().contains("secret files only"),
            "the error names the limitation: {err}"
        );
    }

    #[test]
    fn the_file_provider_resolves_relative_paths_against_its_base() {
        let tmp = std::env::temp_dir().join("svc-test-file-provider-relative");
        std::fs::create_dir_all(tmp.join("sub")).expect("mkdir");
        std::fs::write(tmp.join("sub/token"), "nested").expect("write");
        let got = FileSecretProvider::new(&tmp)
            .resolve(&SecretSource::File("sub/token".into()))
            .expect("resolution succeeds");
        assert_eq!(got, "nested");
    }

    #[test]
    fn the_platform_provider_serves_both_channels() {
        let tmp = std::env::temp_dir().join("svc-test-platform-provider");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        std::fs::write(tmp.join("token"), "from-a-file").expect("write");
        // The env channel needs a real variable: one process-global set,
        // a name unique to this test.
        std::env::set_var("VC_CONFIG_PLATFORM_TEST_ENV", "from-an-env-var");
        let provider = PlatformSecretProvider::new(&tmp);
        let got_env = provider
            .resolve(&SecretSource::Env("VC_CONFIG_PLATFORM_TEST_ENV".into()))
            .expect("the env channel resolves");
        assert_eq!(got_env, "from-an-env-var");
        let got_file = provider
            .resolve(&SecretSource::File("token".into()))
            .expect("the file channel resolves");
        assert_eq!(got_file, "from-a-file");
        std::env::remove_var("VC_CONFIG_PLATFORM_TEST_ENV");
    }
}
