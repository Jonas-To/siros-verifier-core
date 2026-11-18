use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
pub use siros_verifier_core::config::SecretProvider;
use siros_verifier_core::config::SecretSource;
use siros_verifier_core::issuer_set::IssuerSetPolicy;
use siros_verifier_core::Error as CoreError;
use siros_verifier_core_tunnelbana::{VpBackendConfig, ZkpBackendConfig};
use siros_verifier_zkp::circuits::CircuitsConfig;
use siros_verifier_zkp::verify::Tolerance;

// ---- secret providers: the operational implementations of the core trait ---------

/// The env-var [`SecretProvider`] — the platform-native secret channel.
/// A k8s Secret reaches the process as an env var through
/// `secretKeyRef`; the provider just reads it. This is the default.
pub struct EnvVarSecretProvider;

impl SecretProvider for EnvVarSecretProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::Env(name) => match std::env::var(name) {
                Ok(value) if !value.is_empty() => Ok(value),
                Ok(_) => Err(CoreError::Policy(format!(
                    "secret provider: env var {name} is set to the empty string"
                ))),
                Err(_) => Err(CoreError::Policy(format!(
                    "secret provider: env var {name} is not set"
                ))),
            },
            SecretSource::File(path) => Err(CoreError::Policy(format!(
                "secret provider: this provider resolves env vars only, not the secret file {path}"
            ))),
        }
    }
}

/// The file [`SecretProvider`] — the k8s Secret volume-mount model. A
/// mounted Secret materializes its keys as files under one directory;
/// [`FileSecretProvider`] resolves a relative source against that base
/// directory (absolute paths resolve as-given). An empty file is an
/// error (a mounted key that was never filled in) and a missing file an
/// error (the mount is not what the config believes) — matching the
/// env provider's fail-fast contract.
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
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::File(name) => {
                let path = self.path(name);
                let value = std::fs::read_to_string(&path).map_err(|e| {
                    CoreError::Policy(format!(
                        "secret provider: reading {} for {name}: {e}",
                        path.display()
                    ))
                })?;
                if value.is_empty() {
                    return Err(CoreError::Policy(format!(
                        "secret provider: secret file {} for {name} is empty",
                        path.display()
                    )));
                }
                Ok(value)
            }
            SecretSource::Env(name) => Err(CoreError::Policy(format!(
                "secret provider: this provider resolves secret files only, not env var {name}"
            ))),
        }
    }
}

/// Both platform channels in one [`SecretProvider`]: `_env` references
/// resolve through the environment, `_file` references against a base
/// directory (the config directory, so a relative file sits beside the
/// config the way sibling paths resolve). Serves a config that mixes the
/// two reference styles — a k8s deployment with some Secrets as
/// `secretKeyRef` env vars and some as volume mounts.
pub struct PlatformSecretProvider {
    env: EnvVarSecretProvider,
    files: FileSecretProvider,
}

impl PlatformSecretProvider {
    /// `file_base` is the directory relative `_file` references resolve
    /// against — the config file's directory in the boot.
    pub fn new(file_base: impl Into<PathBuf>) -> Self {
        Self {
            env: EnvVarSecretProvider,
            files: FileSecretProvider::new(file_base),
        }
    }
}

impl SecretProvider for PlatformSecretProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::Env(_) => self.env.resolve(source),
            SecretSource::File(_) => self.files.resolve(source),
        }
    }
}

// ---- the client roster: the config+secret default of the core trait ---------------

/// The default client roster (the config+secret implementation of the
/// core's [`siros_verifier_core::config::ClientRegistrationProvider`]):
/// the `[[frontend.config.clients]]` block plus a secret provider.
///
/// Each entry may carry its credential as an inline `client_secret`, as a
/// `client_secret_env` reference, or not at all (a `none`/
/// `private_key_jwt` client). The `_env` reference is resolved through
/// the secret provider at boot and stripped from the entry before it
/// reaches the consumer's parser — the downstream client model never
/// learns about `_env` fields. Both an inline secret and an `_env`
/// reference on one entry is refused, as is a duplicate `client_id`
/// across the roster (the consumer's store keys by id and would silently
/// keep only the last).
#[derive(Clone)]
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
    fn resolve_entry(&self, entry: Value) -> siros_verifier_core::Result<Value> {
        let id = entry
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing client_id>")
            .to_string();
        let object = match entry {
            Value::Object(map) => map,
            _ => {
                return Err(CoreError::Policy(format!(
                    "client {id}: the roster entry is not a JSON object"
                )))
            }
        };
        let inline = object.get("client_secret").cloned();
        let env = object.get("client_secret_env").cloned();
        if inline.is_some() && env.is_some() {
            return Err(CoreError::Policy(format!(
                "client {id}: both client_secret and client_secret_env are set — two sources for one value"
            )));
        }
        let mut object = object;
        if let Some(env) = env {
            let name = env.as_str().ok_or_else(|| {
                CoreError::Policy(format!("client {id}: client_secret_env is not a string"))
            })?;
            let secret = self
                .secrets
                .resolve(&SecretSource::Env(name.to_string()))
                .map_err(|e| CoreError::Policy(format!("client {id}: {e}")))?;
            if secret.is_empty() {
                return Err(CoreError::Policy(format!(
                    "client {id}: client_secret_env {name} is set to the empty string"
                )));
            }
            object.insert("client_secret".into(), Value::String(secret));
        }
        object.remove("client_secret_env");
        Ok(Value::Object(object))
    }

    /// The resolved roster: `_env` references already resolved to inline
    /// values (the same surface as the core's [`ClientRegistrationProvider`],
    /// which this type implements).
    pub fn clients(&self) -> siros_verifier_core::Result<Vec<Value>> {
        let mut resolved = Vec::with_capacity(self.entries.len());
        let mut seen: HashSet<String> = HashSet::with_capacity(self.entries.len());
        for entry in self.entries.clone() {
            let value = self.resolve_entry(entry)?;
            let id = value
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CoreError::Policy("client roster entry has no string client_id".into())
                })?
                .to_string();
            if !seen.insert(id.clone()) {
                return Err(CoreError::Policy(format!(
                    "duplicate client_id '{id}' across the client roster: the consumer's store keys by id and would silently keep only the last"
                )));
            }
            resolved.push(value);
        }
        Ok(resolved)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkpDeploymentConfig {
    #[serde(flatten)]
    pub backend: ZkpBackendConfig,
    pub circuits: CircuitsConfig,
    #[serde(default = "default_issuer_set_policy")]
    pub issuer_set: IssuerSetPolicy,
    #[serde(default)]
    pub tolerance: Tolerance,
}

fn default_issuer_set_policy() -> IssuerSetPolicy {
    IssuerSetPolicy::AllTrusted
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStorageConfig {
    /// `memory` for an explicitly single-process deployment, or `mongodb`.
    pub backend: String,
    #[serde(default)]
    pub uri: Option<String>,
    /// The env var the MongoDB URI comes from (a k8s Secret's
    /// `secretKeyRef`, a Fly secret). Mutually exclusive with `uri` and
    /// `uri_file` — two sources named for one value is two different
    /// beliefs about where it comes from.
    #[serde(default)]
    pub uri_env: Option<String>,
    /// A file the MongoDB URI comes from (a Secret volume mount).
    /// Mutually exclusive with `uri` and `uri_env`.
    #[serde(default)]
    pub uri_file: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub collection: Option<String>,
}

/// Deployment-only settings wrapped around the backend's closed protocol config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub request_signing_key_path: String,
    pub storage: FlowStorageConfig,
    pub request_certificate_chain_path: String,
    pub pdp_endpoint: String,
    #[serde(default)]
    pub pdp_bearer_token: Option<String>,
    /// The env var the PDP bearer token comes from (a k8s Secret's
    /// `secretKeyRef`, a Fly secret). Mutually exclusive with
    /// `pdp_bearer_token` and `pdp_bearer_token_file`.
    #[serde(default)]
    pub pdp_bearer_token_env: Option<String>,
    /// A file the PDP bearer token comes from (a Secret volume mount).
    /// Mutually exclusive with `pdp_bearer_token` and
    /// `pdp_bearer_token_env`.
    #[serde(default)]
    pub pdp_bearer_token_file: Option<String>,
    /// The prior request-signing key, retained for one rotation window:
    /// in-flight flows are re-signed (`request_uri_method = "post"`) by
    /// the pair they were created under. New flows always use the
    /// current key. Both this and its chain must be set together.
    #[serde(default)]
    pub previous_request_signing_key_path: Option<String>,
    /// The prior request certificate chain, paired with the previous key.
    #[serde(default)]
    pub previous_request_certificate_chain_path: Option<String>,
    #[serde(default)]
    pub pdp_id: Option<String>,
    /// Explicitly permit plain HTTP to a non-loopback PDP on a trusted local
    /// development network. Leave false in production.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Local test-only escape hatch for a self-signed status-list endpoint.
    #[serde(default)]
    pub allow_invalid_status_list_certificates: bool,
    #[serde(default)]
    pub receipt_key_id: Option<String>,
    #[serde(default)]
    pub receipt_issuer: Option<String>,
    #[serde(default)]
    pub receipt_audience: Option<String>,
    #[serde(default)]
    pub max_receipt_ttl_secs: Option<i64>,
    #[serde(default)]
    pub zkp: Option<ZkpDeploymentConfig>,
    /// The serialized WRPRC (`rc-wrp+jwt` per ETSI TS 119 475 §5.2) of the
    /// FRONTED relying party — the deployment is an intermediary's. Read at
    /// startup, validated (shape + signature consistency), and carried on
    /// every armed request per ETSI TS 119 472-2 §6.3.2.2's `registration_cert`
    /// element. Absent for a non-intermediary deployment — the request stays
    /// the pre-EAAP shape.
    #[serde(default)]
    pub wrprc_path: Option<String>,
    /// The 472-2 §6.3.2.2 registrar dataset JSON (the B.2 members:
    /// identifier/srvDescription/registryURI/intendedUseIdentifier/purpose/
    /// policyURI, optional credential) — the RP Registrar-provided data the
    /// wallet renders. Absent when the deployment runs without the EAAP
    /// members.
    #[serde(default)]
    pub verifier_info_path: Option<String>,
    #[serde(flatten)]
    pub vp: VpBackendConfig,
}

impl DeploymentConfig {
    pub fn pdp_id(&self) -> &str {
        self.pdp_id.as_deref().unwrap_or(&self.pdp_endpoint)
    }
    pub fn receipt_key_id(&self) -> &str {
        self.receipt_key_id.as_deref().unwrap_or("receipt-dev")
    }
    pub fn receipt_issuer(&self) -> &str {
        self.receipt_issuer
            .as_deref()
            .unwrap_or("siros-verifier-core")
    }
    pub fn receipt_audience(&self) -> &str {
        self.receipt_audience.as_deref().unwrap_or("vp")
    }
    pub fn max_receipt_ttl_secs(&self) -> i64 {
        self.max_receipt_ttl_secs.unwrap_or(300)
    }
}

impl siros_verifier_core::config::ClientRegistrationProvider for ConfigClientRegistration {
    fn clients(&self) -> siros_verifier_core::Result<Vec<Value>> {
        // The inherent method: the same surface, reachable through the
        // core trait.
        ConfigClientRegistration::clients(self)
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use serde_json::json;

    /// A fake provider for deterministic roster tests: hands out a
    /// canned value, refuses everything else.
    struct FakeProvider {
        env: Vec<(&'static str, &'static str)>,
    }

    impl SecretProvider for FakeProvider {
        fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
            match source {
                SecretSource::Env(name) => self
                    .env
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.to_string())
                    .ok_or_else(|| {
                        CoreError::Policy(format!("secret provider: env var {name} is not set"))
                    }),
                SecretSource::File(path) => Err(CoreError::Policy(format!(
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

    // ---- the roster ------------------------------------------------------------

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
    fn both_an_inline_secret_and_an_env_reference_are_refused() {
        let reg = ConfigClientRegistration::new(
            vec![json!({
                "client_id": "rp",
                "client_secret": "inline-value",
                "client_secret_env": "VC_TEST_SECRET",
            })],
            provider(),
        );
        let err = match reg.clients() {
            Ok(_) => panic!("two sources must be refused"),
            Err(e) => e,
        };
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
        let err = match reg.clients() {
            Ok(_) => panic!("a missing variable must be refused"),
            Err(e) => e,
        };
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
        let err = match reg.clients() {
            Ok(_) => panic!("an empty variable must be refused"),
            Err(e) => e,
        };
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
        let err = match reg.clients() {
            Ok(_) => panic!("a duplicate id must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("duplicate client_id 'rp'"),
            "the error names the duplicate: {err}"
        );
    }

    #[test]
    fn a_non_object_roster_entry_is_refused() {
        let reg = ConfigClientRegistration::new(vec![json!("just a string")], provider());
        let err = match reg.clients() {
            Ok(_) => panic!("a non-object entry must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not a JSON object"),
            "the error names the shape: {err}"
        );
    }

    // ---- the concrete providers -------------------------------------------------

    #[test]
    fn the_env_provider_refuses_a_missing_variable() {
        let err = match EnvVarSecretProvider
            .resolve(&SecretSource::Env("VC_CONFIG_TEST_DEFINITELY_UNSET".into()))
        {
            Ok(_) => panic!("a missing variable must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("VC_CONFIG_TEST_DEFINITELY_UNSET"),
            "the error names the variable: {err}"
        );
    }

    #[test]
    fn the_env_provider_refuses_a_file_source() {
        let err = match EnvVarSecretProvider.resolve(&SecretSource::File("/secrets/x".into())) {
            Ok(_) => panic!("the env provider must refuse file sources"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("env vars only"),
            "the error names the limitation: {err}"
        );
    }

    #[test]
    fn the_file_provider_refuses_an_env_source() {
        let err =
            match FileSecretProvider::new("/secrets").resolve(&SecretSource::Env("VC_X".into())) {
                Ok(_) => panic!("the file provider must refuse env sources"),
                Err(e) => e,
            };
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
    fn the_file_provider_refuses_a_missing_file() {
        let tmp = std::env::temp_dir().join("svc-test-file-provider-missing");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let err = match FileSecretProvider::new(&tmp).resolve(&SecretSource::File("gone".into())) {
            Ok(_) => panic!("a missing file must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("reading") && err.to_string().contains("gone"),
            "the error names the file: {err}"
        );
    }

    #[test]
    fn the_file_provider_refuses_an_empty_file() {
        // The fail-fast contract: an empty file is a mounted key that was
        // never filled in — as useless as a missing one.
        let tmp = std::env::temp_dir().join("svc-test-file-provider-empty");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        std::fs::write(tmp.join("token"), "").expect("write");
        let err = match FileSecretProvider::new(&tmp).resolve(&SecretSource::File("token".into())) {
            Ok(_) => panic!("an empty file must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("is empty"),
            "the error names the emptiness: {err}"
        );
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
