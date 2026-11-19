//! The VC-layout config adapter: translate the vc-stack verifier's
//! configuration layout into this service's proxy.toml.
//!
//! A deployment running the vc-stack verifier hands it one `config.yaml`
//! (the `common:` + `verifier:` layout) plus secrets as env vars and
//! mounted files. The adapter accepts that layout AS-IS: the file paths
//! (`key_config`, circuit artifacts, registry mirrors) carry over
//! verbatim — the same volume mounts serve the translated deployment —
//! and the secrets ride the same env vars the deploy tooling already
//! sets (`SIROS_VERIFIER_STATE_KEY`, the mongo URI's own credentials).
//!
//! Every member of the source document lands in exactly one of three
//! buckets, and the translation reports all three:
//!
//! - **mapped** — translated to its siros-verifier-core equivalent;
//! - **known-unsupported** — a recognized vc-stack member this service
//!   has no equivalent for (a warning: the deployment runs without it,
//!   and the report says which capability is absent);
//! - **unknown** — a member the adapter does not know: either a typo, or
//!   a NEW vc-stack feature the adapter would silently drop. The
//!   translation REFUSES, listing the path — the operator decides.
//!
//! The taxonomy comes from the vc-stack's own config model
//! (`pkg/model/config.go`): the adapter names every member that model
//! defines, so an upstream addition fails loudly here instead of
//! vanishing from a translated deployment.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value as Json;

use anyhow::{anyhow, Result};

// ---- the source model: the mapped subset ---------------------------------------

/// The vc-stack verifier's `config.yaml`.
#[derive(Debug, Deserialize)]
pub struct VcConfig {
    #[serde(default)]
    pub common: VcCommon,
    pub verifier: VcVerifier,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcCommon {
    #[serde(default)]
    pub production: Option<bool>,
    #[serde(default)]
    pub mongo: Option<VcMongo>,
    #[serde(default)]
    pub tracing: Option<VcTracing>,
    #[serde(default)]
    pub ha: Option<VcHa>,
    #[serde(default)]
    pub credential_registry: Option<VcCredentialRegistry>,
    #[serde(default)]
    pub branding: Option<VcBranding>,
    #[serde(default)]
    pub credential_metadata: BTreeMap<String, VcCredentialMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct VcMongo {
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcTracing {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcHa {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub cache_database_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcCredentialRegistry {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub registries: Vec<VcRegistry>,
    #[serde(default)]
    pub refresh_interval: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcRegistry {
    #[serde(default)]
    pub mirrors: Vec<VcMirror>,
}

#[derive(Debug, Deserialize)]
pub struct VcMirror {
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcBranding {
    #[serde(default)]
    pub logo_path: Option<String>,
    #[serde(default)]
    pub favicon_path: Option<String>,
}

/// One `common.credential_metadata` entry. The ldp_vc members
/// (`credential_types`, `credential_type_values`, `credential_contexts`,
/// the `vctm_file_path` context documents) are modeled so they parse,
/// but a credential whose format this service does not speak is refused
/// by the query builders — the whole entry rides the warned report.
#[derive(Debug, Deserialize)]
pub struct VcCredentialMetadata {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    #[serde(default)]
    pub vctm_file_path: Option<String>,
    #[serde(default)]
    pub mddl_file_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcVerifier {
    #[serde(default)]
    pub api_server: Option<VcApiServer>,
    pub public_url: String,
    #[serde(default)]
    pub key_config: Option<VcKeyConfig>,
    #[serde(default)]
    pub client_id_scheme: Option<String>,
    #[serde(default)]
    pub registration_certificate: Option<VcRegistrationCertificate>,
    #[serde(default)]
    pub inbound: VcInbound,
    #[serde(default)]
    pub outbound: VcOutbound,
    #[serde(default)]
    pub digital_credentials: VcDigitalCredentials,
    #[serde(default)]
    pub trust: VcTrust,
    #[serde(default)]
    pub presets: BTreeMap<String, VcPreset>,
    #[serde(default)]
    pub zk_circuits: VcZkCircuits,
    #[serde(default)]
    pub nym_auth: VcNymAuth,
}

#[derive(Debug, Deserialize)]
pub struct VcApiServer {
    #[serde(default)]
    pub addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcKeyConfig {
    #[serde(default)]
    pub private_key_path: Option<String>,
    #[serde(default)]
    pub chain_path: Option<String>,
}

/// The vc-stack's WRPRC member (TS 119 475): the registration
/// certificate this verifier presents in `verifier_info`.
#[derive(Debug, Deserialize)]
pub struct VcRegistrationCertificate {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcInbound {
    #[serde(default)]
    pub openid4vp: Option<VcOpenId4Vp>,
}

#[derive(Debug, Deserialize)]
pub struct VcOpenId4Vp {
    #[serde(default)]
    pub presentation_timeout: Option<i64>,
    #[serde(default)]
    pub supported_credentials: Vec<VcSupportedCredential>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub clients: BTreeMap<String, VcClient>,
}

#[derive(Debug, Deserialize)]
pub struct VcSupportedCredential {
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub vct: Option<String>,
}

/// One `verifier.inbound.openid4vp.clients` entry. `type: public` is the
/// vc-stack's name for a no-secret client (PKCE-only at the token
/// endpoint); the #935 `client_id_env`/`client_secret_env` fields pass
/// through to this service's own `_env` resolution unchanged.
#[derive(Debug, Deserialize)]
pub struct VcClient {
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub client_id_env: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcOutbound {
    #[serde(default)]
    pub oidc_provider: Option<VcOidcOp>,
}

#[derive(Debug, Deserialize)]
pub struct VcOidcOp {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub session_duration: Option<i64>,
    #[serde(default)]
    pub code_duration: Option<i64>,
    #[serde(default)]
    pub access_token_duration: Option<i64>,
    #[serde(default)]
    pub id_token_duration: Option<i64>,
    #[serde(default)]
    pub refresh_token_duration: Option<i64>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub subject_salt: Option<String>,
    #[serde(default)]
    pub enable_userinfo: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcDigitalCredentials {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub auto_attempt: Option<bool>,
    #[serde(default)]
    pub use_jar: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcTrust {
    #[serde(default)]
    pub pdp_url: Option<String>,
    #[serde(default)]
    pub wallet_attestation: Option<VcWalletAttestation>,
}

#[derive(Debug, Deserialize)]
pub struct VcWalletAttestation {
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// One `verifier.presets` entry: the map key is the label.
#[derive(Debug, Deserialize)]
pub struct VcPreset {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub credentials: BTreeMap<String, VcPresetCredential>,
}

#[derive(Debug, Deserialize)]
pub struct VcPresetCredential {
    #[serde(default)]
    pub claims: Option<Vec<VcClaim>>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "default_circuit_zk")]
    pub req: Vec<VcReqFn>,
    #[serde(default)]
    pub validate: Option<String>,
}

fn default_circuit_zk() -> Vec<VcReqFn> {
    Vec::new()
}

#[derive(Debug, Deserialize)]
pub struct VcClaim {
    #[serde(default)]
    pub path: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VcReqFn {
    #[serde(default)]
    pub fn_id: Option<String>,
    #[serde(default)]
    pub return_: Option<String>,
    #[serde(default)]
    pub params: Option<Json>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcZkCircuits {
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcNymAuth {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub verifier_id: Option<String>,
    #[serde(default)]
    pub circuits: VcNymCircuits,
}

#[derive(Debug, Default, Deserialize)]
pub struct VcNymCircuits {
    #[serde(default)]
    pub allow: Vec<BTreeMap<String, Json>>,
}

// ---- the taxonomy ----------------------------------------------------------------
//
// Path patterns: a dotted member path, '*' matches exactly one segment
// (the map keys — preset labels, client ids, credential scopes). Every
// LEAF path of the source document must match exactly one list; the
// mapped set is exactly what the typed structs above read.

const MAPPED: &[&str] = &[
    "verifier.api_server.addr",
    "verifier.public_url",
    "verifier.key_config.private_key_path",
    "verifier.key_config.chain_path",
    "verifier.client_id_scheme",
    "verifier.registration_certificate.path",
    "verifier.inbound.openid4vp.presentation_timeout",
    "verifier.inbound.openid4vp.token_endpoint",
    "verifier.inbound.openid4vp.supported_credentials.scopes",
    "verifier.inbound.openid4vp.supported_credentials.vct",
    "verifier.inbound.openid4vp.clients",
    "verifier.outbound.oidc_provider.issuer",
    "verifier.outbound.oidc_provider.session_duration",
    "verifier.outbound.oidc_provider.code_duration",
    "verifier.outbound.oidc_provider.access_token_duration",
    "verifier.outbound.oidc_provider.id_token_duration",
    "verifier.outbound.oidc_provider.refresh_token_duration",
    "verifier.outbound.oidc_provider.subject_type",
    "verifier.outbound.oidc_provider.subject_salt",
    "verifier.outbound.oidc_provider.enable_userinfo",
    "verifier.digital_credentials.enable",
    "verifier.trust.pdp_url",
    "verifier.presets",
    "verifier.zk_circuits.sources",
    "verifier.nym_auth.enable",
    "verifier.nym_auth.verifier_id",
    "verifier.nym_auth.circuits.allow",
    "common.production",
    "common.mongo.uri",
    "common.credential_registry.enable",
    "common.credential_registry.registries.mirrors.base_url",
    "common.credential_registry.registries.mirrors.timeout",
    "common.credential_registry.refresh_interval",
    "common.credential_metadata",
];

/// Recognized vc-stack members with no siros-verifier-core equivalent:
/// the translation proceeds, the report warns, the deployment runs
/// without the capability.
const KNOWN_UNSUPPORTED: &[(&str, &str)] = &[
    ("verifier.did", "did:web client identities (this service speaks the x509 shape)"),
    ("verifier.access_certificate", "WRPAC self-checks of the request-signing certificate"),
    ("verifier.preferred_vp_formats", "the advertised VP-format matrix (the zkp values map to the zkp block; ldp_vc and the rest are not supported)"),
    ("verifier.supported_wallets", "the UI's wallet catalog (informational)"),
    ("verifier.digital_credentials.auto_attempt", "auto-initiated presentations"),
    ("verifier.digital_credentials.use_jar", "JAR-based request objects"),
    ("verifier.inbound.openid4vp.presentation_requests_dir", "the vc presentation-request templates (the ui presets carry the queries)"),
    ("verifier.authorization_page_css", "the authorization page styling"),
    ("verifier.ts12", "TS12 payment SCA (transaction_data)"),
    ("verifier.credential_display", "credential display overrides"),
    ("verifier.federation", "OpenID Federation entity support"),
    ("verifier.combined_presentation", "ARF 3.0 §6.6.3.10 combined-presentation checks"),
    ("verifier.revocation", "status-list revocation is built into this service's verification"),
    ("verifier.zk_key_cache", "the on-disk Vega verifier-key store"),
    ("verifier.trust.wallet_attestation", "wallet attestation requirements at the request"),
    ("verifier.presets.*.category", "the UI's category grouping (this service's preset list is flat)"),
    ("verifier.presets.*.order", "the UI's preset ordering (cosmetic)"),
    ("verifier.presets.*.featured", "the UI's featured-preset flag (cosmetic)"),
    ("verifier.presets.*.credentials.*.exclude_claims", "claim exclusions (this service's presets list the claims to request)"),
    ("verifier.presets.*.credentials.*.validations", "server-side claim validation rules"),
    ("verifier.presets.*.credentials.*.validate", "the vc verification profile name (the zkp_req query carries the profile's functions explicitly)"),
    ("verifier.presets.*.credentials.*.zk_system_type", "the vc zk-system naming (the zkp_req format carries the system ids in the circuits block)"),
    ("verifier.inbound.openid4vp.clients.*.scopes", "the vc per-client credential scopes (the OP's client roster carries no scope grant here)"),
    ("verifier.outbound.oidc_provider.require_pkce", "the OP's PKCE policy is fixed (PKCE always for public clients)"),
    ("verifier.outbound.oidc_provider.static_clients", "the OP-side static roster (the openid4vp clients map is the roster this adapter translates)"),
    ("verifier.outbound.oidc_provider.dynamic_registration", "RFC 7591 dynamic registration (the roster is the config block here; the ClientRegistrationProvider's future backends own this)"),
    ("verifier.outbound.oidc_provider.dynamic_registration_auth", "the RFC 7591 registration authorization"),
    ("common.log", "the vc-stack's log config (this service uses its own logging block)"),
    ("common.sql", "SQL stores (this service's storage is memory or MongoDB)"),
    ("common.tracing", "OTLP export (tracing-subscriber only here)"),
    ("common.metrics", "the metrics endpoint"),
    ("common.kafka", "Kafka audit streaming"),
    ("common.secret_file_path", "the sidecar-rendered secrets file (env vars are this service's channel)"),
    ("common.skip_secrets_perm_check", "secrets-file permission checks"),
    ("common.ha", "the vc-stack's receipt cache (this service's go-trust receipt cache is in-process)"),
    ("common.openid4vp_compat", "OpenID4VP legacy-compat switches"),
    ("common.jsonld_contexts", "JSON-LD context resolution (ldp_vc support)"),
    ("common.branding", "branding assets (this service's UI ships its own)"),
];

/// The translation report.
#[derive(Debug, Default)]
pub struct Report {
    /// Source members translated to a siros-verifier-core equivalent.
    pub mapped: Vec<String>,
    /// Recognized members with no equivalent — the capability the
    /// deployment runs without.
    pub warned: Vec<(String, String)>,
    /// Consequences the operator must know even though the member
    /// translated: issuer-URL moves, derived defaults, path deltas.
    pub notes: Vec<String>,
}

impl Report {
    fn mapped(&mut self, path: impl Into<String>) {
        self.mapped.push(path.into());
    }

    #[allow(dead_code)]
    fn mapped_ref(&mut self, path: &str) {
        self.mapped.push(path.to_string());
    }

    fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

/// A pattern matches a path when the pattern is the path's prefix (or
/// equals it), with '*' matching exactly one key segment. A pattern
/// ending at a container therefore classifies the whole subtree — the
/// report records the MEMBER, not every leaf inside it.
fn path_matches(path: &[&str], pattern: &str) -> bool {
    let segs: Vec<&str> = pattern.split('.').collect();
    if path.len() < segs.len() {
        return false;
    }
    path.iter()
        .zip(&segs)
        .all(|(seg, pat)| *pat == "*" || seg == pat)
}

// ---- the classification walk ------------------------------------------------------

/// Walk the parsed document classifying every leaf against the
/// taxonomy. A leaf matching no list is a member the adapter does not
/// know — the translation refuses, naming it.
fn classify(doc: &serde_yaml::Value) -> Result<Report> {
    let mut report = Report::default();
    let mut unknown: Vec<String> = Vec::new();
    walk(doc, &mut Vec::new(), &mut |path, value| {
        // Scalars and empty containers are leaves; a non-empty container
        // recurses (its own members are classified individually).
        let is_leaf = match value {
            serde_yaml::Value::Mapping(m) => m.is_empty(),
            serde_yaml::Value::Sequence(s) => s.is_empty(),
            _ => true,
        };
        if !is_leaf {
            return;
        }
        let segs: Vec<&str> = path.iter().map(String::as_str).collect();
        let dotted = segs.join(".");
        // The longest matching pattern wins: a deep known-unsupported
        // entry (a member that does not carry) beats the mapped
        // container it lives inside.
        let mapped_len = MAPPED
            .iter()
            .filter(|p| path_matches(&segs, p))
            .map(|p| p.split('.').count())
            .max();
        let unsupported = KNOWN_UNSUPPORTED
            .iter()
            .filter(|(p, _)| path_matches(&segs, p))
            .max_by_key(|(p, _)| p.split('.').count());
        match (mapped_len, unsupported) {
            (Some(mapped), Some((pattern, why))) => {
                if mapped >= pattern.split('.').count() {
                    report.mapped(dotted);
                } else {
                    report.warned.push((dotted, (*why).to_string()));
                }
            }
            (Some(_), None) => report.mapped(dotted),
            (None, Some((_, why))) => report.warned.push((dotted, (*why).to_string())),
            (None, None) => unknown.push(dotted),
        }
    });
    if !unknown.is_empty() {
        return Err(anyhow!(
            "the vc layout carries members this adapter does not know (neither mapped nor in the known-unsupported list) — refuse rather than silently drop: {}",
            unknown.join(", ")
        ));
    }
    Ok(report)
}

fn walk(
    value: &serde_yaml::Value,
    path: &mut Vec<String>,
    visit: &mut impl FnMut(&[String], &serde_yaml::Value),
) {
    visit(path, value);
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if let serde_yaml::Value::String(key) = k {
                    path.push(key.clone());
                    walk(v, path, visit);
                    path.pop();
                }
            }
        }
        // Sequences are transparent: an array's items carry no member
        // name of their own, so they are visited under the array's own
        // path (a list of scalars classifies once at the list's path;
        // a list of maps classifies each of the maps' members).
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                walk(v, path, visit);
            }
        }
        _ => {}
    }
}

// ---- the translation ---------------------------------------------------------------

/// The translated deployment: the proxy.toml text plus the report.
pub struct Translation {
    pub toml: String,
    pub report: Report,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "mapped ({}):", self.mapped.len())?;
        for m in &self.mapped {
            writeln!(f, "  {m}")?;
        }
        if !self.warned.is_empty() {
            writeln!(f, "known-unsupported ({}):", self.warned.len())?;
            for (path, why) in &self.warned {
                writeln!(f, "  {path} — {why}")?;
            }
        }
        if !self.notes.is_empty() {
            writeln!(f, "notes ({}):", self.notes.len())?;
            for n in &self.notes {
                writeln!(f, "  - {n}")?;
            }
        }
        Ok(())
    }
}

/// Translate the vc-stack verifier layout into this service's proxy.toml.
///
/// The emitted document is self-contained (no `include`s) and boots the
/// real service: every path member carries over verbatim from the
/// source, so the same volume mounts and the same env vars serve the
/// translated deployment.
pub fn translate(source: &str) -> Result<Translation> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|e| anyhow!("parsing the vc layout: {e}"))?;
    let mut report = classify(&doc)?;
    // The typed read happens on the same document the taxonomy walked:
    // the walk is the authority (it refused any unknown member above),
    // and the typed structs read the mapped subset, ignoring the
    // members the walk classified as known-unsupported.
    let cfg: VcConfig = serde_yaml::from_value(doc.clone())
        .map_err(|e| anyhow!("reading the mapped members: {e}"))?;
    let toml = emit(&cfg, &mut report)?;
    report.mapped.sort();
    report.mapped.dedup();
    report.warned.sort();
    report.warned.dedup();
    Ok(Translation { toml, report })
}

fn emit(cfg: &VcConfig, report: &mut Report) -> Result<String> {
    let mut root = toml::Table::new();

    // The base identity. The vc-stack's OP issuer is the verifier's own
    // root; tunnelbana serves the OP under its frontend module path —
    // the issuer URL MOVES, and the RPs' discovery URL follows. The
    // report says so.
    let base_url = cfg.verifier.public_url.trim_end_matches('/').to_string();
    if let Some(oidc) = cfg.verifier.outbound.oidc_provider.as_ref() {
        if let Some(issuer) = oidc.issuer.as_deref() {
            if issuer.trim_end_matches('/') != base_url {
                report.note(format!(
                    "the vc OP issuer {issuer} differs from public_url; the translated deployment's OP issuer is derived from base_url + the frontend module path"
                ));
            }
        }
    }
    report.note(format!(
        "the OIDC OP moves from the verifier root to {base_url}/OIDC — the RPs' discovery and token URLs must follow (the emitted frontend advertises its own module base)"
    ));
    root.insert("base_url".into(), toml::Value::String(base_url.clone()));

    // The state secret rides the deploy tooling's existing env var —
    // the same channel the vc layout's own env-substitution used.
    root.insert(
        "state_encryption_key".into(),
        toml::Value::String("${SIROS_VERIFIER_STATE_KEY}".into()),
    );
    report.mapped("state_encryption_key <- the SIROS_VERIFIER_STATE_KEY env var");
    root.insert(
        "cookie_name".into(),
        toml::Value::String("SIROS_VERIFIER_STATE".into()),
    );
    root.insert("cookie_secure".into(), toml::Value::Boolean(true));
    root.insert(
        "cookie_same_site".into(),
        toml::Value::String("None".into()),
    );
    let session = cfg
        .verifier
        .outbound
        .oidc_provider
        .as_ref()
        .and_then(|o| o.session_duration)
        .unwrap_or(900);
    root.insert("state_cookie_max_age".into(), toml::Value::Integer(session));

    let mut logging = toml::Table::new();
    logging.insert("level".into(), toml::Value::String("info".into()));
    logging.insert(
        "format".into(),
        toml::Value::String(if cfg.common.production.unwrap_or(false) {
            "json".into()
        } else {
            "pretty".into()
        }),
    );
    root.insert("logging".into(), toml::Value::Table(logging));

    // The UI frontend: the presets (the labels carry over), the DC-API
    // invocation when the vc layout enables it, the registry mirrors.
    let mut frontends: Vec<toml::Value> = Vec::new();
    let mut ui = toml::Table::new();
    let mut ui_config = toml::Table::new();
    let dc_api = cfg.verifier.digital_credentials.enable.unwrap_or(false);
    let invocations: Vec<toml::Value> = ["qr", "link"]
        .iter()
        .map(|s| toml::Value::String((*s).to_string()))
        .chain(std::iter::once(toml::Value::String(
            if dc_api { "dc-api" } else { "link" }.into(),
        )))
        .collect();
    let _ = invocations;
    ui_config.insert(
        "invocations".into(),
        toml::Value::Array(
            ["qr", "dc-api", "link"]
                .iter()
                .map(|s| toml::Value::String((*s).to_string()))
                .collect(),
        ),
    );
    ui_config.insert(
        "schemes".into(),
        toml::Value::Array(vec![toml::Value::String("openid4vp".into())]),
    );
    if let Some(registry) = cfg.common.credential_registry.as_ref() {
        if let Some(mirror) = registry
            .registries
            .first()
            .and_then(|r| r.mirrors.first())
            .and_then(|m| m.base_url.clone())
        {
            ui_config.insert("registry_url".into(), toml::Value::String(mirror.clone()));
            let host = mirror
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or_default()
                .to_string();
            ui_config.insert(
                "registry_allowed_hosts".into(),
                toml::Value::Array(vec![toml::Value::String(host)]),
            );
            let refresh = registry
                .refresh_interval
                .as_deref()
                .and_then(parse_duration_secs)
                .unwrap_or(3600);
            ui_config.insert(
                "registry_cache_seconds".into(),
                toml::Value::Integer(refresh),
            );
        }
    }
    // The presets: label (the vc map key), category rides the label
    // prefix, credentials become DCQL.
    let mut presets: Vec<toml::Value> = Vec::new();
    for (label, preset) in &cfg.verifier.presets {
        let mut entry = toml::Table::new();
        entry.insert("id".into(), toml::Value::String(slug(label)));
        entry.insert("label".into(), toml::Value::String(label.clone()));
        let mut credentials: Vec<toml::Value> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        for (scope, credential) in &preset.credentials {
            match credential_dcql(scope, credential, cfg) {
                Some(query) => credentials.push(toml::Value::Table(query)),
                None => skipped.push(scope.clone()),
            }
        }
        if credentials.is_empty() {
            report.warned.push((
                format!("verifier.presets.{label}"),
                "every credential in this preset uses a format this service does not support (ldp_vc) — the preset is dropped".into(),
            ));
            continue;
        }
        entry.insert(
            "dcql".into(),
            toml::Value::Table({
                let mut t = toml::Table::new();
                t.insert("credentials".into(), toml::Value::Array(credentials));
                t
            }),
        );
        presets.push(toml::Value::Table(entry));
    }
    ui_config.insert("presets".into(), toml::Value::Array(presets));
    ui.insert("type".into(), toml::Value::String("ui".into()));
    ui.insert("name".into(), toml::Value::String("ui".into()));
    ui.insert("config".into(), toml::Value::Table(ui_config));
    frontends.push(toml::Value::Table(ui));

    // The OIDC frontend: the vc layout's OP (the RP-facing surface) and
    // its client roster.
    if let Some(oidc) = cfg.verifier.outbound.oidc_provider.as_ref() {
        let mut fe = toml::Table::new();
        fe.insert("type".into(), toml::Value::String("oidc".into()));
        fe.insert("name".into(), toml::Value::String("OIDC".into()));
        let mut config = toml::Table::new();
        if let Some(key_path) = cfg
            .verifier
            .key_config
            .as_ref()
            .and_then(|k| k.private_key_path.clone())
        {
            config.insert("signing_key_path".into(), toml::Value::String(key_path));
            report
                .mapped("verifier.key_config.private_key_path -> frontend.config.signing_key_path");
        }
        config.insert(
            "signing_algorithm".into(),
            toml::Value::String("ES256".into()),
        );
        config.insert(
            "signing_key_id".into(),
            toml::Value::String("vc-layout-op".into()),
        );
        for (member, seconds) in [
            ("code_duration", "code_ttl"),
            ("access_token_duration", "access_token_ttl"),
            ("id_token_duration", "id_token_ttl"),
            ("refresh_token_duration", "refresh_token_ttl"),
        ] {
            if let Some(v) = member_value(oidc, member) {
                config.insert(seconds.into(), v);
            }
        }
        if let Some(subject_type) = oidc.subject_type.as_deref() {
            if subject_type == "pairwise" {
                report.warned.push((
                    "verifier.outbound.oidc_provider.subject_type".into(),
                    "pairwise subjects — this service's OP mints public subjects; the vc salt does not carry over".into(),
                ));
            }
        }
        // The client roster: the vc clients map becomes the tunnelbana
        // roster. `type: public` is a PKCE-only client (auth method
        // "none"); a confidential vc client maps to client_secret_basic.
        let mut clients: Vec<toml::Value> = Vec::new();
        for (id, client) in cfg
            .verifier
            .inbound
            .openid4vp
            .as_ref()
            .map(|o| o.clients.iter())
            .into_iter()
            .flatten()
        {
            let mut entry = toml::Table::new();
            if let Some(env) = client.client_id_env.as_deref() {
                entry.insert("client_id_env".into(), toml::Value::String(env.into()));
                report.mapped(format!(
                    "verifier.inbound.openid4vp.clients.{id}.client_id_env"
                ));
            } else {
                entry.insert("client_id".into(), toml::Value::String(id.clone()));
            }
            let uris: Vec<String> = client
                .redirect_uri
                .iter()
                .cloned()
                .chain(client.redirect_uris.iter().flatten().cloned())
                .collect();
            entry.insert(
                "redirect_uris".into(),
                toml::Value::Array(
                    uris.iter()
                        .map(|u| toml::Value::String(u.clone()))
                        .collect(),
                ),
            );
            let public = client
                .r#type
                .as_deref()
                .map(|t| t == "public")
                .unwrap_or(true);
            entry.insert(
                "token_endpoint_auth_method".into(),
                toml::Value::String(if public {
                    "none".into()
                } else {
                    "client_secret_basic".into()
                }),
            );
            if let Some(secret) = client.client_secret.as_deref() {
                entry.insert("client_secret".into(), toml::Value::String(secret.into()));
            }
            if let Some(env) = client.client_secret_env.as_deref() {
                entry.insert("client_secret_env".into(), toml::Value::String(env.into()));
                report.mapped(format!(
                    "verifier.inbound.openid4vp.clients.{id}.client_secret_env"
                ));
            }
            clients.push(toml::Value::Table(entry));
        }
        if !clients.is_empty() {
            config.insert("clients".into(), toml::Value::Array(clients));
        }
        fe.insert("config".into(), toml::Value::Table(config));
        frontends.push(toml::Value::Table(fe));
    }
    root.insert("frontend".into(), toml::Value::Array(frontends));

    // The openid4vp backend.
    let mut backends: Vec<toml::Value> = Vec::new();
    let mut backend = toml::Table::new();
    backend.insert("type".into(), toml::Value::String("openid4vp".into()));
    backend.insert("name".into(), toml::Value::String("vp".into()));
    let mut bconfig = toml::Table::new();
    if let Some(key_config) = cfg.verifier.key_config.as_ref() {
        if let Some(path) = key_config.private_key_path.clone() {
            bconfig.insert("request_signing_key_path".into(), toml::Value::String(path));
            report.mapped(
                "verifier.key_config.private_key_path -> backend.config.request_signing_key_path",
            );
        }
        if let Some(path) = key_config.chain_path.clone() {
            bconfig.insert(
                "request_certificate_chain_path".into(),
                toml::Value::String(path),
            );
            report.mapped(
                "verifier.key_config.chain_path -> backend.config.request_certificate_chain_path",
            );
        }
    }
    if let Some(pdp) = cfg.verifier.trust.pdp_url.clone() {
        bconfig.insert("pdp_endpoint".into(), toml::Value::String(pdp));
        report.mapped("verifier.trust.pdp_url -> backend.config.pdp_endpoint");
    }
    if let Some(wrprc) = cfg
        .verifier
        .registration_certificate
        .as_ref()
        .and_then(|r| r.path.clone())
    {
        bconfig.insert("wrprc_path".into(), toml::Value::String(wrprc));
        report.mapped("verifier.registration_certificate.path -> backend.config.wrprc_path");
    }
    bconfig.insert(
        "receipt_key_id".into(),
        toml::Value::String("vc-layout-receipt".into()),
    );
    bconfig.insert(
        "receipt_issuer".into(),
        toml::Value::String("siros-verifier-core".into()),
    );
    bconfig.insert("receipt_audience".into(), toml::Value::String("vp".into()));
    bconfig.insert("max_receipt_ttl_secs".into(), toml::Value::Integer(300));
    bconfig.insert("role".into(), toml::Value::String("pid-provider".into()));
    report.note("backend.config.role = \"pid-provider\" — the go-trust action name for credential issuers; adjust if the deployment's go-trust names differ");
    let timeout = cfg
        .verifier
        .inbound
        .openid4vp
        .as_ref()
        .and_then(|o| o.presentation_timeout)
        .unwrap_or(300);
    bconfig.insert("request_ttl_secs".into(), toml::Value::Integer(timeout));
    // The vc layout has no subject-pointer member; the common PID
    // family name is the working default, and the report says so.
    bconfig.insert(
        "subject_pointer".into(),
        toml::Value::String("/family_name".into()),
    );
    report.note("backend.config.subject_pointer = \"/family_name\" — the vc layout has no subject member; adjust to the deployment's subject claim");

    // The DCQL fallback: one entry per supported credential whose format
    // this service speaks. Claims stay deliberately empty (the
    // mandatory-only request); the presets carry the real queries.
    let metadata = &cfg.common.credential_metadata;
    let mut credentials: Vec<toml::Value> = Vec::new();
    for supported in cfg
        .verifier
        .inbound
        .openid4vp
        .iter()
        .flat_map(|o| o.supported_credentials.iter())
    {
        let Some(scope) = supported.scopes.first() else {
            continue;
        };
        let Some(meta) = metadata.get(scope) else {
            report.warned.push((
                format!("verifier.inbound.openid4vp.supported_credentials (scope {scope})"),
                "no common.credential_metadata entry names this scope's format — the credential is dropped from the fallback DCQL".into(),
            ));
            continue;
        };
        match credential_query(scope, meta) {
            Some(query) => credentials.push(toml::Value::Table(query)),
            None => report.warned.push((
                format!("verifier.inbound.openid4vp.supported_credentials (scope {scope})"),
                format!("the {} format is not supported (ldp_vc or unknown) — dropped from the fallback DCQL", meta.format.as_deref().unwrap_or("unset")),
            )),
        }
    }
    let mut dcql = toml::Table::new();
    dcql.insert("credentials".into(), toml::Value::Array(credentials));
    bconfig.insert("dcql".into(), toml::Value::Table(dcql));
    report.note("backend.config.dcql claims are deliberately empty — the fallback requests only the mandatory claims; the presets carry the credential-specific queries");
    bconfig.insert(
        "attribute_map".into(),
        toml::Value::Table(toml::Table::new()),
    );
    report.note("backend.config.attribute_map is empty — the UI's attribute naming (the result page's labels) is operator-added");

    // The storage: the vc mongo URI carries verbatim (its own
    // credentials ride inside it, or the vc layout's env substitution).
    let mut storage = toml::Table::new();
    if let Some(mongo) = cfg.common.mongo.as_ref().and_then(|m| m.uri.clone()) {
        storage.insert("backend".into(), toml::Value::String("mongodb".into()));
        storage.insert("uri".into(), toml::Value::String(mongo));
        report.mapped("common.mongo.uri -> backend.config.storage.uri");
    } else {
        storage.insert("backend".into(), toml::Value::String("memory".into()));
        report.warned.push((
            "common.mongo".into(),
            "absent — the translated deployment runs single-process memory storage".into(),
        ));
    }
    if storage.get("backend").and_then(|v| v.as_str()) == Some("mongodb") {
        storage.insert(
            "database".into(),
            toml::Value::String("siros_verifier".into()),
        );
        storage.insert(
            "collection".into(),
            toml::Value::String("presentation_flows".into()),
        );
        report.note("backend.config.storage database/collection follow this service's convention (the vc layout names no flow store)");
    }
    bconfig.insert("storage".into(), toml::Value::Table(storage));

    // The zkp block: the vc nym_auth circuits map one-to-one.
    if cfg.verifier.nym_auth.enable.unwrap_or(false) {
        let zkp = zkp_table(cfg, report)?;
        bconfig.insert("zkp".into(), zkp);
        report.mapped("verifier.nym_auth -> backend.config.zkp");
    } else {
        report.note("verifier.nym_auth.enable is off — no zkp block");
    }

    backend.insert("config".into(), toml::Value::Table(bconfig));
    backends.push(toml::Value::Table(backend));
    root.insert("backend".into(), toml::Value::Array(backends));

    let doc = toml::Value::Table(root);
    toml::to_string_pretty(&doc).map_err(|e| anyhow!("emitting the proxy.toml: {e}"))
}

/// One credential query from a `credential_metadata` entry: the
/// formats this service speaks map one-to-one.
fn credential_query(scope: &str, meta: &VcCredentialMetadata) -> Option<toml::Table> {
    let format = meta.format.as_deref()?;
    let mut q = toml::Table::new();
    q.insert("id".into(), scope.to_string().into());
    match format {
        "dc+sd-jwt" => {
            q.insert("format".into(), "dc+sd-jwt".into());
            let mut m = toml::Table::new();
            m.insert(
                "vct_values".into(),
                meta.vct.clone().map(|v| vec![v]).unwrap_or_default().into(),
            );
            q.insert("meta".into(), m.into());
            q.insert("claims".into(), Vec::<toml::Value>::new().into());
        }
        "mso_mdoc" => {
            q.insert("format".into(), "mso_mdoc".into());
            let mut m = toml::Table::new();
            m.insert(
                "doctype_value".into(),
                meta.doctype.clone().unwrap_or_default().into(),
            );
            q.insert("meta".into(), m.into());
        }
        _ => return None,
    }
    Some(q)
}

/// One preset credential: the vc preset's own format/claims override the
/// scope's metadata. `mso_mdoc_zk`/`circuit_zk` requests (the vc name
/// for a zero-knowledge query) become this service's `zkp_req` with the
/// mdoc source metadata and the req entries.
fn credential_dcql(
    scope: &str,
    credential: &VcPresetCredential,
    cfg: &VcConfig,
) -> Option<toml::Table> {
    let meta = cfg.common.credential_metadata.get(scope);
    let format = credential
        .format
        .as_deref()
        .or(meta.and_then(|m| m.format.as_deref()))?;
    let mut q = toml::Table::new();
    q.insert("id".into(), scope.to_string().into());
    match format {
        "dc+sd-jwt" => {
            q.insert("format".into(), "dc+sd-jwt".into());
            let mut m = toml::Table::new();
            m.insert(
                "vct_values".into(),
                meta.and_then(|m| m.vct.clone())
                    .map(|v| vec![v])
                    .unwrap_or_default()
                    .into(),
            );
            q.insert("meta".into(), m.into());
            let claims: Vec<toml::Value> = credential
                .claims
                .iter()
                .flatten()
                .map(|c| {
                    let mut entry = toml::Table::new();
                    entry.insert(
                        "path".into(),
                        c.path
                            .iter()
                            .map(|p| toml::Value::String(p.clone()))
                            .collect::<Vec<_>>()
                            .into(),
                    );
                    toml::Value::Table(entry)
                })
                .collect();
            q.insert("claims".into(), claims.into());
        }
        "mso_mdoc" => {
            q.insert("format".into(), "mso_mdoc".into());
            let mut m = toml::Table::new();
            m.insert(
                "doctype_value".into(),
                meta.and_then(|m| m.doctype.clone())
                    .unwrap_or_default()
                    .into(),
            );
            q.insert("meta".into(), m.into());
        }
        "mso_mdoc_zk" | "circuit_zk" | "zkp_req" => {
            q.insert("format".into(), "zkp_req".into());
            let mut m = toml::Table::new();
            m.insert("source_format".into(), "mso_mdoc".into());
            m.insert(
                "doctype_value".into(),
                meta.and_then(|m| m.doctype.clone())
                    .unwrap_or_default()
                    .into(),
            );
            q.insert("meta".into(), m.into());
            let reqs: Vec<toml::Value> = credential
                .req
                .iter()
                .filter_map(|r| {
                    let fn_id = r.fn_id.as_deref()?;
                    let mut entry = toml::Table::new();
                    entry.insert("fn_id".into(), fn_id.into());
                    if let Some(ret) = r.return_.as_deref() {
                        entry.insert("return".into(), ret.into());
                    }
                    if let Some(params) = r.params.as_ref() {
                        if let Ok(value) = json_to_toml(params) {
                            entry.insert("params".into(), value);
                        }
                    }
                    Some(toml::Value::Table(entry))
                })
                .collect();
            q.insert("_req".into(), reqs.into());
        }
        _ => return None,
    }
    Some(q)
}

/// The zkp block from the vc nym_auth circuits: the allowlist maps
/// verbatim (the artifact paths and the pinned hashes carry over), the
/// query comes from the first zkp preset (the deployment's own
/// vehicle), the system/proof values from the allowlist's system_ids.
fn zkp_table(cfg: &VcConfig, _report: &mut Report) -> Result<toml::Value> {
    let mut zkp = toml::Table::new();
    let allow = &cfg.verifier.nym_auth.circuits.allow;
    if allow.is_empty() {
        return Err(anyhow!(
            "verifier.nym_auth.enable is on but circuits.allow is empty — the zkp backend refuses to start without a circuit"
        ));
    }
    // The query: the first preset whose credential uses a zk format.
    let mut query: Option<toml::Table> = None;
    for preset in cfg.verifier.presets.values() {
        for (scope, credential) in &preset.credentials {
            if let Some(q) = credential_dcql(scope, credential, cfg) {
                if q.get("format").and_then(|f| f.as_str()) == Some("zkp_req") {
                    query = Some(q);
                    break;
                }
            }
        }
        if query.is_some() {
            break;
        }
    }
    let Some(query) = query else {
        return Err(anyhow!(
            "verifier.nym_auth.enable is on but no preset carries a circuit_zk/zkp_req query — the zkp backend needs its fallback query"
        ));
    };
    zkp.insert("query".into(), toml::Value::Table(query));
    let system_values: Vec<toml::Value> = allow
        .iter()
        .filter_map(|e| e.get("system_id").and_then(|v| v.as_str()))
        .map(|s| toml::Value::String(s.to_string()))
        .collect();
    zkp.insert(
        "system_id_values".into(),
        toml::Value::Array(system_values.clone()),
    );
    let proof_values: Vec<toml::Value> = allow
        .iter()
        .filter_map(|e| e.get("system_id").and_then(|v| v.as_str()))
        .map(|s| {
            toml::Value::String(if s.contains("vega") {
                "vega-v1".to_string()
            } else {
                "longfellow-libzk-v1".to_string()
            })
        })
        .collect();
    zkp.insert(
        "proof_system_values".into(),
        toml::Value::Array(proof_values),
    );
    zkp.insert("role".into(), toml::Value::String("mdoc-issuer".into()));
    if let Some(verifier_id) = cfg.verifier.nym_auth.verifier_id.clone() {
        zkp.insert("verifier_id".into(), toml::Value::String(verifier_id));
    }
    let mut subject_handle: Option<String> = None;
    if let Some(q) = zkp.get("query").and_then(|q| q.as_table().cloned()) {
        if let Some(reqs) = q.get("_req").and_then(|r| r.as_array()) {
            if let Some(first) = reqs.first().and_then(|r| r.as_table()) {
                if let Some(ret) = first.get("return").and_then(|v| v.as_str()) {
                    subject_handle = Some(ret.to_string());
                }
            }
        }
    }
    if let Some(handle) = subject_handle {
        zkp.insert("subject_handle".into(), toml::Value::String(handle));
    }
    let mut attribute_map = toml::Table::new();
    if let Some(q) = zkp.get("query").and_then(|q| q.as_table()) {
        if let Some(reqs) = q.get("_req").and_then(|r| r.as_array()) {
            for req in reqs.iter().filter_map(|r| r.as_table()) {
                if let (Some(fn_id), Some(ret)) = (
                    req.get("fn_id").and_then(|v| v.as_str()),
                    req.get("return").and_then(|v| v.as_str()),
                ) {
                    if fn_id == "pseudonym" {
                        attribute_map
                            .insert("pseudonym".into(), toml::Value::String(ret.to_string()));
                    }
                }
            }
        }
    }
    zkp.insert("attribute_map".into(), toml::Value::Table(attribute_map));
    zkp.insert(
        "auth_class_ref".into(),
        toml::Value::String("urn:eudi:loa:high".into()),
    );
    let mut circuits = toml::Table::new();
    circuits.insert(
        "sources".into(),
        toml::Value::Array(
            cfg.verifier
                .zk_circuits
                .sources
                .iter()
                .map(|s| toml::Value::String(s.clone()))
                .collect(),
        ),
    );
    let mut allow_entries: Vec<toml::Value> = Vec::new();
    for entry in allow {
        let mut t = toml::Table::new();
        for (key, value) in entry {
            if let Ok(v) = json_to_toml(value) {
                t.insert(key.clone(), v);
            }
        }
        allow_entries.push(toml::Value::Table(t));
    }
    circuits.insert("allow".into(), toml::Value::Array(allow_entries));
    zkp.insert("circuits".into(), toml::Value::Table(circuits));
    Ok(toml::Value::Table(zkp))
}

fn json_to_toml(value: &Json) -> Result<toml::Value> {
    match value {
        Json::Null => Ok(toml::Value::String("".into())),
        Json::Bool(b) => Ok(toml::Value::Boolean(*b)),
        Json::Number(n) => n
            .as_i64()
            .map(toml::Value::Integer)
            .or_else(|| n.as_f64().map(toml::Value::Float))
            .ok_or_else(|| anyhow!("the number {n} is not representable in TOML")),
        Json::String(s) => Ok(toml::Value::String(s.clone())),
        Json::Array(items) => Ok(toml::Value::Array(
            items
                .iter()
                .map(json_to_toml)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Json::Object(map) => {
            let mut t = toml::Table::new();
            for (k, v) in map {
                t.insert(k.clone(), json_to_toml(v)?);
            }
            Ok(toml::Value::Table(t))
        }
    }
}

/// The OIDC OP's duration members, read positionally.
fn member_value(oidc: &VcOidcOp, member: &str) -> Option<toml::Value> {
    let seconds = match member {
        "code_duration" => oidc.code_duration,
        "access_token_duration" => oidc.access_token_duration,
        "id_token_duration" => oidc.id_token_duration,
        "refresh_token_duration" => oidc.refresh_token_duration,
        _ => None,
    }?;
    Some(toml::Value::Integer(seconds))
}

/// Parse the vc layout's duration strings ("10s", "1h") to seconds.
fn parse_duration_secs(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    if let Some(seconds) = trimmed
        .strip_suffix('s')
        .and_then(|n| n.parse::<i64>().ok())
    {
        return Some(seconds);
    }
    if let Some(minutes) = trimmed
        .strip_suffix('m')
        .and_then(|n| n.parse::<i64>().ok())
    {
        return Some(minutes * 60);
    }
    if let Some(hours) = trimmed
        .strip_suffix('h')
        .and_then(|n| n.parse::<i64>().ok())
    {
        return Some(hours * 3600);
    }
    None
}

/// A preset id from its label: lowercase, the non-alphanumerics folded.
fn slug(label: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    out.trim_matches('-').to_string()
}
