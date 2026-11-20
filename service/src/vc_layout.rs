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
    /// The source member is `return` (a reserved word in Rust); the
    /// rename is load-bearing — losing it drops every result handle.
    #[serde(rename = "return")]
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
    "verifier.inbound.openid4vp.clients.*.client_id_env",
    "verifier.inbound.openid4vp.clients.*.client_secret",
    "verifier.inbound.openid4vp.clients.*.client_secret_env",
    "verifier.inbound.openid4vp.clients.*.redirect_uri",
    "verifier.inbound.openid4vp.clients.*.redirect_uris",
    "verifier.inbound.openid4vp.clients.*.type",
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
    "verifier.presets.*.credentials.*.claims",
    "verifier.presets.*.credentials.*.claims.path",
    "verifier.presets.*.credentials.*.format",
    "verifier.presets.*.credentials.*.req.fn_id",
    "verifier.presets.*.credentials.*.req.params",
    "verifier.presets.*.credentials.*.req.return",
    "verifier.zk_circuits.sources",
    "verifier.nym_auth.enable",
    "verifier.nym_auth.verifier_id",
    "verifier.nym_auth.circuits.allow.artifact_bytes",
    "verifier.nym_auth.circuits.allow.artifact_path",
    "verifier.nym_auth.circuits.allow.artifact_sha256",
    "verifier.nym_auth.circuits.allow.block_enc_hash",
    "verifier.nym_auth.circuits.allow.block_enc_sig",
    "verifier.nym_auth.circuits.allow.config",
    "verifier.nym_auth.circuits.allow.hash_circuit_id",
    "verifier.nym_auth.circuits.allow.sig_circuit_id",
    "verifier.nym_auth.circuits.allow.system_id",
    "common.production",
    "common.mongo.uri",
    "common.credential_registry.enable",
    "common.credential_registry.registries.mirrors.base_url",
    "common.credential_registry.registries.mirrors.timeout",
    "common.credential_registry.refresh_interval",
    "common.credential_metadata.*.doctype",
    "common.credential_metadata.*.format",
    "common.credential_metadata.*.vct",
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
    ("common.credential_metadata.*.credential_contexts", "ldp_vc context documents"),
    ("common.credential_metadata.*.mddl_file_path", "the mdoc metadata description list — no local metadata source in this service (the doctype rides the query meta)"),
    ("common.credential_metadata.*.vctm_file_path", "the vctm context document — no local metadata source in this service"),
    ("common.credential_metadata.*.credential_type_values", "ldp_vc type values"),
    ("common.credential_metadata.*.credential_types", "ldp_vc type names"),
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

/// The translated deployment: the proxy.toml text, the report, and the
/// bind the vc layout's api_server asked for (the operator's explicit
/// TUNNELBANA_BIND still wins).
pub struct Translation {
    pub toml: String,
    pub report: Report,
    /// The vc `api_server.addr` translated to a host:port bind
    /// (":8080" — the Go form — becomes "0.0.0.0:8080").
    pub bind_hint: Option<String>,
}

/// The translation's policy switches.
#[derive(Debug, Default)]
pub struct TranslateOptions {
    /// Permit a plain-HTTP PDP on a non-loopback address (the vc
    /// layout's own deployments commonly speak HTTP on a private
    /// network — fly's 6PN among them). Off by default: the translation
    /// refuses the URL and names the switch, rather than silently
    /// relaxing the transport policy.
    pub allow_insecure_pdp: bool,
    /// The claim the OIDC subject derives from. REQUIRED when the vc
    /// layout enables the OP (`outbound.oidc_provider`): a holder's
    /// name is not a unique identifier (two holders sharing a family
    /// name would share a subject), so the adapter refuses the OP
    /// without an explicit mapping. Absent an OP, the backend's own
    /// subject pointer defaults to the common PID family_name.
    pub subject_pointer: Option<String>,
    /// The supported credential whose fallback query carries the
    /// subject identifier's claim (`--subject-scope`). REQUIRED with a
    /// subject pointer when the layout supports more than one
    /// credential: the claim must ride a query the credential can
    /// actually fulfill (a PAN belongs on a PID query, not a
    /// diploma's — an unfulfillable claim would break every OP
    /// login). Defaults to the first supported credential, which is
    /// only right when there is exactly one.
    pub subject_scope: Option<String>,
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
pub fn translate(
    source: &str,
    source_dir: &std::path::Path,
    options: &TranslateOptions,
) -> Result<Translation> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|e| anyhow!("parsing the vc layout: {e}"))?;
    let mut report = classify(&doc)?;
    // The typed read happens on the same document the taxonomy walked:
    // the walk is the authority (it refused any unknown member above),
    // and the typed structs read the mapped subset, ignoring the
    // members the walk classified as known-unsupported.
    let cfg: VcConfig = serde_yaml::from_value(doc.clone())
        .map_err(|e| anyhow!("reading the mapped members: {e}"))?;
    let mut context = TranslateContext {
        source_dir,
        options,
        bind_hint: None,
    };
    let (toml, bind_hint) = emit(&cfg, &mut report, &mut context)?;
    report.mapped.sort();
    report.mapped.dedup();
    report.warned.sort();
    report.warned.dedup();
    Ok(Translation {
        toml,
        report,
        bind_hint,
    })
}

/// What the emitter needs beyond the parsed model.
struct TranslateContext<'a> {
    source_dir: &'a std::path::Path,
    options: &'a TranslateOptions,
    bind_hint: Option<String>,
}

/// Absolutize a source-relative file member against the source yaml's
/// own directory — the emitted config is location-independent (it
/// boots from a temp copy), so a relative mount path would resolve
/// against the wrong base.
fn absolute(source_dir: &std::path::Path, path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        source_dir.join(p).to_string_lossy().into_owned()
    }
}

fn emit(
    cfg: &VcConfig,
    report: &mut Report,
    context: &mut TranslateContext,
) -> Result<(String, Option<String>)> {
    let mut root = toml::Table::new();
    root.insert(
        "base_url".into(),
        toml::Value::String(emit_identity(cfg, report)),
    );
    emit_cookies(cfg, &mut root, report);
    emit_logging(cfg, &mut root);
    let mut frontends: Vec<toml::Value> = Vec::new();
    frontends.push(toml::Value::Table(emit_ui_frontend(cfg, report)?));
    if let Some(oidc) = emit_oidc_frontend(cfg, report, context)? {
        frontends.push(toml::Value::Table(oidc));
    }
    root.insert("frontend".into(), toml::Value::Array(frontends));
    let backends = vec![toml::Value::Table(emit_backend(cfg, report, context)?)];
    root.insert("backend".into(), toml::Value::Array(backends));
    let doc = toml::Value::Table(root);
    let toml = toml::to_string_pretty(&doc).map_err(|e| anyhow!("emitting the proxy.toml: {e}"))?;
    Ok((toml, context.bind_hint.take()))
}

/// The deployment's public identity. The vc-stack's OP issuer is the
/// verifier's own root; tunnelbana serves the OP under its frontend
/// module path — the issuer URL MOVES, and the RPs' discovery URL
/// follows. The report says so.
fn emit_identity(cfg: &VcConfig, report: &mut Report) -> String {
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
    // The layout's api_server.addr names the bind the vc service used
    // (":8080" — the Go form — means all interfaces); this service's
    // bind comes from its own TUNNELBANA_BIND, and the operator's
    // rewritten templating states it there.
    if let Some(addr) = cfg
        .verifier
        .api_server
        .as_ref()
        .and_then(|a| a.addr.clone())
    {
        report.note(format!(
            "verifier.api_server.addr {addr} — the bind is this service's own (TUNNELBANA_BIND); state it in the deployment's templating"
        ));
    }
    base_url
}

/// The state secret and the cookie shape. The state secret rides the
/// deploy tooling's existing env var — the same channel the vc layout's
/// own env substitution used.
fn emit_cookies(cfg: &VcConfig, root: &mut toml::Table, report: &mut Report) {
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
}

fn emit_logging(cfg: &VcConfig, root: &mut toml::Table) {
    let mut logging = toml::Table::new();
    logging.insert("level".into(), toml::Value::String("info".into()));
    logging.insert(
        "format".into(),
        toml::Value::String(
            if cfg.common.production.unwrap_or(false) {
                "json"
            } else {
                "pretty"
            }
            .into(),
        ),
    );
    root.insert("logging".into(), toml::Value::Table(logging));
}

/// The ui frontend: the presets (the labels carry over), the DC-API
/// invocation when the vc layout enables it, the registry mirrors.
fn emit_ui_frontend(cfg: &VcConfig, report: &mut Report) -> Result<toml::Table> {
    let mut ui = toml::Table::new();
    let mut ui_config = toml::Table::new();
    // The invocation surface follows the source's digital_credentials
    // flag: a deployment that disabled the DC API must not offer it.
    let mut invocation_names: Vec<&str> = vec!["qr", "link"];
    if cfg.verifier.digital_credentials.enable.unwrap_or(false) {
        invocation_names.insert(1, "dc-api");
    }
    ui_config.insert(
        "invocations".into(),
        toml::Value::Array(
            invocation_names
                .iter()
                .map(|s| toml::Value::String((*s).to_string()))
                .collect(),
        ),
    );
    ui_config.insert(
        "schemes".into(),
        toml::Value::Array(vec![toml::Value::String("openid4vp".into())]),
    );
    emit_registry(cfg, &mut ui_config);
    ui_config.insert(
        "presets".into(),
        toml::Value::Array(emit_presets(cfg, report)?),
    );
    ui.insert("type".into(), toml::Value::String("ui".into()));
    ui.insert("name".into(), toml::Value::String("ui".into()));
    ui.insert("config".into(), toml::Value::Table(ui_config));
    Ok(ui)
}

/// The registry mirrors: the first mirror's base_url becomes the ui
/// frontend's registry source — the exact schema-list endpoint, not the
/// bare base (Ts11Registry::build rejects anything else) — with its
/// host as the allowlist entry. The enable flag gates the whole block:
/// a deployment that disabled registry access must not fetch one.
fn emit_registry(cfg: &VcConfig, ui_config: &mut toml::Table) {
    let registry = match cfg.common.credential_registry.as_ref() {
        Some(r) if r.enable.unwrap_or(false) => r,
        _ => return,
    };
    let Some(mirror) = registry
        .registries
        .first()
        .and_then(|r| r.mirrors.first())
        .and_then(|m| m.base_url.clone())
    else {
        return;
    };
    let endpoint = format!("{}/api/v1/schemas.json", mirror.trim_end_matches('/'));
    ui_config.insert("registry_url".into(), toml::Value::String(endpoint.clone()));
    // The allowed host is the URL's host (no port, no path — the
    // registry compares against Url::host_str()).
    let host = url::Url::parse(&mirror)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
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

/// The presets: label (the vc map key), the credentials become DCQL. A
/// preset whose every credential uses an unsupported format is dropped
/// with the warning naming it.
fn emit_presets(cfg: &VcConfig, report: &mut Report) -> Result<Vec<toml::Value>> {
    let mut presets: Vec<toml::Value> = Vec::new();
    for (label, preset) in &cfg.verifier.presets {
        let mut credentials: Vec<toml::Value> = Vec::new();
        let mut unsupported: Vec<String> = Vec::new();
        for (scope, credential) in &preset.credentials {
            match credential_dcql(scope, credential, cfg)? {
                Some(query) => credentials.push(toml::Value::Table(query)),
                None => unsupported.push(scope.clone()),
            }
        }
        if credentials.is_empty() {
            // A wholly-unsupported preset is a capability the deployment
            // runs without — warned and dropped.
            report.warned.push((
                format!("verifier.presets.{label}"),
                "every credential in this preset uses a format this service does not support (ldp_vc, or the Vega mso_mdoc_zk profile) — the preset is dropped".into(),
            ));
            continue;
        }
        if !unsupported.is_empty() {
            // A MIXED preset would silently lose a credential
            // requirement — the reduced query is not what the operator
            // configured. Refuse it.
            return Err(anyhow!(
                "the preset '{label}' mixes credentials this service supports ({}) with ones it does not ({}) — refusing rather than emitting the reduced query",
                credentials.len(),
                unsupported.join(", ")
            ));
        }
        let mut entry = toml::Table::new();
        entry.insert("id".into(), toml::Value::String(slug(label)));
        entry.insert("label".into(), toml::Value::String(label.clone()));
        let mut dcql = toml::Table::new();
        dcql.insert("credentials".into(), toml::Value::Array(credentials));
        entry.insert("dcql".into(), toml::Value::Table(dcql));
        presets.push(toml::Value::Table(entry));
    }
    if presets.is_empty() {
        return Err(anyhow!(
            "no preset survives the translation — the ui frontend requires at least one, and an empty result means the layout's presentation surface would not boot"
        ));
    }
    Ok(presets)
}

/// The OP frontend: the vc layout's oidc_provider and its client roster.
/// `type: public` is the vc name for a PKCE-only client (auth method
/// "none"); a confidential client maps to client_secret_basic.
fn emit_oidc_frontend(
    cfg: &VcConfig,
    report: &mut Report,
    context: &TranslateContext,
) -> Result<Option<toml::Table>> {
    let Some(oidc) = cfg.verifier.outbound.oidc_provider.as_ref() else {
        return Ok(None);
    };
    // A holder's name is not a unique identifier: the OP demands an
    // explicit subject mapping (--subject-pointer).
    let subject_pointer = context.options.subject_pointer.as_deref().ok_or_else(|| {
        anyhow!(
            "verifier.outbound.oidc_provider is enabled but the vc layout names no subject member — pass --subject-pointer with a UNIQUE identifier claim (two holders sharing a name would share a subject)"
        )
    })?;
    // With more than one supported credential, the claim must ride the
    // scope the operator names — the first supported credential is only
    // right when there is exactly one.
    let supported_count = cfg
        .verifier
        .inbound
        .openid4vp
        .iter()
        .flat_map(|o| o.supported_credentials.iter())
        .count();
    if supported_count > 1 && context.options.subject_scope.is_none() {
        return Err(anyhow!(
            "the layout supports {supported_count} credentials — pass --subject-scope naming the credential whose query carries the subject identifier ({subject_pointer}); the first supported credential would only be right if there were exactly one"
        ));
    }
    report.mapped(format!(
        "--subject-pointer {subject_pointer} -> the OP's subject identifier"
    ));
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
        config.insert(
            "signing_key_path".into(),
            toml::Value::String(absolute(context.source_dir, &key_path)),
        );
        report.mapped("verifier.key_config.private_key_path -> frontend.config.signing_key_path");
    }
    config.insert(
        "signing_algorithm".into(),
        toml::Value::String("ES256".into()),
    );
    config.insert(
        "signing_key_id".into(),
        toml::Value::String("vc-layout-op".into()),
    );
    for (member, ttl) in [
        ("code_duration", "code_ttl"),
        ("access_token_duration", "access_token_ttl"),
        ("id_token_duration", "id_token_ttl"),
        ("refresh_token_duration", "refresh_token_ttl"),
    ] {
        if let Some(v) = member_value(oidc, member) {
            config.insert(ttl.into(), v);
        }
    }
    if oidc.subject_type.as_deref() == Some("pairwise") {
        report.warned.push((
            "verifier.outbound.oidc_provider.subject_type".into(),
            "pairwise subjects — this service's OP mints public subjects; the vc salt does not carry over".into(),
        ));
    }
    let clients = emit_clients(cfg, report);
    if !clients.is_empty() {
        config.insert("clients".into(), toml::Value::Array(clients));
    }
    fe.insert("config".into(), toml::Value::Table(config));
    Ok(Some(fe))
}

/// The client roster: the vc clients map (keyed by client id) becomes
/// the tunnelbana roster; the #935 `_env` fields pass through to this
/// service's own env resolution.
fn emit_clients(cfg: &VcConfig, report: &mut Report) -> Vec<toml::Value> {
    let mut clients: Vec<toml::Value> = Vec::new();
    let openid4vp = match cfg.verifier.inbound.openid4vp.as_ref() {
        Some(o) => o,
        None => return clients,
    };
    for (id, client) in &openid4vp.clients {
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
    clients
}

/// The openid4vp backend's config: the keys, the PDP, the WRPRC, the
/// receipt conventions, the fallback DCQL, the storage, the zkp block.
fn emit_backend(
    cfg: &VcConfig,
    report: &mut Report,
    context: &TranslateContext,
) -> Result<toml::Table> {
    let mut backend = toml::Table::new();
    backend.insert("type".into(), toml::Value::String("openid4vp".into()));
    backend.insert("name".into(), toml::Value::String("vp".into()));
    let mut bconfig = toml::Table::new();
    if let Some(key_config) = cfg.verifier.key_config.as_ref() {
        if let Some(path) = key_config.private_key_path.clone() {
            bconfig.insert(
                "request_signing_key_path".into(),
                toml::Value::String(absolute(context.source_dir, &path)),
            );
            report.mapped(
                "verifier.key_config.private_key_path -> backend.config.request_signing_key_path",
            );
        }
        if let Some(path) = key_config.chain_path.clone() {
            bconfig.insert(
                "request_certificate_chain_path".into(),
                toml::Value::String(absolute(context.source_dir, &path)),
            );
            report.mapped(
                "verifier.key_config.chain_path -> backend.config.request_certificate_chain_path",
            );
        }
    }
    if let Some(pdp) = cfg.verifier.trust.pdp_url.clone() {
        // The transport policy is NOT silently relaxed: a plain-HTTP
        // PDP on a non-loopback address needs the explicit opt-in
        // (the vc layouts commonly speak HTTP on a private network —
        // fly's 6PN among them), and then the emitted config states
        // it as loudly as the native config would.
        let insecure = pdp.starts_with("http://") && !is_loopback_url(&pdp);
        if insecure && !context.options.allow_insecure_pdp {
            return Err(anyhow!(
                "verifier.trust.pdp_url {pdp} is plain HTTP on a non-loopback address — pass --allow-insecure-pdp to permit it (a trusted private network), or point the layout at HTTPS"
            ));
        }
        bconfig.insert("pdp_endpoint".into(), toml::Value::String(pdp));
        if insecure {
            bconfig.insert("allow_insecure_http".into(), toml::Value::Boolean(true));
            report.warned.push((
                "verifier.trust.pdp_url".into(),
                "plain HTTP on a non-loopback address, permitted by the explicit --allow-insecure-pdp opt-in (allow_insecure_http = true in the emitted config)".into(),
            ));
        }
        report.mapped("verifier.trust.pdp_url -> backend.config.pdp_endpoint");
    }
    if let Some(wrprc) = cfg
        .verifier
        .registration_certificate
        .as_ref()
        .and_then(|r| r.path.clone())
    {
        bconfig.insert(
            "wrprc_path".into(),
            toml::Value::String(absolute(context.source_dir, &wrprc)),
        );
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
    // The vc layout has no subject-pointer member. An explicit mapping
    // wins; without one, the common PID family_name is the default —
    // UNLESS the OP rides (emit_oidc_frontend refuses that).
    let subject_pointer = context
        .options
        .subject_pointer
        .clone()
        .unwrap_or_else(|| "/family_name".to_string());
    bconfig.insert(
        "subject_pointer".into(),
        toml::Value::String(subject_pointer.clone()),
    );
    if context.options.subject_pointer.is_none() {
        report.note("backend.config.subject_pointer defaults to /family_name — pass --subject-pointer to map the deployment's subject claim");
    }
    bconfig.insert(
        "dcql".into(),
        toml::Value::Table(emit_fallback_dcql(
            cfg,
            report,
            &subject_pointer,
            context.options.subject_scope.as_deref(),
        )?),
    );
    bconfig.insert(
        "attribute_map".into(),
        toml::Value::Table(toml::Table::new()),
    );
    report.note("backend.config.attribute_map is empty — the UI's attribute naming (the result page's labels) is operator-added");
    emit_storage(cfg, &mut bconfig, report);
    if cfg.verifier.nym_auth.enable.unwrap_or(false) {
        bconfig.insert("zkp".into(), zkp_table(cfg, report, context.source_dir)?);
        report.mapped("verifier.nym_auth -> backend.config.zkp");
    } else {
        report.note("verifier.nym_auth.enable is off — no zkp block");
    }
    backend.insert("config".into(), toml::Value::Table(bconfig));
    Ok(backend)
}

/// The fallback DCQL: one entry per supported credential whose format
/// this service speaks. Claims stay deliberately empty (the
/// mandatory-only request); the presets carry the real queries.
fn emit_fallback_dcql(
    cfg: &VcConfig,
    report: &mut Report,
    subject_pointer: &str,
    subject_scope: Option<&str>,
) -> Result<toml::Table> {
    let metadata = &cfg.common.credential_metadata;
    let mut credentials: Vec<toml::Value> = Vec::new();
    let mut subject_claim: Option<String> = None;
    let mut subject_index: Option<usize> = None;
    let subject_scope_name = subject_scope.map(str::to_string);
    // The identifier's claim path, as a DCQL claims entry.
    let segments: Vec<toml::Value> = subject_pointer
        .trim_start_matches('/')
        .split('/')
        .map(|s| toml::Value::String(s.to_string()))
        .collect();
    let mut subject_claim_path = toml::Table::new();
    subject_claim_path.insert("path".into(), toml::Value::Array(segments));
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
        let mut query = match credential_query(scope, meta) {
            Some(query) => query,
            None => {
                report.warned.push((
                    format!("verifier.inbound.openid4vp.supported_credentials (scope {scope})"),
                    format!(
                        "the {} format is not supported (ldp_vc or unknown) — dropped from the fallback DCQL",
                        meta.format.as_deref().unwrap_or("unset")
                    ),
                ));
                continue;
            }
        };
        // The OP's OIDC logins ride this fallback — the subject
        // identifier's claim must ride a query the credential can
        // FULFILL: the operator names the scope; the first supported
        // credential is only right when there is exactly one.
        let subject_query = match &subject_scope_name {
            Some(want) => scope == want,
            None => subject_claim.is_none(),
        };
        if subject_query {
            subject_claim = Some(scope.clone());
            subject_index = Some(credentials.len());
            if let Some(claims) = query.get_mut("claims").and_then(|c| c.as_array_mut()) {
                claims.push(toml::Value::Table(subject_claim_path.clone()));
            } else {
                query.insert(
                    "claims".into(),
                    toml::Value::Array(vec![toml::Value::Table(subject_claim_path.clone())]),
                );
            }
        }
        credentials.push(toml::Value::Table(query));
    }
    // An explicitly named scope must resolve to an EMITTED query: a
    // scope that does not exist, or one dropped for a missing metadata
    // entry or an unsupported format, would leave the fallback without
    // the subject identifier — a presentation without the claim would
    // pass verification and fail at the subject.
    if let (Some(scope), None) = (&subject_scope_name, &subject_claim) {
        return Err(anyhow!(
            "--subject-scope {scope} does not resolve to an emitted fallback query — the scope is not among supported_credentials, or its format is not supported"
        ));
    }
    // The subject query goes FIRST: the runtime's merge takes the
    // first credential carrying the claim, and a differently-ordered
    // credential with the same claim name would otherwise supply the
    // subject (a diploma's `sub` instead of the selected PID's).
    if let Some(index) = subject_index.filter(|i| *i > 0) {
        let query = credentials.remove(index);
        credentials.insert(0, query);
    }
    let mut dcql = toml::Table::new();
    dcql.insert("credentials".into(), toml::Value::Array(credentials));
    if subject_claim.is_some() {
        report.mapped(
            "--subject-pointer -> backend.config.dcql[0].claims — the fallback requests the subject identifier",
        );
    }
    Ok(dcql)
}

/// The storage: the vc mongo URI carries verbatim (its own credentials
/// ride inside it, or the vc layout's env substitution). Absent mongo —
/// the single-process memory store.
fn emit_storage(cfg: &VcConfig, bconfig: &mut toml::Table, report: &mut Report) {
    let mut storage = toml::Table::new();
    if let Some(mongo) = cfg.common.mongo.as_ref().and_then(|m| m.uri.clone()) {
        storage.insert("backend".into(), toml::Value::String("mongodb".into()));
        storage.insert("uri".into(), toml::Value::String(mongo));
        report.mapped("common.mongo.uri -> backend.config.storage.uri");
        storage.insert(
            "database".into(),
            toml::Value::String("siros_verifier".into()),
        );
        storage.insert(
            "collection".into(),
            toml::Value::String("presentation_flows".into()),
        );
        report.note("backend.config.storage database/collection follow this service's convention (the vc layout names no flow store)");
    } else {
        storage.insert("backend".into(), toml::Value::String("memory".into()));
        report.warned.push((
            "common.mongo".into(),
            "absent — the translated deployment runs single-process memory storage".into(),
        ));
    }
    bconfig.insert("storage".into(), toml::Value::Table(storage));
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
) -> Result<Option<toml::Table>> {
    let meta = cfg.common.credential_metadata.get(scope);
    let format = match credential
        .format
        .as_deref()
        .or(meta.and_then(|m| m.format.as_deref()))
    {
        Some(format) => format,
        None => return Ok(None),
    };
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
            // The vc mdoc claims are [namespace, element] paths — the
            // same shape this service's DCQL speaks; explicit empty
            // when none were selected (the validator requires the
            // member).
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
        // The vc circuit_zk naming and this service's zkp_req are the
        // same shape: an explicit req list of named functions. The
        // Vega-style `mso_mdoc_zk` profile (claims + zk_system_type,
        // no req) is a DIFFERENT proof profile — it falls through to
        // the None arm and the preset is dropped with the warning.
        "circuit_zk" | "zkp_req" => {
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
            // An incomplete request function (no fn_id) is a lost
            // requirement, not a filterable entry — refuse it.
            let mut reqs: Vec<toml::Value> = Vec::with_capacity(credential.req.len());
            for r in &credential.req {
                let fn_id = r.fn_id.as_deref().ok_or_else(|| {
                    anyhow!("preset credential '{scope}': a req entry has no fn_id")
                })?;
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
                reqs.push(toml::Value::Table(entry));
            }
            q.insert("_req".into(), reqs.into());
        }
        _ => return Ok(None),
    }
    Ok(Some(q))
}

/// The zkp block from the vc nym_auth circuits: the allowlist maps
/// verbatim (the artifact paths and the pinned hashes carry over), the
/// query comes from the first zkp preset (the deployment's own
/// vehicle), the system/proof values from the allowlist's system_ids.
fn zkp_table(
    cfg: &VcConfig,
    _report: &mut Report,
    source_dir: &std::path::Path,
) -> Result<toml::Value> {
    let allow = &cfg.verifier.nym_auth.circuits.allow;
    if allow.is_empty() {
        return Err(anyhow!(
            "verifier.nym_auth.enable is on but circuits.allow is empty — the zkp backend refuses to start without a circuit"
        ));
    }
    // Every distinct zkp preset query, in the presets' own order: the
    // first becomes the fallback query, each of the rest rides the
    // profiles list with its own subject handle (a preset is served
    // only when its exact query is configured).
    let queries = zkp_queries_from_presets(cfg);
    let first = queries.first().cloned().ok_or_else(|| {
        anyhow!(
            "verifier.nym_auth.enable is on but no preset carries a circuit_zk/zkp_req query — the zkp backend needs its fallback query"
        )
    })?;
    let handle = query_return(&first, "pseudonym").ok_or_else(|| {
        anyhow!("the zkp query has no pseudonym function — the subject handle must name a pseudonym result")
    })?;
    let mut zkp = toml::Table::new();
    zkp.insert("query".into(), toml::Value::Table(first));
    zkp.insert("system_id_values".into(), system_id_values(allow));
    zkp.insert("proof_system_values".into(), proof_system_values(allow));
    zkp.insert("role".into(), toml::Value::String("mdoc-issuer".into()));
    if let Some(verifier_id) = cfg.verifier.nym_auth.verifier_id.clone() {
        zkp.insert("verifier_id".into(), toml::Value::String(verifier_id));
    }
    zkp.insert("subject_handle".into(), toml::Value::String(handle.clone()));
    let mut attribute_map = toml::Table::new();
    attribute_map.insert("pseudonym".into(), toml::Value::String(handle));
    zkp.insert("attribute_map".into(), toml::Value::Table(attribute_map));
    zkp.insert(
        "auth_class_ref".into(),
        toml::Value::String("urn:eudi:loa:high".into()),
    );
    let mut profiles: Vec<toml::Value> = Vec::new();
    for query in queries.iter().skip(1) {
        let handle = query_return(query, "pseudonym").ok_or_else(|| {
            anyhow!("a zkp preset query has no pseudonym function — the subject handle must name a pseudonym result")
        })?;
        let mut profile = toml::Table::new();
        profile.insert("query".into(), toml::Value::Table(query.clone()));
        profile.insert("subject_handle".into(), toml::Value::String(handle.clone()));
        let mut map = toml::Table::new();
        map.insert("pseudonym".into(), toml::Value::String(handle));
        profile.insert("attribute_map".into(), toml::Value::Table(map));
        profiles.push(toml::Value::Table(profile));
    }
    if !profiles.is_empty() {
        zkp.insert("profiles".into(), toml::Value::Array(profiles));
    }
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
                // The artifact path is a file member: absolutize it
                // like every other source-relative path.
                if key == "artifact_path" {
                    if let Some(path) = v.as_str() {
                        t.insert(key.clone(), toml::Value::String(absolute(source_dir, path)));
                        continue;
                    }
                }
                t.insert(key.clone(), v);
            }
        }
        allow_entries.push(toml::Value::Table(t));
    }
    circuits.insert("allow".into(), toml::Value::Array(allow_entries));
    zkp.insert("circuits".into(), toml::Value::Table(circuits));
    Ok(toml::Value::Table(zkp))
}

/// Every distinct zkp preset query, in the presets' own order.
fn zkp_queries_from_presets(cfg: &VcConfig) -> Vec<toml::Table> {
    let mut queries: Vec<toml::Table> = Vec::new();
    for preset in cfg.verifier.presets.values() {
        for (scope, credential) in &preset.credentials {
            if let Some(q) = credential_dcql(scope, credential, cfg).ok().flatten() {
                if q.get("format").and_then(|f| f.as_str()) == Some("zkp_req")
                    && !queries.iter().any(|existing| existing == &q)
                {
                    queries.push(q);
                }
            }
        }
    }
    queries
}

/// The allowlist's system ids, in order.
fn system_id_values(allow: &[BTreeMap<String, Json>]) -> toml::Value {
    toml::Value::Array(
        allow
            .iter()
            .filter_map(|e| e.get("system_id").and_then(|v| v.as_str()))
            .map(|s| toml::Value::String(s.to_string()))
            .collect(),
    )
}

/// The proof-system name for each allowlist entry: the vc layout names
/// the system id; the proof system follows it (vega's entries carry
/// vega's prover name, everything else the longfellow one).
fn proof_system_values(allow: &[BTreeMap<String, Json>]) -> toml::Value {
    toml::Value::Array(
        allow
            .iter()
            .filter_map(|e| e.get("system_id").and_then(|v| v.as_str()))
            .map(|s| {
                toml::Value::String(if s.contains("vega") {
                    "vega-v1".to_string()
                } else {
                    "longfellow-libzk-v1".to_string()
                })
            })
            .collect(),
    )
}

/// A req function's return value, by its fn_id — the subject handle and
/// the attribute map derive from the pseudonym function's return name.
fn query_return(query: &toml::Table, fn_id: &str) -> Option<String> {
    let reqs = query.get("_req")?.as_array()?;
    for req in reqs.iter().filter_map(|r| r.as_table()) {
        if req.get("fn_id").and_then(|v| v.as_str()) == Some(fn_id) {
            return req
                .get("return")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
    }
    None
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

/// Whether a URL's host is a loopback address (the only plain-HTTP PDP
/// the native config permits without the escape hatch).
fn is_loopback_url(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
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
